package kubeauth

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	cleanhttp "github.com/hashicorp/go-cleanhttp"
	authv1 "k8s.io/api/authentication/v1"
	kubeerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// This is the result from a token review.
type tokenReviewResult struct {
	Name      string
	Namespace string
	UID       string
}

// This exists so we can use a mock TokenReview when running tests
type tokenClient interface {
	Request(ctx context.Context, jwt string, sa serviceAccount) (authv1.TokenRequestStatus, error)
	Review(ctx context.Context, jwt string, audience []string) (*tokenReviewResult, error)
}

type tokenClientFactory func(*kubeConfig) tokenClient

// This is the real implementation that calls the kubernetes API
type kubernetesTokenClient struct {
	config *kubeConfig
}

func tokenReviewAPIFactory(config *kubeConfig) tokenClient {
	return &kubernetesTokenClient{
		config: config,
	}
}

func (t *kubernetesTokenClient) Request(ctx context.Context, jwt string, sa serviceAccount) (authv1.TokenRequestStatus, error) {
	client := t.getHTTPClient()

	expirationSeconds := sa.Expiration - sa.IssuedAt
	// Create the TokenReview Object and marshal it into json
	trReq := &authv1.TokenRequest{
		Spec: authv1.TokenRequestSpec{
			Audiences:         sa.Audience,
			ExpirationSeconds: &expirationSeconds,
			// The TokenRequest API only accepts pods or secret objects as owners.
			// Neither is universally appropriate here as we will normally be using
			// this API when running from outside the cluster.
			BoundObjectRef: nil,
		},
	}
	trJSON, err := json.Marshal(trReq)
	if err != nil {
		return authv1.TokenRequestStatus{}, err
	}

	// Build the request to the token review API
	// POST /api/v1/namespaces/{namespace}/serviceaccounts/{name}/token
	url := fmt.Sprintf("%s/api/v1/namespaces/%s/serviceaccounts/%s/token",
		strings.TrimSuffix(t.config.Host, "/"),
		sa.namespace(),
		sa.name(),
	)
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(trJSON))
	if err != nil {
		return authv1.TokenRequestStatus{}, err
	}

	// Set the JWT as the Bearer token
	req.Header.Set("Authorization", strings.TrimSpace(fmt.Sprintf("Bearer %s", jwt)))

	// Set the MIME type headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return authv1.TokenRequestStatus{}, err
	}

	// Parse the resp into a TokenRequestStatus object or a kubernetes error type
	body, err := parseError(resp)
	switch {
	case kubeerrors.IsUnauthorized(err):
		// Try to give some extra description for the most common cases.
		return authv1.TokenRequestStatus{}, errors.New("token request failed: service account unauthorized; this could mean the token has expired or the service account has insufficient permissions")
	case err != nil:
		return authv1.TokenRequestStatus{}, err
	}

	requestResp := &authv1.TokenRequest{}
	err = json.Unmarshal(body, requestResp)
	if err != nil {
		return authv1.TokenRequestStatus{}, err
	}

	return requestResp.Status, nil
}

func (t *kubernetesTokenClient) Review(ctx context.Context, jwt string, aud []string) (*tokenReviewResult, error) {
	client := t.getHTTPClient()

	// Create the TokenReview Object and marshal it into json
	trReq := &authv1.TokenReview{
		Spec: authv1.TokenReviewSpec{
			Token:     jwt,
			Audiences: aud,
		},
	}
	trJSON, err := json.Marshal(trReq)
	if err != nil {
		return nil, err
	}

	// Build the request to the token review API
	url := fmt.Sprintf("%s/apis/authentication.k8s.io/v1/tokenreviews", strings.TrimSuffix(t.config.Host, "/"))
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(trJSON))
	if err != nil {
		return nil, err
	}

	// If we have a configured TokenReviewer JWT use it as the bearer, otherwise
	// try to use the passed in JWT.
	bearer := fmt.Sprintf("Bearer %s", jwt)
	if len(t.config.TokenReviewerJWT) > 0 {
		bearer = fmt.Sprintf("Bearer %s", t.config.TokenReviewerJWT)
	}
	bearer = strings.TrimSpace(bearer)

	// Set the JWT as the Bearer token
	req.Header.Set("Authorization", bearer)

	// Set the MIME type headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	// Parse the resp into a tokenreview object or a kubernetes error type
	r, err := parseReviewResponse(resp)
	switch {
	case kubeerrors.IsUnauthorized(err):
		// If the err is unauthorized that means the token has since been deleted;
		// this can happen if the service account is deleted, and even if it has
		// since been recreated the token will have changed, which means our
		// caller will need to be updated accordingly.
		return nil, errors.New("lookup failed: service account unauthorized; this could mean it has been deleted or recreated with a new token")
	case err != nil:
		return nil, err
	}

	if r.Status.Error != "" {
		return nil, fmt.Errorf("lookup failed: %s", r.Status.Error)
	}

	if !r.Status.Authenticated {
		return nil, errors.New("lookup failed: service account jwt not valid")
	}

	// The username is of format: system:serviceaccount:(NAMESPACE):(SERVICEACCOUNT)
	parts := strings.Split(r.Status.User.Username, ":")
	if len(parts) != 4 {
		return nil, errors.New("lookup failed: unexpected username format")
	}

	// Validate the user that comes back from token review is a service account
	if parts[0] != "system" || parts[1] != "serviceaccount" {
		return nil, errors.New("lookup failed: username returned is not a service account")
	}

	return &tokenReviewResult{
		Name:      parts[3],
		Namespace: parts[2],
		UID:       string(r.Status.User.UID),
	}, nil
}

// parseReviewResponse takes the API response and either returns the appropriate error
// or the TokenReview Object.
func parseReviewResponse(resp *http.Response) (*authv1.TokenReview, error) {
	body, err := parseError(resp)
	if err != nil {
		return nil, err
	}

	// Unmarshal the resp body into a TokenReview Object
	trResp := &authv1.TokenReview{}
	err = json.Unmarshal(body, trResp)
	if err != nil {
		return nil, err
	}

	return trResp, nil
}

// parseError checks for Kubernetes errors from an HTTP response, and returns
// the body for further parsing if none found.
func parseError(resp *http.Response) ([]byte, error) {
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// If the request was not a success create a kubernetes error
	if resp.StatusCode < http.StatusOK || resp.StatusCode > 299 {
		return nil, kubeerrors.NewGenericServerResponse(resp.StatusCode, "POST", schema.GroupResource{}, "", strings.TrimSpace(string(body)), 0, true)
	}

	// Check for non-success status in metadata.
	status := &metav1.Status{}
	err = json.Unmarshal(body, status)
	if err == nil && status.Status != metav1.StatusSuccess {
		return nil, kubeerrors.FromObject(runtime.Object(status))
	}

	return body, nil
}

func (t *kubernetesTokenClient) getHTTPClient() *http.Client {
	client := cleanhttp.DefaultClient()

	// If we have a CA cert build the TLSConfig
	if len(t.config.CACert) > 0 {
		certPool := x509.NewCertPool()
		certPool.AppendCertsFromPEM([]byte(t.config.CACert))

		tlsConfig := &tls.Config{
			MinVersion: tls.VersionTLS12,
			RootCAs:    certPool,
		}

		client.Transport.(*http.Transport).TLSClientConfig = tlsConfig
	}

	return client
}

// mock review is used while testing
type mockTokenReview struct {
	saName      string
	saNamespace string
	saUID       string
}

func mockTokenReviewFactory(name, namespace, UID string) tokenClientFactory {
	return func(config *kubeConfig) tokenClient {
		return &mockTokenReview{
			saName:      name,
			saNamespace: namespace,
			saUID:       UID,
		}
	}
}

func (t *mockTokenReview) Request(_ context.Context, _ string, _ serviceAccount) (authv1.TokenRequestStatus, error) {
	return authv1.TokenRequestStatus{}, nil
}

func (t *mockTokenReview) Review(ctx context.Context, cjwt string, aud []string) (*tokenReviewResult, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	return &tokenReviewResult{
		Name:      t.saName,
		Namespace: t.saNamespace,
		UID:       t.saUID,
	}, nil
}
