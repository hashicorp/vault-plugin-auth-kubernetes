package kubeauth

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	cleanhttp "github.com/hashicorp/go-cleanhttp"
	corev1 "k8s.io/api/core/v1"
	kubeerrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

const allowedAnnotationPrefix = "auth-metadata.vault.hashicorp.com/"

type serviceAccountReader interface {
	ReadAnnotations(ctx context.Context, name, namespace string) (map[string]string, error)
}

type serviceAccountReaderFactory func(*kubeConfig) serviceAccountReader

func serviceAccountAPIFactory(config *kubeConfig) serviceAccountReader {
	s := &serviceAccountAPI{
		client: cleanhttp.DefaultPooledClient(),
		config: config,
	}

	// If we have a CA cert build the TLSConfig
	if len(config.CACert) > 0 {
		certPool := x509.NewCertPool()
		certPool.AppendCertsFromPEM([]byte(config.CACert))

		tlsConfig := &tls.Config{
			MinVersion: tls.VersionTLS12,
			RootCAs:    certPool,
		}

		s.client.Transport.(*http.Transport).TLSClientConfig = tlsConfig
	}

	return s
}

type serviceAccountAPI struct {
	client *http.Client
	config *kubeConfig
}

func (s *serviceAccountAPI) ReadAnnotations(ctx context.Context, name, namespace string) (map[string]string, error) {
	url := fmt.Sprintf("%s/api/v1/namespaces/%s/serviceaccounts/%s", strings.TrimSuffix(s.config.Host, "/"), namespace, name)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	bearer := fmt.Sprintf("Bearer %s", strings.TrimSpace(s.config.TokenReviewerJWT))

	req.Header.Set("Authorization", bearer)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	rsp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to talk to kubernetes API: %v", err)
	}

	svcAccount, err := parseServiceAccountResponse(rsp)
	if err != nil {
		return nil, fmt.Errorf("failed to parse serviceaccount response: %v", err)
	}

	// Filter for annotations that have a prefix and are destined for this plugin
	filtered := map[string]string{}
	for key, value := range svcAccount.Annotations {
		if strings.HasPrefix(key, allowedAnnotationPrefix) {
			// Normalise the annotations to match the current snake_case pattern.
			// Ex: auth-metadata.vault.hashicorp.com/service-role: authorization
			// Will become: service_role: authorization
			key := strings.ReplaceAll(strings.TrimPrefix(key, allowedAnnotationPrefix), "-", "_")
			filtered[key] = value
		}
	}

	return filtered, nil
}

// parseResponse takes the API response and either returns the appropriate error
// or the TokenReview Object.
func parseServiceAccountResponse(rsp *http.Response) (*corev1.ServiceAccount, error) {
	body, err := ioutil.ReadAll(rsp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read out body: %v", err)
	}
	defer rsp.Body.Close()

	if rsp.StatusCode < http.StatusOK || rsp.StatusCode > http.StatusPartialContent {
		return nil, kubeerrors.NewGenericServerResponse(rsp.StatusCode, "POST", schema.GroupResource{}, "", strings.TrimSpace(string(body)), 0, true)
	}

	svcAccount := &corev1.ServiceAccount{}
	err = json.Unmarshal(body, svcAccount)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal into corev1.ServiceAccount: %v", err)
	}

	return svcAccount, nil
}
