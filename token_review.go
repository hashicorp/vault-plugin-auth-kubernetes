package kubeauth

import (
	"errors"
	"fmt"
	"strings"

	kubeerrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/client-go/kubernetes"
	authv1 "k8s.io/client-go/pkg/apis/authentication/v1"
	"k8s.io/client-go/rest"
)

// This is the result from the token review
type tokenReviewResult struct {
	Name      string
	Namespace string
	UID       string
}

// This exists so we can use a mock TokenReview when running tests
type tokenReviewer interface {
	Review(string) (*tokenReviewResult, error)
}

type tokenReviewFactory func(*kubeConfig) tokenReviewer

// This is the real implementation that calls the kubernetes API
type tokenReviewAPI struct {
	config *kubeConfig
}

func tokenReviewAPIFactory(config *kubeConfig) tokenReviewer {
	return &tokenReviewAPI{
		config: config,
	}
}

func (t *tokenReviewAPI) Review(jwt string) (*tokenReviewResult, error) {
	clientConfig := &rest.Config{
		BearerToken: jwt,
		Host:        t.config.Host,
		TLSClientConfig: rest.TLSClientConfig{
			CAData: []byte(t.config.CACert),
		},
	}
	clientset, err := kubernetes.NewForConfig(clientConfig)
	if err != nil {
		return nil, err
	}

	r, err := clientset.AuthenticationV1().TokenReviews().Create(&authv1.TokenReview{
		Spec: authv1.TokenReviewSpec{
			Token: jwt,
		},
	})
	switch {
	case kubeerrors.IsUnauthorized(err):
		// If the err is unauthorized that means the token has since been deleted
		return nil, errors.New("lookup failed: service account deleted")
	case err != nil:
		return nil, err
	case r == nil:
		return nil, errors.New("lookup failed: no status returned")
	}

	if r.Status.Error != "" {
		return nil, fmt.Errorf("lookup failed: %s", r.Status.Error)
	}

	if !r.Status.Authenticated {
		return nil, errors.New("lookup failed: service account jwt not valid")
	}

	// the username is of format: system:serviceaccount:(NAMESPACE):(SERVICEACCOUNT)
	parts := strings.Split(r.Status.User.Username, ":")
	if len(parts) != 4 {
		return nil, errors.New("lookup failed: unexpected username format")
	}

	return &tokenReviewResult{
		Name:      parts[3],
		Namespace: parts[2],
		UID:       string(r.Status.User.UID),
	}, nil
}

// mock review is used while testing
type mockTokenReview struct {
	saName      string
	saNamespace string
	saUID       string
}

func mockTokenReviewFactory(name, namespace, UID string) tokenReviewFactory {
	return func(config *kubeConfig) tokenReviewer {
		return &mockTokenReview{
			saName:      name,
			saNamespace: namespace,
			saUID:       UID,
		}
	}
}

func (t *mockTokenReview) Review(jwt string) (*tokenReviewResult, error) {
	return &tokenReviewResult{
		Name:      t.saName,
		Namespace: t.saNamespace,
		UID:       t.saUID,
	}, nil
}
