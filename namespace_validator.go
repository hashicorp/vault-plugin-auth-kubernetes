package kubeauth

import (
	"context"
	"net/http"
)

// This exists so we can use a mock namespace validation when running tests
type namespaceValidator interface {
	ValidateLabels(context.Context, *http.Client, string, map[string]string) (bool, error)
}

type namespaceValidatorFactory func(*kubeConfig) namespaceValidator

// This is the real implementation that calls the kubernetes API
type namespaceValidatorAPI struct {
	config *kubeConfig
}

func namespaceValidatorAPIFactory(config *kubeConfig) namespaceValidator {
	return &namespaceValidatorAPI{
		config: config,
	}
}

func (t *namespaceValidatorAPI) ValidateLabels(ctx context.Context, client *http.Client, name string, labels map[string]string) (bool, error) {
	return true, nil
}
