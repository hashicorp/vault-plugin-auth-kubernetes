package kubeauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	k8s_yaml "k8s.io/apimachinery/pkg/util/yaml"
)

// This exists so we can use a mock namespace validation when running tests
type namespaceValidator interface {
	ValidateLabels(context.Context, *http.Client, string, string) (bool, error)
}

type namespaceValidateFactory func(*kubeConfig) namespaceValidator

// This is the real implementation that calls the kubernetes API
type namespaceValidateAPI struct {
	config *kubeConfig
}

func namespaceValidateAPIFactory(config *kubeConfig) namespaceValidator {
	return &namespaceValidateAPI{
		config: config,
	}
}

func (v *namespaceValidateAPI) ValidateLabels(ctx context.Context, client *http.Client, namespace string, namespaceSelector string) (bool, error) {
	labelSelector, err := makeLabelSelector(namespaceSelector)
	if err != nil {
		return false, err
	}
	nsLabels, err := v.getNamespaceLabels(ctx, client, namespace)
	if err != nil {
		return false, err
	}
	selector, err := metav1.LabelSelectorAsSelector(&labelSelector)
	if err != nil {
		return false, err
	}
	return selector.Matches(labels.Set(nsLabels)), nil
}

func makeLabelSelector(selector string) (metav1.LabelSelector, error) {
	labelSelector := metav1.LabelSelector{}
	decoder := k8s_yaml.NewYAMLOrJSONDecoder(strings.NewReader(selector), len(selector))
	err := decoder.Decode(&labelSelector)
	if err != nil {
		return labelSelector, err
	}
	return labelSelector, nil
}

func (v *namespaceValidateAPI) getNamespaceLabels(ctx context.Context, client *http.Client, namespace string) (map[string]string, error) {
	url := fmt.Sprintf("%s/api/v1/namespaces/%s", strings.TrimSuffix(v.config.Host, "/"), namespace)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	// Use the configured TokenReviewer JWT as the bearer
	if v.config.TokenReviewerJWT == "" {
		return nil, errors.New("namespace lookup failed: TokenReviewer JWT needs to be configured to use namespace selectors")
	}
	bearer := fmt.Sprintf("Bearer %s", v.config.TokenReviewerJWT)
	setRequestHeader(req, bearer)

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("failed to get namespace (code %d): %s", resp.StatusCode, body)
	}
	var ns v1.Namespace
	err = json.Unmarshal(body, &ns)
	if err != nil {
		return nil, err
	}
	return ns.Labels, nil
}

type mockNamespaceValidator struct {
	labels map[string]string
}

func mockNamespaceValidateFactory(labels map[string]string) namespaceValidateFactory {
	return func(config *kubeConfig) namespaceValidator {
		return &mockNamespaceValidator{
			labels: labels,
		}
	}
}

func (v *mockNamespaceValidator) ValidateLabels(ctx context.Context, client *http.Client, namespace string, namespaceSelector string) (bool, error) {
	labelSelector, err := makeLabelSelector(namespaceSelector)
	if err != nil {
		return false, err
	}
	selector, err := metav1.LabelSelectorAsSelector(&labelSelector)
	if err != nil {
		return false, err
	}
	return selector.Matches(labels.Set(v.labels)), nil
}
