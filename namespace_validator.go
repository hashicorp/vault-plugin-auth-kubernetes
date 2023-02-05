package kubeauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	k8s_yaml "k8s.io/apimachinery/pkg/util/yaml"
)

// This exists so we can use a mock namespace validation when running tests
type namespaceValidator interface {
	ValidateLabels(context.Context, *http.Client, string, metav1.LabelSelector) (bool, error)
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

func (v *namespaceValidatorAPI) ValidateLabels(ctx context.Context, client *http.Client, namespace string, selector metav1.LabelSelector) (bool, error) {
	nsLabels, err := v.getNamespaceLabels(ctx, client, namespace)
	if err != nil {
		return false, err
	}

	labelSelector, err := metav1.LabelSelectorAsSelector(&selector)
	if err != nil {
		return false, err
	}
	return labelSelector.Matches(labels.Set(nsLabels)), nil
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

func (v *namespaceValidatorAPI) getNamespaceLabels(ctx context.Context, client *http.Client, namespace string) (map[string]string, error) {
	url := fmt.Sprintf("%s/api/v1/namespaces/%s", strings.TrimSuffix(v.config.Host, "/"), namespace)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	// If we have a configured TokenReviewer JWT use it as the bearer, otherwise
	// try to use the passed in JWT.
	if v.config.TokenReviewerJWT == "" {
		return nil, errors.New("namespace lookup failed: TokenReviewer JWT needs to be configured to use namespace selectors")
	}
	bearer := fmt.Sprintf("Bearer %s", v.config.TokenReviewerJWT)
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
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("failed to get namespace (code %d): %s", resp.StatusCode, body)
	}
	ns := v1.Namespace{}

	err = json.Unmarshal(body, &ns)
	if err != nil {
		return nil, err
	}
	return ns.Labels, nil
}

type mockNamespaceValidator struct {
	labels map[string]string
}

func mockNamespaceValidatorFactory(labels map[string]string) namespaceValidatorFactory {
	return func(config *kubeConfig) namespaceValidator {
		return &mockNamespaceValidator{
			labels: labels,
		}
	}
}

func (v *mockNamespaceValidator) ValidateLabels(ctx context.Context, client *http.Client, namespace string, selector metav1.LabelSelector) (bool, error) {
	labelSelector, err := metav1.LabelSelectorAsSelector(&selector)
	if err != nil {
		return false, err
	}
	return labelSelector.Matches(labels.Set(v.labels)), nil
}
