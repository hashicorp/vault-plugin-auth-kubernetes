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
	kubeerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	k8s_yaml "k8s.io/apimachinery/pkg/util/yaml"
)

// namespaceValidator defines a namespace validator interface
type namespaceValidator interface {
	validateLabels(context.Context, *http.Client, string, string) (bool, error)
}

type namespaceValidatorFactory func(*kubeConfig) namespaceValidator

// This is the real implementation that calls the kubernetes API
type namespaceValidatorWrapper struct {
	config *kubeConfig
}

func newNsValidatorWrapper(config *kubeConfig) namespaceValidator {
	return &namespaceValidatorWrapper{
		config: config,
	}
}

func (v *namespaceValidatorWrapper) validateLabels(ctx context.Context, client *http.Client, namespace string, namespaceSelector string) (bool, error) {
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

func (v *namespaceValidatorWrapper) getNamespaceLabels(ctx context.Context, client *http.Client, namespace string) (map[string]string, error) {
	url := fmt.Sprintf("%s/api/v1/namespaces/%s", strings.TrimSuffix(v.config.Host, "/"), namespace)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	// Use the configured TokenReviewer JWT as the bearer
	if v.config.TokenReviewerJWT == "" {
		return nil, errors.New("namespace lookup failed: TokenReviewer JWT needs to be configured to use namespace selectors")
	}
	setRequestHeader(req, fmt.Sprintf("Bearer %s", v.config.TokenReviewerJWT))

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		errStatus := &metav1.Status{}
		err = json.Unmarshal(body, errStatus)
		if err == nil && errStatus.Status != metav1.StatusSuccess {
			return nil, fmt.Errorf("failed to get namespace (code %d status %s)",
				resp.StatusCode, kubeerrors.FromObject(runtime.Object(errStatus)))
		}
		return nil, fmt.Errorf("failed to parse error status on namespace retrieval failure err=%s", err)
	}
	var ns v1.Namespace
	err = json.Unmarshal(body, &ns)
	if err != nil {
		return nil, err
	}
	return ns.Labels, nil
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

type mockNamespaceValidator struct {
	labels map[string]string
}

func mockNamespaceValidateFactory(labels map[string]string) namespaceValidatorFactory {
	return func(config *kubeConfig) namespaceValidator {
		return &mockNamespaceValidator{
			labels: labels,
		}
	}
}

func (v *mockNamespaceValidator) validateLabels(ctx context.Context, client *http.Client, namespace string, namespaceSelector string) (bool, error) {
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
