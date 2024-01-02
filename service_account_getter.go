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
	"k8s.io/apimachinery/pkg/runtime"
)

const annotationKeyPrefix = "auth-metadata.vault.hashicorp.com/"

// serviceAccountGetter defines a namespace validator interface
type serviceAccountGetter interface {
	annotations(context.Context, *http.Client, string, string) (map[string]string, error)
}

type serviceAccountGetterFactory func(*kubeConfig) serviceAccountGetter

// serviceAccountGetterWrapper implements the serviceAccountGetter interface
type serviceAccountGetterWrapper struct {
	config *kubeConfig
}

func newServiceAccountGetterWrapper(config *kubeConfig) serviceAccountGetter {
	return &serviceAccountGetterWrapper{
		config: config,
	}
}

func (w *serviceAccountGetterWrapper) annotations(ctx context.Context, client *http.Client, namespace, serviceAccount string) (map[string]string, error) {
	url := fmt.Sprintf("%s/api/v1/namespaces/%s/serviceaccounts/%s",
		strings.TrimSuffix(w.config.Host, "/"), namespace, serviceAccount)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	// Use the configured TokenReviewer JWT as the bearer
	if w.config.TokenReviewerJWT == "" {
		return nil, errors.New("service account lookup failed: TokenReviewer JWT needs to be configured to retrieve service accounts")
	}
	setRequestHeader(req, fmt.Sprintf("Bearer %s", w.config.TokenReviewerJWT))

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		var errStatus metav1.Status
		if err = json.Unmarshal(body, &errStatus); err != nil {
			return nil, fmt.Errorf("failed to parse error status on service account retrieval failure err=%s", err)
		}

		if errStatus.Status != metav1.StatusSuccess {
			return nil, fmt.Errorf("failed to get service account (code %d status %s)",
				resp.StatusCode, kubeerrors.FromObject(runtime.Object(&errStatus)))
		}
	}
	var sa v1.ServiceAccount
	err = json.Unmarshal(body, &sa)
	if err != nil {
		return nil, err
	}

	annotations := map[string]string{}
	for k, v := range sa.Annotations {
		if strings.HasPrefix(k, annotationKeyPrefix) {
			newK := strings.TrimPrefix(k, annotationKeyPrefix)
			annotations[newK] = v
		}
	}
	return annotations, nil
}

type mockServiceAccountGetter struct {
	meta metav1.ObjectMeta
}

func mockServiceAccountGetterFactory(meta metav1.ObjectMeta) serviceAccountGetterFactory {
	return func(config *kubeConfig) serviceAccountGetter {
		return &mockServiceAccountGetter{
			meta: meta,
		}
	}
}

func (v *mockServiceAccountGetter) annotations(context.Context, *http.Client, string, string) (map[string]string, error) {
	annotations := map[string]string{}
	for k, v := range v.meta.Annotations {
		if strings.HasPrefix(k, annotationKeyPrefix) {
			newK := strings.TrimPrefix(k, annotationKeyPrefix)
			annotations[newK] = v
		}
	}
	return annotations, nil
}
