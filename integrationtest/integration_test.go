// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package integrationtest

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/hashicorp/vault-plugin-auth-kubernetes/integrationtest/k8s"
	"github.com/hashicorp/vault/api"
	authenticationv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	matchLabelsKeyValue = `{
	"matchLabels": {
		"target": "integration-test"
	}
}`
	mismatchLabelsKeyValue = `{
	"matchLabels": {
		"target": "not-integration-test"
	}
}`
)

// Set the environment variable INTEGRATION_TESTS to any non-empty value to run
// the tests in this package. The test assumes it has available:
// - A Kubernetes cluster in which:
//   - it can use the `test` namespace
//   - Vault is deployed and accessible
//   - There is a serviceaccount called test-token-reviewer-account with access to the TokenReview API
//
// See `make setup-integration-test` for manual testing.
func TestMain(m *testing.M) {
	if os.Getenv("INTEGRATION_TESTS") != "" {
		os.Exit(run(m))
	}
}

func run(m *testing.M) int {
	localPort, close, err := k8s.SetupPortForwarding(os.Getenv("KUBE_CONTEXT"), "test", "vault-0")
	if err != nil {
		fmt.Println(err)
		return 1
	}
	defer close()

	os.Setenv("VAULT_ADDR", fmt.Sprintf("http://127.0.0.1:%d", localPort))
	os.Setenv("VAULT_TOKEN", "root")

	return m.Run()
}

func createToken(t *testing.T, sa string, audiences []string) string {
	t.Helper()

	k8sClient, err := k8s.ClientFromKubeConfig(os.Getenv("KUBE_CONTEXT"))
	if err != nil {
		t.Fatal(err)
	}

	resp, err := k8sClient.CoreV1().ServiceAccounts("test").CreateToken(context.Background(), sa, &authenticationv1.TokenRequest{
		Spec: authenticationv1.TokenRequestSpec{
			Audiences: audiences,
		},
	}, metav1.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}

	return resp.Status.Token
}

func annotateServiceAccount(t *testing.T, name string, annotations map[string]string) {
	t.Helper()

	k8sClient, err := k8s.ClientFromKubeConfig(os.Getenv("KUBE_CONTEXT"))
	if err != nil {
		t.Fatal(err)
	}

	sa, err := k8sClient.CoreV1().ServiceAccounts("test").Get(context.Background(), name, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}

	for k, v := range annotations {
		sa.Annotations[k] = v
	}

	sa, err = k8sClient.CoreV1().ServiceAccounts("test").Update(context.Background(), sa, metav1.UpdateOptions{})
	if err != nil {
		t.Fatal(err)
	}
}

func createPolicy(t *testing.T, name, policy string) {
	t.Helper()
	// Pick up VAULT_ADDR and VAULT_TOKEN from env vars
	client, err := api.NewClient(nil)
	if err != nil {
		t.Fatal(err)
	}

	_, err = client.Logical().Write(fmt.Sprintf("/sys/policy/%s", name), map[string]interface{}{
		"policy": policy,
	})
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() {
		_, err = client.Logical().Delete(fmt.Sprintf("/sys/policy/%s", name))
		if err != nil {
			t.Fatal(err)
		}
	})
}

func setupKubernetesAuth(t *testing.T, mountConfigOverride map[string]interface{}) *api.Client {
	t.Helper()
	// Pick up VAULT_ADDR and VAULT_TOKEN from env vars
	client, err := api.NewClient(nil)
	if err != nil {
		t.Fatal(err)
	}

	_, err = client.Logical().Write("sys/auth/kubernetes", map[string]interface{}{
		"type": "kubernetes-dev",
	})
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() {
		_, err = client.Logical().Delete("sys/auth/kubernetes")
		if err != nil {
			t.Fatal(err)
		}
	})

	mountConfig := map[string]interface{}{
		"kubernetes_host": "https://kubernetes.default.svc.cluster.local",
	}
	if len(mountConfigOverride) != 0 {
		mountConfig = mountConfigOverride
	}

	_, err = client.Logical().Write("auth/kubernetes/config", mountConfig)
	if err != nil {
		t.Fatal(err)
	}

	return client
}

func setupKubernetesAuthRole(t *testing.T, client *api.Client, boundServiceAccountName string, roleConfigOverride map[string]interface{}) {
	t.Helper()

	roleConfig := map[string]interface{}{
		"bound_service_account_names":      boundServiceAccountName,
		"bound_service_account_namespaces": "test",
	}
	if len(roleConfigOverride) != 0 {
		roleConfig = roleConfigOverride
	}

	_, err := client.Logical().Write("auth/kubernetes/role/test-role", roleConfig)
	if err != nil {
		t.Fatal(err)
	}
}

func setupKVV1Mount(t *testing.T, client *api.Client, path string) {
	_, err := client.Logical().Write(fmt.Sprintf("/sys/mounts/%s", path), map[string]interface{}{
		"type": "kv",
	})
	if err != nil {
		t.Fatalf("Expected to enable kv v1 secrets engine but got: %v", err)
	}

	t.Cleanup(func() {
		_, err = client.Logical().Delete(fmt.Sprintf("/sys/mounts/%s", path))
		if err != nil {
			t.Fatalf("Expected successful kv v1 secrets engine mount delete but got: %v", err)
		}
	})
}

func TestSuccess(t *testing.T) {
	client := setupKubernetesAuth(t, nil)

	setupKubernetesAuthRole(t, client, "vault", nil)

	_, err := client.Logical().Write("auth/kubernetes/login", map[string]interface{}{
		"role": "test-role",
		"jwt":  createToken(t, "vault", nil),
	})
	if err != nil {
		t.Fatalf("Expected successful login but got: %v", err)
	}
}

func TestSuccessWithTokenReviewerJwt(t *testing.T) {
	client := setupKubernetesAuth(t, map[string]interface{}{
		"kubernetes_host":    "https://kubernetes.default.svc.cluster.local",
		"token_reviewer_jwt": createToken(t, "test-token-reviewer-account", nil),
	})

	setupKubernetesAuthRole(t, client, "vault", nil)

	_, err := client.Logical().Write("auth/kubernetes/login", map[string]interface{}{
		"role": "test-role",
		"jwt":  createToken(t, "vault", nil),
	})
	if err != nil {
		t.Fatalf("Expected successful login but got: %v", err)
	}
}

func TestSuccessWithNamespaceLabels(t *testing.T) {
	client := setupKubernetesAuth(t, nil)

	roleConfigOverride := map[string]interface{}{
		"bound_service_account_names":              "vault",
		"bound_service_account_namespace_selector": matchLabelsKeyValue,
	}
	setupKubernetesAuthRole(t, client, "vault", roleConfigOverride)

	_, err := client.Logical().Write("auth/kubernetes/login", map[string]interface{}{
		"role": "test-role",
		"jwt":  createToken(t, "vault", nil),
	})
	if err != nil {
		t.Fatalf("Expected successful login but got: %v", err)
	}
}

func TestFailWithMismatchNamespaceLabels(t *testing.T) {
	client := setupKubernetesAuth(t, nil)

	roleConfigOverride := map[string]interface{}{
		"bound_service_account_names":              "vault",
		"bound_service_account_namespace_selector": mismatchLabelsKeyValue,
	}
	setupKubernetesAuthRole(t, client, "vault", roleConfigOverride)

	_, err := client.Logical().Write("auth/kubernetes/login", map[string]interface{}{
		"role": "test-role",
		"jwt":  createToken(t, "vault", nil),
	})
	respErr, ok := err.(*api.ResponseError)
	if !ok {
		t.Fatalf("Expected api.ResponseError but was: %T", err)
	}
	if respErr.StatusCode != http.StatusForbidden {
		t.Fatalf("Expected 403 but was %d: %s", respErr.StatusCode, respErr.Error())
	}
}

func TestSuccessWithoutTokenReviewerJwtAndDisabledLocalCAJwtAndNamespaceLabels(t *testing.T) {
	client := setupKubernetesAuth(t, map[string]interface{}{
		"kubernetes_host":      "https://kubernetes.default.svc.cluster.local",
		"disable_local_ca_jwt": "true",
	})
	roleConfigOverride := map[string]interface{}{
		"bound_service_account_names":              "*",
		"bound_service_account_namespace_selector": matchLabelsKeyValue,
	}

	setupKubernetesAuthRole(t, client, "vault", roleConfigOverride)

	_, err := client.Logical().Write("auth/kubernetes/login", map[string]interface{}{
		"role": "test-role",
		"jwt":  createToken(t, "vault", nil),
	})
	if err != nil {
		t.Fatalf("Expected successful login but got: %v", err)
	}
}

func TestSuccessWithBadTokenReviewerJwtAndDisabledLocalCAJwtAndNamespaceLabels(t *testing.T) {
	client := setupKubernetesAuth(t, map[string]interface{}{
		"kubernetes_host":      "https://kubernetes.default.svc.cluster.local",
		"disable_local_ca_jwt": "true",
		"token_reviewer_jwt":   badTokenReviewerJwt,
	})
	roleConfigOverride := map[string]interface{}{
		"bound_service_account_names":              "*",
		"bound_service_account_namespace_selector": matchLabelsKeyValue,
	}

	setupKubernetesAuthRole(t, client, "vault", roleConfigOverride)

	_, err := client.Logical().Write("auth/kubernetes/login", map[string]interface{}{
		"role": "test-role",
		"jwt":  createToken(t, "vault", nil),
	})
	if err != nil {
		t.Fatalf("Expected successful login but got: %v", err)
	}
}

func TestFailWithoutTokenReviewerJwtAndDisabledLocalCAJwtAndMismatchNamespaceLabels(t *testing.T) {
	client := setupKubernetesAuth(t, map[string]interface{}{
		"kubernetes_host":      "https://kubernetes.default.svc.cluster.local",
		"disable_local_ca_jwt": "true",
	})
	roleConfigOverride := map[string]interface{}{
		"bound_service_account_names":              "*",
		"bound_service_account_namespace_selector": mismatchLabelsKeyValue,
	}

	setupKubernetesAuthRole(t, client, "vault", roleConfigOverride)

	_, err := client.Logical().Write("auth/kubernetes/login", map[string]interface{}{
		"role": "test-role",
		"jwt":  createToken(t, "vault", nil),
	})
	respErr, ok := err.(*api.ResponseError)
	if !ok {
		t.Fatalf("Expected api.ResponseError but was: %T", err)
	}
	if respErr.StatusCode != http.StatusForbidden {
		t.Fatalf("Expected 403 but was %d: %s", respErr.StatusCode, respErr.Error())
	}
}

func TestFailWithBadTokenReviewerJwt(t *testing.T) {
	client := setupKubernetesAuth(t, map[string]interface{}{
		"kubernetes_host":    "https://kubernetes.default.svc.cluster.local",
		"token_reviewer_jwt": badTokenReviewerJwt,
	})

	setupKubernetesAuthRole(t, client, "vault", nil)

	_, err := client.Logical().Write("auth/kubernetes/login", map[string]interface{}{
		"role": "test-role",
		"jwt":  createToken(t, "vault", nil),
	})
	respErr, ok := err.(*api.ResponseError)
	if !ok {
		t.Fatalf("Expected api.ResponseError but was: %T", err)
	}
	if respErr.StatusCode != http.StatusForbidden {
		t.Fatalf("Expected 403 but was %d: %s", respErr.StatusCode, respErr.Error())
	}
}

func TestSuccessWithAuthAliasMetadataAssignment(t *testing.T) {
	// annotate the service account
	expMetadata := map[string]string{
		"key-1": "foo",
		"key-2": "bar",
	}

	const annotationPrefix = "vault.hashicorp.com/alias-metadata-"
	annotations := map[string]string{}
	for k, v := range expMetadata {
		annotations[annotationPrefix+k] = v
	}
	annotateServiceAccount(t, "vault", annotations)

	client := setupKubernetesAuth(t, map[string]interface{}{
		"kubernetes_host":                   "https://kubernetes.default.svc.cluster.local",
		"use_annotations_as_alias_metadata": true,
	})

	// create policy
	secret, err := client.Logical().Read("sys/auth/kubernetes")
	if err != nil {
		t.Fatalf("Expected successful auth configuration GET but got: %v", err)
	}

	mountAccessor, ok := secret.Data["accessor"]
	if !ok {
		t.Fatal("Expected auth configuration GET response to have \"accessor\"")
	}

	const kvPath = "kv-v1"
	setupKVV1Mount(t, client, kvPath)

	const policyNameFoo = "alias-metadata-foo"
	policy := fmt.Sprintf(`
path "%s/{{identity.entity.aliases.%s.metadata.key-1}}" {
	capabilities = [ "read", "update", "create" ]
}`, kvPath, mountAccessor)
	createPolicy(t, policyNameFoo, policy)

	// config kubernetes auth role and login
	roleConfigOverride := map[string]interface{}{
		"bound_service_account_names":      "vault",
		"bound_service_account_namespaces": "test",
		"policies":                         []string{"default", policyNameFoo},
	}
	setupKubernetesAuthRole(t, client, "vault", roleConfigOverride)

	loginSecret, err := client.Logical().Write("auth/kubernetes/login", map[string]interface{}{
		"role": "test-role",
		"jwt":  createToken(t, "vault", nil),
	})
	if err != nil {
		t.Fatalf("Expected successful login but got: %v", err)
	}

	// verify that the templated policy works by creating key value pairs at kv-v1/data/foo with the kubernetes auth token
	token, err := loginSecret.TokenID()
	if err != nil {
		t.Fatalf("Expected successful token ID read but got: %v", err)
	}

	kvClient, err := api.NewClient(nil)
	if err != nil {
		t.Fatal(err)
	}
	kvClient.SetToken(token)
	if err != nil {
		t.Fatal(err)
	}

	err = kvClient.KVv1(kvPath).Put(context.Background(), "foo",
		map[string]interface{}{
			"apiKey": "abc123",
		})
	if err != nil {
		t.Fatalf("Expected successful KVV1 PUT but got: %v", err)
	}
}

func TestFailWithAuthAliasMetadataAssignmentOnReservedKeys(t *testing.T) {
	// annotate the service account with disallowed keys
	expMetadata := map[string]string{
		"service_account_secret_name": "foo",
		"other-key":                   "bar",
	}

	const annotationPrefix = "vault.hashicorp.com/alias-metadata-"
	annotations := map[string]string{}
	for k, v := range expMetadata {
		annotations[annotationPrefix+k] = v
	}
	annotateServiceAccount(t, "vault", annotations)

	client := setupKubernetesAuth(t, map[string]interface{}{
		"kubernetes_host":                   "https://kubernetes.default.svc.cluster.local",
		"use_annotations_as_alias_metadata": true,
	})

	// config kubernetes auth role and login
	setupKubernetesAuthRole(t, client, "vault", nil)

	_, err := client.Logical().Write("auth/kubernetes/login", map[string]interface{}{
		"role": "test-role",
		"jwt":  createToken(t, "vault", nil),
	})

	if err == nil {
		t.Fatalf("Expected failed login but got nil err")
	}

	respErr, ok := err.(*api.ResponseError)
	if !ok {
		t.Fatalf("Expected api.ResponseError but was: %T", err)
	}
	if respErr.StatusCode != http.StatusBadRequest {
		t.Fatalf("Expected 400 but was %d: %s", respErr.StatusCode, respErr.Error())
	}

	errMsgAliasMetadataReservedKeysFound := "entity alias metadata keys for only internal use found from the client" +
		" token's associated service account annotations"
	if !strings.Contains(respErr.Error(), errMsgAliasMetadataReservedKeysFound) {
		t.Fatalf("Expected failed err to contain %s but got err %s", errMsgAliasMetadataReservedKeysFound,
			respErr.Error())
	}
}

func TestUnauthorizedServiceAccountErrorCode(t *testing.T) {
	client := setupKubernetesAuth(t, nil)

	setupKubernetesAuthRole(t, client, "badServiceAccount", nil)

	_, err := client.Logical().Write("auth/kubernetes/login", map[string]interface{}{
		"role": "test-role",
		"jwt":  createToken(t, "vault", nil),
	})
	respErr, ok := err.(*api.ResponseError)
	if !ok {
		t.Fatalf("Expected api.ResponseError but was: %T", err)
	}
	if respErr.StatusCode != http.StatusForbidden {
		t.Fatalf("Expected 403 but was %d: %s", respErr.StatusCode, respErr.Error())
	}
}

const badTokenReviewerJwt = "eyJhbGciOiJSUzI1NiIsImtpZCI6IkZza1ViNWREek8tQ05uaVk3TU5mRWZ2dEx5bzFuU0tsV3JhUU5nekhVQ28ifQ.eyJhdWQiOlsiaHR0cHM6Ly9rdWJlcm5ldGVzLmRlZmF1bHQuc3ZjLmNsdXN0ZXIubG9jYWwiXSwiZXhwIjoxNjgwODg5NjQ4LCJpYXQiOjE2NDkzNTM2NDgsImlzcyI6Imh0dHBzOi8va3ViZXJuZXRlcy5kZWZhdWx0LnN2Yy5jbHVzdGVyLmxvY2FsIiwia3ViZXJuZXRlcy5pbyI6eyJuYW1lc3BhY2UiOiJ0ZXN0IiwicG9kIjp7Im5hbWUiOiJ2YXVsdC0wIiwidWlkIjoiYTQwNGZiMTktNWQ4MC00OTBlLTkwYjktMGJjNWE3NzA5ODdkIn0sInNlcnZpY2VhY2NvdW50Ijp7Im5hbWUiOiJ2YXVsdCIsInVpZCI6ImI2ZTM2ZDMxLTA2MDQtNDE5MS04Y2JjLTAwYzg4ZWViZDlmOSJ9LCJ3YXJuYWZ0ZXIiOjE2NDkzNTcyNTV9LCJuYmYiOjE2NDkzNTM2NDgsInN1YiI6InN5c3RlbTpzZXJ2aWNlYWNjb3VudDp0ZXN0OnZhdWx0In0.hxzMpKx38rKvaWUBNEg49TioRXt_JT1Z5st4A9NeBWO2xiC8hCDgVJRWqPzejz-sYoQGhZyZcrTa0cbNRIevcR7XH4DnHd27OOzSoj198I2DAdLfw_pntzOjq35-tZhxSYXsfKH69DSpHACpu5HHUAf1aiY3B6cq5Z3gXbtaoHBocfNwvtOirGL8pTYXo1kNCkcahDPfpf3faztyUQ77v0viBKIAqwxDuGks4crqIG5jT_tOnXbb7PahwtE5cS3bMLjQb1j5oEcgq6HF4NMV46Ly479QRoXtYWWsI9OSwl4H7G9Rel3fr9q4IMdCCI5A-FLxL2Fpep9TDwrNQ3mhBQ"

func TestAudienceValidation(t *testing.T) {
	jwtWithDefaultAud := createToken(t, "vault", nil)
	jwtWithAudA := createToken(t, "vault", []string{"a"})
	jwtWithAudB := createToken(t, "vault", []string{"b"})

	for name, tc := range map[string]struct {
		audienceConfig string
		jwt            string
		expectSuccess  bool
	}{
		"config: default, JWT: default": {"https://kubernetes.default.svc.cluster.local", jwtWithDefaultAud, true},
		"config: default, JWT: a":       {"https://kubernetes.default.svc.cluster.local", jwtWithAudA, false},
		"config: a, JWT: a":             {"a", jwtWithAudA, true},
		"config: a, JWT: b":             {"a", jwtWithAudB, false},
		"config: unset, JWT: default":   {"", jwtWithDefaultAud, true},
		"config: unset, JWT: a":         {"", jwtWithAudA, true},
	} {
		t.Run(name, func(t *testing.T) {
			roleConfig := map[string]interface{}{
				"bound_service_account_names":      "vault",
				"bound_service_account_namespaces": "test",
			}
			if tc.audienceConfig != "" {
				roleConfig["audience"] = tc.audienceConfig
			}
			client := setupKubernetesAuth(t, nil)

			setupKubernetesAuthRole(t, client, "vault", roleConfig)

			login := func(jwt string) error {
				_, err := client.Logical().Write("auth/kubernetes/login", map[string]interface{}{
					"role": "test-role",
					"jwt":  jwt,
				})
				return err
			}

			err := login(tc.jwt)
			if err != nil {
				if tc.expectSuccess {
					t.Fatal("Expected successful login", err)
				} else {
					respErr, ok := err.(*api.ResponseError)
					if !ok {
						t.Fatalf("Expected api.ResponseError but was: %T", err)
					}
					if respErr.StatusCode != http.StatusForbidden {
						t.Fatalf("Expected 403 but was %d: %s", respErr.StatusCode, respErr.Error())
					}
				}
			} else if !tc.expectSuccess {
				t.Fatal("Expected error but successfully logged in")
			}
		})
	}
}
