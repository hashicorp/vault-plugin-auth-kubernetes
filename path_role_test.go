package kubeauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/go-test/deep"
	log "github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/sdk/helper/logging"
	"github.com/hashicorp/vault/sdk/helper/tokenutil"
	"github.com/hashicorp/vault/sdk/logical"
)

func getBackend(t *testing.T) (logical.Backend, logical.Storage) {
	defaultLeaseTTLVal := time.Hour * 12
	maxLeaseTTLVal := time.Hour * 24
	b := Backend()

	config := &logical.BackendConfig{
		Logger: logging.NewVaultLogger(log.Trace),

		System: &logical.StaticSystemView{
			DefaultLeaseTTLVal: defaultLeaseTTLVal,
			MaxLeaseTTLVal:     maxLeaseTTLVal,
		},
		StorageView: &logical.InmemStorage{},
	}
	err := b.Setup(context.Background(), config)
	if err != nil {
		t.Fatalf("unable to create backend: %v", err)
	}

	return b, config.StorageView
}

func TestPath_Create(t *testing.T) {
	testCases := map[string]struct {
		data     map[string]interface{}
		expected *roleStorageEntry
		wantErr  error
	}{
		"default": {
			data: map[string]interface{}{
				"bound_service_account_names":      "name",
				"bound_service_account_namespaces": "namespace",
				"policies":                         "test",
				"period":                           "3s",
				"ttl":                              "1s",
				"num_uses":                         12,
				"max_ttl":                          "5s",
				"alias_name_source":                aliasNameSourceDefault,
			},
			expected: &roleStorageEntry{
				TokenParams: tokenutil.TokenParams{
					TokenPolicies:   []string{"test"},
					TokenPeriod:     3 * time.Second,
					TokenTTL:        1 * time.Second,
					TokenMaxTTL:     5 * time.Second,
					TokenNumUses:    12,
					TokenBoundCIDRs: nil,
				},
				Policies:                 []string{"test"},
				Period:                   3 * time.Second,
				ServiceAccountNames:      []string{"name"},
				ServiceAccountNamespaces: []string{"namespace"},
				TTL:                      1 * time.Second,
				MaxTTL:                   5 * time.Second,
				NumUses:                  12,
				BoundCIDRs:               nil,
				AliasNameSource:          aliasNameSourceDefault,
			},
		},
		"alias_name_source_serviceaccount_name": {
			data: map[string]interface{}{
				"bound_service_account_names":      "name",
				"bound_service_account_namespaces": "namespace",
				"policies":                         "test",
				"period":                           "3s",
				"ttl":                              "1s",
				"num_uses":                         12,
				"max_ttl":                          "5s",
				"alias_name_source":                aliasNameSourceSAName,
			},
			expected: &roleStorageEntry{
				TokenParams: tokenutil.TokenParams{
					TokenPolicies:   []string{"test"},
					TokenPeriod:     3 * time.Second,
					TokenTTL:        1 * time.Second,
					TokenMaxTTL:     5 * time.Second,
					TokenNumUses:    12,
					TokenBoundCIDRs: nil,
				},
				Policies:                 []string{"test"},
				Period:                   3 * time.Second,
				ServiceAccountNames:      []string{"name"},
				ServiceAccountNamespaces: []string{"namespace"},
				TTL:                      1 * time.Second,
				MaxTTL:                   5 * time.Second,
				NumUses:                  12,
				BoundCIDRs:               nil,
				AliasNameSource:          aliasNameSourceSAName,
			},
		},
		"invalid_alias_name_source": {
			data: map[string]interface{}{
				"bound_service_account_names":      "name",
				"bound_service_account_namespaces": "namespace",
				"policies":                         "test",
				"period":                           "3s",
				"ttl":                              "1s",
				"num_uses":                         12,
				"max_ttl":                          "5s",
				"alias_name_source":                "_invalid_",
			},
			wantErr: errInvalidAliasNameSource,
		},
		"no_service_account_names": {
			data: map[string]interface{}{
				"policies": "test",
			},
			wantErr: errors.New(`"bound_service_account_names" can not be empty`),
		},
		"no_service_account_namespaces": {
			data: map[string]interface{}{
				"bound_service_account_names": "name",
				"policies":                    "test",
			},
			wantErr: errors.New(`"bound_service_account_namespaces" can not be empty`),
		},
		"mixed_splat_values_names": {
			data: map[string]interface{}{
				"bound_service_account_names":      "*, test",
				"bound_service_account_namespaces": "*",
				"policies":                         "test",
			},
			wantErr: errors.New(`can not mix "*" with values`),
		},
		"mixed_splat_values_namespaces": {
			data: map[string]interface{}{
				"bound_service_account_names":      "*, test",
				"bound_service_account_namespaces": "*",
				"policies":                         "test",
			},
			wantErr: errors.New(`can not mix "*" with values`),
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			b, storage := getBackend(t)
			path := fmt.Sprintf("role/%s", name)
			req := &logical.Request{
				Operation: logical.CreateOperation,
				Path:      path,
				Storage:   storage,
				Data:      tc.data,
			}

			resp, err := b.HandleRequest(context.Background(), req)

			if tc.wantErr != nil {
				var actual error
				if err != nil {
					actual = err
				} else if resp != nil && resp.IsError() {
					actual = resp.Error()
				} else {
					t.Fatalf("expected error")
				}

				if tc.wantErr.Error() != actual.Error() {
					t.Fatalf("expected err %q, actual %q", tc.wantErr, actual)
				}
			} else {
				if tc.wantErr == nil && (err != nil || (resp != nil && resp.IsError())) {
					t.Fatalf("err:%s resp:%#v\n", err, resp)
				}

				actual, err := b.(*kubeAuthBackend).role(context.Background(), storage, name)
				if err != nil {
					t.Fatal(err)
				}

				if diff := deep.Equal(tc.expected, actual); diff != nil {
					t.Fatal(diff)
				}
			}
		})
	}
}

func TestPath_Read(t *testing.T) {
	b, storage := getBackend(t)

	configData := map[string]interface{}{
		"bound_service_account_names":      "name",
		"bound_service_account_namespaces": "namespace",
		"policies":                         "test",
		"period":                           "3s",
		"ttl":                              "1s",
		"num_uses":                         12,
		"max_ttl":                          "5s",
	}

	expected := map[string]interface{}{
		"bound_service_account_names":      []string{"name"},
		"bound_service_account_namespaces": []string{"namespace"},
		"token_policies":                   []string{"test"},
		"policies":                         []string{"test"},
		"token_period":                     int64(3),
		"period":                           int64(3),
		"token_ttl":                        int64(1),
		"ttl":                              int64(1),
		"token_num_uses":                   12,
		"num_uses":                         12,
		"token_max_ttl":                    int64(5),
		"max_ttl":                          int64(5),
		"token_bound_cidrs":                []string{},
		"token_type":                       logical.TokenTypeDefault.String(),
		"token_explicit_max_ttl":           int64(0),
		"token_no_default_policy":          false,
		"alias_name_source":                aliasNameSourceDefault,
	}

	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "role/plugin-test",
		Storage:   storage,
		Data:      configData,
	}

	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	req = &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "role/plugin-test",
		Storage:   storage,
		Data:      configData,
	}

	resp, err = b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	if diff := deep.Equal(expected, resp.Data); diff != nil {
		t.Fatal(diff)
	}
}

func TestPath_Delete(t *testing.T) {
	b, storage := getBackend(t)

	configData := map[string]interface{}{
		"bound_service_account_names":      "name",
		"bound_service_account_namespaces": "namespace",
		"policies":                         "test",
		"period":                           "3s",
		"ttl":                              "1s",
		"num_uses":                         12,
		"max_ttl":                          "5s",
	}

	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "role/plugin-test",
		Storage:   storage,
		Data:      configData,
	}

	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	req = &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      "role/plugin-test",
		Storage:   storage,
		Data:      nil,
	}

	resp, err = b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	if resp != nil {
		t.Fatalf("Unexpected resp data: expected nil got %#v\n", resp.Data)
	}

	req = &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "role/plugin-test",
		Storage:   storage,
		Data:      nil,
	}

	resp, err = b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	if resp != nil {
		t.Fatalf("Unexpected resp data: expected nil got %#v\n", resp.Data)
	}
}

func TestPath_Migration(t *testing.T) {
	b, storage := getBackend(t)

	// Define role entry as it would look if stored with version prior to Vault 1.9.0.
	// Note: it does not have field "alias_name_source".
	entryStr := `{
		"token_bound_cidrs": null,
		"token_explicit_max_ttl": 0,
		"token_max_ttl": 0,
		"token_no_default_policy": false,
		"token_num_uses": 0,
		"token_period": 0,
		"token_policies": null,
		"token_type": 0,
		"token_ttl": 0,
		"bound_service_account_names": [
		  "name"
		],
		"bound_service_account_namespaces": [
		  "namespaces"
		],
		"audience": "",
		"policies": null,
		"num_uses": 0,
		"ttl": 0,
		"max_ttl": 0,
		"period": 0,
		"BoundCIDRs": null
	}`

	entry := logical.StorageEntry{
		Key:   "role/old-entry",
		Value: []byte(entryStr),
	}

	// Store the role entry.
	err := storage.Put(context.Background(), &entry)
	if err != nil {
		t.Fatalf("Could not store role entry: %s\n", err)
	}

	// Read the role that was stored with older version of Vault.
	req := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "role/old-entry",
		Storage:   storage,
	}

	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	// Writing the role back should succeed.
	req = &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "role/new-entry",
		Storage:   storage,
		Data:      resp.Data,
	}

	resp, err = b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	// Get the role from storage and check that AliasNameSource is set to default value.
	raw, err := storage.Get(context.Background(), "role/new-entry")
	if err != nil {
		t.Fatalf("Could not read role entry: %s\n", err)
	}

	role := &roleStorageEntry{}
	if err := json.Unmarshal(raw.Value, role); err != nil {
		t.Fatalf("Could not deserialize role entry: %s\n", err)
	}

	if role.AliasNameSource != aliasNameSourceDefault {
		t.Fatalf("Unexpected AliasNameSource: %s (expected %s)\n", role.AliasNameSource, aliasNameSourceDefault)
	}
}
