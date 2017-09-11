package kubeauth

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"

	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

const (
	configPath string = "config"
	rolePrefix string = "role/"
)

// kubeAuthBackend implements logical backend
type kubeAuthBackend struct {
	*framework.Backend

	reviewFactory tokenReviewFactory

	l sync.RWMutex
}

// Factory returns a new backend as logical.Backend.
func Factory(conf *logical.BackendConfig) (logical.Backend, error) {
	b := Backend()
	if err := b.Setup(conf); err != nil {
		return nil, err
	}
	return b, nil
}

func Backend() *kubeAuthBackend {
	b := &kubeAuthBackend{}

	b.Backend = &framework.Backend{
		AuthRenew:   b.pathLoginRenew,
		BackendType: logical.TypeCredential,
		//Help:        backendHelp,
		PathsSpecial: &logical.Paths{
			Unauthenticated: []string{
				"login",
			},
		},
		Paths: framework.PathAppend(
			[]*framework.Path{
				pathConfig(b),
				pathLogin(b),
			},
			pathsRole(b),
		),
	}

	b.reviewFactory = tokenReviewAPIFactory

	return b
}

// config takes a storage object and returns a kubeConfig object
func (b *kubeAuthBackend) config(s logical.Storage) (*kubeConfig, error) {
	raw, err := s.Get(configPath)
	if err != nil {
		return nil, err
	}
	if raw == nil {
		return nil, nil
	}

	conf := &kubeConfig{}
	if err := json.Unmarshal(raw.Value, conf); err != nil {
		return nil, err
	}

	// Parse the public keys from the CertificatesBytes
	conf.Certificates = make([]interface{}, len(conf.CertificatesBytes))
	for i, certBytes := range conf.CertificatesBytes {
		conf.Certificates[i], err = ParsePublicKeyDER(certBytes)
		if err != nil {
			return nil, err
		}
	}

	return conf, nil
}

// role takes a storage backend and the name and returns the role's storage
// entry
func (b *kubeAuthBackend) role(s logical.Storage, name string) (*roleStorageEntry, error) {
	raw, err := s.Get(fmt.Sprintf("%s%s", rolePrefix, strings.ToLower(name)))
	if err != nil {
		return nil, err
	}
	if raw == nil {
		return nil, nil
	}

	role := &roleStorageEntry{}
	if err := json.Unmarshal(raw.Value, role); err != nil {
		return nil, err
	}

	return role, nil
}
