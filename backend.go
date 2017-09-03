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

type KubeAuthBackend struct {
	*framework.Backend

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

func Backend() *KubeAuthBackend {
	b := &KubeAuthBackend{}

	b.Backend = &framework.Backend{
		AuthRenew:   b.pathLoginRenew,
		BackendType: logical.TypeCredential,
		Invalidate:  b.invalidate,
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
	return b
}

func (b *KubeAuthBackend) invalidate(key string) {
	switch key {
	case "config":
		b.Close()
	}
}

// Close deletes created GCP clients in backend.
func (b *KubeAuthBackend) Close() {
	b.l.Lock()
	defer b.l.Unlock()
}

func (b *KubeAuthBackend) config(s logical.Storage) (*kubeConfig, error) {
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

	conf.Certificates = make([]interface{}, len(conf.CertificatesBytes))
	for i, certBytes := range conf.CertificatesBytes {
		conf.Certificates[i], err = ParsePublicKeyDER(certBytes)
		if err != nil {
			return nil, err
		}
	}

	return conf, nil
}

func (b *KubeAuthBackend) role(s logical.Storage, name string) (*roleStorageEntry, error) {
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
