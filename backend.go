package kubeauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	configPath = "config"
	rolePrefix = "role/"

	// aliasNameSourceUnset provides backwards compatibility with preexisting roles.
	aliasNameSourceUnset   = ""
	aliasNameSourceSAUid   = "serviceaccount_uid"
	aliasNameSourceSAName  = "serviceaccount_name"
	aliasNameSourceDefault = aliasNameSourceSAUid
)

var (
	// when adding new alias name sources make sure to update the corresponding FieldSchema description in path_role.go
	aliasNameSources          = []string{aliasNameSourceSAUid, aliasNameSourceSAName}
	errInvalidAliasNameSource = fmt.Errorf(`invalid alias_name_source, must be one of: %s`, strings.Join(aliasNameSources, ", "))

	// jwtReloadPeriod is the time period how often the in-memory copy of local
	// service account token can be used, before reading it again from disk.
	//
	// The value is selected according to recommendation in Kubernetes 1.21 changelog:
	// "Clients should reload the token from disk periodically (once per minute
	// is recommended) to ensure they continue to use a valid token."
	jwtReloadPeriod = 1 * time.Minute
)

// kubeAuthBackend implements logical.Backend
type kubeAuthBackend struct {
	*framework.Backend

	// reviewFactory is used to configure the strategy for doing a token review.
	// Currently the only options are using the kubernetes API or mocking the
	// review. Mocks should only be used in tests.
	reviewFactory tokenReviewFactory

	// localSATokenReader caches the service account token in memory.
	// It periodically reloads the token to support token rotation/renewal.
	// Local token is used when running in a pod with following configuration
	// - token_reviewer_jwt is not set
	// - disable_local_ca_jwt is true
	localSATokenReader *cachingFileReader

	// localCACert contains the local CA certificate. Local CA certificate is
	// used when running in a pod with following configuration
	// - kubernetes_ca_cert is not set
	// - disable_local_ca_jwt is true
	localCACert string

	l sync.RWMutex
}

// Factory returns a new backend as logical.Backend.
func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := Backend()
	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}
	return b, nil
}

func Backend() *kubeAuthBackend {
	b := &kubeAuthBackend{}

	b.Backend = &framework.Backend{
		InitializeFunc: b.initialize,
		AuthRenew:      b.pathLoginRenew(),
		BackendType:    logical.TypeCredential,
		Help:           backendHelp,
		PathsSpecial: &logical.Paths{
			Unauthenticated: []string{
				"login",
			},
			SealWrapStorage: []string{
				configPath,
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

	// Set the review factory to default to calling into the kubernetes API.
	b.reviewFactory = tokenReviewAPIFactory

	return b
}

// config takes a storage object and returns a kubeConfig object.
// It does not return local token and CA file which are specific to the pod we run in.
func (b *kubeAuthBackend) config(ctx context.Context, s logical.Storage) (*kubeConfig, error) {
	raw, err := s.Get(ctx, configPath)
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
	conf.PublicKeys = make([]interface{}, len(conf.PEMKeys))
	for i, cert := range conf.PEMKeys {
		conf.PublicKeys[i], err = parsePublicKeyPEM([]byte(cert))
		if err != nil {
			return nil, err
		}
	}

	return conf, nil
}

// loadConfig fetches the kubeConfig from storage and optionally decorates it with
// local token and CA certificate.
func (b *kubeAuthBackend) loadConfig(ctx context.Context, s logical.Storage) (*kubeConfig, error) {
	config, err := b.config(ctx, s)
	if err != nil {
		return nil, err
	}
	if config == nil {
		return nil, errors.New("could not load backend configuration")
	}

	// Add the local files if required.
	if !config.DisableLocalCAJwt {
		if len(config.TokenReviewerJWT) == 0 {
			config.TokenReviewerJWT, err = b.localSATokenReader.ReadFile()
			if err != nil {
				return nil, err
			}
		}
		if len(config.CACert) == 0 {
			config.CACert = b.localCACert
		}
	}

	return config, nil
}

// role takes a storage backend and the name and returns the role's storage
// entry
func (b *kubeAuthBackend) role(ctx context.Context, s logical.Storage, name string) (*roleStorageEntry, error) {
	raw, err := s.Get(ctx, fmt.Sprintf("%s%s", rolePrefix, strings.ToLower(name)))
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

	if role.TokenTTL == 0 && role.TTL > 0 {
		role.TokenTTL = role.TTL
	}
	if role.TokenMaxTTL == 0 && role.MaxTTL > 0 {
		role.TokenMaxTTL = role.MaxTTL
	}
	if role.TokenPeriod == 0 && role.Period > 0 {
		role.TokenPeriod = role.Period
	}
	if role.TokenNumUses == 0 && role.NumUses > 0 {
		role.TokenNumUses = role.NumUses
	}
	if len(role.TokenPolicies) == 0 && len(role.Policies) > 0 {
		role.TokenPolicies = role.Policies
	}
	if len(role.TokenBoundCIDRs) == 0 && len(role.BoundCIDRs) > 0 {
		role.TokenBoundCIDRs = role.BoundCIDRs
	}

	return role, nil
}

// initialize will initialize the global data.
func (b *kubeAuthBackend) initialize(ctx context.Context, req *logical.InitializationRequest) error {
	// Check if configuration exists and load local token and CA cert files
	// if they are used.
	config, _ := b.config(ctx, req.Storage)
	if config != nil && !config.DisableLocalCAJwt {
		err := b.loadLocalFiles(len(config.TokenReviewerJWT) == 0, len(config.CACert) == 0)
		if err != nil {
			return err
		}
	}
	return nil
}

// loadLocalFiles reads the local token and/or CA file into memory.
//
// The function should be called only in context where write lock to backend is
// held or it is otherwise guaranteed that we can update backend object.
func (b *kubeAuthBackend) loadLocalFiles(loadJWT, loadCACert bool) error {
	if loadJWT {
		b.localSATokenReader = newCachingFileReader(localJWTPath, jwtReloadPeriod)
		_, err := b.localSATokenReader.ReadFile()
		if err != nil {
			return err
		}
	}

	if loadCACert {
		buf, err := ioutil.ReadFile(localCACertPath)
		if err != nil {
			return err
		}
		b.localCACert = string(buf)
	}
	return nil
}

func validateAliasNameSource(source string) error {
	for _, s := range aliasNameSources {
		if s == source {
			return nil
		}
	}
	return errInvalidAliasNameSource
}

var backendHelp string = `
The Kubernetes Auth Backend allows authentication for Kubernetes service accounts.
`
