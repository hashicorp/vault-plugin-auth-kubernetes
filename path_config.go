package kubeauth

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	localCACertPath = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
	localJWTPath    = "/var/run/secrets/kubernetes.io/serviceaccount/token"
)

// pathConfig returns the path configuration for CRUD operations on the backend
// configuration.
func pathConfig(b *kubeAuthBackend) *framework.Path {
	return &framework.Path{
		Pattern: "config$",
		Fields: map[string]*framework.FieldSchema{
			"kubernetes_host": {
				Type:        framework.TypeString,
				Description: "Host must be a host string, a host:port pair, or a URL to the base of the Kubernetes API server.",
			},

			"kubernetes_ca_cert": {
				Type:        framework.TypeString,
				Description: "PEM encoded CA cert for use by the TLS client used to talk with the API.",
				DisplayAttrs: &framework.DisplayAttributes{
					Name: "Kubernetes CA Certificate",
				},
			},
			"token_reviewer_jwt": {
				Type: framework.TypeString,
				Description: `A service account JWT used to access the
TokenReview API to validate other JWTs during login. If not set
the JWT used for login will be used to access the API.`,
				DisplayAttrs: &framework.DisplayAttributes{
					Name: "Token Reviewer JWT",
				},
			},
			"pem_keys": {
				Type: framework.TypeCommaStringSlice,
				Description: `Optional list of PEM-formated public keys or certificates
used to verify the signatures of kubernetes service account
JWTs. If a certificate is given, its public key will be
extracted. Not every installation of Kubernetes exposes these keys.`,
				DisplayAttrs: &framework.DisplayAttributes{
					Name: "Service account verification keys",
				},
			},
			"issuer": {
				Type:       framework.TypeString,
				Deprecated: true,
				Description: `Optional JWT issuer. If no issuer is specified,
then this plugin will use kubernetes.io/serviceaccount as the default issuer.
(Deprecated, will be removed in a future release)`,
				DisplayAttrs: &framework.DisplayAttributes{
					Name: "JWT Issuer",
				},
			},
			"disable_iss_validation": {
				Type:        framework.TypeBool,
				Deprecated:  true,
				Description: `Disable JWT issuer validation (Deprecated, will be removed in a future release)`,
				Default:     true,
				DisplayAttrs: &framework.DisplayAttributes{
					Name: "Disable JWT Issuer Validation",
				},
			},
			"disable_local_ca_jwt": {
				Type:        framework.TypeBool,
				Description: "Disable defaulting to the local CA cert and service account JWT when running in a Kubernetes pod",
				Default:     false,
				DisplayAttrs: &framework.DisplayAttributes{
					Name: "Disable use of local CA and service account JWT",
				},
			},
			"jwt_rotation_period_seconds": {
				Type: framework.TypeInt,
				Description: `The period with which Vault will attempt to generate
a fresh service account JWT when provided with a time-limited JWT. Defaults to 25%
of the provided JWT's duration, to allow 3 attempts at refreshing before expiry.`,
				Default: 0,
				DisplayAttrs: &framework.DisplayAttributes{
					Name: "JWT rotation period",
				},
			},
		},
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.UpdateOperation: b.pathConfigWrite,
			logical.CreateOperation: b.pathConfigWrite,
			logical.ReadOperation:   b.pathConfigRead,
		},

		HelpSynopsis:    confHelpSyn,
		HelpDescription: confHelpDesc,
	}
}

// pathConfigWrite handles create and update commands to the config
func (b *kubeAuthBackend) pathConfigRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	if config, err := b.config(ctx, req.Storage); err != nil {
		return nil, err
	} else if config == nil {
		return nil, nil
	} else {
		// Create a map of data to be returned
		resp := &logical.Response{
			Data: map[string]interface{}{
				"kubernetes_host":        config.Host,
				"kubernetes_ca_cert":     config.CACert,
				"pem_keys":               config.PEMKeys,
				"issuer":                 config.Issuer,
				"disable_iss_validation": config.DisableISSValidation,
				"disable_local_ca_jwt":   config.DisableLocalCAJwt,
			},
		}

		return resp, nil
	}
}

// pathConfigWrite handles create and update commands to the config
func (b *kubeAuthBackend) pathConfigWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	host := data.Get("kubernetes_host").(string)
	if host == "" {
		return logical.ErrorResponse("no host provided"), nil
	}

	disableLocalJWT := data.Get("disable_local_ca_jwt").(bool)
	pemList := data.Get("pem_keys").([]string)
	caCert := data.Get("kubernetes_ca_cert").(string)
	issuer := data.Get("issuer").(string)
	disableIssValidation := data.Get("disable_iss_validation").(bool)
	jwt := data.Get("token_reviewer_jwt").(string)
	jwtRotationPeriod := data.Get("jwt_rotation_period_seconds").(int)

	if disableLocalJWT && caCert == "" {
		return logical.ErrorResponse("kubernetes_ca_cert must be given when disable_local_ca_jwt is true"), nil
	}

	config := &kubeConfig{
		PublicKeys:           make([]interface{}, len(pemList)),
		PEMKeys:              pemList,
		Host:                 host,
		CACert:               caCert,
		TokenReviewerJWT:     jwt,
		Issuer:               issuer,
		DisableISSValidation: disableIssValidation,
		DisableLocalCAJwt:    disableLocalJWT,
	}

	var err error
	for i, pem := range pemList {
		config.PublicKeys[i], err = parsePublicKeyPEM([]byte(pem))
		if err != nil {
			return logical.ErrorResponse(err.Error()), nil
		}
	}

	// TODO: Need to ensure local CA loader is considered
	if jwt != "" {
		// Validate it's a JWT
		sa, err := parseJWT(jwt)
		if err != nil {
			return nil, err
		}

		if jwtRotationPeriod != 0 || sa.Expiration != 0 {
			// We will rotate the JWT periodically. Do it once immediately to surface any errors early.
			tokenClient := tokenReviewAPIFactory(config)
			resp, err := tokenClient.Request(ctx, jwt, sa)
			if err != nil {
				return nil, err
			}
			config.TokenReviewerJWT = resp.Token
			config.NextJWTRotationUnix = sa.IssuedAt + int64(jwtRotationPeriod)

			tokenDuration := sa.Expiration - sa.IssuedAt
			if jwtRotationPeriod == 0 {
				config.NextJWTRotationUnix = sa.IssuedAt + (2*tokenDuration)/3
			} else if int64(jwtRotationPeriod) < tokenDuration {
				// We check JWT rotation against the real duration of a token because
				// it's possible that the Kubernetes API will return a token with
				// duration less than we asked for.
				return logical.ErrorResponse("jwt_rotation_period_seconds must be less than the token duration; token duration=%d", tokenDuration), nil
			}
		}
	}

	entry, err := logical.StorageEntryJSON(configPath, config)
	if err != nil {
		return nil, err
	}

	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}
	return nil, nil
}

// kubeConfig contains the public key certificate used to verify the signature
// on the service account JWTs
type kubeConfig struct {
	// PublicKeys is the list of public key objects used to verify JWTs
	PublicKeys []interface{} `json:"-"`
	// PEMKeys is the list of public key PEMs used to store the keys
	// in storage.
	PEMKeys []string `json:"pem_keys"`
	// Host is the url string for the kubernetes API
	Host string `json:"host"`
	// CACert is the CA Cert to use to call into the kubernetes API
	CACert string `json:"ca_cert"`
	// TokenReviewJWT is the bearer to use during the TokenReview API call
	TokenReviewerJWT string `json:"token_reviewer_jwt"`
	// Issuer is the claim that specifies who issued the token
	Issuer string `json:"issuer"`
	// DisableISSValidation is optional parameter to allow to skip ISS validation
	DisableISSValidation bool `json:"disable_iss_validation"`
	// DisableLocalJWT is an optional parameter to disable defaulting to using
	// the local CA cert and service account jwt when running in a Kubernetes
	// pod
	DisableLocalCAJwt bool `json:"disable_local_ca_jwt"`
	// JWTRotationPeriodSeconds sets how early to start trying to rotate the
	// reviewer token.
	JWTRotationPeriodSeconds int `json:"jwt_rotation_period_seconds"`

	// NextJWTRotation durably stores the next time after which we should attempt
	// to rotate the service account JWT. Not settable or gettable by users.
	NextJWTRotationUnix int64 `json:"next_jwt_rotation_unix,omitempty"`
}

// PasrsePublicKeyPEM is used to parse RSA and ECDSA public keys from PEMs
func parsePublicKeyPEM(data []byte) (interface{}, error) {
	block, data := pem.Decode(data)
	if block != nil {
		var rawKey interface{}
		var err error
		if rawKey, err = x509.ParsePKIXPublicKey(block.Bytes); err != nil {
			if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
				rawKey = cert.PublicKey
			} else {
				return nil, err
			}
		}

		if rsaPublicKey, ok := rawKey.(*rsa.PublicKey); ok {
			return rsaPublicKey, nil
		}
		if ecPublicKey, ok := rawKey.(*ecdsa.PublicKey); ok {
			return ecPublicKey, nil
		}
	}

	return nil, errors.New("data does not contain any valid RSA or ECDSA public keys")
}

const confHelpSyn = `Configures the JWT Public Key and Kubernetes API information.`
const confHelpDesc = `
The Kubernetes Auth backend validates service account JWTs and verifies their
existence with the Kubernetes TokenReview API. This endpoint configures the
public key used to validate the JWT signature and the necessary information to
access the Kubernetes API.
`
