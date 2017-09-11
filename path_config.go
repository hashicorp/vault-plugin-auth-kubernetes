package kubeauth

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"

	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

const warningACLReadAccess string = "Read access to this endpoint should be controlled via ACLs as it will return the configuration information as-is, including any passwords."

// pathConfig returns the path configuration for CRUD operations on the backend
// configuration.
func pathConfig(b *kubeAuthBackend) *framework.Path {
	return &framework.Path{
		Pattern: "config$",
		Fields: map[string]*framework.FieldSchema{
			"certificates": {
				Type:        framework.TypeCommaStringSlice,
				Description: "List of PEM-formated certificates used to verify the signatures of kubernetes service account JWTs",
			},
			"kubernetes_host": {
				Type:        framework.TypeString,
				Description: "Host must be a host string, a host:port pair, or a URL to the base of the apiserver.",
			},
			"kubernetes_ca_cert": {
				Type:        framework.TypeString,
				Description: "PEM encoded CA cert for use by the TLS client used to talk with the API.",
			},
		},
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.UpdateOperation: b.pathConfigWrite(),
			logical.CreateOperation: b.pathConfigWrite(),
		},

		HelpSynopsis:    confHelpSyn,
		HelpDescription: confHelpDesc,
	}
}

// pathConfigWrite handles create and update commands to the config
func (b *kubeAuthBackend) pathConfigWrite() framework.OperationFunc {
	return func(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		pemBytesList := data.Get("certificates").([]string)
		if len(pemBytesList) == 0 {
			return logical.ErrorResponse("no certificate provided"), nil
		}

		host := data.Get("kubernetes_host").(string)
		if host == "" {
			return logical.ErrorResponse("no host provided"), nil
		}

		config := &kubeConfig{
			Certificates:      make([]interface{}, len(pemBytesList)),
			CertificatesBytes: make([][]byte, len(pemBytesList)),
			Host:              host,
			CACert:            data.Get("kubernetes_ca_cert").(string),
		}

		var err error
		for i, pemBytes := range pemBytesList {
			config.Certificates[i], err = ParsePublicKeyPEM([]byte(pemBytes))
			if err != nil {
				return logical.ErrorResponse(err.Error()), nil
			}
			config.CertificatesBytes[i], err = x509.MarshalPKIXPublicKey(config.Certificates[i])
			if err != nil {
				return nil, err
			}
		}

		entry, err := logical.StorageEntryJSON(configPath, config)
		if err != nil {
			return nil, err
		}

		if err := req.Storage.Put(entry); err != nil {
			return nil, err
		}
		return nil, nil
	}
}

// kubeConfig contains the public key certificate used to verify the signature
// on the service account JWTs
type kubeConfig struct {
	// Certificates is the list of public key objects used to verify JWTs
	Certificates []interface{} `json:"-"`
	// CertificatesBytes is the list of public key bytes used to store the keys
	// in storage.
	CertificatesBytes [][]byte `json:"cert_bytes"`
	// Host is the url string for the kubernetes API
	Host string `json:"host"`
	// CACert is the CA Cert to use to call into the kubernetes API
	CACert string `json:"ca_cert"`
}

// PasrsePublickKeyPEM is used to parse RSA and ECDSA public keys from PEMs
func ParsePublicKeyPEM(data []byte) (interface{}, error) {
	var block *pem.Block
	for {
		block, data = pem.Decode(data)
		if block == nil {
			return nil, errors.New("data does not contain any valid RSA or ECDSA public keys")
		}

		if cert, err := ParsePublicKeyDER(block.Bytes); err == nil {
			return cert, nil
		}
	}
}

// ParsePublickKeyDER is used to parse RSA and ECDSA public keys from DER
// formatted bytes.
func ParsePublicKeyDER(data []byte) (interface{}, error) {
	if publicKey, err := parseRSAPublicKey(data); err == nil {
		return publicKey, nil
	}
	if publicKey, err := parseECPublicKey(data); err == nil {
		return publicKey, nil
	}

	return nil, errors.New("data does not contain any valid RSA or ECDSA public keys")
}

// parsePublicKey attempts to parse the given block data into a public key
// interface.
func parsePublicKey(data []byte) (interface{}, error) {
	var parsedKey interface{}
	var err error
	if parsedKey, err = x509.ParsePKIXPublicKey(data); err != nil {
		if cert, err := x509.ParseCertificate(data); err == nil {
			parsedKey = cert.PublicKey
		} else {
			return nil, err
		}
	}

	return parsedKey, nil
}

// parseRSAPublickKey parses the data and attempts to cast it as a RSA public
// key
func parseRSAPublicKey(data []byte) (*rsa.PublicKey, error) {
	raw, err := parsePublicKey(data)
	if err != nil {
		return nil, err
	}

	rsaPub, ok := raw.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("could not parse RSA public key from data")
	}

	return rsaPub, nil
}

// parseRSAPublickKey parses the data and attempts to cast it as a RSA public
// key
func parseECPublicKey(data []byte) (*ecdsa.PublicKey, error) {
	raw, err := parsePublicKey(data)
	if err != nil {
		return nil, err
	}

	rsaPub, ok := raw.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("could not parse ECDSA public key from data")
	}

	return rsaPub, nil
}

const confHelpSyn = `Configures the JWT Public Key and Kubernetes API information.`
const confHelpDesc = `
The Kubernetes Auth backend validates service account JWTs and verifies their
existence with the Kubernetes TokenReview API. This endpoint configures the
public key used to validate the JWT signature and the necessary information to
access the Kubernetes API.
`
