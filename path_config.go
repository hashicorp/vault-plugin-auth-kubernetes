package kubeauth

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"

	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

const warningACLReadAccess string = "Read access to this endpoint should be controlled via ACLs as it will return the configuration information as-is, including any passwords."

func pathConfig(b *KubeAuthBackend) *framework.Path {
	return &framework.Path{
		Pattern: "config$",
		Fields: map[string]*framework.FieldSchema{
			"certificates": {
				Type:        framework.TypeCommaStringSlice,
				Description: "The PEM-formated certificate used to sign kubernetes service account JWTs",
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

func (b *KubeAuthBackend) pathConfigWrite() framework.OperationFunc {
	return func(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		pemBytesList := data.Get("certificates").([]string)
		if len(pemBytesList) == 0 {
			return logical.ErrorResponse("no certificate provided"), nil
		}

		config := &kubeConfig{
			Certificates:      make([]interface{}, len(pemBytesList)),
			CertificatesBytes: make([][]byte, len(pemBytesList)),
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
	Certificates      []interface{} `json:"-"`
	CertificatesBytes [][]byte      `json:"cert_bytes"`
}

const confHelpSyn = `Configure credentials used to query the GCP IAM API to verify authenticating service accounts`
const confHelpDesc = `
The GCP IAM auth backend makes queries to the GCP IAM auth backend to verify a service account
attempting login. It verifies the service account exists and retrieves a public key to verify
signed JWT requests passed in on login. The credentials should have the following permissions:
iam AUTH:
* iam.serviceAccountKeys.get
`

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

func ParsePublicKeyDER(data []byte) (interface{}, error) {
	if publicKey, err := parseRSAPublicKey(data); err == nil {
		return publicKey, nil
	} else {
		fmt.Println(err)
	}
	if publicKey, err := parseECPublicKey(data); err == nil {
		return publicKey, nil
	} else {
		fmt.Println(err)
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
