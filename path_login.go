package kubeauth

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/SermoDigital/jose/crypto"
	"github.com/SermoDigital/jose/jws"
	"github.com/SermoDigital/jose/jwt"
	"github.com/hashicorp/vault/helper/strutil"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
	"github.com/mitchellh/mapstructure"
)

var (
	expectedJWTIssuer       string = "kubernetes/serviceaccount"
	ServiceAccountNameClaim string = "kubernetes.io/serviceaccount/service-account.name"
	ServiceAccountUIDClaim  string = "kubernetes.io/serviceaccount/service-account.uid"
	SecretNameClaim         string = "kubernetes.io/serviceaccount/secret.name"
	NamespaceClaim          string = "kubernetes.io/serviceaccount/namespace"

	errMismatchedSigningMethod = errors.New("invalid signing method")
)

func pathLogin(b *KubeAuthBackend) *framework.Path {
	return &framework.Path{
		Pattern: "login$",
		Fields: map[string]*framework.FieldSchema{
			"role": {
				Type:        framework.TypeString,
				Description: `Name of the role against which the login is being attempted. Required.`,
			},
			"jwt": {
				Type:        framework.TypeString,
				Description: `A signed JWT for authenticating a service account.`,
			},
		},

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.UpdateOperation: b.pathLogin(),
		},

		HelpSynopsis:    pathLoginHelpSyn,
		HelpDescription: pathLoginHelpDesc,
	}
}

func (b *KubeAuthBackend) pathLogin() framework.OperationFunc {
	return func(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		roleName := data.Get("role").(string)
		if len(roleName) == 0 {
			return logical.ErrorResponse("missing role_name"), logical.ErrInvalidRequest
		}

		jwtStr := data.Get("jwt").(string)
		if len(jwtStr) == 0 {
			return logical.ErrorResponse("missing jwt"), logical.ErrInvalidRequest
		}

		b.l.RLock()
		defer b.l.RUnlock()

		role, err := b.role(req.Storage, strings.ToLower(roleName))
		if err != nil {
			return nil, err
		} else if role == nil {
			return logical.ErrorResponse(fmt.Sprintf("could not load role \"%s\"", roleName)), logical.ErrInvalidRequest
		}

		config, err := b.config(req.Storage)
		if err != nil {
			return nil, err
		}
		if config == nil {
			return nil, errors.New("could not load backend configuration")
		}

		serviceAccount, err := b.parseAndValidateJWT([]byte(jwtStr), role, config)
		if err != nil {
			return nil, err
		}

		resp := &logical.Response{
			Auth: &logical.Auth{
				Period: role.Period,
				Persona: &logical.Persona{
					Name: serviceAccount.UID,
				},
				Policies: role.Policies,
				Metadata: map[string]string{
					"service_account_uid":       serviceAccount.UID,
					"service_account_name":      serviceAccount.Name,
					"service_account_namespace": serviceAccount.Namespace,
					"service_account_secret":    serviceAccount.SecretName,
					"role": roleName,
				},
				DisplayName: serviceAccount.Name,
				LeaseOptions: logical.LeaseOptions{
					Renewable: true,
					TTL:       role.TTL,
				},
			},
		}

		return resp, nil
	}
}

func (b *KubeAuthBackend) parseAndValidateJWT(jwtBytes []byte, role *roleStorageEntry, config *kubeConfig) (*serviceAccount, error) {
	// Parse Headers
	{
		parsedJWS, err := jws.Parse(jwtBytes)
		if err != nil {
			return nil, err
		}
		headers := parsedJWS.Protected()

		var algStr string
		if headers.Has("alg") {
			algStr = headers.Get("alg").(string)
		} else {
			return nil, errors.New("provided JWT must have 'alg' header value")
		}

		switch jws.GetSigningMethod(algStr).(type) {
		case *crypto.SigningMethodECDSA:
			if _, ok := config.Certificate.(*ecdsa.PublicKey); !ok {
				return nil, errMismatchedSigningMethod
			}
		case *crypto.SigningMethodRSA:
			if _, ok := config.Certificate.(*rsa.PublicKey); !ok {
				return nil, errMismatchedSigningMethod
			}
		}
	}

	// Parse claims
	parsedJWT, err := jws.ParseJWT(jwtBytes)
	if err != nil {
		return nil, err
	}

	var serviceAccount *serviceAccount = &serviceAccount{}
	validator := &jwt.Validator{
		Expected: jwt.Claims{
			"iss": expectedJWTIssuer,
		},
		Fn: func(c jwt.Claims) error {
			err := mapstructure.Decode(c, serviceAccount)
			if err != nil {
				return err
			}

			if len(role.ServiceAccountNamespaces) > 0 && !strutil.StrListContains(role.ServiceAccountNamespaces, serviceAccount.Namespace) {
				return errors.New("namespace not authorized")
			}

			if !strutil.StrListContains(role.ServiceAccountUUIDs, serviceAccount.UID) {
				return errors.New("service account uid not authorized")
			}

			return serviceAccount.lookup()
		},
	}

	if err := parsedJWT.Validate(config.Certificate.(*rsa.PublicKey), crypto.SigningMethodRS256, validator); err != nil {
		return nil, err
	}

	return serviceAccount, nil
}

type serviceAccount struct {
	Name       string `mapstructure:"kubernetes.io/serviceaccount/service-account.name"`
	UID        string `mapstructure:"kubernetes.io/serviceaccount/service-account.uid"`
	SecretName string `mapstructure:"kubernetes.io/serviceaccount/secret.name"`
	Namespace  string `mapstructure:"kubernetes.io/serviceaccount/namespace"`
}

func (s *serviceAccount) lookup() error {
	return nil
}

// Invoked when the token issued by this backend is attempting a renewal.
func (b *KubeAuthBackend) pathLoginRenew(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	roleName := req.Auth.InternalData["role_name"].(string)
	if roleName == "" {
		return nil, fmt.Errorf("failed to fetch role_name during renewal")
	}

	// Ensure that the Role still exists.
	role, err := b.role(req.Storage, roleName)
	if err != nil {
		return nil, fmt.Errorf("failed to validate role %s during renewal:%s", roleName, err)
	}
	if role == nil {
		return nil, fmt.Errorf("role %s does not exist during renewal", roleName)
	}

	// If 'Period' is set on the Role, the token should never expire.
	// Replenish the TTL with 'Period's value.
	if role.Period > time.Duration(0) {
		// If 'Period' was updated after the token was issued,
		// token will bear the updated 'Period' value as its TTL.
		req.Auth.TTL = role.Period
		return &logical.Response{Auth: req.Auth}, nil
	} else {
		return framework.LeaseExtend(role.TTL, role.MaxTTL, b.System())(req, data)
	}
}

const pathLoginHelpSyn = `Authenticates Kubernetes service accounts with Vault.`
const pathLoginHelpDesc = `
Authenticate Kubernetes service accounts.
`
