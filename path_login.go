package kubeauth

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"errors"
	"fmt"
	"time"

	"github.com/SermoDigital/jose/crypto"
	"github.com/SermoDigital/jose/jws"
	"github.com/SermoDigital/jose/jwt"
	multierror "github.com/hashicorp/go-multierror"
	"github.com/hashicorp/vault/helper/strutil"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
	"github.com/mitchellh/mapstructure"
)

var (
	// expectedJWTIssuer is used to verify the iss header on the JWT.
	expectedJWTIssuer string = "kubernetes/serviceaccount"

	uidJWTClaimKey string = "kubernetes.io/serviceaccount/service-account.uid"

	// errMismatchedSigningMethod is used if the certificate doesn't match the
	// JWT's expected signing method.
	errMismatchedSigningMethod = errors.New("invalid signing method")
)

// pathLogin returns the path configurations for login endpoints
func pathLogin(b *kubeAuthBackend) *framework.Path {
	return &framework.Path{
		Pattern: "login$",
		Fields: map[string]*framework.FieldSchema{
			"role": {
				Type:        framework.TypeString,
				Description: `Name of the role against which the login is being attempted. This field is required`,
			},
			"jwt": {
				Type:        framework.TypeString,
				Description: `A signed JWT for authenticating a service account. This field is required.`,
			},
		},

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.UpdateOperation:           b.pathLogin(),
			logical.PersonaLookaheadOperation: b.personaLookahead(),
		},

		HelpSynopsis:    pathLoginHelpSyn,
		HelpDescription: pathLoginHelpDesc,
	}
}

// pathLogin is used to authenticate to this backend
func (b *kubeAuthBackend) pathLogin() framework.OperationFunc {
	return func(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		roleName := data.Get("role").(string)
		if len(roleName) == 0 {
			return logical.ErrorResponse("missing role"), nil
		}

		jwtStr := data.Get("jwt").(string)
		if len(jwtStr) == 0 {
			return logical.ErrorResponse("missing jwt"), nil
		}

		b.l.RLock()
		defer b.l.RUnlock()

		role, err := b.role(req.Storage, roleName)
		if err != nil {
			return nil, err
		}
		if role == nil {
			return logical.ErrorResponse(fmt.Sprintf("invalid role name \"%s\"", roleName)), logical.ErrInvalidRequest
		}

		config, err := b.config(req.Storage)
		if err != nil {
			return nil, err
		}
		if config == nil {
			return nil, errors.New("could not load backend configuration")
		}

		serviceAccount, err := b.parseAndValidateJWT(jwtStr, role, config)
		if err != nil {
			return nil, err
		}

		// look up the JWT token in the kubernetes API
		err = serviceAccount.lookup(jwtStr, b.reviewFactory(config))
		if err != nil {
			return nil, err
		}

		resp := &logical.Response{
			Auth: &logical.Auth{
				NumUses: role.NumUses,
				Period:  role.Period,
				Persona: &logical.Persona{
					Name: serviceAccount.UID,
				},
				InternalData: map[string]interface{}{
					"role": roleName,
				},
				Policies: role.Policies,
				Metadata: map[string]string{
					"service_account_uid":         serviceAccount.UID,
					"service_account_name":        serviceAccount.Name,
					"service_account_namespace":   serviceAccount.Namespace,
					"service_account_secret_name": serviceAccount.SecretName,
					"role": roleName,
				},
				DisplayName: serviceAccount.Name,
				LeaseOptions: logical.LeaseOptions{
					Renewable: true,
					TTL:       role.TTL,
				},
			},
		}

		// If 'Period' is set, use the value of 'Period' as the TTL.
		// Otherwise, set the normal TTL.
		if role.Period > time.Duration(0) {
			resp.Auth.TTL = role.Period
		} else {
			resp.Auth.TTL = role.TTL
		}

		return resp, nil
	}
}

// personaLookahead returns the persona object with the SA UID from the JWT
// Claims.
func (b *kubeAuthBackend) personaLookahead() framework.OperationFunc {
	return func(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		jwtStr := data.Get("jwt").(string)
		if len(jwtStr) == 0 {
			return logical.ErrorResponse("missing jwt"), nil
		}

		// Parse into JWT
		parsedJWT, err := jws.ParseJWT([]byte(jwtStr))
		if err != nil {
			return nil, err
		}

		saUID, ok := parsedJWT.Claims().Get(uidJWTClaimKey).(string)
		if !ok || saUID == "" {
			return nil, errors.New("could not parse UID from claims")
		}

		return &logical.Response{
			Auth: &logical.Auth{
				Persona: &logical.Persona{
					Name: saUID,
				},
			},
		}, nil
	}
}

// parseAndValidateJWT is used to parse, validate and lookup the JWT token.
func (b *kubeAuthBackend) parseAndValidateJWT(jwtStr string, role *roleStorageEntry, config *kubeConfig) (*serviceAccount, error) {

	// verifyFunc is called for each certificate that is configured in the
	// backend until one of the certificates succeeds.
	verifyFunc := func(cert interface{}) (*serviceAccount, error) {
		// Parse Headers and verify the signing method matches the public key type
		// configured. This is done in its own scope since we don't need most of
		// these variables later.
		var signingMethod crypto.SigningMethod
		{
			parsedJWS, err := jws.Parse([]byte(jwtStr))
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

			signingMethod = jws.GetSigningMethod(algStr)
			switch signingMethod.(type) {
			case *crypto.SigningMethodECDSA:
				if _, ok := cert.(*ecdsa.PublicKey); !ok {
					return nil, errMismatchedSigningMethod
				}
			case *crypto.SigningMethodRSA:
				if _, ok := cert.(*rsa.PublicKey); !ok {
					return nil, errMismatchedSigningMethod
				}
			default:
				return nil, errors.New("unsupported JWT signing method")
			}
		}

		// Parse into JWT
		parsedJWT, err := jws.ParseJWT([]byte(jwtStr))
		if err != nil {
			return nil, err
		}

		serviceAccount := &serviceAccount{}
		validator := &jwt.Validator{
			Expected: jwt.Claims{
				"iss": expectedJWTIssuer,
			},
			Fn: func(c jwt.Claims) error {
				// Decode claims into a service account object
				err := mapstructure.Decode(c, serviceAccount)
				if err != nil {
					return err
				}

				// verify the namespace is allowed
				if len(role.ServiceAccountNamespaces) > 1 || role.ServiceAccountNamespaces[0] != "*" {
					if !strutil.StrListContains(role.ServiceAccountNamespaces, serviceAccount.Namespace) {
						return errors.New("namespace not authorized")
					}
				}

				// verify the service account name is allowed
				if len(role.ServiceAccountNames) > 1 || role.ServiceAccountNames[0] != "*" {
					if !strutil.StrListContains(role.ServiceAccountNames, serviceAccount.Name) {
						return errors.New("service account name not authorized")
					}
				}

				return nil
			},
		}

		// validates the signature and then runs the claim validation
		if err := parsedJWT.Validate(cert, signingMethod, validator); err != nil {
			return nil, err
		}

		return serviceAccount, nil
	}

	var validationErr error
	// for each configured certificate run the verifyFunc
	for _, cert := range config.PublicKeys {
		serviceAccount, err := verifyFunc(cert)
		switch err {
		case nil:
			return serviceAccount, nil
		case rsa.ErrVerification, crypto.ErrECDSAVerification, errMismatchedSigningMethod:
			// if the error is a failure to verify or a signing method mismatch
			// continue onto the next cert, storing the error to be returned if
			// this is the last cert.
			validationErr = multierror.Append(validationErr, err)
			continue
		default:
			return nil, err
		}
	}

	return nil, validationErr
}

// serviceAccount holds the metadata from the JWT token and is used to lookup
// the JWT in the kubernetes API and compare the results.
type serviceAccount struct {
	Name       string `mapstructure:"kubernetes.io/serviceaccount/service-account.name"`
	UID        string `mapstructure:"kubernetes.io/serviceaccount/service-account.uid"`
	SecretName string `mapstructure:"kubernetes.io/serviceaccount/secret.name"`
	Namespace  string `mapstructure:"kubernetes.io/serviceaccount/namespace"`
}

// lookup calls the TokenReview API in kubernetes to verify the token and secret
// still exist.
func (s *serviceAccount) lookup(jwtStr string, tr tokenReviewer) error {
	r, err := tr.Review(jwtStr)
	if err != nil {
		return err
	}

	// Verify the returned metadata matches the expected data from the service
	// account.
	if s.Name != r.Name {
		return errors.New("JWT names did not match")
	}
	if s.UID != r.UID {
		return errors.New("JWT UIDs did not match")
	}
	if s.Namespace != r.Namespace {
		return errors.New("JWT namepaces did not match")
	}

	return nil
}

// Invoked when the token issued by this backend is attempting a renewal.
func (b *kubeAuthBackend) pathLoginRenew(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	roleName := req.Auth.InternalData["role"].(string)
	if roleName == "" {
		return nil, fmt.Errorf("failed to fetch role_name during renewal")
	}

	b.l.RLock()
	defer b.l.RUnlock()

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
	}

	return framework.LeaseExtend(role.TTL, role.MaxTTL, b.System())(req, data)
}

const pathLoginHelpSyn = `Authenticates Kubernetes service accounts with Vault.`
const pathLoginHelpDesc = `
Authenticate Kubernetes service accounts.
`
