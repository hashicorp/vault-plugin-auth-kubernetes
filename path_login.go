package kubeauth

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/SermoDigital/jose/crypto"
	"github.com/SermoDigital/jose/jws"
	"github.com/SermoDigital/jose/jwt"
	"github.com/hashicorp/vault/helper/strutil"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
	"github.com/mitchellh/mapstructure"

	kubeerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

var (
	expectedJWTIssuer       string = "kubernetes/serviceaccount"
	ServiceAccountNameClaim string = "kubernetes.io/serviceaccount/service-account.name"
	ServiceAccountUIDClaim  string = "kubernetes.io/serviceaccount/service-account.uid"
	SecretNameClaim         string = "kubernetes.io/serviceaccount/secret.name"
	NamespaceClaim          string = "kubernetes.io/serviceaccount/namespace"

	errMismatchedSigningMethod = errors.New("invalid signing method")

	serviceAccountUsernameTpl string = "system:serviceaccount:%s:%s"
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

		serviceAccount, err := b.parseAndValidateJWT(jwtStr, role, config)
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

func (b *KubeAuthBackend) parseAndValidateJWT(jwtStr string, role *roleStorageEntry, config *kubeConfig) (*serviceAccount, error) {

	verifyFunc := func(cert interface{}) (*serviceAccount, error) {
		// Parse Headers and verify the signing method matches the public key type
		// configured. This is done in its own scope since we don't need any of
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
			}
		}

		// Parse claims
		parsedJWT, err := jws.ParseJWT([]byte(jwtStr))
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

				if !strutil.StrListContains(role.ServiceAccountNames, serviceAccount.Name) {
					return errors.New("service account name not authorized")
				}

				return serviceAccount.lookup(jwtStr, config)
			},
		}

		if err := parsedJWT.Validate(cert, signingMethod, validator); err != nil {
			return nil, err
		}

		return serviceAccount, nil
	}

	var validationErr error
	for _, cert := range config.Certificates {
		serviceAccount, err := verifyFunc(cert)
		switch err {
		case nil:
			return serviceAccount, nil
		case rsa.ErrVerification, crypto.ErrECDSAVerification, errMismatchedSigningMethod:
			validationErr = err
			continue
		default:
			return nil, err
		}
	}

	return nil, validationErr
}

type serviceAccount struct {
	Name       string `mapstructure:"kubernetes.io/serviceaccount/service-account.name"`
	UID        string `mapstructure:"kubernetes.io/serviceaccount/service-account.uid"`
	SecretName string `mapstructure:"kubernetes.io/serviceaccount/secret.name"`
	Namespace  string `mapstructure:"kubernetes.io/serviceaccount/namespace"`
}

func (s *serviceAccount) lookup(jwtStr string, config *kubeConfig) error {
	clientConfig := &rest.Config{
		BearerToken: jwtStr,
		Host:        config.Host,
		TLSClientConfig: rest.TLSClientConfig{
			Insecure: true,
		},
	}
	clientset, err := kubernetes.NewForConfig(clientConfig)
	if err != nil {
		return err
	}

	sa, err := clientset.CoreV1().ServiceAccounts(s.Namespace).Get(s.Name, metav1.GetOptions{})
	log.Println(sa, err)
	switch {
	case kubeerrors.IsNotFound(err), kubeerrors.IsUnauthorized(err):
		return errors.New("lookup failed: service account not found")
	case err != nil:
		return err
	default:
	}

	// TODO: Is any of this necessary? If the token is deteled in kube simply
	// trying to access the api might be enough.
	if sa.ObjectMeta.DeletionTimestamp != nil {
		return errors.New("lookup failed: service account deleted")
	}
	if string(sa.ObjectMeta.UID) != s.UID {
		return errors.New("lookup failed: service account changed")
	}

	secret, err := clientset.CoreV1().Secrets(s.Namespace).Get(s.SecretName, metav1.GetOptions{})
	switch {
	case kubeerrors.IsNotFound(err), kubeerrors.IsUnauthorized(err):
		return errors.New("lookup failed: secret not found")
	case err != nil:
		return err
	default:
	}

	if secret.ObjectMeta.DeletionTimestamp != nil {
		return errors.New("lookup failed: secret deleted")
	}

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
