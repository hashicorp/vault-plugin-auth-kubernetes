package kubeauth

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/hashicorp/vault/helper/strutil"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"

	kubeerrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/client-go/kubernetes"
	authv1 "k8s.io/client-go/pkg/apis/authentication/v1"
	"k8s.io/client-go/rest"
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

		serviceAccount, err := b.lookupJWT(jwtStr, config)
		if err != nil {
			return nil, err
		}

		if !strutil.StrListContains(role.ServiceAccountNamespaces, serviceAccount.Namespace) {
			return nil, errors.New("namespace not authorized")
		}

		if !strutil.StrListContains(role.ServiceAccountNames, serviceAccount.Name) {
			return nil, errors.New("service account name not authorized")
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

func (b *KubeAuthBackend) lookupJWT(jwtStr string, config *kubeConfig) (*serviceAccount, error) {
	clientConfig := &rest.Config{
		BearerToken: jwtStr,
		Host:        config.Host,
		TLSClientConfig: rest.TLSClientConfig{
			CAData: []byte(config.CACert),
		},
	}
	clientset, err := kubernetes.NewForConfig(clientConfig)
	if err != nil {
		return nil, err
	}

	r, err := clientset.AuthenticationV1().TokenReviews().Create(&authv1.TokenReview{
		Spec: authv1.TokenReviewSpec{
			Token: jwtStr,
		},
	})
	switch {
	case kubeerrors.IsUnauthorized(err):
		return nil, errors.New("lookup failed: service account deleted")
	case err != nil:
		return nil, err
	default:
	}
	if !r.Status.Authenticated {
		return nil, errors.New("lookup failed: service account jwt not valid")
	}

	parts := strings.Split(r.Status.User.Username, ":")
	if len(parts) != 4 {
		return nil, errors.New("lookup failed: unexpected username format")
	}

	return &serviceAccount{
		Name:      parts[3],
		UID:       string(r.Status.User.UID),
		Namespace: parts[2],
	}, nil
}

type serviceAccount struct {
	Name      string `mapstructure:"kubernetes.io/serviceaccount/service-account.name"`
	UID       string `mapstructure:"kubernetes.io/serviceaccount/service-account.uid"`
	Namespace string `mapstructure:"kubernetes.io/serviceaccount/namespace"`
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
