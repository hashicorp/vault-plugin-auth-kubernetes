package kubeauth

import (
	"fmt"
	"strings"
	"time"

	"github.com/fatih/structs"
	"github.com/hashicorp/vault/helper/policyutil"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

func pathsRole(b *KubeAuthBackend) []*framework.Path {
	return []*framework.Path{
		&framework.Path{
			Pattern: "role/?",
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.ListOperation: b.pathRoleList,
			},
			HelpSynopsis:    strings.TrimSpace(roleHelp["role-list"][0]),
			HelpDescription: strings.TrimSpace(roleHelp["role-list"][1]),
		},
		&framework.Path{
			Pattern: "role/" + framework.GenericNameRegex("role_name"),
			Fields: map[string]*framework.FieldSchema{
				"role_name": &framework.FieldSchema{
					Type:        framework.TypeString,
					Description: "Name of the role.",
				},
				"service_account_uuids": &framework.FieldSchema{
					Type:        framework.TypeCommaStringSlice,
					Description: `Comma separated list of service account uuids able to access this role.`,
				},
				"service_account_namespaces": &framework.FieldSchema{
					Type:        framework.TypeCommaStringSlice,
					Description: "Comma separated list of namespaces allowed to access this role. If not set defaults to all namespaces.",
				},
				"policies": &framework.FieldSchema{
					Type:        framework.TypeCommaStringSlice,
					Default:     "default",
					Description: "Comma separated list of policies on the role.",
				},
				"token_num_uses": &framework.FieldSchema{
					Type:        framework.TypeInt,
					Description: `Number of times issued tokens can be used`,
				},
				"token_ttl": &framework.FieldSchema{
					Type: framework.TypeDurationSecond,
					Description: `Duration in seconds after which the issued token should expire. Defaults
to 0, in which case the value will fall back to the system/mount defaults.`,
				},
				"token_max_ttl": &framework.FieldSchema{
					Type: framework.TypeDurationSecond,
					Description: `Duration in seconds after which the issued token should not be allowed to
be renewed. Defaults to 0, in which case the value will fall back to the system/mount defaults.`,
				},
				"period": &framework.FieldSchema{
					Type:    framework.TypeDurationSecond,
					Default: 0,
					Description: `If set, indicates that the token generated using this role
should never expire. The token should be renewed within the
duration specified by this value. At each renewal, the token's
TTL will be set to the value of this parameter.`,
				},
			},
			ExistenceCheck: b.pathRoleExistenceCheck,
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.CreateOperation: b.pathRoleCreateUpdate,
				logical.UpdateOperation: b.pathRoleCreateUpdate,
				logical.ReadOperation:   b.pathRoleRead,
				logical.DeleteOperation: b.pathRoleDelete,
			},
			HelpSynopsis:    strings.TrimSpace(roleHelp["role"][0]),
			HelpDescription: strings.TrimSpace(roleHelp["role"][1]),
		},
	}
}

// pathRoleExistenceCheck returns whether the role with the given name exists or not.
func (b *KubeAuthBackend) pathRoleExistenceCheck(req *logical.Request, data *framework.FieldData) (bool, error) {
	role, err := b.role(req.Storage, data.Get("role_name").(string))
	if err != nil {
		return false, err
	}
	return role != nil, nil
}

// pathRoleList is used to list all the Roles registered with the backend.
func (b *KubeAuthBackend) pathRoleList(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	b.l.RLock()
	defer b.l.RUnlock()

	roles, err := req.Storage.List("role/")
	if err != nil {
		return nil, err
	}
	return logical.ListResponse(roles), nil
}

// pathRoleRead grabs a read lock and reads the options set on the role from the storage
func (b *KubeAuthBackend) pathRoleRead(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	roleName := data.Get("role_name").(string)
	if roleName == "" {
		return logical.ErrorResponse("missing role_name"), nil
	}

	if role, err := b.role(req.Storage, strings.ToLower(roleName)); err != nil {
		return nil, err
	} else if role == nil {
		return nil, nil
	} else {
		// Convert the 'time.Duration' values to second.
		role.TTL /= time.Second
		role.MaxTTL /= time.Second
		role.Period /= time.Second

		// Create a map of data to be returned
		data := structs.New(role).Map()
		resp := &logical.Response{
			Data: data,
		}

		return resp, nil
	}
}

// pathRoleDelete removes the role from the storage
func (b *KubeAuthBackend) pathRoleDelete(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	roleName := data.Get("role_name").(string)
	if roleName == "" {
		return logical.ErrorResponse("missing role_name"), nil
	}

	// Acquire the lock before deleting the role.
	b.l.Lock()
	defer b.l.Unlock()

	// Delete the role itself
	if err := req.Storage.Delete("role/" + strings.ToLower(roleName)); err != nil {
		return nil, err
	}

	return nil, nil
}

// pathRoleCreateUpdate registers a new role with the backend or updates the options
// of an existing role
func (b *KubeAuthBackend) pathRoleCreateUpdate(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	roleName := data.Get("role_name").(string)
	if roleName == "" {
		return logical.ErrorResponse("missing role_name"), nil
	}

	// Check if the role already exists
	role, err := b.role(req.Storage, roleName)
	if err != nil {
		return nil, err
	}

	// Create a new entry object if this is a CreateOperation
	if role == nil && req.Operation == logical.CreateOperation {
		role = &roleStorageEntry{}
	} else if role == nil {
		return nil, fmt.Errorf("role entry not found during update operation")
	}

	if policiesRaw, ok := data.GetOk("policies"); ok {
		role.Policies = policyutil.ParsePolicies(policiesRaw)
	} else if req.Operation == logical.CreateOperation {
		role.Policies = policyutil.ParsePolicies(data.Get("policies"))
	}

	periodRaw, ok := data.GetOk("period")
	if ok {
		role.Period = time.Second * time.Duration(periodRaw.(int))
	} else if req.Operation == logical.CreateOperation {
		role.Period = time.Second * time.Duration(data.Get("period").(int))
	}
	if role.Period > b.System().MaxLeaseTTL() {
		return logical.ErrorResponse(fmt.Sprintf("'period' of '%s' is greater than the backend's maximum lease TTL of '%s'", role.Period.String(), b.System().MaxLeaseTTL().String())), nil
	}

	if tokenNumUsesRaw, ok := data.GetOk("token_num_uses"); ok {
		role.TokenNumUses = tokenNumUsesRaw.(int)
	} else if req.Operation == logical.CreateOperation {
		role.TokenNumUses = data.Get("token_num_uses").(int)
	}
	if role.TokenNumUses < 0 {
		return logical.ErrorResponse("token_num_uses cannot be negative"), nil
	}

	if tokenTTLRaw, ok := data.GetOk("token_ttl"); ok {
		role.TTL = time.Second * time.Duration(tokenTTLRaw.(int))
	} else if req.Operation == logical.CreateOperation {
		role.TTL = time.Second * time.Duration(data.Get("token_ttl").(int))
	}

	if tokenMaxTTLRaw, ok := data.GetOk("token_max_ttl"); ok {
		role.MaxTTL = time.Second * time.Duration(tokenMaxTTLRaw.(int))
	} else if req.Operation == logical.CreateOperation {
		role.MaxTTL = time.Second * time.Duration(data.Get("token_max_ttl").(int))
	}

	// Check that the TTL value provided is less than the MaxTTL.
	// Sanitizing the TTL and MaxTTL is not required now and can be performed
	// at credential issue time.
	if role.MaxTTL > time.Duration(0) && role.TTL > role.MaxTTL {
		return logical.ErrorResponse("token_ttl should not be greater than token_max_ttl"), nil
	}

	var resp *logical.Response
	if role.MaxTTL > b.System().MaxLeaseTTL() {
		resp = &logical.Response{}
		resp.AddWarning("token_max_ttl is greater than the backend mount's maximum TTL value; issued tokens' max TTL value will be truncated")
	}

	if serviceAccountUUIDs, ok := data.GetOk("service_account_uuids"); ok {
		role.ServiceAccountUUIDs = serviceAccountUUIDs.([]string)
	} else if req.Operation == logical.CreateOperation {
		role.ServiceAccountUUIDs = data.Get("service_account_uuids").([]string)
	}
	if len(role.ServiceAccountUUIDs) == 0 {
		return logical.ErrorResponse("\"service_account_uuids\" can not be empty"), nil
	}

	if namespaces, ok := data.GetOk("service_account_namespaces"); ok {
		role.ServiceAccountNamespaces = namespaces.([]string)
	} else if req.Operation == logical.CreateOperation {
		role.ServiceAccountNamespaces = data.Get("service_account_namespaces").([]string)
	}

	// Store the entry.
	entry, err := logical.StorageEntryJSON("role/"+strings.ToLower(roleName), role)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, fmt.Errorf("failed to create storage entry for role %s", roleName)
	}
	if err = req.Storage.Put(entry); err != nil {
		return nil, err
	}

	return resp, nil
}

// roleStorageEntry stores all the options that are set on an role
type roleStorageEntry struct {
	// Policies that are to be required by the token to access this role
	Policies []string `json:"policies" structs:"policies" mapstructure:"policies"`

	// TokenNumUses defines the number of allowed uses of the token issued
	TokenNumUses int `json:"token_num_uses" mapstructure:"token_num_uses" structs:"token_num_uses"`

	// Duration before which an issued token must be renewed
	TTL time.Duration `json:"ttl" structs:"ttl" mapstructure:"ttl"`

	// Duration after which an issued token should not be allowed to be renewed
	MaxTTL time.Duration `json:"max_ttl" structs:"max_ttl" mapstructure:"max_ttl"`

	// Period, if set, indicates that the token generated using this role
	// should never expire. The token should be renewed within the duration
	// specified by this value. The renewal duration will be fixed if the
	// value is not modified on the role. If the `Period` in the role is modified,
	// a token will pick up the new value during its next renewal.
	Period time.Duration `json:"period" mapstructure:"period" structs:"period"`

	ServiceAccountUUIDs []string `json:"service_account_uuids" mapstructure:"service_account_uuids" structs:"service_account_uuids"`

	ServiceAccountNamespaces []string `json:"service_account_namespaces" mapstructure:"service_account_namespaces" structs:"service_account_namespaces"`
}

var roleHelp = map[string][2]string{
	"role-list": {
		"Lists all the roles registered with the backend.",
		"The list will contain the names of the roles.",
	},
	"role": {
		"Register an role with the backend.",
		`A role can represent a service, a machine or anything that can be IDed.
The set of policies on the role defines access to the role, meaning, any
Vault token with a policy set that is a superset of the policies on the
role registered here will have access to the role. If a SecretID is desired
to be generated against only this specific role, it can be done via
'role/<role_name>/secret-id' and 'role/<role_name>/custom-secret-id' endpoints.
The properties of the SecretID created against the role and the properties
of the token issued with the SecretID generated againt the role, can be
configured using the parameters of this endpoint.`,
	},
}
