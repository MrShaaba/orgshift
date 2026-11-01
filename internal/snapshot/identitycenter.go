package snapshot

import (
	"encoding/json"
	"strings"
)

// ReservedSSORolePrefix is the name prefix of the IAM roles IAM Identity
// Center provisions in a member account for each permission set. The full
// name is AWSReservedSSO_<permission set name>_<16 hex characters>, under the
// path /aws-reserved/sso.amazonaws.com/<region>/.
const ReservedSSORolePrefix = "AWSReservedSSO_"

// Principal types of an account assignment.
const (
	PrincipalUser  = "USER"
	PrincipalGroup = "GROUP"
)

// IdentityCenter describes the IAM Identity Center instance that is attached
// to an organization: its permission sets and the account assignments that
// grant users and groups access to member accounts. It is absent when the
// organization has no instance.
type IdentityCenter struct {
	// InstanceARN is arn:aws:sso:::instance/ssoins-…; IdentityStoreID is the
	// d-… identifier of the directory the users and groups live in.
	InstanceARN     string `json:"instance_arn"`
	IdentityStoreID string `json:"identity_store_id,omitempty"`
	// Region is where the instance lives; the AWSReservedSSO_* roles carry
	// it in their path.
	Region string `json:"region,omitempty"`
	// OwnerAccountID is the management account, or the delegated
	// administrator the snapshot was collected from.
	OwnerAccountID string              `json:"owner_account_id,omitempty"`
	Name           string              `json:"name,omitempty"`
	PermissionSets []PermissionSet     `json:"permission_sets"`
	Assignments    []AccountAssignment `json:"account_assignments"`
}

// PermissionSet is a reusable bundle of policies that becomes one IAM role
// in every account it is assigned to.
type PermissionSet struct {
	ARN         string `json:"arn"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	// SessionDuration is an ISO 8601 duration such as PT1H.
	SessionDuration string `json:"session_duration,omitempty"`
	// ManagedPolicies are AWS managed policy ARNs; CustomerManagedPolicies
	// are policy names (with their path) that must exist in each account.
	ManagedPolicies         []string        `json:"managed_policies,omitempty"`
	CustomerManagedPolicies []string        `json:"customer_managed_policies,omitempty"`
	InlinePolicy            json.RawMessage `json:"inline_policy,omitempty"`
	PermissionsBoundary     string          `json:"permissions_boundary,omitempty"`
	// ProvisionedAccounts lists the accounts where the role for this
	// permission set exists. Optional; when empty, the role is assumed to
	// exist wherever the permission set has an assignment.
	ProvisionedAccounts []string `json:"provisioned_accounts,omitempty"`
}

// AccountAssignment grants one user or group one permission set in one
// account.
type AccountAssignment struct {
	AccountID        string `json:"account_id"`
	PermissionSetARN string `json:"permission_set_arn"`
	// PrincipalType is USER or GROUP; PrincipalID is the identity store ID.
	PrincipalType string `json:"principal_type"`
	PrincipalID   string `json:"principal_id"`
	// PrincipalName is the user name or group display name, when known.
	PrincipalName string `json:"principal_name,omitempty"`
}

// PermissionSet returns the permission set with the given ARN, or nil. It
// is safe to call on a nil receiver.
func (ic *IdentityCenter) PermissionSet(arn string) *PermissionSet {
	if ic == nil {
		return nil
	}
	for i := range ic.PermissionSets {
		if ic.PermissionSets[i].ARN == arn {
			return &ic.PermissionSets[i]
		}
	}
	return nil
}

// PermissionSetByName returns the permission set with the given name, or
// nil. Names are unique inside one instance. Safe on a nil receiver.
func (ic *IdentityCenter) PermissionSetByName(name string) *PermissionSet {
	if ic == nil {
		return nil
	}
	for i := range ic.PermissionSets {
		if ic.PermissionSets[i].Name == name {
			return &ic.PermissionSets[i]
		}
	}
	return nil
}

// AssignmentsFor returns the assignments on an account in snapshot order.
// Safe on a nil receiver.
func (ic *IdentityCenter) AssignmentsFor(accountID string) []AccountAssignment {
	if ic == nil {
		return nil
	}
	var out []AccountAssignment
	for _, a := range ic.Assignments {
		if a.AccountID == accountID {
			out = append(out, a)
		}
	}
	return out
}

// ProvisionedIn returns the permission sets whose role exists in an
// account: those listing it under provisioned_accounts, plus (when a
// permission set has no such list) those with an assignment on it. The
// result is in snapshot order. Safe on a nil receiver.
func (ic *IdentityCenter) ProvisionedIn(accountID string) []PermissionSet {
	if ic == nil {
		return nil
	}
	assigned := map[string]bool{}
	for _, a := range ic.Assignments {
		if a.AccountID == accountID {
			assigned[a.PermissionSetARN] = true
		}
	}
	var out []PermissionSet
	for _, ps := range ic.PermissionSets {
		if contains(ps.ProvisionedAccounts, accountID) || (len(ps.ProvisionedAccounts) == 0 && assigned[ps.ARN]) {
			out = append(out, ps)
		}
	}
	return out
}

// ReservedRolePattern is the name of the IAM role Identity Center creates
// for a permission set, with the random suffix left as a wildcard.
func (ps PermissionSet) ReservedRolePattern() string {
	return ReservedSSORolePrefix + ps.Name + "_*"
}

// ReservedRolePath is the IAM path of the provisioned roles of an instance.
func (ic *IdentityCenter) ReservedRolePath() string {
	region := "<region>"
	if ic != nil && ic.Region != "" {
		region = ic.Region
	}
	return "/aws-reserved/sso.amazonaws.com/" + region + "/"
}

// Label is how an assignment's principal is shown: "group Name" or
// "user Name", falling back to the identity store ID.
func (a AccountAssignment) Label() string {
	name := a.PrincipalName
	if name == "" {
		name = a.PrincipalID
	}
	return strings.ToLower(a.PrincipalType) + " " + name
}

func contains(list []string, s string) bool {
	for _, l := range list {
		if l == s {
			return true
		}
	}
	return false
}
