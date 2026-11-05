// Package snapshot defines the versioned, offline representation of an AWS
// organization that orgshift collects, generates as fixtures and evaluates.
//
// A snapshot is a plain JSON document. It never contains credentials and is
// meant to be stored, diffed and shared like any other configuration artifact.
// The schema is documented in docs/snapshot.md.
package snapshot

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

// SchemaVersion is the current snapshot schema version. Loaders reject
// documents written with a newer version and upgrade older ones in memory.
//
// Version 2 (2026-11) added the coverage block, which records what the
// collector could and could not inspect. A version 1 document is accepted
// and treated as having unknown coverage for every domain, so an empty list
// in it no longer reads as "nothing exists".
//
// Version 3 (2026-11) added the workloads block (per account: CloudFormation
// stacks, a resource sample and the resource policies that reference
// organization identity), the three workloads.* coverage domains and the
// instances of each StackSet. A version 2 document is accepted: it has no
// workload inventory, so those domains read as unknown, and a completeness
// assertion made before they existed does not cover them.
const SchemaVersion = 3

// PolicyType mirrors the policy type names used by AWS Organizations.
type PolicyType string

// Policy types understood by the evaluator.
const (
	PolicyTypeSCP    PolicyType = "SERVICE_CONTROL_POLICY"
	PolicyTypeRCP    PolicyType = "RESOURCE_CONTROL_POLICY"
	PolicyTypeTag    PolicyType = "TAG_POLICY"
	PolicyTypeBackup PolicyType = "BACKUP_POLICY"
)

// AllPolicyTypes lists the policy types in the order the UI shows them.
var AllPolicyTypes = []PolicyType{PolicyTypeSCP, PolicyTypeRCP, PolicyTypeTag, PolicyTypeBackup}

// Short returns the short label used in the UI and in reports.
func (t PolicyType) Short() string {
	switch t {
	case PolicyTypeSCP:
		return "SCP"
	case PolicyTypeRCP:
		return "RCP"
	case PolicyTypeTag:
		return "TAG"
	case PolicyTypeBackup:
		return "BACKUP"
	}
	return string(t)
}

// Snapshot is the top-level document.
type Snapshot struct {
	SchemaVersion int `json:"schema_version"`
	// UpgradedFrom is set in memory (never written) when Parse upgraded the
	// document from an older schema version.
	UpgradedFrom int    `json:"-"`
	GeneratedAt  string `json:"generated_at,omitempty"`
	// Source records how the snapshot was produced: "fixture", "collector" or "manual".
	Source string `json:"source,omitempty"`

	Organization Organization `json:"organization"`
	Root         Root         `json:"root"`
	OUs          []OU         `json:"organizational_units"`
	Accounts     []Account    `json:"accounts"`
	Policies     []Policy     `json:"policies"`

	ResourceShares          []ResourceShare          `json:"resource_shares"`
	DelegatedAdministrators []DelegatedAdministrator `json:"delegated_administrators"`
	TrustedAccessServices   []string                 `json:"trusted_access_services"`
	OrganizationTrails      []OrganizationTrail      `json:"organization_trails"`
	ConfigAggregators       []ConfigAggregator       `json:"config_aggregators"`
	StackSets               []StackSet               `json:"stack_sets"`

	// Coverage records which domains the collector inspected and how each
	// call ended. Without it every domain is of unknown completeness.
	Coverage *Coverage `json:"coverage,omitempty"`

	// ControlTower describes the Control Tower landing zone, when there is one.
	ControlTower *ControlTower `json:"control_tower,omitempty"`
	// IdentityCenter describes the IAM Identity Center instance, its
	// permission sets and account assignments, when there is one.
	IdentityCenter *IdentityCenter `json:"identity_center,omitempty"`

	// Workloads holds the workload inventory of the member accounts that
	// were inspected, keyed by account ID. See AccountWorkloads.
	Workloads map[string]*AccountWorkloads `json:"workloads,omitempty"`

	// Usage holds per-account information that the evaluator needs about the
	// account being moved: actions in use, inbound access from other
	// principals and a sample of tagged resources. Keyed by account ID.
	Usage map[string]*AccountUsage `json:"usage,omitempty"`
}

// Organization describes the organization itself.
type Organization struct {
	ID                  string `json:"id"`
	ARN                 string `json:"arn,omitempty"`
	ManagementAccountID string `json:"management_account_id"`
	FeatureSet          string `json:"feature_set,omitempty"`
	// Name is a friendly label; AWS has no such attribute, so it is set by the
	// collector flag or the fixture generator.
	Name string `json:"name,omitempty"`
}

// Root is the organization root.
type Root struct {
	ID   string `json:"id"`
	ARN  string `json:"arn,omitempty"`
	Name string `json:"name"`
	// EnabledPolicyTypes lists the policy types enabled at this root.
	EnabledPolicyTypes []PolicyType `json:"enabled_policy_types"`
}

// OU is an organizational unit.
type OU struct {
	ID       string `json:"id"`
	ARN      string `json:"arn,omitempty"`
	Name     string `json:"name"`
	ParentID string `json:"parent_id"`
}

// Account is a member account.
type Account struct {
	ID           string `json:"id"`
	ARN          string `json:"arn,omitempty"`
	Name         string `json:"name"`
	Email        string `json:"email,omitempty"`
	Status       string `json:"status,omitempty"`
	JoinedMethod string `json:"joined_method,omitempty"`
	// JoinedAt is when the account was created in or invited into the
	// organization (RFC 3339). Organizations refuses to remove an account it
	// created until four days have passed.
	JoinedAt       string            `json:"joined_at,omitempty"`
	ParentID       string            `json:"parent_id"`
	Tags           map[string]string `json:"tags,omitempty"`
	EnabledRegions []string          `json:"enabled_regions,omitempty"`
}

// Policy is an organization policy of any type together with its targets.
type Policy struct {
	ID          string     `json:"id"`
	ARN         string     `json:"arn,omitempty"`
	Name        string     `json:"name"`
	Description string     `json:"description,omitempty"`
	Type        PolicyType `json:"type"`
	AWSManaged  bool       `json:"aws_managed"`
	// Document is the policy content as stored by AWS (IAM JSON for SCP and
	// RCP, the tag or backup policy JSON syntax otherwise).
	Document json.RawMessage `json:"document"`
	// Targets lists root, OU and account IDs the policy is attached to.
	Targets []string `json:"targets"`
}

// ResourceShare is an AWS RAM resource share seen from the owning organization.
type ResourceShare struct {
	ARN                     string `json:"arn"`
	Name                    string `json:"name"`
	OwnerAccountID          string `json:"owner_account_id"`
	Status                  string `json:"status,omitempty"`
	AllowExternalPrincipals bool   `json:"allow_external_principals"`
	// RetainSharingOnAccountLeave mirrors RAM's
	// RetainSharingOnAccountLeaveOrganization: a share with account
	// principals keeps reaching them after they leave the organization (as
	// an invitation). Shares with organization or OU principals never retain.
	RetainSharingOnAccountLeave bool `json:"retain_sharing_on_account_leave_organization,omitempty"`
	// Principals are account IDs, organization ARNs, OU ARNs, IAM role or
	// user ARNs, or service principals.
	Principals []string         `json:"principals"`
	Resources  []SharedResource `json:"resources"`
}

// SharedResource is one resource inside a resource share.
type SharedResource struct {
	ARN string `json:"arn"`
	// Type uses the RAM resource type notation, for example
	// "ec2:TransitGateway", "ec2:Subnet", "route53resolver:ResolverRule",
	// "ec2:IpamPool" or "ec2:PrefixList".
	Type string `json:"type"`
}

// DelegatedAdministrator records that an account administers a service for
// the organization.
type DelegatedAdministrator struct {
	AccountID        string `json:"account_id"`
	ServicePrincipal string `json:"service_principal"`
	DelegationDate   string `json:"delegation_date,omitempty"`
}

// OrganizationTrail is a CloudTrail trail with IsOrganizationTrail set.
type OrganizationTrail struct {
	Name           string `json:"name"`
	ARN            string `json:"arn,omitempty"`
	OwnerAccountID string `json:"owner_account_id"`
	HomeRegion     string `json:"home_region,omitempty"`
	S3BucketName   string `json:"s3_bucket_name,omitempty"`
}

// ConfigAggregator is an AWS Config aggregator with an organization source.
type ConfigAggregator struct {
	Name               string `json:"name"`
	AccountID          string `json:"account_id"`
	Region             string `json:"region,omitempty"`
	OrganizationSource bool   `json:"organization_source"`
}

// StackSet is a CloudFormation StackSet. Only service-managed StackSets are
// affected by organization membership, but self-managed ones are kept too.
type StackSet struct {
	Name                         string   `json:"name"`
	ID                           string   `json:"id,omitempty"`
	AdministrationAccountID      string   `json:"administration_account_id"`
	PermissionModel              string   `json:"permission_model"`
	AutoDeployment               bool     `json:"auto_deployment"`
	RetainStacksOnAccountRemoval bool     `json:"retain_stacks_on_account_removal"`
	TargetOUs                    []string `json:"target_ous,omitempty"`
	TargetAccounts               []string `json:"target_accounts,omitempty"`
	Regions                      []string `json:"regions,omitempty"`
	Description                  string   `json:"description,omitempty"`
	// Instances are the StackSet's deployments, one per account and Region
	// (schema version 3). They link the StackSet to the stacks it created
	// in member accounts.
	Instances []StackInstance `json:"instances,omitempty"`
}

// AccountUsage is what the evaluator knows about how an account is used.
type AccountUsage struct {
	// Actions are IAM actions that principals inside the account perform.
	Actions []ActionInUse `json:"actions,omitempty"`
	// InboundAccess lists principals outside the account that access its
	// resources. Resource control policies apply to these requests.
	InboundAccess []InboundAccess `json:"inbound_access,omitempty"`
	// TaggedResources is a sample of resources with their tags, used to
	// check tag policy compliance.
	TaggedResources []TaggedResource `json:"tagged_resources,omitempty"`
}

// ActionInUse is one action an account's principals rely on.
type ActionInUse struct {
	// Action is "service:Action". Wildcards are accepted for imports that
	// only know the service, for example "dynamodb:*".
	Action string `json:"action"`
	// Resource is an optional ARN or ARN pattern. When empty the evaluator
	// treats the resource as unknown.
	Resource string `json:"resource,omitempty"`
	// Regions limits where the action is used. When empty the account's
	// enabled regions are assumed. Global services always use us-east-1.
	Regions []string `json:"regions,omitempty"`
	// PrincipalArn and PrincipalTags describe the caller when known. They are
	// needed to evaluate aws:PrincipalArn and aws:PrincipalTag conditions.
	PrincipalArn  string            `json:"principal_arn,omitempty"`
	PrincipalTags map[string]string `json:"principal_tags,omitempty"`
	// Source is "manual" or "iam-last-accessed".
	Source   string `json:"source,omitempty"`
	LastUsed string `json:"last_used,omitempty"`
	Note     string `json:"note,omitempty"`
}

// InboundAccess is access to the account's resources by an outside principal.
type InboundAccess struct {
	// Principal is an account ID, an IAM ARN or a service principal.
	Principal string `json:"principal"`
	// PrincipalOrgID can be given when the principal's organization is known
	// and not part of either snapshot.
	PrincipalOrgID string   `json:"principal_org_id,omitempty"`
	Actions        []string `json:"actions"`
	Resource       string   `json:"resource,omitempty"`
	Regions        []string `json:"regions,omitempty"`
	Note           string   `json:"note,omitempty"`
}

// TaggedResource is a resource with its tags, for tag policy checks.
type TaggedResource struct {
	ARN string `json:"arn"`
	// Type uses the tag policy resource type notation, for example
	// "ec2:instance" or "s3:bucket".
	Type   string            `json:"type"`
	Region string            `json:"region,omitempty"`
	Tags   map[string]string `json:"tags"`
}

// Fingerprint identifies a policy by its content: the first 16 hex digits
// of the SHA-256 of the compacted document. Two policies with the same ID in
// different organizations (or the same policy before and after an edit)
// have different fingerprints, so caches keyed by it never collide.
func (p *Policy) Fingerprint() string {
	var buf bytes.Buffer
	data := p.Document
	if err := json.Compact(&buf, p.Document); err == nil {
		data = buf.Bytes()
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:8])
}

// Key is the namespaced identity of a policy inside one snapshot: the
// organization, the policy ID and the content fingerprint.
func (s *Snapshot) PolicyKey(p *Policy) string {
	return s.Organization.ID + "|" + p.ID + "|" + p.Fingerprint()
}

// UsageFor returns the usage block for an account, or an empty one.
func (s *Snapshot) UsageFor(accountID string) *AccountUsage {
	if s.Usage != nil {
		if u := s.Usage[accountID]; u != nil {
			return u
		}
	}
	return &AccountUsage{}
}

// PolicyTypeEnabled reports whether a policy type is enabled at the root.
func (s *Snapshot) PolicyTypeEnabled(t PolicyType) bool {
	for _, e := range s.Root.EnabledPolicyTypes {
		if e == t {
			return true
		}
	}
	return false
}
