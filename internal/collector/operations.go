// Package collector reads an AWS organization through read-only API calls
// and produces a snapshot. Every operation it may call is listed in Catalog
// with its semantics (read, read-billable, session) and the collector
// responsibility that needs it; a test fails the build if the package, the
// preflight or the CLI references anything else, if a write operation ever
// appears, or if a billable read is not behind an opt-in. The IAM templates
// in docs/iam are generated from the same catalog.
package collector

import (
	"sort"
	"strings"
)

// Kind classifies what an operation does to the accounts it is called
// against. The classification is by semantics, not by verb: a Search,
// Lookup or Select is a read; StartQuery on CloudTrail Lake is a read that
// costs money; AssumeRole obtains a session and changes nothing.
type Kind string

// Operation kinds.
const (
	// KindRead returns existing state and is free of charge.
	KindRead Kind = "read"
	// KindReadBillable returns existing state but AWS bills the call (per
	// query, per TB scanned). Only ever called behind an explicit opt-in.
	KindReadBillable Kind = "read-billable"
	// KindSession obtains or describes temporary credentials. AWS labels
	// sts:AssumeRole "Write" in its access-level tables because it issues a
	// session; it changes no resource in any account.
	KindSession Kind = "session"
	// KindWrite changes state. It is never present in the catalog; the test
	// fails if it is.
	KindWrite Kind = "write"
)

// Responsibility names the role a collector credential plays. One IAM
// template is generated per responsibility.
type Responsibility string

// Collector responsibilities.
const (
	// RoleOrgManagement reads Organizations, the regions of every account
	// and the shares owned by the management account; it also assumes the
	// member and network roles. Lives in the management account (or in an
	// Organizations delegated administrator for the read calls that can be
	// delegated).
	RoleOrgManagement Responsibility = "org-management"
	// RoleControlTower reads the landing zone, baselines and controls. The
	// Control Tower APIs answer only from the management account, in the
	// home region.
	RoleControlTower Responsibility = "control-tower"
	// RoleIdentityCenter reads the Identity Center instance, permission sets
	// and assignments, in the instance's region, from the management
	// account or the Identity Center delegated administrator.
	RoleIdentityCenter Responsibility = "identity-center"
	// RoleMemberInspection is assumed in member accounts to read what only
	// the account itself can see: its stacks, a resource sample and the
	// policies tied to organization identity (the workload inventory), and
	// later IAM last-accessed data and networking state.
	RoleMemberInspection Responsibility = "member-inspection"
	// RoleNetwork lists the RAM shares owned by a network account (RAM only
	// shows the caller's own shares).
	RoleNetwork Responsibility = "network"
)

// Responsibilities lists the responsibilities in template order.
var Responsibilities = []Responsibility{RoleOrgManagement, RoleControlTower, RoleIdentityCenter, RoleMemberInspection, RoleNetwork}

// Operation is one API operation the collector uses or plans to use.
type Operation struct {
	// Service is the IAM service prefix (organizations, ram, sso, ...).
	Service string
	// Name is the API operation.
	Name string
	Kind Kind
	// Responsibilities lists the roles that call the operation.
	Responsibilities []Responsibility
	// Domain is the coverage domain the operation fills; "" for session
	// operations.
	Domain string
	// OptIn is the configuration key and flag that must be on before a
	// read-billable operation is called. Required for KindReadBillable.
	OptIn string
	// Used is true when this build calls the operation. Planned operations
	// are listed so their semantics and opt-ins are decided before the code
	// that calls them exists; they are kept out of the generated IAM
	// policies.
	Used bool
	// Purpose says what the call is for.
	Purpose string
	// Resource is the IAM resource type the action can be scoped to, as an
	// ARN pattern, or "" when the action does not support resource-level
	// permissions and needs Resource "*".
	Resource string
	// Note justifies a kind that the verb does not make obvious (a Start
	// that is a billable read, a Generate that is a read, an Assume that is
	// a session). Required when the name does not start with a read verb.
	Note string
	// Actions are the IAM actions the call needs when they are not simply
	// service:Name: s3:ListBuckets is authorized as s3:ListAllMyBuckets,
	// and describing every stack needs cloudformation:ListStacks as well.
	Actions []string
}

// Action renders the operation as service:Name.
func (o Operation) Action() string { return o.Service + ":" + o.Name }

// IAM returns the IAM actions the operation needs.
func (o Operation) IAM() []string {
	if len(o.Actions) > 0 {
		return o.Actions
	}
	return []string{o.Action()}
}

// For reports whether the operation belongs to a responsibility.
func (o Operation) For(r Responsibility) bool {
	for _, x := range o.Responsibilities {
		if x == r {
			return true
		}
	}
	return false
}

// Opt-in keys for billable reads. The CLI flags carry the same names.
const (
	OptInCloudTrailLake = "billable.cloudtrail_lake (--with-cloudtrail-lake)"
	OptInConfigQueries  = "billable.config_queries (--with-config-queries)"
	OptInBucketPolicies = "billable.bucket_policies (--with-bucket-policies)"
)

// Domains that exist only in the catalog because the data they fill lives
// under usage or in a later snapshot version.
const (
	domainUsageActions   = "usage.actions"
	domainUsageResources = "usage.tagged_resources"
	domainNetworkPaths   = "network_paths"
)

// ARN patterns for resource-level permissions, as the Service Authorization
// Reference documents them.
const (
	arnOrgRootOrOU  = "arn:${Partition}:organizations::${ManagementAccountId}:root/o-*/r-* and ou/o-*/ou-*"
	arnOrgPolicy    = "arn:${Partition}:organizations::${ManagementAccountId}:policy/o-*/*/p-*"
	arnOrgAccount   = "arn:${Partition}:organizations::${ManagementAccountId}:account/o-*/*"
	arnOrgTaggable  = "arn:${Partition}:organizations::${ManagementAccountId}:{root,ou,account,policy}/o-*/*"
	arnAccount      = "arn:${Partition}:account::${ManagementAccountId}:account/o-*/*"
	arnRAMShare     = "arn:${Partition}:ram:${Region}:${Account}:resource-share/*"
	arnLandingZone  = "arn:${Partition}:controltower:${Region}:${Account}:landingzone/*"
	arnControl      = "arn:${Partition}:controlcatalog:::control/*"
	arnSSOInstance  = "arn:${Partition}:sso:::instance/ssoins-*"
	arnSSOPermSet   = "arn:${Partition}:sso:::permissionSet/ssoins-*/ps-*"
	arnIdentityUser = "arn:${Partition}:identitystore::${Account}:identitystore/d-* and arn:${Partition}:identitystore:::user/* or group/*"
	arnTrail        = "arn:${Partition}:cloudtrail:${Region}:${Account}:trail/*"
	arnStackSet     = "arn:${Partition}:cloudformation:${Region}:${Account}:stackset/*"
	arnEventStore   = "arn:${Partition}:cloudtrail:${Region}:${Account}:eventdatastore/*"
	arnAggregator   = "arn:${Partition}:config:${Region}:${Account}:config-aggregator/*"
	arnIAMEntity    = "arn:${Partition}:iam::${Account}:{role,user,group}/*"
	arnResolverRule = "arn:${Partition}:route53resolver:${Region}:${Account}:resolver-rule/*"
	arnMemberRole   = "arn:${Partition}:iam::*:role/${MemberInspectionRoleName}"
	arnStack        = "arn:${Partition}:cloudformation:${Region}:${Account}:stack/*/*"
	arnExplorerView = "arn:${Partition}:resource-explorer-2:${Region}:${Account}:view/*/*"
	arnBucket       = "arn:${Partition}:s3:::*"
)

var (
	orgMgmt   = []Responsibility{RoleOrgManagement}
	ct        = []Responsibility{RoleControlTower}
	idc       = []Responsibility{RoleIdentityCenter}
	member    = []Responsibility{RoleMemberInspection}
	netOrMgmt = []Responsibility{RoleOrgManagement, RoleNetwork}
	netMember = []Responsibility{RoleMemberInspection, RoleNetwork}
	everyRole = Responsibilities
)

// Catalog is the complete list of operations orgshift calls or plans to
// call. Nothing outside it is referenced by the collector, the preflight or
// the CLI (see operations_test.go).
var Catalog = []Operation{
	// Organizations: the organization, the tree, policies and services.
	{Service: "organizations", Name: "DescribeOrganization", Kind: KindRead, Responsibilities: orgMgmt, Domain: "organization", Used: true, Purpose: "organization ID, management account and feature set"},
	{Service: "organizations", Name: "ListRoots", Kind: KindRead, Responsibilities: orgMgmt, Domain: "tree", Used: true, Purpose: "the root and the policy types enabled on it"},
	{Service: "organizations", Name: "ListOrganizationalUnitsForParent", Kind: KindRead, Responsibilities: orgMgmt, Domain: "tree", Used: true, Purpose: "the OU hierarchy", Resource: arnOrgRootOrOU},
	{Service: "organizations", Name: "ListAccountsForParent", Kind: KindRead, Responsibilities: orgMgmt, Domain: "tree", Used: true, Purpose: "the accounts under each root and OU, with join dates", Resource: arnOrgRootOrOU},
	{Service: "organizations", Name: "ListPolicies", Kind: KindRead, Responsibilities: orgMgmt, Domain: "policies", Used: true, Purpose: "SCPs, RCPs, tag and backup policies"},
	{Service: "organizations", Name: "DescribePolicy", Kind: KindRead, Responsibilities: orgMgmt, Domain: "policies", Used: true, Purpose: "the document of each policy", Resource: arnOrgPolicy},
	{Service: "organizations", Name: "ListTargetsForPolicy", Kind: KindRead, Responsibilities: orgMgmt, Domain: "policies", Used: true, Purpose: "where each policy is attached", Resource: arnOrgPolicy},
	{Service: "organizations", Name: "ListTagsForResource", Kind: KindRead, Responsibilities: orgMgmt, Domain: "account_tags", Used: true, Purpose: "account tags", Resource: arnOrgTaggable},
	{Service: "organizations", Name: "ListDelegatedAdministrators", Kind: KindRead, Responsibilities: orgMgmt, Domain: "delegated_administrators", Used: true, Purpose: "accounts that administer a service"},
	{Service: "organizations", Name: "ListDelegatedServicesForAccount", Kind: KindRead, Responsibilities: orgMgmt, Domain: "delegated_administrators", Used: true, Purpose: "which services each delegated administrator administers", Resource: arnOrgAccount},
	{Service: "organizations", Name: "ListAWSServiceAccessForOrganization", Kind: KindRead, Responsibilities: orgMgmt, Domain: "trusted_access", Used: true, Purpose: "services with trusted access"},

	// Account Management: enabled regions per account.
	{Service: "account", Name: "ListRegions", Kind: KindRead, Responsibilities: orgMgmt, Domain: "enabled_regions", Used: true, Purpose: "enabled regions of every member account (needs trusted access for account.amazonaws.com)", Resource: arnAccount},

	// RAM: shares owned by the calling account.
	{Service: "ram", Name: "GetResourceShares", Kind: KindRead, Responsibilities: netOrMgmt, Domain: "resource_shares", Used: true, Purpose: "resource shares owned by the caller, with the retain-on-leave setting"},
	{Service: "ram", Name: "ListPrincipals", Kind: KindRead, Responsibilities: netOrMgmt, Domain: "resource_shares", Used: true, Purpose: "the principals of each share", Resource: arnRAMShare},
	{Service: "ram", Name: "ListResources", Kind: KindRead, Responsibilities: netOrMgmt, Domain: "resource_shares", Used: true, Purpose: "the resources in each share", Resource: arnRAMShare},

	// Control Tower and the Control Catalog.
	{Service: "controltower", Name: "ListLandingZones", Kind: KindRead, Responsibilities: ct, Domain: "control_tower", Used: true, Purpose: "the landing zone ARN"},
	{Service: "controltower", Name: "GetLandingZone", Kind: KindRead, Responsibilities: ct, Domain: "control_tower", Used: true, Purpose: "version, drift, auto-enrollment and the manifest", Resource: arnLandingZone},
	{Service: "controltower", Name: "ListEnabledBaselines", Kind: KindRead, Responsibilities: ct, Domain: "control_tower", Used: true, Purpose: "registered OUs and enrolled accounts (child baselines)"},
	{Service: "controltower", Name: "ListEnabledControls", Kind: KindRead, Responsibilities: ct, Domain: "control_tower", Used: true, Purpose: "controls enabled on each registered OU"},
	{Service: "controlcatalog", Name: "GetControl", Kind: KindRead, Responsibilities: ct, Domain: "control_tower", Used: true, Purpose: "name and behavior of each enabled control", Resource: arnControl},

	// IAM Identity Center and its identity store.
	{Service: "sso", Name: "ListInstances", Kind: KindRead, Responsibilities: idc, Domain: "identity_center", Used: true, Purpose: "the instance and its identity store"},
	{Service: "sso", Name: "ListPermissionSets", Kind: KindRead, Responsibilities: idc, Domain: "identity_center", Used: true, Purpose: "every permission set", Resource: arnSSOInstance},
	{Service: "sso", Name: "DescribePermissionSet", Kind: KindRead, Responsibilities: idc, Domain: "identity_center", Used: true, Purpose: "name and session duration", Resource: arnSSOPermSet},
	{Service: "sso", Name: "ListManagedPoliciesInPermissionSet", Kind: KindRead, Responsibilities: idc, Domain: "identity_center", Used: true, Purpose: "AWS managed policies attached", Resource: arnSSOPermSet},
	{Service: "sso", Name: "ListCustomerManagedPolicyReferencesInPermissionSet", Kind: KindRead, Responsibilities: idc, Domain: "identity_center", Used: true, Purpose: "customer managed policies referenced", Resource: arnSSOPermSet},
	{Service: "sso", Name: "GetInlinePolicyForPermissionSet", Kind: KindRead, Responsibilities: idc, Domain: "identity_center", Used: true, Purpose: "the inline policy", Resource: arnSSOPermSet},
	{Service: "sso", Name: "GetPermissionsBoundaryForPermissionSet", Kind: KindRead, Responsibilities: idc, Domain: "identity_center", Used: true, Purpose: "the permissions boundary", Resource: arnSSOPermSet},
	{Service: "sso", Name: "ListAccountsForProvisionedPermissionSet", Kind: KindRead, Responsibilities: idc, Domain: "identity_center", Used: true, Purpose: "accounts each permission set is provisioned in", Resource: arnSSOPermSet},
	{Service: "sso", Name: "ListAccountAssignments", Kind: KindRead, Responsibilities: idc, Domain: "identity_center", Used: true, Purpose: "assignments per account and permission set", Resource: arnSSOPermSet},
	{Service: "identitystore", Name: "DescribeUser", Kind: KindRead, Responsibilities: idc, Domain: "identity_center", Used: true, Purpose: "user names for assignment principals", Resource: arnIdentityUser},
	{Service: "identitystore", Name: "DescribeGroup", Kind: KindRead, Responsibilities: idc, Domain: "identity_center", Used: true, Purpose: "group names for assignment principals", Resource: arnIdentityUser},

	// STS: identity validation and role chains.
	{Service: "sts", Name: "GetCallerIdentity", Kind: KindSession, Responsibilities: everyRole, Used: true, Purpose: "verify that the credentials belong to the account the configuration names before anything is read",
		Note: "returns the caller's own identity; needs no permission and cannot be denied"},
	{Service: "sts", Name: "AssumeRole", Kind: KindSession, Responsibilities: orgMgmt, Used: true, Purpose: "assume-role chains in the configuration and the member inspection and network roles", Resource: arnMemberRole,
		Note: "issues temporary credentials for a role that already trusts the caller; AWS lists it as Write because it creates a session, but it changes no resource in any account"},

	// CloudFormation StackSets administered from the management account.
	{Service: "cloudformation", Name: "ListStackSets", Kind: KindRead, Responsibilities: orgMgmt, Domain: "stack_sets", Used: true, Purpose: "the StackSets administered from the management account"},
	{Service: "cloudformation", Name: "DescribeStackSet", Kind: KindRead, Responsibilities: orgMgmt, Domain: "stack_sets", Used: true, Purpose: "permission model, target OUs, automatic deployment and RetainStacksOnAccountRemoval of each StackSet", Resource: arnStackSet},
	{Service: "cloudformation", Name: "ListStackInstances", Kind: KindRead, Responsibilities: orgMgmt, Domain: "stack_sets", Used: true, Purpose: "the stack each StackSet has in each account and Region", Resource: arnStackSet},

	// The workload inventory, read inside member accounts through the
	// member inspection role. CloudFormation, IAM and Resource Explorer do
	// not charge for these calls and AWS publishes no price for the
	// Resource Groups Tagging API. S3 bills every request, so the two S3
	// calls are billable reads behind an opt-in.
	{Service: "cloudformation", Name: "DescribeStacks", Kind: KindRead, Responsibilities: member, Domain: "workloads.stacks", Used: true, Purpose: "every stack of a Region: status, tags, output keys and export names, parameters (read for infrastructure identifiers only), termination protection",
		Actions: []string{"cloudformation:DescribeStacks", "cloudformation:ListStacks"}},
	{Service: "cloudformation", Name: "ListStackResources", Kind: KindRead, Responsibilities: member, Domain: "workloads.stacks", Used: true, Purpose: "the resource types of each stack and how many of each", Resource: arnStack},
	{Service: "cloudformation", Name: "ListExports", Kind: KindRead, Responsibilities: member, Domain: "workloads.stacks", Used: true, Purpose: "the exported output names of the account and Region"},
	{Service: "cloudformation", Name: "ListImports", Kind: KindRead, Responsibilities: member, Domain: "workloads.stacks", Used: true, Purpose: "the stacks that import each export"},
	{Service: "cloudformation", Name: "GetTemplate", Kind: KindRead, Responsibilities: member, Domain: "workloads.stacks", Used: true, Purpose: "the template of each stack, read in memory for cross-account stack outputs, infrastructure identifiers and conditions on organization identity; the template is never stored", Resource: arnStack},
	{Service: "tag", Name: "GetResources", Kind: KindRead, Responsibilities: member, Domain: "workloads.resources", Used: true, Purpose: "a sample of the resources that are or were tagged, for tag policy checks and deployment provenance"},
	{Service: "resource-explorer-2", Name: "ListIndexes", Kind: KindRead, Responsibilities: member, Domain: "workloads.resources", Used: true, Purpose: "whether the account has a Resource Explorer aggregator index, and in which Region"},
	{Service: "resource-explorer-2", Name: "Search", Kind: KindRead, Responsibilities: member, Domain: "workloads.resources", Used: true, Purpose: "the resource sample from the aggregator index, when there is one (at most the first 1,000 results)", Resource: arnExplorerView,
		Note: "a search over the Resource Explorer index: it returns the matching resources and changes nothing"},
	{Service: "iam", Name: "ListRoles", Kind: KindRead, Responsibilities: member, Domain: "workloads.policies", Used: true, Purpose: "the trust policy of every role, read for conditions on the organization ID or path"},
	{Service: "s3", Name: "ListBuckets", Kind: KindReadBillable, Responsibilities: member, Domain: "workloads.policies", OptIn: OptInBucketPolicies, Used: true, Purpose: "the buckets of the account with their Regions",
		Actions: []string{"s3:ListAllMyBuckets"}, Note: "S3 bills it as a LIST request, so it is a billable read behind an opt-in"},
	{Service: "s3", Name: "GetBucketPolicy", Kind: KindReadBillable, Responsibilities: member, Domain: "workloads.policies", OptIn: OptInBucketPolicies, Used: true, Purpose: "the policy of each bucket, read for conditions on the organization ID or path", Resource: arnBucket,
		Note: "S3 bills every request that is not a DELETE or CANCEL; a policy read falls under GET and all other requests, so it is a billable read behind an opt-in"},

	// Planned: Organizations services (Section 5).
	{Service: "cloudtrail", Name: "DescribeTrails", Kind: KindRead, Responsibilities: orgMgmt, Domain: "organization_trails", Purpose: "organization trails", Resource: arnTrail},
	{Service: "cloudtrail", Name: "GetTrailStatus", Kind: KindRead, Responsibilities: orgMgmt, Domain: "organization_trails", Purpose: "whether each organization trail is logging", Resource: arnTrail},
	{Service: "config", Name: "DescribeConfigurationAggregators", Kind: KindRead, Responsibilities: member, Domain: "config_aggregators", Purpose: "organization Config aggregators in the audit account", Resource: arnAggregator},
	{Service: "servicecatalog", Name: "SearchProvisionedProducts", Kind: KindRead, Responsibilities: ct, Domain: "control_tower.enrolled_accounts", Purpose: "Account Factory provisioned products, for enrolment provenance"},

	// Planned: what only the member account can see (Sections 5 and 8).
	{Service: "iam", Name: "GenerateServiceLastAccessedDetails", Kind: KindRead, Responsibilities: member, Domain: domainUsageActions, Purpose: "start a last-accessed report for a role or user", Resource: arnIAMEntity,
		Note: "AWS lists it at access level Read: it starts a report job about existing data and changes nothing in the account"},
	{Service: "iam", Name: "GetServiceLastAccessedDetails", Kind: KindRead, Responsibilities: member, Domain: domainUsageActions, Purpose: "read the last-accessed report"},
	{Service: "cloudtrail", Name: "LookupEvents", Kind: KindRead, Responsibilities: member, Domain: domainUsageActions, Purpose: "management events of the last 90 days (free, slow)"},
	{Service: "cloudtrail", Name: "StartQuery", Kind: KindReadBillable, Responsibilities: orgMgmt, Domain: domainUsageActions, OptIn: OptInCloudTrailLake, Purpose: "one aggregated CloudTrail Lake query for actions in use", Resource: arnEventStore,
		Note: "starts a SQL query over an event data store; AWS bills the data scanned, so it is a billable read behind an opt-in and never a write"},
	{Service: "cloudtrail", Name: "GetQueryResults", Kind: KindReadBillable, Responsibilities: orgMgmt, Domain: domainUsageActions, OptIn: OptInCloudTrailLake, Purpose: "results of the Lake query", Resource: arnEventStore},
	{Service: "cloudtrail", Name: "DescribeQuery", Kind: KindReadBillable, Responsibilities: orgMgmt, Domain: domainUsageActions, OptIn: OptInCloudTrailLake, Purpose: "status and bytes scanned of the Lake query", Resource: arnEventStore},
	{Service: "config", Name: "SelectAggregateResourceConfig", Kind: KindReadBillable, Responsibilities: member, Domain: domainUsageResources, OptIn: OptInConfigQueries, Purpose: "resource inventories from an aggregator", Resource: arnAggregator,
		Note: "a SQL select over the aggregator; AWS bills each advanced query, so it is a billable read behind an opt-in"},
	{Service: "ram", Name: "GetResourceShareAssociations", Kind: KindRead, Responsibilities: member, Domain: "resource_shares", Purpose: "shares the account receives", Resource: arnRAMShare},
	{Service: "ec2", Name: "DescribeTransitGatewayAttachments", Kind: KindRead, Responsibilities: netMember, Domain: domainNetworkPaths, Purpose: "transit gateway attachments in use"},
	{Service: "ec2", Name: "DescribeTransitGatewayVpcAttachments", Kind: KindRead, Responsibilities: netMember, Domain: domainNetworkPaths, Purpose: "VPC attachments to shared transit gateways"},
	{Service: "ec2", Name: "DescribeVpcs", Kind: KindRead, Responsibilities: netMember, Domain: domainNetworkPaths, Purpose: "VPCs, including shared ones"},
	{Service: "ec2", Name: "DescribeSubnets", Kind: KindRead, Responsibilities: netMember, Domain: domainNetworkPaths, Purpose: "subnets, including shared ones"},
	{Service: "ec2", Name: "DescribeRouteTables", Kind: KindRead, Responsibilities: netMember, Domain: domainNetworkPaths, Purpose: "routes through transit gateways and peerings"},
	{Service: "ec2", Name: "DescribeVpcPeeringConnections", Kind: KindRead, Responsibilities: netMember, Domain: domainNetworkPaths, Purpose: "peerings that cross accounts"},
	{Service: "ec2", Name: "DescribeManagedPrefixLists", Kind: KindRead, Responsibilities: netMember, Domain: domainNetworkPaths, Purpose: "shared prefix lists referenced by routes and rules"},
	{Service: "route53resolver", Name: "ListResolverRuleAssociations", Kind: KindRead, Responsibilities: member, Domain: domainNetworkPaths, Purpose: "Resolver rules associated with the account's VPCs", Resource: arnResolverRule},
}

// Lookup finds an operation by IAM action ("organizations:ListRoots"),
// including the actions an operation needs under another name
// ("s3:ListAllMyBuckets" for s3:ListBuckets).
func Lookup(action string) (Operation, bool) {
	for _, o := range Catalog {
		if o.Action() == action {
			return o, true
		}
	}
	for _, o := range Catalog {
		for _, a := range o.IAM() {
			if a == action {
				return o, true
			}
		}
	}
	return Operation{}, false
}

// ByName finds the catalog entries with an operation name, whatever the
// service.
func ByName(name string) []Operation {
	var out []Operation
	for _, o := range Catalog {
		if o.Name == name {
			out = append(out, o)
		}
	}
	return out
}

// Allowed reports whether an operation name is one this build may call:
// present in the catalog, used, and never a write.
func Allowed(name string) bool {
	for _, o := range ByName(name) {
		if o.Used && o.Kind != KindWrite {
			return true
		}
	}
	return false
}

// Semantics returns the kind of an operation name, or KindWrite when the
// name is not in the catalog: anything unknown is treated as a write.
func Semantics(name string) Kind {
	ops := ByName(name)
	if len(ops) == 0 {
		return KindWrite
	}
	return ops[0].Kind
}

// readVerbs are the verbs whose semantics are plainly a read. An operation
// whose name starts with none of them must carry a Note.
var readVerbs = []string{"List", "Describe", "Get", "Search", "Lookup", "Select", "Query", "Scan", "Batch", "Check", "Validate", "Simulate", "Test", "Export"}

// writeVerbs are verbs that always mean a write; an operation starting with
// one of them is refused whatever kind it declares.
var writeVerbs = []string{"Create", "Delete", "Update", "Put", "Attach", "Detach", "Move", "Tag", "Untag", "Enable", "Disable", "Invite", "Remove", "Accept", "Reject", "Register", "Deregister", "Close", "Leave", "Associate", "Disassociate", "Promote", "Cancel", "Decline", "Stop", "Modify", "Set", "Add", "Replace", "Reset", "Provision", "Import", "Deploy", "Run", "Invoke", "Send", "Terminate", "Reboot", "Restore", "Rotate", "Revoke", "Grant", "Authorize", "Deauthorize", "Allocate", "Release", "Purchase", "Publish", "Submit", "Upload"}

// ReadVerb reports whether a name starts with a verb that is plainly a read.
func ReadVerb(name string) bool { return hasVerb(name, readVerbs) }

// WriteVerb reports whether a name starts with a verb that always writes.
func WriteVerb(name string) bool { return hasVerb(name, writeVerbs) }

func hasVerb(name string, verbs []string) bool {
	for _, v := range verbs {
		if strings.HasPrefix(name, v) && len(name) > len(v) && name[len(v)] >= 'A' && name[len(v)] <= 'Z' {
			return true
		}
	}
	return false
}

// IsReadOnly reports whether an operation may be called by a read-only
// collector without an opt-in: a catalog entry of kind read or session.
func IsReadOnly(name string) bool {
	k := Semantics(name)
	return k == KindRead || k == KindSession
}

// Billable returns the billable reads this build can call, each behind its
// opt-in.
func Billable() []Operation {
	var out []Operation
	for _, o := range Catalog {
		if o.Used && o.Kind == KindReadBillable {
			out = append(out, o)
		}
	}
	return out
}

// IAMActions renders the IAM actions of the operations this build calls,
// sorted, the opt-in billable ones included. sts:GetCallerIdentity needs no
// permission and is left out.
func IAMActions() []string {
	seen := map[string]bool{}
	var out []string
	for _, o := range Catalog {
		if !o.Used || o.Name == "GetCallerIdentity" {
			continue
		}
		for _, a := range o.IAM() {
			if !seen[a] {
				seen[a] = true
				out = append(out, a)
			}
		}
	}
	sort.Strings(out)
	return out
}

// ActionsFor returns the IAM actions a responsibility needs, sorted and
// de-duplicated: the operations this build calls when planned is false,
// the planned ones when it is true. sts:GetCallerIdentity needs no
// permission and is left out.
func ActionsFor(r Responsibility, planned bool) []string {
	seen := map[string]bool{}
	var out []string
	for _, o := range OperationsFor(r, planned) {
		for _, a := range o.IAM() {
			if !seen[a] {
				seen[a] = true
				out = append(out, a)
			}
		}
	}
	sort.Strings(out)
	return out
}

// OperationsFor returns the catalog entries of a responsibility in catalog
// order, used ones when planned is false, planned ones when it is true.
func OperationsFor(r Responsibility, planned bool) []Operation {
	var out []Operation
	for _, o := range Catalog {
		if o.For(r) && o.Used == !planned && o.Name != "GetCallerIdentity" {
			out = append(out, o)
		}
	}
	return out
}
