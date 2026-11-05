package snapshot

import (
	"encoding/json"
	"strings"

	"github.com/MrShaaba/orgshift/internal/policy"
)

// Workload collection domains. Each has one coverage record per inspected
// account and Region, so a simulation knows whether the inventory of the
// account it moves was read.
const (
	// DomainWorkloadStacks: CloudFormation stacks, their resource types,
	// outputs, exports and imports, and what their templates reference.
	DomainWorkloadStacks = "workloads.stacks"
	// DomainWorkloadResources: the resource sample with tags. A sample by
	// design: the record says when it was capped.
	DomainWorkloadResources = "workloads.resources"
	// DomainWorkloadPolicies: resource-based policies that reference
	// organization identity (bucket policies, role trust policies).
	DomainWorkloadPolicies = "workloads.policies"
)

// WorkloadDomains lists the workload domains in matrix order.
var WorkloadDomains = []string{DomainWorkloadStacks, DomainWorkloadResources, DomainWorkloadPolicies}

// IsWorkloadDomain reports whether a coverage domain belongs to the
// workload inventory added by schema version 3.
func IsWorkloadDomain(domain string) bool {
	for _, d := range WorkloadDomains {
		if d == domain {
			return true
		}
	}
	return false
}

// Sources of the resource sample.
const (
	// ResourceSourceTaggingAPI: tag:GetResources, which returns resources
	// that are tagged or were tagged once, never untagged ones.
	ResourceSourceTaggingAPI = "tagging-api"
	// ResourceSourceResourceExplorer: resource-explorer-2:Search through an
	// aggregator index, which also returns untagged resources and stops at
	// the first 1,000 results of a query.
	ResourceSourceResourceExplorer = "resource-explorer"
	// ResourceSourceManual: written by hand.
	ResourceSourceManual = "manual"
)

// AccountWorkloads is what was read inside one member account: its
// CloudFormation stacks, a sample of its resources with their tags, and
// the resource-based policies that reference organization identity. It
// holds configuration facts only: no template bodies, no parameter or
// output values, no resource contents.
type AccountWorkloads struct {
	// Regions lists the Regions that were inspected.
	Regions []string `json:"regions"`
	Stacks  []Stack  `json:"stacks"`
	// Resources is a sample of the account's resources. It is a sample by
	// design; ResourcesTruncated says the cap was reached.
	Resources          []WorkloadResource `json:"resources"`
	ResourceSource     string             `json:"resource_source,omitempty"`
	ResourcesTruncated bool               `json:"resources_truncated,omitempty"`
	// ResourcePolicies are the policies that reference organization
	// identity; policies that do not are counted in PoliciesInspected and
	// not kept.
	ResourcePolicies  []ResourcePolicy `json:"resource_policies"`
	PoliciesInspected int              `json:"policies_inspected,omitempty"`
	CollectedAt       string           `json:"collected_at,omitempty"`
}

// Stack is one CloudFormation stack.
type Stack struct {
	Name        string            `json:"name"`
	ID          string            `json:"id,omitempty"`
	Region      string            `json:"region"`
	Status      string            `json:"status,omitempty"`
	Description string            `json:"description,omitempty"`
	Tags        map[string]string `json:"tags,omitempty"`
	// TerminationProtection is EnableTerminationProtection.
	TerminationProtection bool `json:"termination_protection"`
	// ParentID is set on nested stacks.
	ParentID  string `json:"parent_id,omitempty"`
	CreatedAt string `json:"created_at,omitempty"`
	UpdatedAt string `json:"updated_at,omitempty"`
	// ResourceTypes counts the stack's resources by CloudFormation type.
	ResourceTypes map[string]int `json:"resource_types"`
	// Outputs lists the output keys and the export names; output values are
	// not stored.
	Outputs []StackOutput `json:"outputs,omitempty"`
	// Imports are the exports of other stacks in the same account and
	// Region that this stack imports with Fn::ImportValue.
	Imports []StackImport `json:"imports,omitempty"`
	// ExternalOutputs are outputs of other stacks read with
	// Fn::GetStackOutput, which unlike an import can cross accounts and
	// Regions through an IAM role.
	ExternalOutputs []ExternalOutput `json:"external_outputs,omitempty"`
	// References are identifiers of resources outside the stack that its
	// parameters or template name: subnets, transit gateways, ARNs in other
	// accounts.
	References []ResourceReference `json:"references,omitempty"`
	// StackSet links the stack to the StackSet that created it, when known.
	StackSet *StackSetRef `json:"stack_set,omitempty"`
}

// ResourceCount is the number of resources in the stack.
func (s Stack) ResourceCount() int {
	n := 0
	for _, c := range s.ResourceTypes {
		n += c
	}
	return n
}

// StackOutput is one output of a stack.
type StackOutput struct {
	Key string `json:"key"`
	// ExportName is set when the output is exported for Fn::ImportValue.
	ExportName string `json:"export_name,omitempty"`
}

// StackImport is one Fn::ImportValue dependency.
type StackImport struct {
	ExportName string `json:"export_name"`
	// ExportingStack is the stack that exports the value, when it is in the
	// inventory.
	ExportingStack string `json:"exporting_stack,omitempty"`
}

// ExternalOutput is one Fn::GetStackOutput reference.
type ExternalOutput struct {
	StackName  string `json:"stack_name"`
	OutputName string `json:"output_name"`
	Region     string `json:"region,omitempty"`
	// RoleARN is the role CloudFormation assumes to describe the referenced
	// stack; its account is where the stack lives. Empty for a reference
	// inside the account.
	RoleARN string `json:"role_arn,omitempty"`
	// AccountID is the account of RoleARN, or "" for the stack's own.
	AccountID string `json:"account_id,omitempty"`
}

// Kinds of resource references.
const (
	RefSubnet         = "subnet"
	RefTransitGateway = "transit-gateway"
	RefVPC            = "vpc"
	RefResolverRule   = "resolver-rule"
	RefPrefixList     = "prefix-list"
	RefARN            = "arn"
)

// ResourceReference is an identifier of a resource outside the stack.
type ResourceReference struct {
	Kind string `json:"kind"`
	ID   string `json:"id"`
	// AccountID is the owning account when the identifier is an ARN that
	// names one.
	AccountID string `json:"account_id,omitempty"`
	// Via says where the identifier was found ("parameter AppSubnetIds").
	Via string `json:"via,omitempty"`
}

// Evidence for a StackSet link.
const (
	// StackSetEvidenceInstance: the stack ID is listed by ListStackInstances
	// for the StackSet.
	StackSetEvidenceInstance = "stack-instance"
	// StackSetEvidenceName: the stack name starts with "StackSet-", the
	// form StackSets uses in AWS's own examples; not a documented rule.
	StackSetEvidenceName = "stack-name"
)

// StackSetRef links a stack to a StackSet.
type StackSetRef struct {
	Name     string `json:"name"`
	ID       string `json:"id,omitempty"`
	Evidence string `json:"evidence"`
}

// WorkloadResource is one sampled resource.
type WorkloadResource struct {
	ARN string `json:"arn"`
	// Type uses the service:type notation of tag policies and Resource
	// Explorer, for example "ec2:instance" or "s3:bucket".
	Type   string            `json:"type"`
	Region string            `json:"region,omitempty"`
	Tags   map[string]string `json:"tags"`
	// Stack is the stack that lists the resource, when the collector could
	// tell from ListStackResources; the aws:cloudformation:stack-name tag is
	// the other way to tell and stays in Tags.
	Stack string `json:"stack,omitempty"`
}

// Kinds of resource policies.
const (
	PolicyKindBucket    = "s3-bucket-policy"
	PolicyKindRoleTrust = "iam-role-trust-policy"
	PolicyKindTemplate  = "template-policy"
)

// OrgConditionKeys are the condition keys that tie a policy to
// organization identity.
var OrgConditionKeys = []string{"aws:PrincipalOrgID", "aws:PrincipalOrgPaths", "aws:ResourceOrgID", "aws:ResourceOrgPaths", "aws:SourceOrgID", "aws:SourceOrgPaths"}

// IsOrgConditionKey reports whether a condition key is one of
// OrgConditionKeys (case-insensitive, as IAM compares key names).
func IsOrgConditionKey(key string) bool {
	for _, k := range OrgConditionKeys {
		if strings.EqualFold(k, key) {
			return true
		}
	}
	return false
}

// ResourcePolicy is a resource-based policy that references organization
// identity.
type ResourcePolicy struct {
	Kind string `json:"kind"`
	// ResourceARN is the resource the policy protects; for a template
	// policy it may be empty and Resource names the logical ID.
	ResourceARN string `json:"resource_arn,omitempty"`
	Resource    string `json:"resource,omitempty"`
	// Stack is the stack whose template defines the policy, for
	// PolicyKindTemplate.
	Stack string `json:"stack,omitempty"`
	// Source is the operation the policy was read with.
	Source string `json:"source,omitempty"`
	// Document is the policy as IAM JSON, when it was read from the service
	// (bucket policies, trust policies). Template policies can contain
	// intrinsic functions and carry Conditions only.
	Document json.RawMessage `json:"document,omitempty"`
	// Conditions are the organization conditions found in the policy.
	Conditions []OrgCondition `json:"conditions"`
}

// OrgCondition is one condition on an organization key.
type OrgCondition struct {
	Sid      string   `json:"sid,omitempty"`
	Effect   string   `json:"effect,omitempty"`
	Operator string   `json:"operator"`
	Key      string   `json:"key"`
	Values   []string `json:"values"`
	// Dynamic is true when a value is computed in the template (a Ref or a
	// Sub) and therefore not known offline.
	Dynamic bool `json:"dynamic,omitempty"`
}

// StackInstance is one deployment of a StackSet into an account and Region.
type StackInstance struct {
	AccountID string `json:"account_id"`
	Region    string `json:"region"`
	// StackID is the ID of the stack in the target account; it joins the
	// instance to AccountWorkloads.Stacks.
	StackID string `json:"stack_id,omitempty"`
	Status  string `json:"status,omitempty"`
	// OrganizationalUnitID is the OU the deployment targeted
	// (service-managed StackSets).
	OrganizationalUnitID string `json:"organizational_unit_id,omitempty"`
}

// WorkloadsFor returns the workload inventory of an account, or nil.
func (s *Snapshot) WorkloadsFor(accountID string) *AccountWorkloads {
	if s == nil || s.Workloads == nil {
		return nil
	}
	return s.Workloads[accountID]
}

// StackSetByName finds a StackSet by name.
func (s *Snapshot) StackSetByName(name string) *StackSet {
	for i := range s.StackSets {
		if s.StackSets[i].Name == name {
			return &s.StackSets[i]
		}
	}
	return nil
}

// StackSetOfStack finds the StackSet whose instance list contains a stack,
// by stack ID or, failing that, by account, Region and the StackSet name
// carried in the stack name. The boolean says the match is by instance ID.
func (s *Snapshot) StackSetOfStack(accountID string, st Stack) (*StackSet, bool) {
	for i := range s.StackSets {
		for _, inst := range s.StackSets[i].Instances {
			if inst.StackID != "" && inst.StackID == st.ID {
				return &s.StackSets[i], true
			}
		}
	}
	if st.StackSet != nil && st.StackSet.Name != "" {
		if ss := s.StackSetByName(st.StackSet.Name); ss != nil {
			return ss, st.StackSet.Evidence == StackSetEvidenceInstance
		}
	}
	if name := StackSetNameFromStack(st.Name); name != "" {
		// The stack name is StackSet-<name>-<uuid>; match the longest
		// StackSet name that is a prefix of the remainder.
		var best *StackSet
		for i := range s.StackSets {
			n := s.StackSets[i].Name
			if strings.HasPrefix(name, n) && (best == nil || len(n) > len(best.Name)) {
				best = &s.StackSets[i]
			}
		}
		if best != nil {
			return best, false
		}
	}
	return nil, false
}

// StackSetNameFromStack returns the part of a stack name after the
// "StackSet-" prefix, or "" when the name does not carry it. The remainder
// is the StackSet name followed by a generated identifier; the prefix is
// the form AWS's examples show, not a documented rule.
func StackSetNameFromStack(stackName string) string {
	const prefix = "StackSet-"
	if !strings.HasPrefix(stackName, prefix) {
		return ""
	}
	return stackName[len(prefix):]
}

// TypeFromARN derives the service:type notation from an ARN, for sources
// that return ARNs only. It returns "" when the ARN has no recognizable
// resource type.
func TypeFromARN(arn string) string {
	parts := strings.SplitN(arn, ":", 6)
	if len(parts) < 6 || parts[0] != "arn" {
		return ""
	}
	service, resource := parts[2], parts[5]
	switch service {
	case "s3":
		if !strings.Contains(resource, "/") {
			return "s3:bucket"
		}
		return "s3:object"
	case "sns":
		return "sns:topic"
	case "sqs":
		return "sqs:queue"
	}
	for i, r := range resource {
		if r == '/' || r == ':' {
			return service + ":" + resource[:i]
		}
	}
	return service + ":" + resource
}

// RegionFromARN returns the Region of an ARN, or "".
func RegionFromARN(arn string) string {
	parts := strings.SplitN(arn, ":", 6)
	if len(parts) == 6 && parts[0] == "arn" {
		return parts[3]
	}
	return ""
}

// AccountFromARN returns the account of an ARN, or "".
func AccountFromARN(arn string) string {
	parts := strings.SplitN(arn, ":", 6)
	if len(parts) == 6 && parts[0] == "arn" && len(parts[4]) == 12 {
		return parts[4]
	}
	return ""
}

// ExtractOrgConditions returns the conditions on organization keys in an
// IAM policy document, statement by statement. It returns nil for a
// document that names none, and an error for one that does not parse.
func ExtractOrgConditions(doc json.RawMessage) ([]OrgCondition, error) {
	d, err := policy.Parse(doc)
	if err != nil {
		return nil, err
	}
	var out []OrgCondition
	for i := range d.Statements {
		st := &d.Statements[i]
		for _, c := range st.Conditions {
			if IsOrgConditionKey(c.Key) {
				out = append(out, OrgCondition{Sid: st.Sid, Effect: st.Effect, Operator: c.Operator, Key: c.Key, Values: append([]string(nil), c.Values...)})
			}
		}
	}
	return out, nil
}
