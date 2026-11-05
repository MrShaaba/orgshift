// Package workload turns the workload inventory of a snapshot into an
// inventory view with deployment provenance: for every stack and every
// sampled resource, how it was most likely deployed and which evidence the
// classification rests on. Provenance is computed from the snapshot each
// time, never stored, so a better rule does not need a new collection.
//
// The classification is evidence, not proof. A stack instance listed by its
// StackSet is a fact; a stack name that starts with "StackSet-" or a tag
// that says "terraform" is a convention; and "unknown" is a valid answer
// that the reports keep visible instead of guessing.
package workload

import (
	"fmt"
	"sort"
	"strings"

	"github.com/MrShaaba/orgshift/internal/snapshot"
)

// Kind is how a stack or resource was deployed.
type Kind string

// Provenance kinds.
const (
	// KindControlTower: deployed by Control Tower or Account Factory (the
	// AWSControlTowerBP-* baseline StackSets, aws-controltower-* resources).
	KindControlTower Kind = "control-tower"
	// KindStackSetServiceManaged: an instance of a service-managed StackSet,
	// which follows organization and OU membership.
	KindStackSetServiceManaged Kind = "stackset-service-managed"
	// KindStackSetSelfManaged: an instance of a self-managed StackSet, which
	// is tied to account IDs and roles, not to the organization.
	KindStackSetSelfManaged Kind = "stackset-self-managed"
	// KindStackSetUnknown: the stack looks like a StackSet instance but no
	// StackSet record says which permission model it uses.
	KindStackSetUnknown Kind = "stackset-unknown-model"
	// KindStack: a CloudFormation stack that no StackSet created.
	KindStack Kind = "stack"
	// KindTerraform: tags follow a Terraform-style convention.
	KindTerraform Kind = "terraform"
	// KindUnknown: nothing says how the resource was deployed.
	KindUnknown Kind = "unknown"
)

// Kinds lists the kinds in report order.
var Kinds = []Kind{KindControlTower, KindStackSetServiceManaged, KindStackSetSelfManaged, KindStackSetUnknown, KindStack, KindTerraform, KindUnknown}

// Label is the human name of a kind.
func (k Kind) Label() string {
	switch k {
	case KindControlTower:
		return "Control Tower or Account Factory"
	case KindStackSetServiceManaged:
		return "service-managed StackSet"
	case KindStackSetSelfManaged:
		return "self-managed StackSet"
	case KindStackSetUnknown:
		return "StackSet, permission model unknown"
	case KindStack:
		return "plain CloudFormation stack"
	case KindTerraform:
		return "Terraform-style tag convention"
	}
	return "unknown"
}

// Group is how a workload gets into a new account under the recreate
// strategy.
type Group string

// Redeployment groups.
const (
	// GroupPlatform: recreated by Control Tower or by a StackSet when the
	// new account is vended, enrolled or lands in a target OU.
	GroupPlatform Group = "platform"
	// GroupPipeline: defined by a template or by Terraform, so it can be
	// redeployed from that definition; the pipeline itself is not collected.
	GroupPipeline Group = "pipeline"
	// GroupManual: no deployment definition is known.
	GroupManual Group = "manual-or-unknown"
)

// Groups lists the groups in report order.
var Groups = []Group{GroupPipeline, GroupPlatform, GroupManual}

// Group returns the redeployment group of a kind.
func (k Kind) Group() Group {
	switch k {
	case KindControlTower, KindStackSetServiceManaged, KindStackSetSelfManaged, KindStackSetUnknown:
		return GroupPlatform
	case KindStack, KindTerraform:
		return GroupPipeline
	}
	return GroupManual
}

// Title is the human name of a group.
func (g Group) Title() string {
	switch g {
	case GroupPlatform:
		return "recreated by Control Tower or a StackSet"
	case GroupPipeline:
		return "redeployable from a template or pipeline"
	}
	return "manual or unknown"
}

// Confidence levels of a classification.
const (
	ConfidenceHigh   = "high"
	ConfidenceMedium = "medium"
	ConfidenceLow    = "low"
)

// Provenance is a classification with the evidence it rests on.
type Provenance struct {
	Kind Kind `json:"kind"`
	// Evidence lists what the classification rests on, most specific first.
	Evidence   []string `json:"evidence"`
	Confidence string   `json:"confidence"`
	// StackSet names the owning StackSet for the StackSet kinds.
	StackSet string `json:"stack_set,omitempty"`
}

// StackView is a stack with its provenance and, for StackSet instances,
// the settings of the owning StackSet when the snapshot has them.
type StackView struct {
	snapshot.Stack
	Resources  int        `json:"resources"`
	Provenance Provenance `json:"provenance"`
	// StackSetSettings is nil when no StackSet record matches.
	StackSetSettings *StackSetSettings `json:"stack_set_settings,omitempty"`
}

// StackSetSettings are the settings that decide what happens to an
// instance when its account leaves a target OU or the organization.
type StackSetSettings struct {
	Name                         string   `json:"name"`
	PermissionModel              string   `json:"permission_model"`
	AdministrationAccountID      string   `json:"administration_account_id"`
	AutoDeployment               bool     `json:"auto_deployment"`
	RetainStacksOnAccountRemoval bool     `json:"retain_stacks_on_account_removal"`
	TargetOUs                    []string `json:"target_ous,omitempty"`
	// MatchedByInstance is true when the stack ID is in the StackSet's
	// instance list; false when the match rests on the stack name.
	MatchedByInstance bool `json:"matched_by_instance"`
}

// ResourceView is a sampled resource with its provenance.
type ResourceView struct {
	snapshot.WorkloadResource
	Provenance Provenance `json:"provenance"`
}

// GroupSummary counts one redeployment group.
type GroupSummary struct {
	Group Group  `json:"group"`
	Title string `json:"title"`
	// Stacks and StackResources count stacks and the resources inside them;
	// SampledResources counts sampled resources that belong to no stack in
	// the inventory.
	Stacks           int          `json:"stacks"`
	StackResources   int          `json:"stack_resources"`
	SampledResources int          `json:"sampled_resources"`
	Kinds            map[Kind]int `json:"kinds"`
}

// Inventory is the workload view of one account.
type Inventory struct {
	AccountID   string `json:"account_id"`
	AccountName string `json:"account_name,omitempty"`
	// Collected is false when the snapshot has no workloads block for the
	// account; everything else is then empty.
	Collected bool     `json:"collected"`
	Regions   []string `json:"regions"`
	// Coverage is the status of each workload domain for this account.
	Coverage           []DomainStatus            `json:"coverage"`
	Stacks             []StackView               `json:"stacks"`
	Resources          []ResourceView            `json:"resources"`
	ResourceSource     string                    `json:"resource_source,omitempty"`
	ResourcesTruncated bool                      `json:"resources_truncated,omitempty"`
	Policies           []snapshot.ResourcePolicy `json:"resource_policies"`
	PoliciesInspected  int                       `json:"policies_inspected"`
	Groups             []GroupSummary            `json:"groups"`
	// StacksByKind and ResourcesByKind count the classifications.
	StacksByKind    map[Kind]int `json:"stacks_by_kind"`
	ResourcesByKind map[Kind]int `json:"resources_by_kind"`
	Notes           []string     `json:"notes,omitempty"`
}

// DomainStatus is the coverage of one workload domain for the account.
type DomainStatus struct {
	Domain string                  `json:"domain"`
	Status snapshot.CoverageStatus `json:"status"`
	Detail string                  `json:"detail,omitempty"`
}

// Evaluation levels of the workload layer.
const (
	// Evaluated: every workload domain was read for the account.
	Evaluated = "evaluated"
	// PartiallyEvaluated: some domains were read, others were not.
	PartiallyEvaluated = "partially-evaluated"
	// NotEvaluated: no workload inventory for the account.
	NotEvaluated = "not-evaluated"
)

// Evaluation says how much of the workload layer the inventory supports.
func (inv *Inventory) Evaluation() string {
	complete, any := 0, false
	for _, c := range inv.Coverage {
		if c.Status.Complete() {
			complete++
		}
		if c.Status != snapshot.CoverageUnknown {
			any = true
		}
	}
	switch {
	case complete == len(inv.Coverage) && inv.Collected:
		return Evaluated
	case complete > 0 || (any && inv.Collected):
		return PartiallyEvaluated
	}
	return NotEvaluated
}

// Build computes the inventory view of an account.
func Build(s *snapshot.Snapshot, accountID string) *Inventory {
	inv := &Inventory{AccountID: accountID, Regions: []string{}, Stacks: []StackView{}, Resources: []ResourceView{}, Policies: []snapshot.ResourcePolicy{},
		StacksByKind: map[Kind]int{}, ResourcesByKind: map[Kind]int{}}
	if a, ok := s.Index().AccountByID[accountID]; ok {
		inv.AccountName = a.Name
	}
	for _, d := range snapshot.WorkloadDomains {
		ds := DomainStatus{Domain: d, Status: s.DomainStatus(d, accountID)}
		var details []string
		for _, r := range s.DomainRecords(d) {
			if r.AccountID != "" && r.AccountID != accountID {
				continue
			}
			switch {
			case r.Error != "":
				details = append(details, r.Error)
			case r.Reason != "":
				details = append(details, r.Reason)
			}
		}
		// A record for other accounts only says nothing about this one.
		if !hasRecordFor(s, d, accountID) {
			ds.Status = snapshot.CoverageUnknown
			details = []string{"no coverage record for this account"}
		}
		ds.Detail = strings.Join(details, "; ")
		inv.Coverage = append(inv.Coverage, ds)
	}
	w := s.WorkloadsFor(accountID)
	if w == nil {
		inv.Notes = append(inv.Notes, "The snapshot has no workload inventory for this account; name it under member_inspection.accounts and collect again, or add a workloads block by hand.")
		inv.Groups = groupSummaries(inv)
		return inv
	}
	inv.Collected = true
	inv.Regions = append(inv.Regions, w.Regions...)
	inv.ResourceSource, inv.ResourcesTruncated = w.ResourceSource, w.ResourcesTruncated
	inv.Policies = append(inv.Policies, w.ResourcePolicies...)
	inv.PoliciesInspected = w.PoliciesInspected
	byName := map[string]*StackView{}
	for _, st := range w.Stacks {
		v := StackView{Stack: st, Resources: st.ResourceCount()}
		v.Provenance, v.StackSetSettings = classifyStack(s, accountID, st)
		inv.Stacks = append(inv.Stacks, v)
		inv.StacksByKind[v.Provenance.Kind]++
	}
	for i := range inv.Stacks {
		byName[inv.Stacks[i].Region+"/"+inv.Stacks[i].Name] = &inv.Stacks[i]
		if _, ok := byName[inv.Stacks[i].Name]; !ok {
			byName[inv.Stacks[i].Name] = &inv.Stacks[i]
		}
	}
	for _, r := range w.Resources {
		v := ResourceView{WorkloadResource: r, Provenance: classifyResource(r, byName)}
		inv.Resources = append(inv.Resources, v)
		inv.ResourcesByKind[v.Provenance.Kind]++
	}
	switch w.ResourceSource {
	case snapshot.ResourceSourceTaggingAPI:
		inv.Notes = append(inv.Notes, "The resource sample comes from the Resource Groups Tagging API, which returns resources that are tagged or were tagged once and never untagged ones; resources that never carried a tag are not in it.")
	case snapshot.ResourceSourceResourceExplorer:
		inv.Notes = append(inv.Notes, "The resource sample comes from Resource Explorer, which returns at most the first 1,000 results of a query.")
	}
	if w.ResourcesTruncated {
		inv.Notes = append(inv.Notes, "The resource sample was capped; more resources exist than were sampled, so counts are lower bounds.")
	}
	inv.Groups = groupSummaries(inv)
	return inv
}

func hasRecordFor(s *snapshot.Snapshot, domain, accountID string) bool {
	for _, r := range s.DomainRecords(domain) {
		if r.AccountID == "" || r.AccountID == accountID {
			return true
		}
	}
	return s.CoverageAsserted(domain)
}

func groupSummaries(inv *Inventory) []GroupSummary {
	sums := map[Group]*GroupSummary{}
	for _, g := range Groups {
		sums[g] = &GroupSummary{Group: g, Title: g.Title(), Kinds: map[Kind]int{}}
	}
	inStack := map[string]bool{}
	for _, st := range inv.Stacks {
		g := sums[st.Provenance.Kind.Group()]
		g.Stacks++
		g.StackResources += st.Resources
		g.Kinds[st.Provenance.Kind]++
		inStack[st.Name] = true
	}
	for _, r := range inv.Resources {
		if name := stackOf(r.WorkloadResource); name != "" && inStack[name] {
			continue // counted with its stack
		}
		g := sums[r.Provenance.Kind.Group()]
		g.SampledResources++
		g.Kinds[r.Provenance.Kind]++
	}
	var out []GroupSummary
	for _, g := range Groups {
		out = append(out, *sums[g])
	}
	return out
}

// stackOf returns the stack a sampled resource belongs to: the stack the
// collector matched, or the aws:cloudformation:stack-name tag.
func stackOf(r snapshot.WorkloadResource) string {
	if r.Stack != "" {
		return r.Stack
	}
	return r.Tags["aws:cloudformation:stack-name"]
}

// controlTowerStackSet reports whether a StackSet or stack name is one of
// Control Tower's. The enrollment documentation lists the baseline
// StackSets as AWSControlTowerBP-*.
func controlTowerName(name string) bool {
	return strings.HasPrefix(name, "AWSControlTowerBP-") || strings.HasPrefix(name, "AWSControlTower")
}

// classifyStack decides how a stack was deployed.
func classifyStack(s *snapshot.Snapshot, accountID string, st snapshot.Stack) (Provenance, *StackSetSettings) {
	ss, byInstance := s.StackSetOfStack(accountID, st)
	var settings *StackSetSettings
	if ss != nil {
		settings = &StackSetSettings{Name: ss.Name, PermissionModel: ss.PermissionModel, AdministrationAccountID: ss.AdministrationAccountID,
			AutoDeployment: ss.AutoDeployment, RetainStacksOnAccountRemoval: ss.RetainStacksOnAccountRemoval, TargetOUs: ss.TargetOUs, MatchedByInstance: byInstance}
	}
	remainder := snapshot.StackSetNameFromStack(st.Name)
	// Control Tower first: its baselines are StackSets too, and the name
	// says more than the mechanism.
	switch {
	case ss != nil && controlTowerName(ss.Name):
		return Provenance{Kind: KindControlTower, StackSet: ss.Name, Confidence: ConfidenceHigh,
			Evidence: []string{fmt.Sprintf("instance of StackSet %s, one of the AWSControlTowerBP-* baselines Control Tower deploys when it enrolls an account", ss.Name)}}, settings
	case remainder != "" && controlTowerName(remainder):
		return Provenance{Kind: KindControlTower, Confidence: ConfidenceHigh,
			Evidence: []string{fmt.Sprintf("stack name %s carries the name of an AWSControlTowerBP-* baseline StackSet, which Control Tower deploys when it enrolls an account", st.Name)}}, settings
	}
	if ss != nil {
		kind := KindStackSetUnknown
		switch ss.PermissionModel {
		case "SERVICE_MANAGED":
			kind = KindStackSetServiceManaged
		case "SELF_MANAGED":
			kind = KindStackSetSelfManaged
		}
		p := Provenance{Kind: kind, StackSet: ss.Name, Confidence: ConfidenceHigh}
		how := fmt.Sprintf("permission model %s, administered from %s", orUnknown(ss.PermissionModel), orUnknown(ss.AdministrationAccountID))
		if byInstance {
			p.Evidence = append(p.Evidence, fmt.Sprintf("the stack ID is listed as an instance of StackSet %s (%s)", ss.Name, how))
		} else {
			p.Confidence = ConfidenceMedium
			p.Evidence = append(p.Evidence, fmt.Sprintf("stack name %s carries the name of StackSet %s (%s); the StackSet- prefix is the form AWS's examples show, not a documented rule, and no instance record confirms it", st.Name, ss.Name, how))
		}
		return p, settings
	}
	if remainder != "" {
		return Provenance{Kind: KindStackSetUnknown, Confidence: ConfidenceMedium,
			Evidence: []string{fmt.Sprintf("stack name %s starts with StackSet-, the form StackSets uses in AWS's examples (not a documented rule)", st.Name),
				"no StackSet in the snapshot matches it: a self-managed StackSet administered from another account is not visible from the organization's management account"}}, nil
	}
	if key, value, ok := terraformTag(st.Tags); ok {
		return Provenance{Kind: KindTerraform, Confidence: ConfidenceMedium,
			Evidence: []string{fmt.Sprintf("stack tag %s=%s follows a Terraform-style convention (a convention, not an AWS record)", key, value)}}, nil
	}
	p := Provenance{Kind: KindStack, Confidence: ConfidenceHigh,
		Evidence: []string{"a CloudFormation stack whose name and ID match no StackSet instance; whatever pipeline deploys it is not collected"}}
	if v := st.Tags["aws:servicecatalog:provisionedProductArn"]; v != "" {
		p.Evidence = append(p.Evidence, "stack tag aws:servicecatalog:provisionedProductArn says a Service Catalog provisioned product created it")
	}
	return p, nil
}

// classifyResource decides how a sampled resource was deployed.
func classifyResource(r snapshot.WorkloadResource, stacks map[string]*StackView) Provenance {
	if name := stackOf(r); name != "" {
		how := "tag aws:cloudformation:stack-name=" + name
		if r.Stack != "" {
			how = "listed among the resources of stack " + name
		}
		if st, ok := stacks[r.Region+"/"+name]; ok || stacks[name] != nil {
			if !ok {
				st = stacks[name]
			}
			p := st.Provenance
			p.Evidence = append([]string{how + "; inherits the stack's classification"}, st.Provenance.Evidence...)
			return p
		}
		if rem := snapshot.StackSetNameFromStack(name); rem != "" {
			if controlTowerName(rem) {
				return Provenance{Kind: KindControlTower, Confidence: ConfidenceHigh, Evidence: []string{how + ", an AWSControlTowerBP-* baseline stack; the stack itself is not in the inventory"}}
			}
			return Provenance{Kind: KindStackSetUnknown, Confidence: ConfidenceMedium, Evidence: []string{how + ", a name in the StackSet- form; the stack itself is not in the inventory (another Region, or deleted)"}}
		}
		return Provenance{Kind: KindStack, Confidence: ConfidenceMedium, Evidence: []string{how + "; the stack itself is not in the inventory (another Region, or deleted)"}}
	}
	if key, value, ok := terraformTag(r.Tags); ok {
		return Provenance{Kind: KindTerraform, Confidence: ConfidenceMedium,
			Evidence: []string{fmt.Sprintf("tag %s=%s follows a Terraform-style convention (a convention, not an AWS record); the state and the pipeline behind it are not collected", key, value)}}
	}
	if controlTowerResource(r.ARN) {
		return Provenance{Kind: KindControlTower, Confidence: ConfidenceMedium,
			Evidence: []string{"the resource name carries the aws-controltower or AWSControlTower prefix Control Tower gives the resources it creates (a naming convention)"}}
	}
	why := "no CloudFormation stack lists it, it carries no aws:cloudformation:stack-name tag and no Terraform-style tag"
	if len(r.Tags) == 0 {
		why = "it carries no tags at all and no CloudFormation stack lists it"
	}
	return Provenance{Kind: KindUnknown, Confidence: ConfidenceLow,
		Evidence: []string{why + "; a resource created by hand, by a script or by a tool that leaves no marker looks the same"}}
}

func controlTowerResource(arn string) bool {
	l := strings.ToLower(arn)
	return strings.Contains(l, "aws-controltower") || strings.Contains(l, "awscontroltower")
}

// terraformTag looks for a tag that follows a Terraform-style convention
// and returns it. The keys are compared case-insensitively.
func terraformTag(tags map[string]string) (key, value string, ok bool) {
	keys := make([]string, 0, len(tags))
	for k := range tags {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		lk, lv := strings.ToLower(k), strings.ToLower(tags[k])
		switch {
		case lk == "terraform" && lv != "" && lv != "false" && lv != "no" && lv != "0":
			return k, tags[k], true
		case strings.HasPrefix(lk, "terraform-") || strings.HasPrefix(lk, "terraform_") || strings.HasPrefix(lk, "tf-") || strings.HasPrefix(lk, "tf_") || strings.HasPrefix(lk, "tfc-"):
			return k, tags[k], true
		case strings.Contains(lv, "terraform") || strings.Contains(lv, "opentofu"):
			switch lk {
			case "managed-by", "managedby", "managed_by", "provisioned-by", "provisionedby", "provisioner", "created-by", "createdby", "iac", "tool", "deployed-by":
				return k, tags[k], true
			}
		}
	}
	return "", "", false
}

func orUnknown(s string) string {
	if s == "" {
		return "unknown"
	}
	return s
}

// Accounts lists the accounts of a snapshot that have a workload inventory,
// sorted.
func Accounts(s *snapshot.Snapshot) []string {
	var out []string
	for id := range s.Workloads {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}
