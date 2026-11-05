package workload

import (
	"fmt"
	"sort"
	"strings"

	"github.com/MrShaaba/orgshift/internal/snapshot"
)

// RedeployPlan is what the recreate strategy has to bring into a new
// account, grouped by how each item gets there: redeployed from a template
// or pipeline, recreated by the platform (Control Tower or a StackSet) or
// rebuilt by hand because nothing says how it was deployed. It is an
// inventory with counts, not an estimate of effort.
type RedeployPlan struct {
	// Evaluation is the evaluation level of the inventory the plan rests on.
	Evaluation string          `json:"evaluation"`
	Groups     []RedeployGroup `json:"groups"`
	// Dependencies are facts of the inventory that constrain a redeployment:
	// deployment order, references to other accounts, shared networking,
	// policies tied to organization identity, stateful resources.
	Dependencies []string `json:"dependencies"`
	// Unknowns are what the inventory cannot say.
	Unknowns []string `json:"unknowns"`
}

// RedeployGroup is one provenance group with its items.
type RedeployGroup struct {
	Group            Group          `json:"group"`
	Title            string         `json:"title"`
	Stacks           int            `json:"stacks"`
	StackResources   int            `json:"stack_resources"`
	SampledResources int            `json:"sampled_resources"`
	Items            []RedeployItem `json:"items"`
}

// RedeployItem is a stack, or a sampled resource outside every stack.
type RedeployItem struct {
	// Type is stack or resource.
	Type string `json:"type"`
	// Name is the stack name or the resource ARN.
	Name         string `json:"name"`
	Region       string `json:"region,omitempty"`
	ResourceType string `json:"resource_type,omitempty"`
	Provenance   Kind   `json:"provenance"`
	Label        string `json:"provenance_label"`
	Confidence   string `json:"confidence"`
	// Resources is the number of resources in a stack.
	Resources int `json:"resources,omitempty"`
	// StackSet names the owning StackSet, when one is known.
	StackSet string `json:"stack_set,omitempty"`
}

// statefulTypes are stack resource types that hold data, so redeploying the
// template brings back an empty resource.
var statefulTypes = map[string]bool{
	"AWS::RDS::DBInstance": true, "AWS::RDS::DBCluster": true, "AWS::DynamoDB::Table": true, "AWS::DynamoDB::GlobalTable": true, "AWS::S3::Bucket": true,
	"AWS::EFS::FileSystem": true, "AWS::ElastiCache::ReplicationGroup": true, "AWS::ElastiCache::CacheCluster": true, "AWS::OpenSearchService::Domain": true,
	"AWS::Redshift::Cluster": true, "AWS::SecretsManager::Secret": true, "AWS::KMS::Key": true, "AWS::SQS::Queue": true, "AWS::Kinesis::Stream": true,
	"AWS::DocDB::DBCluster": true, "AWS::Neptune::DBCluster": true, "AWS::FSx::FileSystem": true, "AWS::Cognito::UserPool": true, "AWS::ECR::Repository": true,
}

// Redeploy builds the redeployment plan of the inventory.
func (inv *Inventory) Redeploy() *RedeployPlan {
	plan := &RedeployPlan{Evaluation: inv.Evaluation(), Groups: []RedeployGroup{}, Dependencies: []string{}, Unknowns: []string{}}
	groups := map[Group]*RedeployGroup{}
	for _, g := range Groups {
		groups[g] = &RedeployGroup{Group: g, Title: g.Title(), Items: []RedeployItem{}}
	}
	inStack := map[string]bool{}
	stateful := map[string]int{}
	var conventions []string
	for _, st := range inv.Stacks {
		g := groups[st.Provenance.Kind.Group()]
		g.Stacks++
		g.StackResources += st.Resources
		g.Items = append(g.Items, RedeployItem{Type: "stack", Name: st.Name, Region: st.Region, Provenance: st.Provenance.Kind, Label: st.Provenance.Kind.Label(),
			Confidence: st.Provenance.Confidence, Resources: st.Resources, StackSet: st.Provenance.StackSet})
		inStack[st.Name] = true
		if st.Provenance.Kind.Group() == GroupPipeline {
			for t, n := range st.ResourceTypes {
				if statefulTypes[t] {
					stateful[t] += n
				}
			}
		}
		if st.Provenance.Confidence != ConfidenceHigh {
			conventions = append(conventions, "stack "+st.Name)
		}
	}
	var manual []string
	for _, r := range inv.Resources {
		if name := stackOf(r.WorkloadResource); name != "" && inStack[name] {
			continue // counted with its stack
		}
		g := groups[r.Provenance.Kind.Group()]
		g.SampledResources++
		g.Items = append(g.Items, RedeployItem{Type: "resource", Name: r.ARN, Region: r.Region, ResourceType: r.Type, Provenance: r.Provenance.Kind, Label: r.Provenance.Kind.Label(), Confidence: r.Provenance.Confidence})
		switch {
		case r.Provenance.Kind.Group() == GroupManual:
			manual = append(manual, r.ARN)
		case r.Provenance.Confidence != ConfidenceHigh:
			conventions = append(conventions, r.ARN)
		}
	}
	for _, g := range Groups {
		plan.Groups = append(plan.Groups, *groups[g])
	}
	if !inv.Collected {
		plan.Unknowns = append(plan.Unknowns, "The snapshot has no workload inventory for the account, so nothing is known about what would have to be redeployed.")
		return plan
	}

	// Dependencies.
	exporters := map[string][]string{}
	var exporterOrder []string
	for _, st := range inv.Stacks {
		for _, im := range st.Imports {
			from := im.ExportingStack
			if from == "" {
				from = "a stack outside the inventory (export " + im.ExportName + ")"
			}
			if _, ok := exporters[from]; !ok {
				exporterOrder = append(exporterOrder, from)
			}
			if !containsString(exporters[from], st.Name) {
				exporters[from] = append(exporters[from], st.Name)
			}
		}
	}
	for _, from := range exporterOrder {
		plan.Dependencies = append(plan.Dependencies, fmt.Sprintf("Order: %s exports values that %s import(s), so it is deployed first and cannot be deleted or have that output changed while they exist.", from, strings.Join(exporters[from], ", ")))
	}
	for _, st := range inv.Stacks {
		for _, ex := range st.ExternalOutputs {
			if ex.AccountID == "" || ex.AccountID == inv.AccountID {
				continue
			}
			plan.Dependencies = append(plan.Dependencies, fmt.Sprintf("Cross-account reference: %s reads output %s of stack %s in account %s through %s; the role's trust has to admit the new account before the stack can be created there.", st.Name, ex.OutputName, ex.StackName, ex.AccountID, ex.RoleARN))
		}
		byKind := map[string][]string{}
		var kinds []string
		for _, ref := range st.References {
			if _, ok := byKind[ref.Kind]; !ok {
				kinds = append(kinds, ref.Kind)
			}
			byKind[ref.Kind] = append(byKind[ref.Kind], ref.ID)
		}
		for _, k := range kinds {
			plan.Dependencies = append(plan.Dependencies, fmt.Sprintf("Existing infrastructure: %s takes %s %s from outside its template; the new account needs equivalents of its own or shared with it.", st.Name, k, strings.Join(byKind[k], ", ")))
		}
	}
	if len(stateful) > 0 {
		plan.Dependencies = append(plan.Dependencies, "Data: redeploying a template brings back empty resources; these hold state that needs its own migration: "+countList(stateful)+".")
	}
	if n := len(inv.Policies); n > 0 {
		var names []string
		for _, p := range inv.Policies {
			switch {
			case p.ResourceARN != "":
				names = append(names, p.ResourceARN)
			default:
				names = append(names, p.Resource+" of stack "+p.Stack)
			}
		}
		plan.Dependencies = append(plan.Dependencies, fmt.Sprintf("Organization identity: %d policy(ies) are conditioned on the organization ID or path (%s) and have to name the destination when they are re-created.", n, strings.Join(names, ", ")))
	}
	if g := groups[GroupPlatform]; g.Stacks > 0 {
		sets := map[string]bool{}
		for _, it := range g.Items {
			switch {
			case it.StackSet != "":
				sets[it.StackSet] = true
			case it.Provenance == KindControlTower:
				sets["the Control Tower baseline"] = true
			}
		}
		names := make([]string, 0, len(sets))
		for n := range sets {
			names = append(names, n)
		}
		sort.Strings(names)
		line := fmt.Sprintf("Platform: %d stack(s) with %d resource(s) were deployed into the account by the source's platform", g.Stacks, g.StackResources)
		if len(names) > 0 {
			line += " (" + strings.Join(names, ", ") + ")"
		}
		plan.Dependencies = append(plan.Dependencies, line+"; they are not redeployed from the account. The destination's Control Tower and StackSets have to provide what the workloads use of them.")
	}

	// Unknowns.
	if len(manual) > 0 {
		plan.Unknowns = append(plan.Unknowns, fmt.Sprintf("%d sampled resource(s) carry no evidence of how they were deployed (created by hand, by a script, or by a tool that leaves no trace in tags): %s.", len(manual), strings.Join(manual, ", ")))
	}
	if len(conventions) > 0 {
		plan.Unknowns = append(plan.Unknowns, fmt.Sprintf("%d classification(s) rest on a naming or tag convention rather than a record (medium confidence): %s.", len(conventions), strings.Join(conventions, ", ")))
	}
	if groups[GroupPipeline].Stacks > 0 {
		plan.Unknowns = append(plan.Unknowns, "Which pipeline or person deploys a plain stack is not collected: the template is in CloudFormation, but its parameters' sources, secrets and the pipeline's own configuration are not in the snapshot.")
	}
	switch inv.ResourceSource {
	case snapshot.ResourceSourceTaggingAPI:
		plan.Unknowns = append(plan.Unknowns, "Resources outside CloudFormation that never carried a tag are not in the sample (the Resource Groups Tagging API does not return them), so the manual-or-unknown group is a lower bound.")
	case snapshot.ResourceSourceResourceExplorer:
		plan.Unknowns = append(plan.Unknowns, "The sample comes from Resource Explorer, which returns at most the first 1,000 results of a query and only the resource types and Regions it indexes.")
	}
	if inv.ResourcesTruncated {
		plan.Unknowns = append(plan.Unknowns, "The resource sample was capped: more resources exist than were sampled, and the counts outside stacks are lower bounds.")
	}
	for _, c := range inv.Coverage {
		if !c.Status.Complete() {
			plan.Unknowns = append(plan.Unknowns, fmt.Sprintf("%s was not completely collected (%s), so what it would show is missing from this list.", c.Domain, c.Status))
		}
	}
	plan.Unknowns = append(plan.Unknowns, "Data volumes, cutover windows, DNS and the dependencies between applications are not in the snapshot.")
	return plan
}

// Line summarizes a group in one sentence.
func (g RedeployGroup) Line() string {
	parts := []string{}
	if g.Stacks > 0 {
		parts = append(parts, fmt.Sprintf("%d stack(s) with %d resource(s)", g.Stacks, g.StackResources))
	}
	if g.SampledResources > 0 {
		parts = append(parts, fmt.Sprintf("%d sampled resource(s) outside any stack", g.SampledResources))
	}
	if len(parts) == 0 {
		return "nothing found"
	}
	return strings.Join(parts, " and ")
}

// StackNames lists the stacks of a group.
func (g RedeployGroup) StackNames() []string {
	var out []string
	for _, it := range g.Items {
		if it.Type == "stack" {
			out = append(out, it.Name)
		}
	}
	return out
}

// Names lists the items of a group, stacks first.
func (g RedeployGroup) Names() []string {
	out := make([]string, 0, len(g.Items))
	for _, it := range g.Items {
		out = append(out, it.Name)
	}
	return out
}

func containsString(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func countList(m map[string]int) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s x%d", k, m[k]))
	}
	return strings.Join(parts, ", ")
}

// Departed returns the account's workload inventory as it is once the
// account has left the organization: the stacks that a service-managed
// StackSet deletes on removal (automatic deployment on, stacks not
// retained) are gone with the sampled resources they contained, and
// everything else is unchanged. The second value names the deleted stacks.
// It returns nil when the snapshot has no inventory for the account.
func Departed(s *snapshot.Snapshot, accountID string) (*snapshot.AccountWorkloads, []string) {
	w := s.WorkloadsFor(accountID)
	if w == nil {
		return nil, nil
	}
	out := *w
	out.Stacks, out.Resources = nil, nil
	gone := map[string]bool{}
	var deleted []string
	for _, st := range w.Stacks {
		p, settings := classifyStack(s, accountID, st)
		if p.Kind == KindStackSetServiceManaged && settings != nil && settings.AutoDeployment && !settings.RetainStacksOnAccountRemoval {
			gone[st.Name] = true
			deleted = append(deleted, st.Name)
			continue
		}
		out.Stacks = append(out.Stacks, st)
	}
	for _, r := range w.Resources {
		if gone[stackOf(r)] {
			continue
		}
		out.Resources = append(out.Resources, r)
	}
	return &out, deleted
}
