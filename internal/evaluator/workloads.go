package evaluator

import (
	"fmt"
	"sort"
	"strings"

	"github.com/MrShaaba/orgshift/internal/policy"
	"github.com/MrShaaba/orgshift/internal/snapshot"
	"github.com/MrShaaba/orgshift/internal/workload"
)

// Documentation the workload findings were verified against.
const (
	refCFNExports     = "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/using-cfn-stack-exports.html"
	refGetStackOutput = "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/intrinsic-function-reference-getstackoutput.html"
	refStackSetAuto   = "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/stacksets-orgs-manage-auto-deployment.html"
	refAutoDeployment = "https://docs.aws.amazon.com/AWSCloudFormation/latest/APIReference/API_AutoDeployment.html"
	refTaggingAPI     = "https://docs.aws.amazon.com/resourcegroupstagging/latest/APIReference/API_GetResources.html"
	refConditionKeys  = "https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-keys.html"
)

// WorkloadModelVersion dates the workload model: what CloudFormation,
// StackSets, the Tagging API and Resource Explorer do, as read from the
// official documentation on that day.
const WorkloadModelVersion = "2026-11-05"

// WorkloadModel describes the model for the result's model list.
func WorkloadModel() ModelRef {
	return ModelRef{ID: "workload-behaviour", Version: WorkloadModelVersion, Reference: refStackSetAuto,
		Note: "Service-managed StackSets with automatic deployment delete an account's stack instances when it is removed from a target organization or OU, unless RetainStacksOnAccountRemoval is set, in which case the stacks stay and are detached; what happens with automatic deployment off is not documented. " +
			"Export and Fn::ImportValue are limited to one account and Region and block deleting or changing the exported output while it is imported; Fn::GetStackOutput can cross accounts and Regions through an IAM role and is resolved at create or update time only. " +
			"The stack name form StackSet-<name>-<id> appears in AWS's examples and is not a documented rule. " +
			"The Resource Groups Tagging API returns resources that are tagged or were tagged once, never untagged ones; Resource Explorer returns at most the first 1,000 results of a query. " +
			"Verified against " + refAutoDeployment + ", " + refStackSetAuto + ", " + refCFNExports + ", " + refGetStackOutput + " and " + refTaggingAPI + "."}
}

// SourceWorkload marks findings about an operation derived from the
// workload inventory rather than observed or declared.
const SourceWorkload = "workload"

// Evidence kinds of the workloads check. The runbook keys its steps on them.
const (
	// EvidenceStackInstance: a stack that is an instance of a
	// service-managed StackSet of the organization.
	EvidenceStackInstance = "stack-instance"
	// EvidenceExternalStackSet: a stack deployed by a StackSet that does not
	// depend on the organization (self-managed, or administered from an
	// account the snapshot does not show).
	EvidenceExternalStackSet = "stack-external-stackset"
	// EvidenceStackImport: a stack that imports an export of another stack.
	EvidenceStackImport = "stack-import"
	// EvidenceStackOutputReference: a stack that reads an output of a stack
	// in another account with Fn::GetStackOutput.
	EvidenceStackOutputReference = "stack-output-reference"
	// EvidenceStackReference: a stack that references a resource shared
	// through RAM.
	EvidenceStackReference = "stack-reference"
	// EvidenceResourcePolicy: a resource policy conditioned on organization
	// identity.
	EvidenceResourcePolicy = "resource-policy"
)

// WorkloadLayer says how much of the workload layer the evaluation could
// assess and what the inventory holds, in numbers.
type WorkloadLayer struct {
	// Evaluation is evaluated, partially-evaluated or not-evaluated.
	Evaluation string `json:"evaluation"`
	Detail     string `json:"detail"`
	// Coverage is the status of each workload domain for the account.
	Coverage              []workload.DomainStatus `json:"coverage"`
	Stacks                int                     `json:"stacks"`
	StackResources        int                     `json:"stack_resources"`
	SampledResources      int                     `json:"sampled_resources"`
	ResourceSource        string                  `json:"resource_source,omitempty"`
	ResourcesTruncated    bool                    `json:"resources_truncated,omitempty"`
	PoliciesOnOrgIdentity int                     `json:"policies_on_organization_identity"`
	PoliciesInspected     int                     `json:"policies_inspected"`
	// Groups counts the inventory by how it would be redeployed.
	Groups []workload.GroupSummary `json:"groups"`
}

// derivedOperations returns the operations the workload inventory shows
// the account needs: assuming the role behind every cross-account
// Fn::GetStackOutput reference. They are evaluated against the SCP and RCP
// chains like observed and declared operations.
func (e *evaluation) derivedOperations() []snapshot.ActionInUse {
	w := e.from.WorkloadsFor(e.accountID)
	if w == nil {
		return nil
	}
	seen := map[string]bool{}
	var out []snapshot.ActionInUse
	for _, st := range w.Stacks {
		for _, ex := range st.ExternalOutputs {
			if ex.RoleARN == "" || ex.AccountID == "" || ex.AccountID == e.accountID || seen[ex.RoleARN] {
				continue
			}
			seen[ex.RoleARN] = true
			out = append(out, snapshot.ActionInUse{Action: "sts:AssumeRole", Resource: ex.RoleARN, Source: SourceWorkload,
				Note: fmt.Sprintf("CloudFormation assumes %s to resolve Fn::GetStackOutput in stack %s (output %s of stack %s in account %s)", ex.RoleARN, st.Name, ex.OutputName, ex.StackName, ex.AccountID)})
		}
	}
	return out
}

// taggedSample merges the resource sample of the usage block with the
// collected one, by ARN; the collected record wins because it carries the
// tags the service reported.
func (e *evaluation) taggedSample() []snapshot.TaggedResource {
	var out []snapshot.TaggedResource
	index := map[string]int{}
	add := func(r snapshot.TaggedResource) {
		if i, ok := index[r.ARN]; ok {
			out[i] = r
			return
		}
		index[r.ARN] = len(out)
		out = append(out, r)
	}
	if u := e.from.UsageFor(e.accountID); u != nil {
		for _, r := range u.TaggedResources {
			add(r)
		}
	}
	if w := e.from.WorkloadsFor(e.accountID); w != nil {
		for _, r := range w.Resources {
			add(snapshot.TaggedResource{ARN: r.ARN, Type: r.Type, Region: r.Region, Tags: r.Tags})
		}
	}
	return out
}

// shareFate says whether a share reaches the account before and after the
// move, and whether RAM retains it for the account when it leaves.
func (e *evaluation) shareFate(sh snapshot.ResourceShare) (before, after, retained bool) {
	for _, p := range sh.Principals {
		sc := classifyPrincipal(p)
		if reaches(sc, e.src.orgID, e.accountID, e.src.path) {
			before = true
		}
		if e.crossOrg {
			if sc.kind == "account" && sc.id == e.accountID && sh.RetainSharingOnAccountLeave && sh.AllowExternalPrincipals {
				retained = true
			}
			continue
		}
		if reaches(sc, e.dst.orgID, e.accountID, e.dst.path) {
			after = true
		}
	}
	return before, after, retained
}

// evaluateWorkloads assesses the workload layer from the inventory: what
// happens to StackSet instances, to references between stacks and
// accounts, to resources on shared networking and to policies tied to
// organization identity. Tag compliance of the sample is in the tag check.
func (e *evaluation) evaluateWorkloads(c *Check) *WorkloadLayer {
	inv := workload.Build(e.from, e.accountID)
	layer := &WorkloadLayer{Evaluation: inv.Evaluation(), Coverage: inv.Coverage, Groups: inv.Groups, Stacks: len(inv.Stacks), SampledResources: len(inv.Resources),
		ResourceSource: inv.ResourceSource, ResourcesTruncated: inv.ResourcesTruncated, PoliciesOnOrgIdentity: len(inv.Policies), PoliciesInspected: inv.PoliciesInspected}
	for _, st := range inv.Stacks {
		layer.StackResources += st.Resources
	}
	if !inv.Collected {
		layer.Detail = "no workload inventory for the account, so nothing about its stacks, resources or resource policies was assessed"
		c.Summary = "The workload layer was not evaluated: the snapshot has no workload inventory for this account."
		if !e.crossOrg {
			c.add(Finding{Status: StatusInfo, Category: CategoryMissingEvidence, Title: "No workload inventory for this account",
				Detail: "The snapshot holds no stacks, resource sample or resource policies for the account. A move inside the organization changes only what follows the OU path: OU-targeted StackSets, OU-scoped shares and conditions on aws:PrincipalOrgPaths. The StackSet and share checks use the organization-level lists; conditions in resource policies were not assessed. Name the account under member_inspection.accounts and collect again to evaluate the layer."})
		}
		return layer
	}
	e.workloadStackSets(c, inv)
	e.workloadReferences(c, inv)
	e.workloadSharedResources(c, inv)
	e.workloadPolicies(c, inv)
	sortFindings(c.Findings)

	what := "evaluated"
	switch layer.Evaluation {
	case workload.PartiallyEvaluated:
		what = "partially evaluated (see the coverage gaps)"
	case workload.NotEvaluated:
		what = "not evaluated"
	}
	layer.Detail = fmt.Sprintf("%d stack(s) with %d resource(s), %d sampled resource(s) from %s, %d of %d policies read reference organization identity",
		layer.Stacks, layer.StackResources, layer.SampledResources, orUnknown(layer.ResourceSource), layer.PoliciesOnOrgIdentity, layer.PoliciesInspected)
	if inv.ResourcesTruncated {
		layer.Detail += "; the resource sample was capped"
	}
	c.Summary = fmt.Sprintf("Workload layer %s: %s. %d item(s) to settle, %d informational.", what, layer.Detail,
		countStatus(c.Findings, StatusReview)+countStatus(c.Findings, StatusNoGo), countStatus(c.Findings, StatusInfo))
	return layer
}

func stackEvidence(st workload.StackView, note string) Evidence {
	lines := []string{fmt.Sprintf("region %s, status %s, %d resource(s): %s", st.Region, orUnknown(st.Status), st.Resources, typeCounts(st.ResourceTypes))}
	lines = append(lines, "provenance: "+st.Provenance.Kind.Label()+" ("+st.Provenance.Confidence+" confidence): "+strings.Join(st.Provenance.Evidence, "; "))
	if note != "" {
		lines = append(lines, note)
	}
	return Evidence{Kind: "stack", Side: "source", Reference: st.Name, Note: strings.Join(lines, "\n")}
}

func kindEvidence(kind string, st workload.StackView, note string) Evidence {
	ev := stackEvidence(st, note)
	ev.Kind = kind
	return ev
}

func typeCounts(types map[string]int) string {
	keys := make([]string, 0, len(types))
	for k := range types {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s x%d", k, types[k]))
	}
	return strings.Join(parts, ", ")
}

// importersOf lists the stacks that import an export of the given stack.
func importersOf(inv *workload.Inventory, st workload.StackView) []string {
	exports := map[string]bool{}
	for _, o := range st.Outputs {
		if o.ExportName != "" {
			exports[o.ExportName] = true
		}
	}
	var out []string
	for _, other := range inv.Stacks {
		if other.Name == st.Name && other.Region == st.Region {
			continue
		}
		for _, im := range other.Imports {
			if exports[im.ExportName] && other.Region == st.Region {
				out = append(out, fmt.Sprintf("%s (imports %s)", other.Name, im.ExportName))
			}
		}
	}
	return out
}

// workloadStackSets reports what happens to the StackSet instances in the
// account when it stops being a deployment target.
func (e *evaluation) workloadStackSets(c *Check, inv *workload.Inventory) {
	dstTargets := snapshot.OUPath(e.dst.path)
	inList := func(list []string, ids ...string) bool {
		for _, l := range list {
			for _, id := range ids {
				if l == id {
					return true
				}
			}
		}
		return false
	}
	leaving := "the organization"
	var controlTower []workload.StackView
	for _, st := range inv.Stacks {
		ss := st.StackSetSettings
		switch st.Provenance.Kind {
		case workload.KindControlTower:
			controlTower = append(controlTower, st)
			continue
		case workload.KindStackSetUnknown:
			if e.crossOrg {
				c.add(Finding{Status: StatusReview, Category: CategoryPotentialImpact, Confidence: ConfidenceMedium,
					Title:    fmt.Sprintf("Stack %s looks like a StackSet instance, but no StackSet in the snapshot owns it", st.Name),
					Detail:   "Its name has the StackSet- form, which is how StackSets names the stacks it creates in AWS's own examples (not a documented rule), and no StackSet read from the management account lists it. A self-managed StackSet administered from another account would look like this: it is tied to account IDs and IAM roles, not to the organization, so the instance would stay and remain operable from that account. Find the administrator before the move and decide whether the instance should follow, be removed or be re-created.",
					Evidence: []Evidence{kindEvidence(EvidenceExternalStackSet, st, "")}, Regions: []string{st.Region}, References: []string{refStackSetAuto}})
			}
			continue
		case workload.KindStackSetSelfManaged:
			if e.crossOrg && ss != nil {
				c.add(Finding{Status: StatusReview, Category: CategoryPotentialImpact, Confidence: ConfidenceMedium,
					Title:    fmt.Sprintf("Self-managed StackSet %s keeps operating stack %s after the move", ss.Name, st.Name),
					Detail:   fmt.Sprintf("A self-managed StackSet deploys through an administration role in account %s and an execution role in this account; neither depends on the organization. The instance stays, and account %s can keep updating or deleting it for as long as the execution role trusts it. Decide whether that access across organizations should remain; otherwise remove the instance from the StackSet with the stacks retained, or delete the execution role.", orUnknown(ss.AdministrationAccountID), orUnknown(ss.AdministrationAccountID)),
					Evidence: []Evidence{kindEvidence(EvidenceExternalStackSet, st, "")}, Regions: []string{st.Region}, References: []string{refStackSetAuto}})
			}
			continue
		case workload.KindStackSetServiceManaged:
		default:
			continue
		}
		if ss == nil {
			continue
		}
		if !e.crossOrg {
			if inList(ss.TargetOUs, dstTargets...) || inList(ss.TargetAccounts, e.accountID) {
				continue // still a target at the new position
			}
			leaving = "the StackSet's target OUs (" + orNoneStr(strings.Join(ss.TargetOUs, ", ")) + ")"
		}
		confidence := ConfidenceHigh
		match := "the stack ID is one of the StackSet's instances"
		if !ss.MatchedByInstance {
			confidence = ConfidenceMedium
			match = "matched by the StackSet name in the stack name, which is a convention; no instance record confirms it"
		}
		ev := []Evidence{stackEvidence(st, fmt.Sprintf("StackSet %s: service-managed, auto-deployment %t, retain stacks on account removal %t, targets %s; %s", ss.Name, ss.AutoDeployment, ss.RetainStacksOnAccountRemoval, orNoneStr(strings.Join(ss.TargetOUs, ", ")), match))}
		ev[0].Kind = EvidenceStackInstance
		switch {
		case ss.AutoDeployment && !ss.RetainStacksOnAccountRemoval:
			detail := fmt.Sprintf("StackSet %s is service-managed with automatic deployment on and RetainStacksOnAccountRemoval off. When an account is removed from a target organization or OU, StackSets deletes its stack instances and their resources: here %s. Whatever in the account uses them stops working at that moment, and the resources are not there for a rollback either. Before the move, either turn RetainStacksOnAccountRemoval on for the StackSet (the stack then stays in the account, detached from the StackSet and no longer updated) or make sure the destination deploys an equivalent.",
				ss.Name, typeCounts(st.ResourceTypes))
			if importers := importersOf(inv, st); len(importers) > 0 {
				detail += fmt.Sprintf(" The stack exports values that %s still import; CloudFormation refuses to delete a stack whose export is imported, so the StackSet's delete operation fails and leaves the instance behind in a failed state until the imports are removed.", strings.Join(importers, ", "))
			}
			c.add(Finding{Status: StatusReview, Category: CategoryDeclaredImpact, Confidence: confidence,
				Title:  fmt.Sprintf("StackSet instance %s is deleted when the account leaves %s: %d resource(s)", st.Name, leaving, st.Resources),
				Detail: detail, Evidence: ev, Regions: []string{st.Region}, References: []string{refAutoDeployment, refStackSetAuto}})
		case ss.AutoDeployment:
			c.add(Finding{Status: StatusInfo, Category: CategoryInformational, Confidence: confidence,
				Title:    fmt.Sprintf("StackSet instance %s stays in the account, detached from StackSet %s", st.Name, ss.Name),
				Detail:   fmt.Sprintf("RetainStacksOnAccountRemoval is on, so when the account leaves %s the stack and its %d resource(s) are kept in their current state and are no longer part of the StackSet: nobody updates them from then on. Adopt the stack in the destination or replace it.", leaving, st.Resources),
				Evidence: ev, Regions: []string{st.Region}, References: []string{refAutoDeployment, refStackSetAuto}})
		default:
			c.add(Finding{Status: StatusReview, Category: CategoryPotentialImpact, Confidence: ConfidenceMedium,
				Title:    fmt.Sprintf("What happens to StackSet instance %s when the account leaves %s is not documented", st.Name, leaving),
				Detail:   fmt.Sprintf("StackSet %s is service-managed with automatic deployment off. The documentation describes the deletion or retention of instances only for automatic deployment; with it off it does not say whether the instance is deleted, left in place or fails on the StackSet's next operation. Ask the StackSet's administrator (account %s) to remove the instance explicitly, with or without retaining the stack, before the move.", ss.Name, orUnknown(ss.AdministrationAccountID)),
				Evidence: ev, Regions: []string{st.Region}, References: []string{refAutoDeployment, refStackSetAuto}})
		}
	}
	if len(controlTower) > 0 && e.crossOrg {
		resources := 0
		var names []string
		var ev []Evidence
		for _, st := range controlTower {
			resources += st.Resources
			names = append(names, st.Name)
			ev = append(ev, stackEvidence(st, ""))
		}
		c.add(Finding{Status: StatusInfo, Category: CategoryInformational, Confidence: ConfidenceHigh,
			Title:    fmt.Sprintf("%d Control Tower baseline stack(s) with %d resource(s) belong to the source landing zone", len(controlTower), resources),
			Detail:   "These stacks are the baseline Control Tower deployed when it enrolled the account (" + strings.Join(names, ", ") + "). Unenrolling the account before it leaves removes them; leaving while enrolled keeps them in the account unmanaged, where they can conflict with the destination's baseline (an existing Config recorder blocks enrollment). The Control Tower check has the sequence.",
			Evidence: ev, References: []string{refCTUnmanage, refCTEnroll}})
	}
}

// workloadReferences reports the dependencies between stacks: imports
// inside the account and outputs read from other accounts.
func (e *evaluation) workloadReferences(c *Check, inv *workload.Inventory) {
	var imports []string
	var importEvidence []Evidence
	for _, st := range inv.Stacks {
		for _, im := range st.Imports {
			from := "a stack that is not in the inventory"
			if im.ExportingStack != "" {
				from = im.ExportingStack
			}
			imports = append(imports, fmt.Sprintf("%s imports %s from %s", st.Name, im.ExportName, from))
		}
		if len(st.Imports) > 0 {
			importEvidence = append(importEvidence, kindEvidence(EvidenceStackImport, st, ""))
		}
	}
	if len(imports) > 0 && e.crossOrg {
		c.add(Finding{Status: StatusInfo, Category: CategoryInformational, Confidence: ConfidenceHigh,
			Title:    fmt.Sprintf("%d import(s) between stacks of the account move with it", len(imports)),
			Detail:   "Export and Fn::ImportValue work inside one account and Region only, so an import can never point at another account and these keep working after a transfer: " + strings.Join(imports, "; ") + ". CloudFormation refuses to delete an exporting stack or change its exported output while another stack imports it, which fixes the order when the stacks are re-created in a new account: the exporting stack first. References to stacks in other accounts use Fn::GetStackOutput and are reported separately.",
			Evidence: importEvidence, References: []string{refCFNExports}})
	}
	for _, st := range inv.Stacks {
		for _, ex := range st.ExternalOutputs {
			if ex.AccountID == "" || ex.AccountID == e.accountID {
				continue
			}
			where := fmt.Sprintf("account %s, which is in neither snapshot", ex.AccountID)
			if org, ok := e.orgOfAccount(ex.AccountID); ok {
				switch {
				case org == e.src.orgID && e.crossOrg:
					where = fmt.Sprintf("account %s, which stays in organization %s", ex.AccountID, org)
				case org == e.dst.orgID && e.crossOrg:
					where = fmt.Sprintf("account %s, which is in the destination organization %s", ex.AccountID, org)
				default:
					where = fmt.Sprintf("account %s of organization %s", ex.AccountID, org)
				}
			}
			ev := stackEvidence(st, fmt.Sprintf("Fn::GetStackOutput: stack %s, output %s, region %s, role %s", ex.StackName, ex.OutputName, orUnknown(ex.Region), ex.RoleARN))
			ev.Kind = EvidenceStackOutputReference
			if !e.crossOrg {
				// Inside one organization the reference rests on the role's
				// trust, which the move does not touch; the sts:AssumeRole
				// call is evaluated as a derived operation against the SCPs
				// and RCPs of the new position, and reported there if denied.
				continue
			}
			c.add(Finding{Status: StatusReview, Category: CategoryPotentialImpact, Confidence: ConfidenceMedium, Source: SourceWorkload,
				Title: fmt.Sprintf("Stack %s reads output %s of stack %s in account %s", st.Name, ex.OutputName, ex.StackName, ex.AccountID),
				Detail: fmt.Sprintf("The reference uses Fn::GetStackOutput through role %s in %s. It is a weak reference: the value is resolved when the consuming stack is created or updated and nothing changes at the moment of the move. The next update of %s resolves it again, across organizations by then: CloudFormation's execution role in this account has to assume %s, which the role's trust policy (in the other account, not collected here), the destination's SCPs on this account and the RCPs of the role's organization decide. The sts:AssumeRole call was evaluated as a derived operation: see the SCP and RCP checks for a denial. If the value changes or the producing stack is deleted, this stack is not told; plan where the value comes from once the accounts are in different organizations.",
					ex.RoleARN, where, st.Name, ex.RoleARN),
				Action: "sts:AssumeRole", Resource: ex.RoleARN, Evidence: []Evidence{ev}, Regions: []string{st.Region}, References: []string{refGetStackOutput}})
		}
	}
}

// ongoingSubnetTypes are stack resource types that keep creating resources
// in their subnets after deployment.
var ongoingSubnetTypes = map[string]string{
	"AWS::AutoScaling::AutoScalingGroup": "launches instances into its subnets whenever it scales or replaces one",
	"AWS::ECS::Service":                  "starts tasks with network interfaces in its subnets on every deployment and replacement",
	"AWS::EKS::Nodegroup":                "launches nodes into its subnets when it scales or replaces one",
	"AWS::Lambda::Function":              "creates network interfaces in its subnets when it is attached to a VPC",
	"AWS::Batch::ComputeEnvironment":     "launches compute into its subnets on demand",
	"AWS::EMR::Cluster":                  "launches instances into its subnet when it resizes",
}

// workloadSharedResources reports the stacks that sit on networking shared
// through RAM shares the account loses with the move.
func (e *evaluation) workloadSharedResources(c *Check, inv *workload.Inventory) {
	type hit struct {
		share snapshot.ResourceShare
		kind  string
		ids   []string
		via   []string
	}
	for _, st := range inv.Stacks {
		hits := map[string]*hit{}
		var order []string
		for _, ref := range st.References {
			for _, sh := range e.from.ResourceShares {
				if sh.OwnerAccountID == e.accountID {
					continue
				}
				for _, res := range sh.Resources {
					if !strings.HasSuffix(res.ARN, "/"+ref.ID) && res.ARN != ref.ID {
						continue
					}
					before, after, retained := e.shareFate(sh)
					if !before || after || retained {
						continue
					}
					key := sh.ARN + "|" + res.Type
					h, ok := hits[key]
					if !ok {
						h = &hit{share: sh, kind: res.Type}
						hits[key] = h
						order = append(order, key)
					}
					h.ids = append(h.ids, ref.ID)
					if ref.Via != "" && !contains(h.via, ref.Via) {
						h.via = append(h.via, ref.Via)
					}
				}
			}
		}
		for _, key := range order {
			h := hits[key]
			b := behaviourOf(h.kind)
			status, category, confidence := StatusReview, CategoryDeclaredImpact, ConfidenceHigh
			var detail string
			switch b.dataPlane {
			case dataPlaneStops:
				status = StatusNoGo
				detail = fmt.Sprintf("Traffic is affected at once: %s.", b.detail)
			case dataPlaneContinues:
				detail = fmt.Sprintf("What the documentation says happens when the share ends: %s.", b.detail)
			default:
				category, confidence = CategoryPotentialImpact, ConfidenceMedium
				detail = "What happens to resources already using a shared resource of this type is not verified against the service documentation; treat the stack as potentially affected."
			}
			var ongoing []string
			if h.kind == "ec2:Subnet" {
				types := make([]string, 0, len(st.ResourceTypes))
				for t := range st.ResourceTypes {
					types = append(types, t)
				}
				sort.Strings(types)
				for _, t := range types {
					if why, ok := ongoingSubnetTypes[t]; ok {
						ongoing = append(ongoing, t+", which "+why)
					}
				}
				if len(ongoing) > 0 {
					// Creating resources in the subnet is what the workload
					// does in normal operation, so the documented loss of
					// that ability is a blocker rather than a caveat.
					status = StatusNoGo
					detail += " The stack contains " + strings.Join(ongoing, "; ") + ". Those launches need to create resources in the subnet, which fails once the share ends: what is running keeps running, and nothing can be replaced or scaled out."
				}
				detail += " A stack update that replaces a resource in the subnet fails for the same reason."
			}
			if h.kind == "ec2:TransitGateway" {
				if st.ResourceTypes["AWS::EC2::TransitGatewayAttachment"]+st.ResourceTypes["AWS::EC2::TransitGatewayVpcAttachment"] > 0 {
					detail += " The stack owns the attachment: it keeps carrying traffic, but a stack update that replaces it, or redeploying the stack, fails because the account can no longer create attachments to this transit gateway."
				}
			}
			if b.orgOnly && e.crossOrg {
				detail += " Sharing them again is not a way out: this resource type can only be shared inside one organization, so the workload has to move to networking of the destination before the account leaves."
			}
			ev := stackEvidence(st, fmt.Sprintf("references %s (%s)", strings.Join(h.ids, ", "), orNoneStr(strings.Join(h.via, ", "))))
			ev.Kind = EvidenceStackReference
			refs := []string{refRAMSharing}
			if b.reference != "" {
				refs = append(refs, b.reference)
			}
			c.add(Finding{Status: status, Category: category, Confidence: confidence, Source: SourceWorkload,
				Title:    fmt.Sprintf("Stack %s sits on %s shared through %s, which the account loses", st.Name, describeShared(h.kind, len(h.ids)), h.share.Name),
				Detail:   fmt.Sprintf("It references %s (%s), shared by account %s with %s. ", strings.Join(h.ids, ", "), orNoneStr(strings.Join(h.via, ", ")), h.share.OwnerAccountID, describeScopes(h.share.Principals)) + detail,
				Evidence: []Evidence{ev, shareEvidence("source", h.share)}, Regions: []string{st.Region}, References: refs})
		}
	}
}

func describeShared(kind string, n int) string {
	switch kind {
	case "ec2:Subnet":
		if n == 1 {
			return "a subnet"
		}
		return fmt.Sprintf("%d subnets", n)
	case "ec2:TransitGateway":
		return "a transit gateway"
	}
	return kind
}

// ownResourceRequest is a request by the account's own principals against
// one of the account's own resources, with the account at the given side.
func (e *evaluation) ownResourceRequest(s *side, action, resource string) policy.Request {
	req := e.ownRequest(s, snapshot.ActionInUse{Action: action, Resource: resource}, "")
	req.Context.Set("aws:ResourceAccount", policy.Known(e.accountID))
	req.Context.Set("aws:ResourceOrgID", policy.Known(s.orgID))
	req.Context.Set("aws:ResourceOrgPaths", policy.Known(orgPath(s.orgID, s.path)))
	return req
}

// outsideRequest is a request by some principal of an organization, in
// another account, against one of the account's resources at side s.
func (e *evaluation) outsideRequest(orgID string, s *side, action, resource string) policy.Request {
	ctx := policy.Context{}
	ctx.Set("aws:PrincipalOrgID", policy.Known(orgID))
	ctx.Set("aws:PrincipalIsAWSService", policy.Known("false"))
	ctx.Set("aws:ResourceAccount", policy.Known(e.accountID))
	ctx.Set("aws:ResourceOrgID", policy.Known(s.orgID))
	ctx.Set("aws:ResourceOrgPaths", policy.Known(orgPath(s.orgID, s.path)))
	return policy.Request{Action: action, Resource: resource, Context: ctx}
}

func policyKindLabel(kind string) string {
	switch kind {
	case snapshot.PolicyKindBucket:
		return "Bucket policy"
	case snapshot.PolicyKindRoleTrust:
		return "Trust policy"
	}
	return "Template policy"
}

func policyTarget(p snapshot.ResourcePolicy) string {
	switch {
	case p.ResourceARN != "":
		return p.ResourceARN
	case p.Stack != "":
		return "resource " + p.Resource + " of stack " + p.Stack
	}
	return p.Resource
}

func hasOrgCondition(st *policy.Statement) bool {
	for _, cond := range st.Conditions {
		if snapshot.IsOrgConditionKey(cond.Key) {
			return true
		}
	}
	return false
}

func orgConditionText(st *policy.Statement) string {
	var parts []string
	for _, cond := range st.Conditions {
		if snapshot.IsOrgConditionKey(cond.Key) {
			parts = append(parts, fmt.Sprintf("%s %s %s", cond.Operator, cond.Key, strings.Join(cond.Values, ", ")))
		}
	}
	return strings.Join(parts, " and ")
}

// workloadPolicies reports the resource policies whose effect changes with
// the organization or the OU path.
func (e *evaluation) workloadPolicies(c *Check, inv *workload.Inventory) {
	for _, p := range inv.Policies {
		label, target := policyKindLabel(p.Kind), policyTarget(p)
		if len(p.Document) == 0 {
			e.templatePolicy(c, p, label, target)
			continue
		}
		doc, err := policy.Parse(p.Document)
		if err != nil {
			c.add(Finding{Status: StatusReview, Category: CategoryUnsupported, Confidence: ConfidenceMedium, Title: fmt.Sprintf("%s of %s could not be parsed", label, target), Detail: err.Error(),
				Evidence: []Evidence{{Kind: EvidenceResourcePolicy, Side: "source", PolicyType: p.Kind, Reference: target, StatementJSON: p.Document}}})
			continue
		}
		status := StatusGo
		var lines []string
		var evidence []Evidence
		ownDenied := false
		for i := range doc.Statements {
			st := &doc.Statements[i]
			if !hasOrgCondition(st) {
				continue
			}
			action := "s3:GetObject"
			if p.Kind == snapshot.PolicyKindRoleTrust {
				action = "sts:AssumeRole"
			}
			if len(st.Actions) > 0 {
				action = st.Actions[0]
			}
			resource := p.ResourceARN
			if len(st.Resources) > 0 {
				resource = st.Resources[0]
			}
			cond := orgConditionText(st)
			var stLines []string
			stStatus := StatusGo
			// The account's own principals, before and after.
			if p.Kind != snapshot.PolicyKindRoleTrust {
				before := st.Applies(e.ownResourceRequest(&e.src, action, resource)).Outcome
				after := st.Applies(e.ownResourceRequest(&e.dst, action, resource))
				switch {
				case !st.IsAllow() && before != policy.Yes && after.Outcome == policy.Yes:
					stStatus, ownDenied = StatusNoGo, true
					stLines = append(stLines, fmt.Sprintf("it denies %s to the account's own principals after the move: today they are exempt (%s), afterwards they are not", strings.Join(st.Actions, ", "), cond))
				case !st.IsAllow() && before != policy.Yes && after.Outcome == policy.Unknown:
					stStatus = Worst(stStatus, StatusReview)
					stLines = append(stLines, fmt.Sprintf("it may deny the account's own principals after the move (%s; %s)", cond, after.Reason))
				case st.IsAllow() && before == policy.Yes && after.Outcome != policy.Yes:
					stStatus = Worst(stStatus, StatusReview)
					stLines = append(stLines, fmt.Sprintf("it stops admitting the account's own principals (%s); inside one account an identity policy can still grant the access, so whether anything breaks depends on policies this check does not read", cond))
				}
			}
			// Other accounts of the organization the account leaves, and of the one it joins.
			if e.crossOrg {
				srcOrg := st.Applies(e.outsideRequest(e.src.orgID, &e.dst, action, resource)).Outcome
				dstOrg := st.Applies(e.outsideRequest(e.dst.orgID, &e.dst, action, resource)).Outcome
				switch {
				case st.IsAllow() && srcOrg != policy.No && dstOrg == policy.No:
					stStatus = Worst(stStatus, StatusReview)
					stLines = append(stLines, fmt.Sprintf("it keeps admitting principals of %s, the organization the account leaves, and does not admit principals of %s (%s)", e.src.orgID, e.dst.orgID, cond))
				case !st.IsAllow() && srcOrg == policy.No && dstOrg != policy.No:
					stStatus = Worst(stStatus, StatusReview)
					stLines = append(stLines, fmt.Sprintf("principals of %s stay exempt from it while principals of %s, the account's new organization, are denied (%s)", e.src.orgID, e.dst.orgID, cond))
				}
			}
			if len(stLines) == 0 {
				continue
			}
			status = Worst(status, stStatus)
			lines = append(lines, fmt.Sprintf("Statement %s (%s): %s.", st.Label(), st.Effect, strings.Join(stLines, "; ")))
			evidence = append(evidence, Evidence{Kind: EvidenceResourcePolicy, Side: "source", PolicyType: p.Kind, Reference: target, Statement: st.Label(), StatementJSON: st.Raw, Note: "read with " + orUnknown(p.Source)})
		}
		if len(lines) == 0 {
			continue
		}
		f := Finding{Status: status, Category: CategoryPotentialImpact, Confidence: ConfidenceMedium, Source: SourceWorkload, Resource: p.ResourceARN, Evidence: evidence, References: []string{refConditionKeys}}
		fix := " Change the policy to name the destination organization (or both, for the transition) before the move."
		switch {
		case ownDenied:
			f.Category, f.Confidence = CategoryDeclaredImpact, ConfidenceHigh
			f.Title = fmt.Sprintf("%s of %s denies the account's own principals after the move", label, target)
			f.Detail = strings.Join(lines, " ") + " A Deny in a resource policy applies to principals of the resource's own account too, so the applications in this account lose the resource the moment the account changes organization." + fix
		case p.Kind == snapshot.PolicyKindRoleTrust:
			f.Title = fmt.Sprintf("%s of %s stays tied to the organization the account leaves", label, target)
			f.Detail = strings.Join(lines, " ") + " Decide whether principals of the former organization should keep assuming the role, and note that the destination's RCPs also apply to sts:AssumeRole on it (the RCP check evaluates the inbound entries of the usage list)." + fix
		default:
			f.Title = fmt.Sprintf("%s of %s ties access to organization identity that changes with the move", label, target)
			f.Detail = strings.Join(lines, " ") + fix
		}
		c.add(f)
	}
}

// templatePolicy reports a policy found in a template, of which only the
// organization conditions are kept.
func (e *evaluation) templatePolicy(c *Check, p snapshot.ResourcePolicy, label, target string) {
	srcPath, dstPath := orgPath(e.src.orgID, e.src.path), orgPath(e.dst.orgID, e.dst.path)
	var lines []string
	dynamic := false
	for _, cond := range p.Conditions {
		text := fmt.Sprintf("%s %s %s %s", orUnknown(cond.Effect), cond.Operator, cond.Key, strings.Join(cond.Values, ", "))
		if cond.Dynamic {
			dynamic = true
			lines = append(lines, text+" (a value is computed in the template and not known offline)")
			continue
		}
		for _, v := range cond.Values {
			org := v
			if i := strings.Index(v, "/"); i > 0 {
				org = v[:i]
			}
			switch {
			case e.crossOrg && org == e.src.orgID:
				lines = append(lines, text+": names "+e.src.orgID+", the organization the account leaves")
			case !e.crossOrg && strings.Contains(strings.ToLower(cond.Key), "orgpaths") && pathCovers(v, srcPath) != pathCovers(v, dstPath):
				lines = append(lines, fmt.Sprintf("%s: covers the account's path %s but not %s", text, pick(pathCovers(v, srcPath), srcPath, dstPath), pick(pathCovers(v, srcPath), dstPath, srcPath)))
			}
		}
	}
	if len(lines) == 0 {
		return
	}
	f := Finding{Status: StatusReview, Category: CategoryPotentialImpact, Confidence: ConfidenceMedium, Source: SourceWorkload,
		Title:    fmt.Sprintf("%s for %s is conditioned on organization identity that changes with the move", label, target),
		Detail:   strings.Join(lines, "; ") + ". Only the organization conditions are kept from a template, not the statement around them, so who is admitted or denied cannot be evaluated here: review the resource in the template of stack " + orUnknown(p.Stack) + " and update the value before the next deployment.",
		Evidence: []Evidence{{Kind: EvidenceResourcePolicy, Side: "source", PolicyType: p.Kind, Reference: target, Note: "found in the template read with " + orUnknown(p.Source)}}, References: []string{refConditionKeys}}
	if dynamic {
		f.Category = CategoryUnsupported
	}
	c.add(f)
}

// pathCovers reports whether an aws:PrincipalOrgPaths pattern covers a path.
func pathCovers(pattern, path string) bool {
	if strings.HasSuffix(pattern, "*") {
		return strings.HasPrefix(path, strings.TrimSuffix(pattern, "*"))
	}
	return pattern == path
}

func pick(first bool, a, b string) string {
	if first {
		return a
	}
	return b
}
