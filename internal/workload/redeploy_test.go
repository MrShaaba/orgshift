package workload

import (
	"strings"
	"testing"

	"github.com/MrShaaba/orgshift/internal/fixtures"
	"github.com/MrShaaba/orgshift/internal/snapshot"
)

func TestRedeployPlanGroupsByProvenance(t *testing.T) {
	l := fixtures.Larkspur()
	plan := Build(l, fixtures.LarkspurPaymentsProd).Redeploy()
	if plan.Evaluation != Evaluated || len(plan.Groups) != 3 {
		t.Fatalf("plan: %+v", plan)
	}
	byGroup := map[Group]RedeployGroup{}
	for _, g := range plan.Groups {
		byGroup[g.Group] = g
	}
	pipe := byGroup[GroupPipeline]
	if pipe.Stacks != 5 || pipe.StackResources != 27 || pipe.SampledResources != 3 || len(pipe.Items) != 8 || pipe.Line() != "5 stack(s) with 27 resource(s) and 3 sampled resource(s) outside any stack" ||
		strings.Join(pipe.StackNames(), ",") != "payments-network,payments-api,payments-settlement-storage,payments-ledger-db,payments-dr-standby" {
		t.Errorf("pipeline group: %+v", pipe)
	}
	platform := byGroup[GroupPlatform]
	if platform.Stacks != 3 || platform.StackResources != 10 || platform.SampledResources != 0 || platform.Items[0].StackSet != fixtures.LarkspurBaselineStackSet || platform.Items[0].Provenance != KindStackSetServiceManaged {
		t.Errorf("platform group: %+v", platform)
	}
	manual := byGroup[GroupManual]
	if manual.Stacks != 0 || manual.SampledResources != 3 || manual.Items[0].Type != "resource" || manual.Items[0].Confidence != ConfidenceLow || manual.Line() != "3 sampled resource(s) outside any stack" {
		t.Errorf("manual group: %+v", manual)
	}
	deps := strings.Join(plan.Dependencies, "\n")
	for _, want := range []string{
		"Order: payments-network exports values that payments-api import(s), so it is deployed first",
		"Cross-account reference: payments-api reads output LogDestinationArn of stack shared-observability in account 111111111113",
		"Existing infrastructure: payments-api takes subnet subnet-",
		"Existing infrastructure: payments-network takes transit-gateway tgw-",
		"Data: redeploying a template brings back empty resources", "AWS::RDS::DBInstance x1", "AWS::S3::Bucket x1",
		"Organization identity: 3 policy(ies) are conditioned on the organization ID or path",
		"Platform: 3 stack(s) with 10 resource(s) were deployed into the account by the source's platform (larkspur-baseline-roles, larkspur-config-recorder)",
	} {
		if !strings.Contains(deps, want) {
			t.Errorf("dependencies should contain %q:\n%s", want, deps)
		}
	}
	unknowns := strings.Join(plan.Unknowns, "\n")
	for _, want := range []string{
		"3 sampled resource(s) carry no evidence of how they were deployed", "function:settlement-notifier",
		"3 classification(s) rest on a naming or tag convention rather than a record (medium confidence)",
		"Which pipeline or person deploys a plain stack is not collected",
		"never carried a tag are not in the sample", "Data volumes, cutover windows, DNS",
	} {
		if !strings.Contains(unknowns, want) {
			t.Errorf("unknowns should contain %q:\n%s", want, unknowns)
		}
	}
}

func TestRedeployPlanSaysWhatItCannotKnow(t *testing.T) {
	// No inventory: nothing is listed and the plan says so.
	plan := Build(fixtures.LarkspurPartial(), fixtures.LarkspurPaymentsProd).Redeploy()
	if plan.Evaluation != NotEvaluated || len(plan.Unknowns) != 1 || !strings.Contains(plan.Unknowns[0], "no workload inventory") || len(plan.Dependencies) != 0 {
		t.Errorf("plan without an inventory: %+v", plan)
	}
	for _, g := range plan.Groups {
		if g.Stacks+g.SampledResources != 0 || g.Line() != "nothing found" {
			t.Errorf("empty group: %+v", g)
		}
	}
	// A capped sample and a denied domain are unknowns of the plan.
	l := fixtures.Larkspur()
	l.Workloads[fixtures.LarkspurPaymentsProd].ResourcesTruncated = true
	for i := range l.Coverage.Domains {
		d := &l.Coverage.Domains[i]
		if d.Domain == snapshot.DomainWorkloadPolicies && d.AccountID == fixtures.LarkspurPaymentsProd {
			d.Status = snapshot.CoverageAccessDenied
		}
	}
	plan = Build(l, fixtures.LarkspurPaymentsProd).Redeploy()
	unknowns := strings.Join(plan.Unknowns, "\n")
	if plan.Evaluation != PartiallyEvaluated || !strings.Contains(unknowns, "The resource sample was capped") || !strings.Contains(unknowns, "workloads.policies was not completely collected (access_denied)") {
		t.Errorf("partial plan: %s\n%s", plan.Evaluation, unknowns)
	}
	// Resource Explorer has its own limit.
	plan = Build(fixtures.Fernhill(), fixtures.FernhillRetailProd).Redeploy()
	if !strings.Contains(strings.Join(plan.Unknowns, "\n"), "at most the first 1,000 results") || !strings.Contains(strings.Join(plan.Dependencies, "\n"), "the Control Tower baseline") {
		t.Errorf("Fernhill retail plan: %+v", plan)
	}
}

func TestDepartedInventoryDropsWhatStackSetsDelete(t *testing.T) {
	l := fixtures.Larkspur()
	w, deleted := Departed(l, fixtures.LarkspurPaymentsProd)
	if w == nil || len(deleted) != 1 || !strings.HasPrefix(deleted[0], "StackSet-"+fixtures.LarkspurBaselineStackSet) {
		t.Fatalf("deleted on leaving: %v", deleted)
	}
	if len(w.Stacks) != 7 || len(w.Resources) != 12 || len(w.ResourcePolicies) != 3 {
		t.Errorf("departed inventory: %d stacks, %d resources", len(w.Stacks), len(w.Resources))
	}
	for _, r := range w.Resources {
		if strings.Contains(r.ARN, "role/larkspur-audit") {
			t.Errorf("a role of the deleted instance should be gone: %s", r.ARN)
		}
	}
	// The source snapshot is not modified.
	if len(l.Workloads[fixtures.LarkspurPaymentsProd].Stacks) != 8 || len(l.Workloads[fixtures.LarkspurPaymentsProd].Resources) != 14 {
		t.Error("Departed must not change the snapshot it reads")
	}
	// Retained instances stay.
	for i := range l.StackSets {
		l.StackSets[i].RetainStacksOnAccountRemoval = true
	}
	if w, deleted := Departed(l, fixtures.LarkspurPaymentsProd); len(deleted) != 0 || len(w.Stacks) != 8 {
		t.Errorf("with retention nothing is deleted: %v", deleted)
	}
	if w, _ := Departed(l, "111111111117"); w != nil {
		t.Error("no inventory, nothing departs")
	}
}

func TestAssertedEmptyInventoryIsCollected(t *testing.T) {
	l := fixtures.Larkspur()
	l.Workloads = nil
	var kept []snapshot.DomainCoverage
	for _, d := range l.Coverage.Domains {
		if !snapshot.IsWorkloadDomain(d.Domain) {
			kept = append(kept, d)
		}
	}
	l.Coverage.Domains, l.Coverage.AssertedComplete = kept, true
	inv := Build(l, fixtures.LarkspurPaymentsProd)
	if !inv.Collected || inv.Evaluation() != Evaluated || len(inv.Stacks) != 0 || !strings.Contains(strings.Join(inv.Notes, " "), "empty rather than missing") {
		t.Errorf("an asserted-complete snapshot without a block has an empty inventory: %+v", inv)
	}
	// The same document upgraded from schema version 2 asserted completeness
	// before the workload domains existed.
	l.UpgradedFrom = 2
	if inv := Build(l, fixtures.LarkspurPaymentsProd); inv.Collected || inv.Evaluation() != NotEvaluated {
		t.Errorf("a version 2 assertion does not cover workloads: %+v", inv.Coverage)
	}
}
