package workload

import (
	"strings"
	"testing"

	"github.com/MrShaaba/orgshift/internal/fixtures"
	"github.com/MrShaaba/orgshift/internal/snapshot"
)

func stackNamed(t *testing.T, inv *Inventory, prefix string) StackView {
	t.Helper()
	for _, st := range inv.Stacks {
		if strings.HasPrefix(st.Name, prefix) {
			return st
		}
	}
	t.Fatalf("no stack starting with %s", prefix)
	return StackView{}
}

func resourceNamed(t *testing.T, inv *Inventory, substr string) ResourceView {
	t.Helper()
	for _, r := range inv.Resources {
		if strings.Contains(r.ARN, substr) {
			return r
		}
	}
	t.Fatalf("no resource containing %s", substr)
	return ResourceView{}
}

func TestProvenanceOfThePlantedWorkloads(t *testing.T) {
	l := fixtures.Larkspur()
	inv := Build(l, fixtures.LarkspurPaymentsProd)
	if !inv.Collected || inv.Evaluation() != Evaluated || inv.AccountName != "larkspur-payments-prod" || len(inv.Regions) != 2 {
		t.Fatalf("inventory header: %+v", inv.Coverage)
	}
	if len(inv.Stacks) != 8 || len(inv.Policies) != 3 || inv.PoliciesInspected != 17 || inv.ResourceSource != snapshot.ResourceSourceTaggingAPI {
		t.Fatalf("counts: %d stacks, %d policies", len(inv.Stacks), len(inv.Policies))
	}
	// A service-managed StackSet instance, matched by its instance ID.
	base := stackNamed(t, inv, "StackSet-"+fixtures.LarkspurBaselineStackSet)
	if base.Provenance.Kind != KindStackSetServiceManaged || base.Provenance.Confidence != ConfidenceHigh || base.Provenance.StackSet != fixtures.LarkspurBaselineStackSet ||
		!strings.Contains(base.Provenance.Evidence[0], "listed as an instance of StackSet") {
		t.Errorf("baseline stack: %+v", base.Provenance)
	}
	if ss := base.StackSetSettings; ss == nil || !ss.MatchedByInstance || !ss.AutoDeployment || ss.RetainStacksOnAccountRemoval || ss.PermissionModel != "SERVICE_MANAGED" {
		t.Errorf("baseline StackSet settings: %+v", base.StackSetSettings)
	}
	if rec := stackNamed(t, inv, "StackSet-"+fixtures.LarkspurRecorderStackSet); rec.StackSetSettings == nil || !rec.StackSetSettings.RetainStacksOnAccountRemoval {
		t.Errorf("recorder keeps its stacks: %+v", rec.StackSetSettings)
	}
	// Plain stacks say what is not known about them.
	api := stackNamed(t, inv, fixtures.LarkspurAPIStack)
	if api.Provenance.Kind != KindStack || api.Provenance.Confidence != ConfidenceHigh || !strings.Contains(api.Provenance.Evidence[0], "pipeline deploys it is not collected") {
		t.Errorf("api stack: %+v", api.Provenance)
	}
	if len(api.Imports) != 2 || api.Imports[0].ExportingStack != fixtures.LarkspurNetworkStack || len(api.ExternalOutputs) != 1 || api.ExternalOutputs[0].AccountID != "111111111113" || len(api.References) != 2 {
		t.Errorf("api dependencies: %+v", api.Stack)
	}
	// Resources inherit from their stack, follow tag conventions or stay unknown.
	if r := resourceNamed(t, inv, "role/larkspur-audit"); r.Provenance.Kind != KindStackSetServiceManaged || !strings.Contains(r.Provenance.Evidence[0], "inherits the stack's classification") {
		t.Errorf("a role created by the StackSet instance: %+v", r.Provenance)
	}
	if r := resourceNamed(t, inv, "table/fraud-scores"); r.Provenance.Kind != KindTerraform || r.Provenance.Confidence != ConfidenceMedium || !strings.Contains(r.Provenance.Evidence[0], "Terraform=true") || !strings.Contains(r.Provenance.Evidence[0], "convention") {
		t.Errorf("terraform tag: %+v", r.Provenance)
	}
	if r := resourceNamed(t, inv, "function:settlement-notifier"); r.Provenance.Kind != KindUnknown || r.Provenance.Confidence != ConfidenceLow || !strings.Contains(r.Provenance.Evidence[0], "looks the same") {
		t.Errorf("unknown is a valid answer and says why: %+v", r.Provenance)
	}
	if r := resourceNamed(t, inv, ":volume/"); r.Provenance.Kind != KindUnknown || !strings.Contains(r.Provenance.Evidence[0], "no tags at all") {
		t.Errorf("a resource with an empty tag set: %+v", r.Provenance)
	}
	// Every classification names its evidence.
	for _, st := range inv.Stacks {
		if len(st.Provenance.Evidence) == 0 || st.Provenance.Confidence == "" {
			t.Errorf("stack %s has no evidence", st.Name)
		}
	}
	for _, r := range inv.Resources {
		if len(r.Provenance.Evidence) == 0 || r.Provenance.Confidence == "" {
			t.Errorf("resource %s has no evidence", r.ARN)
		}
	}
	// Redeployment groups: the two worker instances are Terraform, the
	// Lambda, the queue and the volume are unknown.
	groups := map[Group]GroupSummary{}
	for _, g := range inv.Groups {
		groups[g.Group] = g
	}
	if g := groups[GroupPlatform]; g.Stacks != 3 || g.StackResources != 10 || g.SampledResources != 0 {
		t.Errorf("platform group: %+v", g)
	}
	if g := groups[GroupPipeline]; g.Stacks != 5 || g.SampledResources != 3 || g.Kinds[KindTerraform] != 3 {
		t.Errorf("pipeline group (five plain stacks, three Terraform-tagged resources outside stacks): %+v", g)
	}
	if g := groups[GroupManual]; g.Stacks != 0 || g.SampledResources != 3 {
		t.Errorf("manual or unknown group: %+v", g)
	}
	if inv.StacksByKind[KindStack] != 5 || inv.StacksByKind[KindStackSetServiceManaged] != 3 || inv.ResourcesByKind[KindUnknown] != 3 {
		t.Errorf("kind counts: %+v %+v", inv.StacksByKind, inv.ResourcesByKind)
	}
}

func TestControlTowerAndUnknownStackSets(t *testing.T) {
	f := fixtures.Fernhill()
	retail := Build(f, fixtures.FernhillRetailProd)
	ct := stackNamed(t, retail, "StackSet-AWSControlTowerBP-BASELINE-CONFIG")
	if ct.Provenance.Kind != KindControlTower || ct.Provenance.Confidence != ConfidenceHigh || !strings.Contains(ct.Provenance.Evidence[0], "AWSControlTowerBP-*") {
		t.Errorf("control tower baseline: %+v", ct.Provenance)
	}
	if r := resourceNamed(t, retail, "aws-controltower-ConfigRecorderRole"); r.Provenance.Kind != KindControlTower || r.Provenance.Confidence != ConfidenceMedium {
		t.Errorf("a Control Tower resource by name: %+v", r.Provenance)
	}
	if b := stackNamed(t, retail, "StackSet-"+fixtures.FernhillBaselineStackSet); b.Provenance.Kind != KindStackSetServiceManaged {
		t.Errorf("fernhill baseline: %+v", b.Provenance)
	}
	if r := resourceNamed(t, retail, "fernhill-retail-exports"); r.Provenance.Kind != KindTerraform {
		t.Errorf("managed-by=terraform: %+v", r.Provenance)
	}
	sandbox := Build(f, "222222222227")
	tooling := stackNamed(t, sandbox, "StackSet-team-tooling")
	if tooling.Provenance.Kind != KindStackSetUnknown || tooling.Provenance.Confidence != ConfidenceMedium || tooling.StackSetSettings != nil ||
		!strings.Contains(strings.Join(tooling.Provenance.Evidence, " "), "not a documented rule") || !strings.Contains(strings.Join(tooling.Provenance.Evidence, " "), "not visible") {
		t.Errorf("a StackSet nobody in the organization administers: %+v", tooling.Provenance)
	}
	if r := resourceNamed(t, sandbox, "fernhill-sandbox-scratch"); r.Provenance.Kind != KindTerraform {
		t.Errorf("provisioner=terraform: %+v", r.Provenance)
	}
}

func TestNameMatchIsWeakerThanAnInstanceRecord(t *testing.T) {
	l := fixtures.Larkspur()
	// Drop the instance records: the stack name still carries the StackSet
	// name, which is a convention and reads as medium confidence.
	for i := range l.StackSets {
		l.StackSets[i].Instances = nil
	}
	w := l.Workloads[fixtures.LarkspurPaymentsProd]
	for i := range w.Stacks {
		w.Stacks[i].StackSet = nil
	}
	inv := Build(l, fixtures.LarkspurPaymentsProd)
	base := stackNamed(t, inv, "StackSet-"+fixtures.LarkspurBaselineStackSet)
	if base.Provenance.Kind != KindStackSetServiceManaged || base.Provenance.Confidence != ConfidenceMedium || base.StackSetSettings == nil || base.StackSetSettings.MatchedByInstance ||
		!strings.Contains(base.Provenance.Evidence[0], "no instance record confirms it") {
		t.Errorf("name-only match: %+v", base.Provenance)
	}
}

func TestAccountWithoutInventory(t *testing.T) {
	l := fixtures.Larkspur()
	inv := Build(l, "111111111117")
	if inv.Collected || inv.Evaluation() != NotEvaluated || len(inv.Stacks) != 0 || len(inv.Notes) == 0 {
		t.Errorf("no inventory: %+v", inv)
	}
	for _, c := range inv.Coverage {
		if c.Status != snapshot.CoverageUnknown || !strings.Contains(c.Detail, "no coverage record for this account") {
			t.Errorf("a record for other accounts says nothing about this one: %+v", c)
		}
	}
	partial := fixtures.LarkspurPartial()
	inv = Build(partial, "111111111116")
	if inv.Collected || inv.Evaluation() != NotEvaluated || inv.Coverage[0].Status != snapshot.CoverageAccessDenied {
		t.Errorf("denied inventory: %+v", inv.Coverage)
	}
	if got := Accounts(l); len(got) != 3 || got[0] != fixtures.LarkspurPaymentsProd {
		t.Errorf("accounts with an inventory: %v", got)
	}
}

func TestPartialEvaluation(t *testing.T) {
	l := fixtures.Larkspur()
	for i := range l.Coverage.Domains {
		d := &l.Coverage.Domains[i]
		if d.Domain == snapshot.DomainWorkloadPolicies && d.AccountID == fixtures.LarkspurPaymentsProd {
			d.Status, d.Error = snapshot.CoverageAccessDenied, "AccessDenied: s3:GetBucketPolicy"
		}
	}
	if got := Build(l, fixtures.LarkspurPaymentsProd).Evaluation(); got != PartiallyEvaluated {
		t.Errorf("one denied domain makes the layer partially evaluated, got %s", got)
	}
}

func TestTerraformTagConvention(t *testing.T) {
	yes := []map[string]string{{"Terraform": "true"}, {"managed-by": "Terraform"}, {"ManagedBy": "terraform-cloud"}, {"tf-workspace": "prod"}, {"provisioner": "opentofu"}, {"terraform_module": "vpc"}}
	no := []map[string]string{{"Terraform": "false"}, {"owner": "terraform-team"}, {"managed-by": "cloudformation"}, {}, {"name": "tf"}}
	for _, tags := range yes {
		if _, _, ok := terraformTag(tags); !ok {
			t.Errorf("%v should read as a Terraform-style convention", tags)
		}
	}
	for _, tags := range no {
		if _, _, ok := terraformTag(tags); ok {
			t.Errorf("%v should not read as Terraform", tags)
		}
	}
	for _, k := range Kinds {
		if k.Label() == "" || k.Group().Title() == "" {
			t.Errorf("kind %s needs a label and a group", k)
		}
	}
}
