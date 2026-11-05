package fixtures

import (
	"bytes"
	"testing"

	"github.com/MrShaaba/orgshift/internal/snapshot"
)

func TestFixturesValidateAndRoundTrip(t *testing.T) {
	for name, s := range All() {
		if err := s.Validate(); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		data, err := snapshot.Marshal(s)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := snapshot.Parse(data); err != nil {
			t.Fatalf("%s: re-parse failed: %v", name, err)
		}
	}
}

func TestFixturesAreDeterministic(t *testing.T) {
	a, _ := snapshot.Marshal(Larkspur())
	b, _ := snapshot.Marshal(Larkspur())
	if !bytes.Equal(a, b) {
		t.Fatal("Larkspur fixture is not deterministic")
	}
	c, _ := snapshot.Marshal(Fernhill())
	if bytes.Equal(a, c) {
		t.Fatal("the two organizations should differ")
	}
}

func TestPlantedProblemsArePresent(t *testing.T) {
	l, f := Larkspur(), Fernhill()
	if l.Organization.ID == f.Organization.ID {
		t.Fatal("fixtures must be different organizations")
	}
	if u := l.UsageFor(LarkspurPaymentsProd); len(u.Actions) == 0 || len(u.InboundAccess) == 0 || len(u.TaggedResources) == 0 {
		t.Fatal("payments account should have actions, inbound access and tagged resources")
	}
	want := map[string]bool{"Fernhill-EU-Only-Regions": false, "Fernhill-Payments-Controls": false,
		"Fernhill-Block-External-Principals": false, "Fernhill-Cost-Allocation": false}
	for _, p := range f.Policies {
		if _, ok := want[p.Name]; ok {
			want[p.Name] = true
		}
	}
	for name, found := range want {
		if !found {
			t.Errorf("planted policy %s missing", name)
		}
	}
	networking := 0
	for _, sh := range l.ResourceShares {
		for _, r := range sh.Resources {
			if r.Type == "ec2:TransitGateway" || r.Type == "ec2:Subnet" {
				networking++
			}
		}
	}
	if networking < 2 {
		t.Fatal("expected an org-scoped TGW and subnet share")
	}
}

func TestIdentityCenterFixture(t *testing.T) {
	l, f := Larkspur(), Fernhill()
	ic := l.IdentityCenter
	if ic == nil || ic.InstanceARN != LarkspurIdentityCenterInstance || len(ic.PermissionSets) != 5 {
		t.Fatalf("Larkspur should run Identity Center with five permission sets: %+v", ic)
	}
	if got := ic.AssignmentsFor(LarkspurPaymentsProd); len(got) != 4 {
		t.Errorf("payments account should carry four assignments, got %d", len(got))
	}
	if got := ic.ProvisionedIn(LarkspurPaymentsProd); len(got) != 4 || got[3].Name != "DataPlatformOperator" {
		t.Errorf("payments account should have four provisioned roles including the stale DataPlatformOperator: %+v", got)
	}
	if f.IdentityCenter.PermissionSetByName(LarkspurPaymentsEngineerSet) != nil || f.IdentityCenter.PermissionSetByName("ReadOnlyAccess") == nil {
		t.Error("Fernhill should match ReadOnlyAccess by name and lack PaymentsEngineer")
	}
	if f.IdentityCenter.IdentityStoreID == ic.IdentityStoreID {
		t.Error("the two instances must use different identity stores")
	}
}

func TestPlantedWorkloadProblemsArePresent(t *testing.T) {
	l, f := Larkspur(), Fernhill()
	w := l.WorkloadsFor(LarkspurPaymentsProd)
	if w == nil || len(w.Stacks) != 8 || w.ResourceSource != snapshot.ResourceSourceTaggingAPI {
		t.Fatalf("payments account should carry a workload inventory: %+v", w)
	}
	var baseline, api, network *snapshot.Stack
	for i := range w.Stacks {
		st := &w.Stacks[i]
		switch {
		case st.StackSet != nil && st.StackSet.Name == LarkspurBaselineStackSet:
			baseline = st
		case st.Name == LarkspurAPIStack:
			api = st
		case st.Name == LarkspurNetworkStack:
			network = st
		}
	}
	// A service-managed StackSet instance that is deleted on leaving.
	ss := l.StackSetByName(LarkspurBaselineStackSet)
	if baseline == nil || ss == nil || ss.PermissionModel != "SERVICE_MANAGED" || !ss.AutoDeployment || ss.RetainStacksOnAccountRemoval || len(ss.Instances) != 3 {
		t.Fatalf("baseline StackSet instance: %+v %+v", baseline, ss)
	}
	if got, byInstance := l.StackSetOfStack(LarkspurPaymentsProd, *baseline); got != ss || !byInstance {
		t.Error("the stack ID should be one of the StackSet's instances")
	}
	// A cross-stack export and a cross-account output reference.
	if api == nil || len(api.Imports) != 2 || api.Imports[0].ExportingStack != LarkspurNetworkStack || len(api.ExternalOutputs) != 1 || api.ExternalOutputs[0].RoleARN != LarkspurObservabilityRole {
		t.Fatalf("payments-api imports and external outputs: %+v", api)
	}
	if network == nil || len(network.Outputs) != 3 || network.Outputs[1].ExportName != "payments-app-sg" {
		t.Fatalf("payments-network exports: %+v", network)
	}
	// An app on subnets shared through RAM.
	shared := map[string]bool{}
	for _, sh := range l.ResourceShares {
		for _, r := range sh.Resources {
			shared[r.ARN[len(r.ARN)-24:]] = true
		}
	}
	for _, ref := range api.References {
		if ref.Kind != snapshot.RefSubnet || !shared[ref.ID] {
			t.Errorf("payments-api should reference a subnet that a RAM share carries: %+v", ref)
		}
	}
	// A bucket policy on aws:PrincipalOrgID.
	var bucket *snapshot.ResourcePolicy
	for i := range w.ResourcePolicies {
		if w.ResourcePolicies[i].ResourceARN == LarkspurSettlementBucket {
			bucket = &w.ResourcePolicies[i]
		}
	}
	if bucket == nil || bucket.Kind != snapshot.PolicyKindBucket || len(bucket.Conditions) != 2 || bucket.Conditions[1].Effect != "Deny" || bucket.Conditions[1].Key != "aws:PrincipalOrgID" {
		t.Fatalf("settlement bucket policy: %+v", bucket)
	}
	// Resources missing the cost-center tag.
	missing := 0
	for _, r := range w.Resources {
		if _, ok := r.Tags["cost-center"]; !ok {
			if _, ok := r.Tags["Cost-Center"]; !ok {
				missing++
			}
		}
	}
	if missing < 5 {
		t.Errorf("expected at least five sampled resources without a cost-center tag, got %d", missing)
	}
	// Coverage: one record per workload domain for each inventoried account.
	for _, id := range []string{LarkspurPaymentsProd, "111111111116", "111111111118"} {
		for _, d := range snapshot.WorkloadDomains {
			found := false
			for _, rec := range l.DomainRecords(d) {
				if rec.AccountID == id && rec.Status.Complete() {
					found = true
				}
			}
			if !found {
				t.Errorf("%s has no complete %s record", id, d)
			}
		}
	}
	// Fernhill: Control Tower baseline stacks and a StackSet nobody administers.
	retail := f.WorkloadsFor(FernhillRetailProd)
	if retail == nil || retail.ResourceSource != snapshot.ResourceSourceResourceExplorer || len(retail.Stacks) != 5 {
		t.Fatalf("retail inventory: %+v", retail)
	}
	if p := LarkspurPartial(); p.Workloads != nil || p.DomainStatus(snapshot.DomainWorkloadStacks, "111111111116") != snapshot.CoverageAccessDenied {
		t.Error("the partial copy could not assume the member role")
	}
}
