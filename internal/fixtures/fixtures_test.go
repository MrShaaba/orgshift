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
