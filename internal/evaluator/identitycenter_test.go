package evaluator

import (
	"strings"
	"testing"

	"github.com/MrShaaba/orgshift/internal/fixtures"
)

func TestIdentityCenterCrossOrg(t *testing.T) {
	res, err := Evaluate(Input{From: fixtures.Larkspur(), To: fixtures.Fernhill(), AccountID: fixtures.LarkspurPaymentsProd, TargetOUID: fixtures.FernhillPaymentsOU})
	if err != nil {
		t.Fatal(err)
	}
	ic := check(res, "identity-center")
	if ic.Status != StatusReview || !strings.HasPrefix(ic.Summary, "4 assignment(s) across 3 permission set(s) and 4 provisioned role(s) go away") || !strings.Contains(ic.Summary, "2 permission set name(s) exist in the target, 1 do not") {
		t.Fatalf("identity center check wrong: %s %q", ic.Status, ic.Summary)
	}
	// Every assignment on the account is listed, grouped by permission set.
	pe := find(t, res, "identity-center", func(f Finding) bool {
		return strings.HasPrefix(f.Title, "Permission set PaymentsEngineer: 2 assignment(s)")
	})
	if pe.Status != StatusReview || !strings.Contains(pe.Title, "group Payments-Engineers, user oncall.payments") || !strings.Contains(pe.Detail, "no permission set named PaymentsEngineer") {
		t.Errorf("PaymentsEngineer finding wrong: %+v", pe)
	}
	kinds := map[string]int{}
	for _, ev := range pe.Evidence {
		kinds[ev.Kind]++
	}
	if kinds["account-assignment"] != 2 || kinds["permission-set"] != 1 {
		t.Errorf("PaymentsEngineer evidence should be two assignments and one permission set, got %v", kinds)
	}
	if len(pe.Evidence[2].StatementJSON) == 0 || !strings.Contains(pe.Evidence[2].Note, "customer managed policies (must exist in the account): /larkspur/LarkspurPaymentsEngineer") {
		t.Errorf("permission set evidence should carry the inline policy and the customer managed policy: %+v", pe.Evidence[2])
	}
	admin := find(t, res, "identity-center", func(f Finding) bool {
		return strings.HasPrefix(f.Title, "Permission set AdministratorAccess: 1 assignment(s)")
	})
	if !strings.Contains(admin.Title, "(group Platform-Admins)") || !strings.Contains(admin.Detail, "same name") || !strings.Contains(admin.Detail, "session duration PT1H vs PT2H") || !strings.Contains(admin.Detail, "identity store d-fern0000001") {
		t.Errorf("AdministratorAccess finding should match by name and list the differences: %s", admin.Detail)
	}
	if len(admin.Evidence) != 3 || admin.Evidence[2].Side != "target" {
		t.Errorf("a matched permission set carries the target's evidence too: %+v", admin.Evidence)
	}
	ro := find(t, res, "identity-center", func(f Finding) bool { return strings.HasPrefix(f.Title, "Permission set ReadOnlyAccess") })
	if !strings.Contains(ro.Detail, "managed policies only in the target: arn:aws:iam::aws:policy/job-function/ViewOnlyAccess") {
		t.Errorf("ReadOnlyAccess should report the extra managed policy: %s", ro.Detail)
	}
	// The roles, including the stale one.
	roles := find(t, res, "identity-center", func(f Finding) bool { return strings.Contains(f.Title, "AWSReservedSSO_* role(s) are deleted") })
	if roles.Status != StatusReview || !strings.HasPrefix(roles.Title, "4 AWSReservedSSO_* role(s)") || !strings.Contains(roles.Title, "AWSReservedSSO_DataPlatformOperator_*") {
		t.Errorf("roles finding wrong: %+v", roles)
	}
	if !strings.Contains(roles.Detail, "/aws-reserved/sso.amazonaws.com/us-east-1/") || !strings.Contains(roles.Detail, "1 of them (AWSReservedSSO_DataPlatformOperator_*) are provisioned without any assignment") {
		t.Errorf("roles detail should name the path and the stale role: %s", roles.Detail)
	}
	if len(roles.Evidence) != 4 || !strings.Contains(roles.Evidence[3].Note, "(stale)") {
		t.Errorf("one evidence line per role with the stale one marked: %+v", roles.Evidence)
	}
	info := find(t, res, "identity-center", func(f Finding) bool {
		return f.Status == StatusInfo && strings.Contains(f.Title, "re-created in the target")
	})
	if !strings.Contains(info.Detail, "exist in both instances: AdministratorAccess, ReadOnlyAccess") || !strings.Contains(info.Detail, "Missing in the target: PaymentsEngineer") {
		t.Errorf("target info should list matched and missing names: %s", info.Detail)
	}
	for _, f := range ic.Findings {
		if f.Status == StatusNoGo {
			t.Errorf("Identity Center never blocks a move: %s", f.Title)
		}
	}
}

func TestIdentityCenterSameOrgAndAbsence(t *testing.T) {
	l := fixtures.Larkspur()
	res, err := Evaluate(Input{From: l, AccountID: "111111111116", TargetOUID: "ou-lark-prod"})
	if err != nil {
		t.Fatal(err)
	}
	if c := check(res, "identity-center"); c.Status != StatusGo || len(c.Findings) != 0 || c.Summary != "Same organization: the 2 assignment(s) and 3 provisioned role(s) on the account are unchanged by a move between OUs." {
		t.Errorf("same-org move should be a quiet GO with counts: %+v", c)
	}

	// Source without an instance, target with one.
	noIC := fixtures.Larkspur()
	noIC.IdentityCenter = nil
	res, err = Evaluate(Input{From: noIC, To: fixtures.Fernhill(), AccountID: fixtures.LarkspurPaymentsProd, TargetOUID: fixtures.FernhillPaymentsOU})
	if err != nil {
		t.Fatal(err)
	}
	c := check(res, "identity-center")
	if c.Status != StatusGo || len(c.Findings) != 1 || c.Findings[0].Status != StatusInfo || !strings.Contains(c.Findings[0].Title, "Target organization grants access") {
		t.Errorf("no source instance should give one INFO about the target: %+v", c)
	}

	// Source with an instance, target without.
	noIC = fixtures.Fernhill()
	noIC.IdentityCenter = nil
	res, err = Evaluate(Input{From: fixtures.Larkspur(), To: noIC, AccountID: fixtures.LarkspurPaymentsProd, TargetOUID: fixtures.FernhillPaymentsOU})
	if err != nil {
		t.Fatal(err)
	}
	c = check(res, "identity-center")
	if c.Status != StatusReview || !strings.HasSuffix(c.Summary, "nothing in the target snapshot replaces them.") {
		t.Errorf("no target instance: %+v", c)
	}
	find(t, res, "identity-center", func(f Finding) bool {
		return f.Status == StatusInfo && strings.Contains(f.Title, "Target organization has no IAM Identity Center instance")
	})
	pe := find(t, res, "identity-center", func(f Finding) bool { return strings.HasPrefix(f.Title, "Permission set PaymentsEngineer") })
	if !strings.Contains(pe.Detail, "has no Identity Center instance in its snapshot") || len(pe.Evidence) != 3 {
		t.Errorf("without a target instance the finding says so and has no target evidence: %+v", pe)
	}

	// An account with nothing assigned or provisioned.
	l = fixtures.Larkspur()
	l.IdentityCenter.Assignments = nil
	for i := range l.IdentityCenter.PermissionSets {
		l.IdentityCenter.PermissionSets[i].ProvisionedAccounts = []string{"111111111111"}
	}
	res, err = Evaluate(Input{From: l, To: fixtures.Fernhill(), AccountID: fixtures.LarkspurPaymentsProd, TargetOUID: fixtures.FernhillPaymentsOU})
	if err != nil {
		t.Fatal(err)
	}
	c = check(res, "identity-center")
	if c.Status != StatusGo || !strings.Contains(c.Summary, "no assignments or provisioned roles") || len(c.Findings) != 1 || c.Findings[0].Status != StatusInfo {
		t.Errorf("nothing to lose should be GO with one INFO: %+v", c)
	}

	// Neither side.
	a, b := fixtures.Larkspur(), fixtures.Fernhill()
	a.IdentityCenter, b.IdentityCenter = nil, nil
	res, err = Evaluate(Input{From: a, To: b, AccountID: fixtures.LarkspurPaymentsProd, TargetOUID: fixtures.FernhillPaymentsOU})
	if err != nil {
		t.Fatal(err)
	}
	if c = check(res, "identity-center"); c.Status != StatusGo || len(c.Findings) != 0 || !strings.HasPrefix(c.Summary, "Neither") {
		t.Errorf("no instance anywhere should be a quiet GO: %+v", c)
	}
}

func TestIdentityCenterFernhillToLarkspur(t *testing.T) {
	res, err := Evaluate(Input{From: fixtures.Fernhill(), To: fixtures.Larkspur(), AccountID: fixtures.FernhillRetailProd, TargetOUID: fixtures.LarkspurWorkloadsOU})
	if err != nil {
		t.Fatal(err)
	}
	c := check(res, "identity-center")
	if !strings.HasPrefix(c.Summary, "3 assignment(s) across 3 permission set(s) and 3 provisioned role(s)") {
		t.Errorf("retail-prod summary wrong: %s", c.Summary)
	}
	dev := find(t, res, "identity-center", func(f Finding) bool { return strings.HasPrefix(f.Title, "Permission set BusinessUnitDeveloper") })
	if !strings.Contains(dev.Detail, "no permission set named BusinessUnitDeveloper") || !strings.Contains(dev.Detail, "identity store d-lark0000001") {
		t.Errorf("BusinessUnitDeveloper has no counterpart in Larkspur: %s", dev.Detail)
	}
	roles := find(t, res, "identity-center", func(f Finding) bool { return strings.Contains(f.Title, "AWSReservedSSO_* role(s)") })
	if !strings.Contains(roles.Detail, "/aws-reserved/sso.amazonaws.com/eu-west-1/") || strings.Contains(roles.Detail, "stale") || strings.Contains(roles.Detail, "without any assignment") {
		t.Errorf("Fernhill roles are all assigned and live in eu-west-1: %s", roles.Detail)
	}
}

func TestPermissionSetDifferences(t *testing.T) {
	l, f := fixtures.Larkspur().IdentityCenter, fixtures.Fernhill().IdentityCenter
	got := permissionSetDifferences(*l.PermissionSetByName("ReadOnlyAccess"), *f.PermissionSetByName("ReadOnlyAccess"))
	if strings.Join(got, "; ") != "managed policies only in the target: arn:aws:iam::aws:policy/job-function/ViewOnlyAccess; session duration PT8H vs PT12H" {
		t.Errorf("unexpected differences: %q", got)
	}
	same := *l.PermissionSetByName("AdministratorAccess")
	if d := permissionSetDifferences(same, same); len(d) != 0 {
		t.Errorf("a permission set must not differ from itself: %q", d)
	}
	other := same
	other.InlinePolicy = []byte(`{"Version":"2012-10-17"}`)
	other.PermissionsBoundary = "x"
	if d := permissionSetDifferences(same, other); strings.Join(d, "; ") != "only the target has an inline policy; permissions boundary none vs x" {
		t.Errorf("unexpected differences: %q", d)
	}
}
