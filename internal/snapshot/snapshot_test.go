package snapshot

import (
	"encoding/json"
	"strings"
	"testing"
)

func minimal() *Snapshot {
	return &Snapshot{
		SchemaVersion: SchemaVersion,
		Organization:  Organization{ID: "o-test00000001", ManagementAccountID: "111111111111"},
		Root:          Root{ID: "r-test", Name: "Root", EnabledPolicyTypes: []PolicyType{PolicyTypeSCP}},
		OUs: []OU{
			{ID: "ou-test-aaaa", Name: "Workloads", ParentID: "r-test"},
			{ID: "ou-test-bbbb", Name: "Prod", ParentID: "ou-test-aaaa"},
		},
		Accounts: []Account{
			{ID: "111111111111", Name: "management", ParentID: "r-test"},
			{ID: "111111111112", Name: "prod-app", ParentID: "ou-test-bbbb"},
		},
		Policies: []Policy{
			{ID: "p-FullAWSAccess", Name: "FullAWSAccess", Type: PolicyTypeSCP, AWSManaged: true,
				Document: json.RawMessage(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`),
				Targets:  []string{"r-test", "ou-test-aaaa", "ou-test-bbbb", "111111111111", "111111111112"}},
		},
	}
}

func TestRoundTrip(t *testing.T) {
	s := minimal()
	data, err := Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	back, err := Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	if back.Organization.ID != s.Organization.ID || len(back.Accounts) != 2 {
		t.Fatalf("round trip lost data: %+v", back)
	}
}

func TestPath(t *testing.T) {
	ix := minimal().Index()
	p := ix.PathTo("111111111112")
	if got := PathString(p); got != "Root / Workloads / Prod / prod-app" {
		t.Fatalf("unexpected path %q", got)
	}
	if ids := OUPath(p); len(ids) != 3 || ids[2] != "ou-test-bbbb" {
		t.Fatalf("unexpected ou path %v", ids)
	}
	if ix.PathTo("nope") != nil {
		t.Fatal("unknown id should have no path")
	}
	acct, _ := ix.Node("111111111112")
	under := ix.PathUnder("ou-test-aaaa", acct)
	if got := PathString(under); got != "Root / Workloads / prod-app" {
		t.Fatalf("unexpected hypothetical path %q", got)
	}
}

func TestValidateRejectsBrokenReferences(t *testing.T) {
	cases := map[string]func(*Snapshot){
		"missing parent":    func(s *Snapshot) { s.Accounts[1].ParentID = "ou-missing" },
		"bad account id":    func(s *Snapshot) { s.Accounts[1].ID = "12345" },
		"dangling target":   func(s *Snapshot) { s.Policies[0].Targets = append(s.Policies[0].Targets, "ou-nope") },
		"bad policy json":   func(s *Snapshot) { s.Policies[0].Document = json.RawMessage(`{`) },
		"unknown type":      func(s *Snapshot) { s.Policies[0].Type = "FANCY_POLICY" },
		"usage non-account": func(s *Snapshot) { s.Usage = map[string]*AccountUsage{"ou-test-aaaa": {}} },
		"creation date":     func(s *Snapshot) { s.Organization.CreatedAt = "last spring" },
		"ou cycle": func(s *Snapshot) {
			s.OUs[0].ParentID = "ou-test-bbbb"
		},
	}
	for name, mutate := range cases {
		s := minimal()
		mutate(s)
		if err := s.Validate(); err == nil {
			t.Errorf("%s: expected a validation error", name)
		}
	}
}

func TestParseRejectsNewerSchemaAndUnknownFields(t *testing.T) {
	if _, err := Parse([]byte(`{"schema_version": 99}`)); err == nil || !strings.Contains(err.Error(), "newer") {
		t.Fatalf("expected newer-version error, got %v", err)
	}
	if _, err := Parse([]byte(`{"schema_version": 1, "organization": {"id":"o-x"}, "root": {"id":"r-x"}, "bogus": 1}`)); err == nil {
		t.Fatal("expected unknown field error")
	}
	if _, err := Parse([]byte(`{}`)); err == nil {
		t.Fatal("expected missing schema version error")
	}
}

func TestControlTowerValidationAndLookups(t *testing.T) {
	s := minimal()
	s.Policies = append(s.Policies, Policy{ID: "p-gr", Name: GuardrailPolicyPrefix + "abcdef", Type: PolicyTypeSCP,
		Document: json.RawMessage(`{"Version":"2012-10-17","Statement":[]}`), Targets: []string{"ou-test-aaaa"}})
	s.ControlTower = &ControlTower{
		LandingZoneARN: "arn:aws:controltower:us-east-1:111111111111:landingzone/TEST", AuditAccountID: "111111111112",
		RegisteredOUs:    []RegisteredOU{{OUID: "ou-test-aaaa", Status: "SUCCEEDED"}},
		EnrolledAccounts: []EnrolledAccount{{AccountID: "111111111112", VendedByAccountFactory: true}},
		EnabledControls: []EnabledControl{
			{ControlIdentifier: "arn:aws:controltower:us-east-1::control/AWS-GR_ENCRYPTED_VOLUMES", Behavior: ControlDetective, TargetOUID: "ou-test-aaaa"},
			{ControlIdentifier: "arn:aws:controltower:us-east-1::control/AWS-GR_CONFIG_ENABLED", Behavior: ControlPreventive, TargetOUID: "ou-test-bbbb"},
		},
	}
	if err := s.Validate(); err != nil {
		t.Fatalf("valid Control Tower block rejected: %v", err)
	}
	data, _ := Marshal(s)
	back, err := Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	ct := back.ControlTower
	if ct == nil || ct.RegisteredOU("ou-test-aaaa") == nil || ct.RegisteredOU("ou-test-bbbb") != nil {
		t.Fatalf("registered OU lookup wrong: %+v", ct)
	}
	if e := ct.Enrolled("111111111112"); e == nil || !e.VendedByAccountFactory || ct.Enrolled("111111111111") != nil {
		t.Fatalf("enrolment lookup wrong: %+v", ct.EnrolledAccounts)
	}
	along := ct.ControlsAlong(back.Index().PathTo("111111111112"))
	if len(along) != 2 || ControlShortID(along[0].ControlIdentifier) != "AWS-GR_ENCRYPTED_VOLUMES" || along[1].TargetOUID != "ou-test-bbbb" {
		t.Fatalf("controls along the path wrong: %+v", along)
	}
	if !back.Policies[1].ControlTowerManaged() || back.Policies[0].ControlTowerManaged() {
		t.Fatal("guardrail detection by name prefix is wrong")
	}
	var nilCT *ControlTower
	if nilCT.RegisteredOU("x") != nil || nilCT.Enrolled("x") != nil || nilCT.ControlsAlong(nil) != nil {
		t.Fatal("nil Control Tower must behave as absent")
	}

	bad := minimal()
	bad.ControlTower = &ControlTower{
		AuditAccountID:   "ou-test-aaaa",
		RegisteredOUs:    []RegisteredOU{{OUID: "111111111112"}, {OUID: "ou-test-aaaa"}, {OUID: "ou-test-aaaa"}},
		EnrolledAccounts: []EnrolledAccount{{AccountID: "ou-test-aaaa"}},
		EnabledControls:  []EnabledControl{{TargetOUID: "r-test", Behavior: "SOMETIMES"}},
	}
	err = bad.Validate()
	if err == nil {
		t.Fatal("expected validation errors")
	}
	for _, want := range []string{"shared account", "is not an ou", "listed twice", "is not an account", "no control_identifier", "is not an ou", "unknown behavior"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("validation error should mention %q, got:\n%v", want, err)
		}
	}
}

func TestControlLabel(t *testing.T) {
	cases := map[string]EnabledControl{
		"AWS-GR_ENCRYPTED_VOLUMES": {ControlIdentifier: "arn:aws:controltower:eu-west-1::control/AWS-GR_ENCRYPTED_VOLUMES", Name: "Detect whether encryption is enabled"},
		"CT.S3.PR.1":               {ControlIdentifier: "arn:aws:controlcatalog:::control/7f3kq9x2m1pz8r4v6t0nb5cy", Name: "CT.S3.PR.1: Require block public access"},
		"Some long catalog name":   {ControlIdentifier: "arn:aws:controlcatalog:::control/7f3kq9x2m1pz8r4v6t0nb5cy", Name: "Some long catalog name"},
		"7f3kq9x2m1pz8r4v6t0nb5cy": {ControlIdentifier: "arn:aws:controlcatalog:::control/7f3kq9x2m1pz8r4v6t0nb5cy"},
	}
	for want, c := range cases {
		if got := c.Label(); got != want {
			t.Errorf("Label(%+v) = %q, want %q", c, got, want)
		}
	}
}

func TestIdentityCenterValidationAndLookups(t *testing.T) {
	s := minimal()
	const admin, ro = "arn:aws:sso:::permissionSet/ssoins-test/ps-admin", "arn:aws:sso:::permissionSet/ssoins-test/ps-readonly"
	s.IdentityCenter = &IdentityCenter{
		InstanceARN: "arn:aws:sso:::instance/ssoins-test", IdentityStoreID: "d-test", Region: "us-east-1", OwnerAccountID: "111111111111",
		PermissionSets: []PermissionSet{
			{ARN: admin, Name: "AdministratorAccess", ManagedPolicies: []string{"arn:aws:iam::aws:policy/AdministratorAccess"}},
			{ARN: ro, Name: "ReadOnlyAccess", ProvisionedAccounts: []string{"111111111112"}},
		},
		Assignments: []AccountAssignment{
			{AccountID: "111111111112", PermissionSetARN: admin, PrincipalType: PrincipalGroup, PrincipalID: "g-1", PrincipalName: "Admins"},
			{AccountID: "111111111111", PermissionSetARN: admin, PrincipalType: PrincipalUser, PrincipalID: "u-1"},
		},
	}
	if err := s.Validate(); err != nil {
		t.Fatalf("valid Identity Center block rejected: %v", err)
	}
	data, _ := Marshal(s)
	back, err := Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	ic := back.IdentityCenter
	if ic.PermissionSet(ro) == nil || ic.PermissionSetByName("AdministratorAccess") == nil || ic.PermissionSetByName("Nope") != nil {
		t.Fatalf("permission set lookups wrong: %+v", ic.PermissionSets)
	}
	if got := ic.AssignmentsFor("111111111112"); len(got) != 1 || got[0].Label() != "group Admins" {
		t.Fatalf("assignments wrong: %+v", got)
	}
	if got := ic.AssignmentsFor("111111111111"); len(got) != 1 || got[0].Label() != "user u-1" {
		t.Fatalf("label should fall back to the id: %+v", got)
	}
	// Provisioned: ReadOnlyAccess by its explicit list, AdministratorAccess by assignment.
	prov := ic.ProvisionedIn("111111111112")
	if len(prov) != 2 || prov[0].ReservedRolePattern() != "AWSReservedSSO_AdministratorAccess_*" || prov[1].Name != "ReadOnlyAccess" {
		t.Fatalf("provisioned lookup wrong: %+v", prov)
	}
	if got := ic.ProvisionedIn("111111111111"); len(got) != 1 || got[0].Name != "AdministratorAccess" {
		t.Fatalf("an explicit provisioned list must not be widened by assignments elsewhere: %+v", got)
	}
	if ic.ReservedRolePath() != "/aws-reserved/sso.amazonaws.com/us-east-1/" {
		t.Fatal(ic.ReservedRolePath())
	}
	var nilIC *IdentityCenter
	if nilIC.PermissionSet("x") != nil || nilIC.AssignmentsFor("x") != nil || nilIC.ProvisionedIn("x") != nil || nilIC.ReservedRolePath() != "/aws-reserved/sso.amazonaws.com/<region>/" {
		t.Fatal("nil Identity Center must behave as absent")
	}

	bad := minimal()
	bad.IdentityCenter = &IdentityCenter{
		OwnerAccountID: "ou-test-aaaa",
		PermissionSets: []PermissionSet{{ARN: admin, Name: "A"}, {ARN: admin, Name: "A", InlinePolicy: json.RawMessage(`{`), ProvisionedAccounts: []string{"r-test"}}},
		Assignments:    []AccountAssignment{{AccountID: "ou-test-aaaa", PermissionSetARN: "arn:nope", PrincipalType: "ROBOT"}},
	}
	err = bad.Validate()
	if err == nil {
		t.Fatal("expected validation errors")
	}
	for _, want := range []string{"instance_arn is required", "owner account", "listed twice", "used twice", "not valid JSON", "is not an account", "not in permission_sets", "unknown type", "no principal_id"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("validation error should mention %q, got:\n%v", want, err)
		}
	}
}
