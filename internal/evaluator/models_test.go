package evaluator

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/MrShaaba/orgshift/internal/fixtures"
	"github.com/MrShaaba/orgshift/internal/snapshot"
)

func TestRCPApplicabilityModel(t *testing.T) {
	if len(rcpServices) != 62 {
		t.Errorf("the model lists 62 services on %s, got %d", RCPModelVersion, len(rcpServices))
	}
	cases := map[string]bool{"s3:GetObject": true, "kms:Decrypt": true, "sts:AssumeRole": true, "logs:PutLogEvents": true, "ecr:BatchGetImage": true, "cognito-idp:AdminGetUser": true,
		"ec2:RunInstances": false, "iam:CreateUser": false, "dynamodb:PutItem": true, "lambda:InvokeFunction": false, "*": true, "KMS:Decrypt": true}
	for action, want := range cases {
		if got, _ := rcpApplies(action); got != want {
			t.Errorf("rcpApplies(%s) = %v want %v", action, got, want)
		}
	}
	if applies, why := rcpApplies("kms:RetireGrant"); applies || why != rcpExemptReason {
		t.Errorf("kms:RetireGrant must be exempt, got %v %q", applies, why)
	}
	if m := RCPModel(); m.Version != RCPModelVersion || m.Reference != RCPModelReference || !strings.Contains(m.Note, "62 services") {
		t.Errorf("model ref: %+v", m)
	}
}

func TestRCPCheckReportsUngovernedActionsInsteadOfSkippingSilently(t *testing.T) {
	res, err := Evaluate(Input{From: fixtures.Larkspur(), To: fixtures.Fernhill(), AccountID: fixtures.LarkspurPaymentsProd, TargetOUID: fixtures.FernhillPaymentsOU})
	if err != nil {
		t.Fatal(err)
	}
	rcp := check(res, "rcp")
	f := find(t, res, "rcp", func(f Finding) bool {
		return strings.Contains(f.Title, "services RCPs do not govern and were not evaluated against RCPs")
	})
	if f.Status != StatusInfo || !strings.Contains(f.Detail, "ec2:RunInstances") || !strings.Contains(f.Detail, RCPModelVersion) || len(f.References) == 0 {
		t.Errorf("ungoverned actions finding: %+v", f)
	}
	if strings.Contains(f.Detail, "s3:GetObject") || strings.Contains(f.Detail, "kms:Decrypt") {
		t.Errorf("governed actions must not be listed as ungoverned: %s", f.Detail)
	}
	if !strings.Contains(rcp.Summary, "applicability model "+RCPModelVersion) {
		t.Errorf("summary should name the model: %s", rcp.Summary)
	}
	// dynamodb joined the list after launch: it must be evaluated now.
	for _, f := range rcp.Findings {
		if strings.Contains(f.Title, "do not govern") && strings.Contains(f.Detail, "dynamodb:*") {
			t.Error("dynamodb is RCP-governed and must be evaluated")
		}
	}
}

// rcpOrgs builds a source organization with the moving account A, a sibling
// B that owns a KMS key behind an RCP that only admits the organization, and
// a target organization. A uses the key.
func rcpOrgs(t *testing.T, resource string) (*snapshot.Snapshot, *snapshot.Snapshot) {
	t.Helper()
	full := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`
	rcpFull := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"*","Resource":"*"}]}`
	orgOnly := `{"Version":"2012-10-17","Statement":[{"Sid":"OrgOnly","Effect":"Deny","Principal":"*","Action":"kms:*","Resource":"*","Condition":{"StringNotEqualsIfExists":{"aws:PrincipalOrgID":"o-source000001"}}}]}`
	src := &snapshot.Snapshot{
		SchemaVersion: snapshot.SchemaVersion, Source: "fixture",
		Organization: snapshot.Organization{ID: "o-source000001", ManagementAccountID: "111111111111"},
		Root:         snapshot.Root{ID: "r-src1", Name: "Root", EnabledPolicyTypes: []snapshot.PolicyType{snapshot.PolicyTypeSCP, snapshot.PolicyTypeRCP}},
		OUs:          []snapshot.OU{{ID: "ou-src-data", Name: "Data", ParentID: "r-src1"}},
		Accounts: []snapshot.Account{
			{ID: "111111111111", Name: "mgmt", ParentID: "r-src1", EnabledRegions: []string{"us-east-1"}},
			{ID: "111111111112", Name: "A", ParentID: "r-src1", EnabledRegions: []string{"us-east-1"}},
			{ID: "111111111113", Name: "B", ParentID: "ou-src-data", EnabledRegions: []string{"us-east-1"}},
		},
		Policies: []snapshot.Policy{
			{ID: "p-FullAWSAccess", Name: "FullAWSAccess", Type: snapshot.PolicyTypeSCP, AWSManaged: true, Document: json.RawMessage(full), Targets: []string{"r-src1", "ou-src-data", "111111111111", "111111111112", "111111111113"}},
			{ID: "p-RCPFullAWSAccess", Name: "RCPFullAWSAccess", Type: snapshot.PolicyTypeRCP, AWSManaged: true, Document: json.RawMessage(rcpFull), Targets: []string{"r-src1", "ou-src-data", "111111111111", "111111111112", "111111111113"}},
			{ID: "p-src-rcp1", Name: "Data-OrgOnly", Type: snapshot.PolicyTypeRCP, Document: json.RawMessage(orgOnly), Targets: []string{"ou-src-data"}},
		},
		Usage:    map[string]*snapshot.AccountUsage{"111111111112": {Actions: []snapshot.ActionInUse{{Action: "kms:Decrypt", Resource: resource}}}},
		Coverage: &snapshot.Coverage{AssertedComplete: true, AssertedBy: "test"},
	}
	dst := &snapshot.Snapshot{
		SchemaVersion: snapshot.SchemaVersion, Source: "fixture",
		Organization: snapshot.Organization{ID: "o-target000001", ManagementAccountID: "222222222221"},
		Root:         snapshot.Root{ID: "r-dst1", Name: "Root", EnabledPolicyTypes: []snapshot.PolicyType{snapshot.PolicyTypeSCP, snapshot.PolicyTypeRCP}},
		Accounts:     []snapshot.Account{{ID: "222222222221", Name: "mgmt", ParentID: "r-dst1", EnabledRegions: []string{"us-east-1"}}},
		Policies: []snapshot.Policy{
			{ID: "p-FullAWSAccess", Name: "FullAWSAccess", Type: snapshot.PolicyTypeSCP, AWSManaged: true, Document: json.RawMessage(full), Targets: []string{"r-dst1", "222222222221"}},
			{ID: "p-RCPFullAWSAccess", Name: "RCPFullAWSAccess", Type: snapshot.PolicyTypeRCP, AWSManaged: true, Document: json.RawMessage(rcpFull), Targets: []string{"r-dst1", "222222222221"}},
		},
		Coverage: &snapshot.Coverage{AssertedComplete: true, AssertedBy: "test"},
	}
	for _, s := range []*snapshot.Snapshot{src, dst} {
		if err := s.Validate(); err != nil {
			t.Fatal(err)
		}
	}
	return src, dst
}

func TestRCPOfTheResourceOwnerApplies(t *testing.T) {
	// The key stays behind in B: after the move A is an external principal to it.
	src, dst := rcpOrgs(t, "arn:aws:kms:us-east-1:111111111113:key/k1")
	res, err := Evaluate(Input{From: src, To: dst, AccountID: "111111111112", TargetOUID: "r-dst1"})
	if err != nil {
		t.Fatal(err)
	}
	f := find(t, res, "rcp", func(f Finding) bool { return f.Action == "kms:Decrypt" && f.Status == StatusNoGo })
	if !strings.Contains(f.Detail, "belongs to account 111111111113") || f.Evidence[0].Side != "source" || f.Evidence[0].PolicyName != "Data-OrgOnly" {
		t.Errorf("the owner's RCP from the source organization must be the evidence: %+v", f)
	}
	if !strings.Contains(check(res, "rcp").Summary, "evaluated against the owner's RCPs") {
		t.Errorf("summary: %s", check(res, "rcp").Summary)
	}
	// Inside one organization the caller's organization does not change: nothing to report.
	res, err = Evaluate(Input{From: src, AccountID: "111111111112", TargetOUID: "ou-src-data"})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range check(res, "rcp").Findings {
		if f.Action == "kms:Decrypt" {
			t.Errorf("same-org move must not flag the owner's RCP: %+v", f)
		}
	}
	// A resource in an account neither snapshot knows: REVIEW, not GO.
	src, dst = rcpOrgs(t, "arn:aws:kms:us-east-1:999999999999:key/k1")
	res, err = Evaluate(Input{From: src, To: dst, AccountID: "111111111112", TargetOUID: "r-dst1"})
	if err != nil {
		t.Fatal(err)
	}
	f = find(t, res, "rcp", func(f Finding) bool { return strings.HasPrefix(f.Title, "RCP evaluation skipped") })
	if f.Status != StatusReview || !strings.Contains(f.Detail, "neither snapshot") {
		t.Errorf("unknown owner: %+v", f)
	}
	// A resource in the management account: RCPs do not apply there.
	src, dst = rcpOrgs(t, "arn:aws:kms:us-east-1:111111111111:key/k1")
	res, err = Evaluate(Input{From: src, To: dst, AccountID: "111111111112", TargetOUID: "r-dst1"})
	if err != nil {
		t.Fatal(err)
	}
	f = find(t, res, "rcp", func(f Finding) bool { return strings.HasPrefix(f.Title, "RCP evaluation skipped") })
	if f.Status != StatusInfo || !strings.Contains(f.Detail, "management account") {
		t.Errorf("management account exemption: %+v", f)
	}
}

// shareOrg builds one organization with a network account that shares
// resources with the Workloads OU, and a workload account in that OU that
// moves to the root; opts tweak the share and the usage list.
type shareCase struct {
	types    []string
	actions  []string
	retain   bool
	external bool
	toAcct   bool // address the share to the account instead of the OU
}

func shareOrg(t *testing.T, c shareCase) *snapshot.Snapshot {
	t.Helper()
	full := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`
	principal := "arn:aws:organizations::111111111111:ou/o-share0000001/ou-shr-work"
	if c.toAcct {
		principal = "111111111113"
	}
	var res []snapshot.SharedResource
	for i, typ := range c.types {
		res = append(res, snapshot.SharedResource{ARN: "arn:aws:ec2:us-east-1:111111111112:thing/" + string(rune('a'+i)), Type: typ})
	}
	var acts []snapshot.ActionInUse
	for _, a := range c.actions {
		acts = append(acts, snapshot.ActionInUse{Action: a})
	}
	if len(acts) == 0 {
		acts = []snapshot.ActionInUse{{Action: "s3:GetObject"}}
	}
	s := &snapshot.Snapshot{
		SchemaVersion: snapshot.SchemaVersion, Source: "fixture",
		Organization: snapshot.Organization{ID: "o-share0000001", ManagementAccountID: "111111111111"},
		Root:         snapshot.Root{ID: "r-shr1", Name: "Root", EnabledPolicyTypes: []snapshot.PolicyType{snapshot.PolicyTypeSCP}},
		OUs:          []snapshot.OU{{ID: "ou-shr-work", Name: "Workloads", ParentID: "r-shr1"}},
		Accounts: []snapshot.Account{
			{ID: "111111111111", Name: "mgmt", ParentID: "r-shr1", EnabledRegions: []string{"us-east-1"}},
			{ID: "111111111112", Name: "network", ParentID: "r-shr1", EnabledRegions: []string{"us-east-1"}},
			{ID: "111111111113", Name: "workload", ParentID: "ou-shr-work", EnabledRegions: []string{"us-east-1"}, JoinedMethod: "INVITED"},
		},
		Policies: []snapshot.Policy{{ID: "p-FullAWSAccess", Name: "FullAWSAccess", Type: snapshot.PolicyTypeSCP, AWSManaged: true, Document: json.RawMessage(full), Targets: []string{"r-shr1", "ou-shr-work", "111111111111", "111111111112", "111111111113"}}},
		ResourceShares: []snapshot.ResourceShare{{ARN: "arn:aws:ram:us-east-1:111111111112:resource-share/net", Name: "net", OwnerAccountID: "111111111112", Status: "ACTIVE",
			AllowExternalPrincipals: c.external, RetainSharingOnAccountLeave: c.retain, Principals: []string{principal}, Resources: res}},
		Usage:    map[string]*snapshot.AccountUsage{"111111111113": {Actions: acts}},
		Coverage: &snapshot.Coverage{AssertedComplete: true, AssertedBy: "test"},
	}
	if err := s.Validate(); err != nil {
		t.Fatal(err)
	}
	return s
}

func lostShare(t *testing.T, res *Result) Finding {
	t.Helper()
	return find(t, res, "ram", func(f Finding) bool { return strings.Contains(f.Title, "is lost") })
}

func TestRAMBehaviourModel(t *testing.T) {
	// A transit gateway share whose attachments keep working: REVIEW with the documented behaviour.
	s := shareOrg(t, shareCase{types: []string{"ec2:TransitGateway"}})
	res, err := Evaluate(Input{From: s, AccountID: "111111111113", TargetOUID: "r-shr1"})
	if err != nil {
		t.Fatal(err)
	}
	f := lostShare(t, res)
	if f.Status != StatusReview || !strings.Contains(f.Detail, "existing transit gateway attachments remain functional") || !strings.Contains(strings.Join(f.References, " "), "transit-gateway-unshare") {
		t.Errorf("TGW loss should be REVIEW with the documented behaviour and reference: %+v", f)
	}
	if res.Verdict != StatusReview {
		t.Errorf("verdict %s", res.Verdict)
	}
	// The same share when the account creates attachments: a declared operation needs the share.
	s = shareOrg(t, shareCase{types: []string{"ec2:TransitGateway"}, actions: []string{"ec2:CreateTransitGatewayVpcAttachment"}})
	res, _ = Evaluate(Input{From: s, AccountID: "111111111113", TargetOUID: "r-shr1"})
	if f = lostShare(t, res); f.Status != StatusNoGo || !strings.Contains(f.Detail, "uses ec2:CreateTransitGatewayVpcAttachment, which needs the share") {
		t.Errorf("declared dependency should be NO-GO: %+v", f)
	}
	// A service-wide usage entry is not a declared dependency.
	s = shareOrg(t, shareCase{types: []string{"ec2:TransitGateway"}, actions: []string{"ec2:*"}})
	res, _ = Evaluate(Input{From: s, AccountID: "111111111113", TargetOUID: "r-shr1"})
	if f = lostShare(t, res); f.Status != StatusReview || !strings.Contains(f.Detail, "service-wide entry") {
		t.Errorf("wildcard usage should stay REVIEW with a note: %+v", f)
	}
	// Resolver rules stop answering at once.
	s = shareOrg(t, shareCase{types: []string{"route53resolver:ResolverRule"}})
	res, _ = Evaluate(Input{From: s, AccountID: "111111111113", TargetOUID: "r-shr1"})
	if f = lostShare(t, res); f.Status != StatusNoGo || !strings.Contains(f.Detail, "traffic is affected at once") {
		t.Errorf("Resolver rule loss should be NO-GO: %+v", f)
	}
	// Prefix lists: not verified, so REVIEW that says so.
	s = shareOrg(t, shareCase{types: []string{"ec2:PrefixList"}})
	res, _ = Evaluate(Input{From: s, AccountID: "111111111113", TargetOUID: "r-shr1"})
	if f = lostShare(t, res); f.Status != StatusReview || !strings.Contains(f.Detail, "not verified against the service documentation") {
		t.Errorf("unverified type: %+v", f)
	}
	// Subnets: data plane continues; RunInstances in use is potentially affected.
	s = shareOrg(t, shareCase{types: []string{"ec2:Subnet"}, actions: []string{"ec2:RunInstances"}})
	res, _ = Evaluate(Input{From: s, AccountID: "111111111113", TargetOUID: "r-shr1"})
	if f = lostShare(t, res); f.Status != StatusReview || !strings.Contains(f.Detail, "Potentially affected: ec2:RunInstances") {
		t.Errorf("subnet loss: %+v", f)
	}
	if m := RAMModel(); m.Version != RAMModelVersion || !strings.Contains(m.Note, "RetainSharingOnAccountLeaveOrganization") {
		t.Errorf("model ref: %+v", m)
	}
}

func TestDirectSharesAcrossOrganizations(t *testing.T) {
	other := &snapshot.Snapshot{
		SchemaVersion: snapshot.SchemaVersion, Source: "fixture",
		Organization: snapshot.Organization{ID: "o-other0000001", ManagementAccountID: "222222222221"},
		Root:         snapshot.Root{ID: "r-oth1", Name: "Root", EnabledPolicyTypes: []snapshot.PolicyType{snapshot.PolicyTypeSCP}},
		Accounts:     []snapshot.Account{{ID: "222222222221", Name: "mgmt", ParentID: "r-oth1"}},
		Policies: []snapshot.Policy{{ID: "p-FullAWSAccess", Name: "FullAWSAccess", Type: snapshot.PolicyTypeSCP, AWSManaged: true,
			Document: json.RawMessage(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`), Targets: []string{"r-oth1", "222222222221"}}},
		Coverage: &snapshot.Coverage{AssertedComplete: true, AssertedBy: "test"},
	}
	if err := other.Validate(); err != nil {
		t.Fatal(err)
	}
	// Addressed to the account, no retain flag: RAM ends access when the account leaves.
	s := shareOrg(t, shareCase{types: []string{"ec2:TransitGateway"}, toAcct: true, external: true})
	res, err := Evaluate(Input{From: s, To: other, AccountID: "111111111113", TargetOUID: "r-oth1"})
	if err != nil {
		t.Fatal(err)
	}
	f := lostShare(t, res)
	if !strings.Contains(f.Detail, "addressed to the account ID") || !strings.Contains(f.Detail, "RetainSharingOnAccountLeaveOrganization") {
		t.Errorf("direct share without retain: %+v", f)
	}
	// With the retain flag the share survives, as an invitation.
	s = shareOrg(t, shareCase{types: []string{"ec2:TransitGateway"}, toAcct: true, external: true, retain: true})
	res, _ = Evaluate(Input{From: s, To: other, AccountID: "111111111113", TargetOUID: "r-oth1"})
	f = find(t, res, "ram", func(f Finding) bool { return strings.Contains(f.Title, "keeps reaching the account") })
	if f.Status != StatusInfo || !strings.Contains(check(res, "ram").Summary, "1 share(s) kept") {
		t.Errorf("retained share: %+v / %s", f, check(res, "ram").Summary)
	}
	// Subnets cannot be re-shared across organizations.
	s = shareOrg(t, shareCase{types: []string{"ec2:Subnet"}})
	res, _ = Evaluate(Input{From: s, To: other, AccountID: "111111111113", TargetOUID: "r-oth1"})
	if f = lostShare(t, res); !strings.Contains(f.Detail, "can only be shared inside one organization") {
		t.Errorf("org-only note missing: %s", f.Detail)
	}
}

func TestCrossOrgConstraintsFromTheRemovalRules(t *testing.T) {
	l, f := fixtures.Larkspur(), fixtures.Fernhill()
	// Delegated administration blocks the removal outright.
	res, err := Evaluate(Input{From: l, To: f, AccountID: "111111111113", TargetOUID: "ou-fern-core"})
	if err != nil {
		t.Fatal(err)
	}
	da := find(t, res, "org-services", func(f Finding) bool {
		return strings.HasPrefix(f.Title, "Account is the delegated administrator for guardduty")
	})
	if da.Status != StatusNoGo || !strings.Contains(da.Detail, "RemoveAccountFromOrganization") || len(da.References) == 0 {
		t.Errorf("delegated admin should be a documented blocker: %+v", da)
	}
	// Tags on the account are deleted; the role Organizations created stays.
	find(t, res, "org-services", func(f Finding) bool {
		return strings.Contains(f.Title, "tag(s) on the account are deleted") && f.Status == StatusInfo
	})
	find(t, res, "org-services", func(f Finding) bool {
		return strings.Contains(f.Title, "IAM role Organizations created") && f.Status == StatusInfo
	})

	// A freshly created account cannot leave for four days.
	young := fixtures.Larkspur()
	for i := range young.Accounts {
		if young.Accounts[i].ID == fixtures.LarkspurPaymentsProd {
			young.Accounts[i].JoinedAt = "2025-12-30T12:00:00Z" // snapshot generated 2026-01-01
		}
	}
	res, err = Evaluate(Input{From: young, To: f, AccountID: fixtures.LarkspurPaymentsProd, TargetOUID: fixtures.FernhillPaymentsOU})
	if err != nil {
		t.Fatal(err)
	}
	age := find(t, res, "org-services", func(f Finding) bool { return strings.HasPrefix(f.Title, "The account was created") })
	if age.Status != StatusNoGo || !strings.Contains(age.Detail, "2026-01-03T12:00:00Z") {
		t.Errorf("young account: %+v", age)
	}
	// Unknown creation date: REVIEW. Invited accounts: nothing.
	unknown := fixtures.Larkspur()
	for i := range unknown.Accounts {
		unknown.Accounts[i].JoinedAt = ""
	}
	res, _ = Evaluate(Input{From: unknown, To: f, AccountID: fixtures.LarkspurPaymentsProd, TargetOUID: fixtures.FernhillPaymentsOU})
	if a := find(t, res, "org-services", func(f Finding) bool { return strings.Contains(f.Title, "creation date is not in the snapshot") }); a.Status != StatusReview {
		t.Errorf("unknown date: %+v", a)
	}
	invited := fixtures.Larkspur()
	for i := range invited.Accounts {
		invited.Accounts[i].JoinedMethod, invited.Accounts[i].JoinedAt = "INVITED", "2025-12-31T00:00:00Z"
	}
	res, _ = Evaluate(Input{From: invited, To: f, AccountID: fixtures.LarkspurPaymentsProd, TargetOUID: fixtures.FernhillPaymentsOU})
	for _, fd := range check(res, "org-services").Findings {
		if strings.HasPrefix(fd.Title, "The account was created") || strings.Contains(fd.Title, "IAM role Organizations created") {
			t.Errorf("invited accounts are not subject to the four-day rule or the created role: %+v", fd)
		}
	}
	// Same organization: none of this applies.
	res, _ = Evaluate(Input{From: young, AccountID: fixtures.LarkspurPaymentsProd, TargetOUID: "ou-lark-dev"})
	if n := len(check(res, "org-services").Findings); n != 0 {
		t.Errorf("same-org move should have no org-services findings, got %d", n)
	}
}

func TestControlTowerAutoEnrollmentBranches(t *testing.T) {
	auto := fixtures.Fernhill()
	auto.ControlTower.AutoEnrollment = snapshot.AutoEnrollmentEnabled
	// Out of a registered OU: unenrolled automatically.
	res, err := Evaluate(Input{From: auto, AccountID: fixtures.FernhillRetailProd, TargetOUID: fixtures.FernhillSandboxOU})
	if err != nil {
		t.Fatal(err)
	}
	f := find(t, res, "control-tower", func(f Finding) bool { return strings.HasPrefix(f.Title, "Moving out of the registered OU") })
	if !strings.Contains(f.Detail, "auto-enrollment on") || !strings.Contains(f.Detail, "removes the deployed baselines") || !strings.Contains(strings.Join(f.References, " "), "account-auto-enrollment") {
		t.Errorf("auto-enrollment wording: %+v", f)
	}
	// Between registered OUs with different controls: handled by auto-enrollment, drift possible.
	res, err = Evaluate(Input{From: auto, AccountID: "222222222226", TargetOUID: fixtures.FernhillRetailOU})
	if err != nil {
		t.Fatal(err)
	}
	f = find(t, res, "control-tower", func(f Finding) bool { return strings.Contains(f.Title, "is handled by auto-enrollment") })
	if f.Status != StatusReview || !strings.Contains(f.Detail, "different controls") {
		t.Errorf("registered-to-registered with auto-enrollment: %+v", f)
	}
	for _, fd := range check(res, "control-tower").Findings {
		if strings.Contains(fd.Title, "has to go through Control Tower") {
			t.Error("auto-enrollment must not demand the Account Factory flow")
		}
	}
	// Unknown setting: the finding says the snapshot does not record it.
	unknown := fixtures.Fernhill()
	unknown.ControlTower.AutoEnrollment = ""
	res, _ = Evaluate(Input{From: unknown, AccountID: fixtures.FernhillRetailProd, TargetOUID: fixtures.FernhillSandboxOU})
	f = find(t, res, "control-tower", func(f Finding) bool { return strings.HasPrefix(f.Title, "Moving out of the registered OU") })
	if !strings.Contains(f.Detail, "does not record whether the landing zone has auto-enrollment") {
		t.Errorf("unknown setting wording: %s", f.Detail)
	}
	// Into a registered OU with auto-enrollment on: no Account Factory step needed.
	res, _ = Evaluate(Input{From: fixtures.Larkspur(), To: auto, AccountID: fixtures.LarkspurPaymentsProd, TargetOUID: fixtures.FernhillPaymentsOU})
	f = find(t, res, "control-tower", func(f Finding) bool { return strings.Contains(f.Title, "has to be enrolled") })
	if !strings.Contains(f.Detail, "without an Account Factory step") {
		t.Errorf("enrolment with auto-enrollment: %s", f.Detail)
	}
}

func TestEnrolmentIsReadNotAssumedWhenCollected(t *testing.T) {
	// The enrolled list is empty but was collected (empty coverage): accounts in registered OUs are NOT enrolled.
	f := fixtures.Fernhill()
	f.ControlTower.EnrolledAccounts = nil
	res, err := Evaluate(Input{From: f, AccountID: fixtures.FernhillRetailProd, TargetOUID: fixtures.FernhillSandboxOU})
	if err != nil {
		t.Fatal(err)
	}
	for _, fd := range check(res, "control-tower").Findings {
		if strings.HasPrefix(fd.Title, "Moving out of the registered OU") {
			t.Errorf("an account absent from a collected enrolled list is not enrolled: %+v", fd)
		}
	}
	// Collected from baselines without product information: the provenance is reported as unknown.
	f = fixtures.Fernhill()
	for i := range f.ControlTower.EnrolledAccounts {
		f.ControlTower.EnrolledAccounts[i] = snapshot.EnrolledAccount{AccountID: f.ControlTower.EnrolledAccounts[i].AccountID, Source: snapshot.EnrolledFromBaseline, Status: "SUCCEEDED", ParentOUID: f.ControlTower.EnrolledAccounts[i].ParentOUID}
	}
	res, _ = Evaluate(Input{From: f, AccountID: fixtures.FernhillRetailProd, TargetOUID: fixtures.FernhillSandboxOU})
	find(t, res, "control-tower", func(fd Finding) bool {
		return strings.HasPrefix(fd.Title, "Whether Account Factory vended the account is not recorded") && fd.Status == StatusInfo
	})
	find(t, res, "control-tower", func(fd Finding) bool { return strings.HasPrefix(fd.Title, "Moving out of the registered OU") })
	// Hand-written snapshot without an enrolled list and without coverage: the old assumption, flagged.
	f = fixtures.Fernhill()
	f.ControlTower.EnrolledAccounts = nil
	f.Coverage = nil
	res, _ = Evaluate(Input{From: f, AccountID: fixtures.FernhillRetailProd, TargetOUID: fixtures.FernhillSandboxOU})
	fd := find(t, res, "control-tower", func(fd Finding) bool { return strings.HasPrefix(fd.Title, "Moving out of the registered OU") })
	if !strings.Contains(fd.Detail, "assumed enrolled because its OU is registered") {
		t.Errorf("assumption must be stated: %s", fd.Detail)
	}
}
