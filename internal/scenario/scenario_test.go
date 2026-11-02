package scenario

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/MrShaaba/orgshift/internal/evaluator"
	"github.com/MrShaaba/orgshift/internal/fixtures"
	"github.com/MrShaaba/orgshift/internal/snapshot"
)

var update = flag.Bool("update", false, "rewrite golden files")

func mustParse(t *testing.T, doc string) *Scenario {
	t.Helper()
	sc, err := Parse([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	return sc
}

func stage(t *testing.T, rep *Report, id string) StageResult {
	t.Helper()
	for _, st := range rep.Stages {
		if st.ID == id {
			return st
		}
	}
	t.Fatalf("no stage %s", id)
	return StageResult{}
}

func layer(st StageResult, name string) LayerChange {
	for _, l := range st.Layers {
		if l.Layer == name {
			return l
		}
	}
	return LayerChange{}
}

func hasFinding(fs []evaluator.Finding, substr string) *evaluator.Finding {
	for i := range fs {
		if strings.Contains(fs[i].Title, substr) {
			return &fs[i]
		}
	}
	return nil
}

func transitionFinding(res *evaluator.Result, check, substr string) *evaluator.Finding {
	if res == nil {
		return nil
	}
	for _, c := range res.Checks {
		if c.ID != check {
			continue
		}
		if f := hasFinding(c.Findings, substr); f != nil {
			return f
		}
	}
	return nil
}

func TestExampleAndFixturesParse(t *testing.T) {
	ex := mustParse(t, Example)
	if ex.Strategy != StrategyTransfer || len(ex.Stages) != 7 || len(ex.CriticalOperations) != 2 || len(ex.Proposed.OUs) != 1 || len(ex.Proposed.Policies) != 1 || len(ex.Proposed.ResourceShares) != 1 {
		t.Errorf("example: %+v", ex)
	}
	if !json.Valid(ex.Proposed.Policies[0].DocumentJSON) || !strings.Contains(string(ex.Proposed.Policies[0].DocumentJSON), `"Effect":"Deny"`) {
		t.Errorf("YAML document should become JSON: %s", ex.Proposed.Policies[0].DocumentJSON)
	}
	if len(ex.Declared()) != 2 || ex.Declared()[0].Note == "" {
		t.Errorf("declared operations: %+v", ex.Declared())
	}
	for name, doc := range fixtures.ScenarioFiles() {
		if _, err := Parse([]byte(doc)); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	data, err := ex.JSON()
	if err != nil {
		t.Fatal(err)
	}
	again, err := Parse(data)
	if err != nil {
		t.Fatalf("JSON round trip: %v", err)
	}
	if len(again.Stages) != 7 {
		t.Errorf("round trip lost stages: %d", len(again.Stages))
	}
	// A JSON string document is accepted too.
	doc := strings.Replace(Example, "document:                     # a YAML mapping or a JSON string\n        Version: \"2012-10-17\"\n        Statement:\n          - Sid: NoIAMUsersAtAll\n            Effect: Deny\n            Action: [iam:CreateUser, iam:CreateAccessKey]\n            Resource: \"*\"",
		`document: '{"Version":"2012-10-17","Statement":[{"Sid":"X","Effect":"Deny","Action":"iam:CreateUser","Resource":"*"}]}'`, 1)
	if sc := mustParse(t, doc); !strings.Contains(string(sc.Proposed.Policies[0].DocumentJSON), `"Sid":"X"`) {
		t.Errorf("string document: %s", sc.Proposed.Policies[0].DocumentJSON)
	}
}

func TestValidationErrors(t *testing.T) {
	base := "schema_version: 1\nname: x\naccount: \"111111111115\"\nstages:\n  - id: a\n    title: A\n"
	cases := map[string]struct{ doc, want string }{
		"version":     {"name: x\naccount: \"111111111115\"\nstages: [{id: a, title: A}]\n", "schema_version is required"},
		"account":     {strings.Replace(base, "111111111115", "abc", 1), "is not a 12-digit account ID"},
		"strategy":    {base + "strategy: teleport\n", "strategy must be"},
		"no stages":   {"schema_version: 1\nname: x\naccount: \"111111111115\"\n", "at least one stage"},
		"dup stage":   {base + "  - id: a\n    title: B\n", "is used twice"},
		"org":         {base + "  - id: b\n    title: B\n    membership: {organization: elsewhere}\n", "membership.organization must be"},
		"share ref":   {base + "  - id: b\n    title: B\n    network: {recreate_shares: [nope]}\n", "is not a proposed resource share"},
		"op action":   {base + "critical_operations: [{action: bad, reason: r}]\n", "is not service:Action"},
		"op reason":   {base + "critical_operations: [{action: s3:GetObject}]\n", "needs a reason"},
		"policy doc":  {base + "proposed:\n  policies:\n    - id: p\n      name: P\n      type: SERVICE_CONTROL_POLICY\n      document: {Version: \"2012-10-17\", Statement: [{Effect: Deny, Resource: \"*\"}]}\n", "proposed.policies[0] (p)"},
		"policy type": {base + "proposed:\n  policies:\n    - id: p\n      name: P\n      type: WEIRD\n      document: {}\n", "unknown type"},
		"ou":          {base + "proposed:\n  organizational_units:\n    - id: ou-x\n", "needs a name"},
		"unknown key": {base + "stage: nope\n", "field stage not found"},
	}
	for name, c := range cases {
		_, err := Parse([]byte(c.doc))
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: want %q, got %v", name, c.want, err)
		}
	}
}

func TestReferencesAreCheckedAgainstTheSnapshots(t *testing.T) {
	l, f := fixtures.Larkspur(), fixtures.Fernhill()
	sc := mustParse(t, fixtures.PaymentsToFernhillStaged)
	sc.Stages[3].Placement.ParentID = "ou-nowhere"
	if _, err := Run(Input{Scenario: sc, Source: l, Destination: f}); err == nil || !strings.Contains(err.Error(), "ou-nowhere") {
		t.Errorf("unknown parent: %v", err)
	}
	sc = mustParse(t, fixtures.PaymentsToFernhillStaged)
	sc.Proposed.OUs[0].ID = fixtures.FernhillPaymentsOU
	if _, err := Run(Input{Scenario: sc, Source: l, Destination: f}); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Errorf("proposed OU colliding with an existing one: %v", err)
	}
	sc = mustParse(t, fixtures.PaymentsToFernhillStaged)
	if _, err := Run(Input{Scenario: sc, Source: l}); err == nil || !strings.Contains(err.Error(), "no destination snapshot") {
		t.Errorf("destination stage without a destination: %v", err)
	}
	sc = mustParse(t, fixtures.PaymentsToFernhillStaged)
	sc.AccountID = "999999999999"
	if _, err := Run(Input{Scenario: sc, Source: l, Destination: f}); err == nil || !strings.Contains(err.Error(), "not in the source snapshot") {
		t.Errorf("unknown account: %v", err)
	}
}

func TestCrossOrgStagedScenario(t *testing.T) {
	l, f := fixtures.Larkspur(), fixtures.Fernhill()
	before, _ := json.Marshal(f)
	beforeSrc, _ := json.Marshal(l)
	sc := mustParse(t, fixtures.PaymentsToFernhillStaged)
	rep, err := Run(Input{Scenario: sc, Source: l, Destination: f, Version: "test"})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Stages) != 7 || rep.Subject.CrossOrg == false || rep.Strategy != StrategyTransfer {
		t.Fatalf("report: %+v", rep.Subject)
	}
	// The snapshots are untouched.
	after, _ := json.Marshal(f)
	afterSrc, _ := json.Marshal(l)
	if !bytes.Equal(before, after) || !bytes.Equal(beforeSrc, afterSrc) || snapshot.PathString(l.Index().PathTo(fixtures.LarkspurPaymentsProd)) != snapshot.PathString(rep.Subject.CurrentPath) {
		t.Error("the snapshots must not be modified by the run")
	}
	// Stage 1: the current state, nothing changes, the transition inventories restrictions.
	cur := stage(t, rep, "current")
	if hasFinding(cur.Findings, "Verification point") == nil || cur.Transition == nil || cur.Transition.Subject.CrossOrg {
		t.Errorf("current stage: %+v", cur.Findings)
	}
	for _, l := range cur.Layers {
		if l.Changed {
			t.Errorf("current stage changes nothing: %+v", l)
		}
	}
	// Stage 2: prerequisites re-create the share while still in Larkspur.
	pre := stage(t, rep, "prerequisites")
	if !layer(pre, LayerNetwork).Changed || layer(pre, LayerMembership).Changed || hasFinding(pre.Findings, "fernhill-payments-transit is created") == nil {
		t.Errorf("prerequisites: %+v %+v", pre.Layers, pre.Findings)
	}
	if pre.State.Organization.ID != l.Organization.ID || len(pre.State.Shares) != 1 {
		t.Errorf("prerequisites state: %+v", pre.State)
	}
	// Stage 3: entry at the root is the cross-organization transition.
	enter := stage(t, rep, "enter")
	if !layer(enter, LayerMembership).Changed || enter.Transition == nil || !enter.Transition.Subject.CrossOrg || enter.State.Organization.ID != f.Organization.ID || enter.State.ParentID != f.Root.ID {
		t.Fatalf("entry: %+v %+v", enter.Layers, enter.State)
	}
	if hasFinding(enter.Findings, "standalone") == nil || hasFinding(enter.Findings, "lands at the root") == nil {
		t.Errorf("entry findings: %+v", enter.Findings)
	}
	if f := transitionFinding(enter.Transition, "ram", "fernhill-payments-transit becomes available"); f == nil {
		t.Error("the re-created share should be available on entry")
	}
	if f := transitionFinding(enter.Transition, "org-services", "Standalone account prerequisites"); f == nil || !strings.Contains(f.Detail, "15 days") || f.Category != evaluator.CategoryPotentialImpact {
		t.Errorf("invitation facts: %+v", f)
	}
	if enter.Transition.Subject.DeclaredOperations != 4 || enter.Transition.Subject.TargetOrgPath != f.Organization.ID+"/"+f.Root.ID+"/" {
		t.Errorf("declared operations and target path: %+v", enter.Transition.Subject)
	}
	// Stage 4: the proposed Legacy OU inherits the root guardrails and carries the EU-only SCP.
	legacy := stage(t, rep, "legacy")
	if !layer(legacy, LayerPlacement).Changed || len(legacy.State.ProposedOnPath) != 1 || legacy.State.ProposedOnPath[0] != "ou-proposed-legacy" {
		t.Errorf("legacy placement: %+v %+v", legacy.Layers, legacy.State)
	}
	inh := hasFinding(legacy.Findings, "inherits")
	if inh == nil || !strings.Contains(inh.Detail, "Fernhill-Root-Guardrails") || !strings.Contains(inh.Detail, "override an inherited explicit deny") || inh.Category != evaluator.CategoryKnownRestriction || inh.Confidence != evaluator.ConfidenceHigh {
		t.Errorf("inheritance finding: %+v", inh)
	}
	// The observed attachment (no region given) is denied outside the EU by
	// the regions policy the Legacy OU carries; the declared one names
	// eu-west-1 and passes until the Payments OU forbids it altogether.
	obs := transitionFinding(legacy.Transition, "scp", "ec2:CreateTransitGatewayVpcAttachment becomes denied")
	if obs == nil || obs.Source != evaluator.SourceObserved || !strings.Contains(obs.Detail, "Fernhill-EU-Only-Regions") || strings.Contains(strings.Join(obs.Regions, ","), "eu-west-1") {
		t.Errorf("observed attachment outside the EU: %+v", obs)
	}
	// The EU-only policy attached to the proposed OU denies non-EU regions for the declared ledger restore.
	if f := transitionFinding(legacy.Transition, "scp", "rds:RestoreDBInstanceFromDBSnapshot"); f != nil {
		t.Errorf("the restore is declared for eu-west-1 only and should pass: %+v", f)
	}
	// Stage 6: enrollment into the registered Payments OU; the declared DR attachment is denied there.
	enroll := stage(t, rep, "enroll")
	if !layer(enroll, LayerGovernance).Changed || !enroll.State.Enrolled || !enroll.State.Governed {
		t.Errorf("enroll state: %+v %+v", enroll.Layers, enroll.State)
	}
	prereq := hasFinding(enroll.Findings, "Enrollment prerequisites")
	if prereq == nil || prereq.Status != evaluator.StatusReview || !strings.Contains(prereq.Detail, "declared satisfied") || !strings.Contains(prereq.Detail, "not declared (unknown)") {
		t.Errorf("enrollment prerequisites: %+v", prereq)
	}
	var declaredDenied bool
	for _, c := range enroll.Transition.Checks {
		if c.ID != "scp" {
			continue
		}
		for _, f := range c.Findings {
			if f.Action == "ec2:CreateTransitGatewayVpcAttachment" && f.Source == evaluator.SourceDeclared && f.Status == evaluator.StatusNoGo && f.Category == evaluator.CategoryDeclaredImpact && strings.Contains(f.Detail, "declared critical by the operator") && strings.Contains(f.Detail, "Fernhill-Payments-Controls") {
				declaredDenied = true
			}
		}
	}
	if !declaredDenied {
		t.Fatal("the declared DR attachment in eu-west-1 must be denied by Fernhill-Payments-Controls at the enroll stage")
	}
	if transitionFinding(enroll.Transition, "control-tower", "has to be enrolled") == nil {
		t.Error("the transition into a registered OU reports the enrollment")
	}
	// Stage 7: the tightening policy attached to the account denies the declared IAM user creation.
	tighten := stage(t, rep, "tighten")
	if !layer(tighten, LayerPlacement).Changed || !strings.Contains(layer(tighten, LayerPlacement).Summary, "attach p-proposed-tighten") {
		t.Errorf("tighten layers: %+v", tighten.Layers)
	}
	user := transitionFinding(tighten.Transition, "scp", "iam:CreateUser")
	if user == nil || user.Status != evaluator.StatusInfo {
		// iam:CreateUser is denied at the Fernhill root already (NoIAMUsers), so the tightening is a known restriction, not a new denial.
		t.Errorf("iam:CreateUser is already denied at the root: %+v", user)
	}
	if rep.Verdict != evaluator.StatusNoGo || !strings.Contains(rep.Summary, "NO-GO") {
		t.Errorf("verdict: %s %s", rep.Verdict, rep.Summary)
	}
	if len(rep.Strategies) != 2 || !rep.Strategies[0].Selected || rep.Strategies[1].Selected || len(rep.Strategies[1].Prerequisites) < 3 || !strings.Contains(rep.Strategies[1].Prerequisites[1], "assignment") {
		t.Errorf("strategies: %+v", rep.Strategies)
	}
	if len(rep.Strategies[0].Prerequisites) == 0 || len(rep.Strategies[0].Risks) == 0 {
		t.Errorf("transfer strategy should list prerequisites and risks from the entry stage: %+v", rep.Strategies[0])
	}
	if len(rep.Limitations) == 0 || len(rep.Models) != 3 {
		t.Error("limitations and models")
	}
	for _, st := range rep.Stages {
		if st.Snapshot == nil || st.Transition == nil {
			t.Errorf("stage %s lacks its state or transition", st.ID)
		}
		for _, f := range st.Findings {
			if f.Category == "" {
				t.Errorf("stage %s finding %q has no category", st.ID, f.Title)
			}
		}
	}
	golden(t, "cross-org-payments-to-fernhill-staged", rep)
}

func TestSameOrgStagedScenario(t *testing.T) {
	f := fixtures.Fernhill()
	sc := mustParse(t, fixtures.SandboxToBusinessUnitsStaged)
	rep, err := Run(Input{Scenario: sc, Source: f, Version: "test"})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Subject.CrossOrg || rep.Subject.DestinationOrg.ID != f.Organization.ID || len(rep.Stages) != 5 {
		t.Fatalf("subject: %+v", rep.Subject)
	}
	tr := stage(t, rep, "transitional")
	inh := hasFinding(tr.Findings, "inherits")
	if inh == nil || !strings.Contains(inh.Detail, "unregistered OU Transitional") || !strings.Contains(inh.Detail, "aws-guardrails-kjwqpf") || !strings.Contains(inh.Detail, "Fernhill-EU-Only-Regions") {
		t.Errorf("a proposed unregistered OU under a registered one inherits its guardrails: %+v", inh)
	}
	// Redshift is allowed in the Transitional OU (the sandbox limits no longer apply) and denied again after tightening.
	if f := transitionFinding(tr.Transition, "scp", "redshift:CreateCluster becomes allowed"); f == nil || f.Category != evaluator.CategoryInformational {
		t.Errorf("redshift becomes allowed when leaving the sandbox OU: %+v", f)
	}
	govern := stage(t, rep, "govern")
	if !govern.State.Enrolled || !govern.State.Governed || hasFinding(govern.Findings, "is registered with Control Tower") == nil {
		t.Errorf("govern: %+v %+v", govern.State, govern.Findings)
	}
	if p := hasFinding(govern.Findings, "Enrollment prerequisites"); p == nil || p.Status != evaluator.StatusInfo || p.Category != evaluator.CategoryInformational {
		t.Errorf("both prerequisites declared satisfied: %+v", p)
	}
	tighten := stage(t, rep, "tighten")
	rs := transitionFinding(tighten.Transition, "scp", "redshift:CreateCluster becomes denied")
	if rs == nil || rs.Status != evaluator.StatusNoGo || rs.Source != evaluator.SourceDeclared || !strings.Contains(rs.Detail, "declared critical by the operator") {
		t.Errorf("the declared redshift operation is denied by the tightening policy: %+v", rs)
	}
	if transitionFinding(tighten.Transition, "scp", "redshift:CreateCluster becomes denied").Category != evaluator.CategoryDeclaredImpact {
		t.Error("category")
	}
	golden(t, "same-org-fernhill-sandbox-staged", rep)
}

func TestInheritedDenyCannotBeOverriddenByAProposedAllow(t *testing.T) {
	l := fixtures.Larkspur()
	// A proposed OU under Workloads with a policy that allows everything,
	// including the region the parent denies: the inherited deny wins.
	doc := `schema_version: 1
name: override attempt
account: "111111111116"
critical_operations:
  - action: ec2:RunInstances
    regions: [sa-east-1]
    reason: a region outside the approved list
proposed:
  organizational_units:
    - id: ou-proposed-open
      name: Open
      parent: ou-lark-work
      policies: [p-proposed-allow-all]
  policies:
    - id: p-proposed-allow-all
      name: AllowEverything
      type: SERVICE_CONTROL_POLICY
      document: '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}'
stages:
  - id: move
    title: Into the open OU
    placement:
      parent: ou-proposed-open
`
	rep, err := Run(Input{Scenario: mustParse(t, doc), Source: l})
	if err != nil {
		t.Fatal(err)
	}
	st := rep.Stages[0]
	f := transitionFinding(st.Transition, "scp", "ec2:RunInstances")
	if f == nil || f.Status != evaluator.StatusInfo || !strings.Contains(f.Title, "already denied") || !strings.Contains(f.Detail, "Larkspur-Allowed-Regions") {
		t.Fatalf("the region deny inherited from Workloads must still apply under the proposed OU: %+v", f)
	}
	if inh := hasFinding(st.Findings, "inherits"); inh == nil || !strings.Contains(inh.Detail, "Larkspur-Allowed-Regions / DenyOutsideApprovedRegions") {
		t.Errorf("inheritance finding should name the inherited deny: %+v", inh)
	}
}

func TestManagementAccountCannotBeTransferred(t *testing.T) {
	l, f := fixtures.Larkspur(), fixtures.Fernhill()
	doc := `schema_version: 1
name: move the management account
account: "222222222221"
stages:
  - id: enter
    title: Into Larkspur
    membership:
      organization: destination
`
	// Fernhill's management account runs Control Tower; moving it needs the
	// organization deleted and the landing zone decommissioned.
	rep, err := Run(Input{Scenario: mustParse(t, doc), Source: f, Destination: l})
	if err != nil {
		t.Fatal(err)
	}
	st := rep.Stages[0]
	mgmt := transitionFinding(st.Transition, "org-services", "management account of the source organization")
	if mgmt == nil || mgmt.Status != evaluator.StatusNoGo || !strings.Contains(mgmt.Detail, "deleting the organization") && !strings.Contains(mgmt.Detail, "organization is deleted") {
		t.Fatalf("management account constraint: %+v", mgmt)
	}
	if ct := transitionFinding(st.Transition, "org-services", "runs Control Tower from this management account"); ct == nil || ct.Status != evaluator.StatusNoGo || !strings.Contains(ct.Detail, "decommissioned") {
		t.Errorf("landing zone decommissioning: %+v", ct)
	}
	if rep.Verdict != evaluator.StatusNoGo {
		t.Error("verdict")
	}
}

func TestWorkloadRelocationAndMissingValidation(t *testing.T) {
	l := fixtures.Larkspur()
	doc := `schema_version: 1
name: recreate
account: "111111111116"
strategy: recreate
stages:
  - id: validate
    title: Validate
    network:
      validated: true
  - id: relocate
    title: Relocate
    workload:
      relocate: true
      target_account: "222222222230"
`
	rep, err := Run(Input{Scenario: mustParse(t, doc), Source: l})
	if err != nil {
		t.Fatal(err)
	}
	v := stage(t, rep, "validate")
	if f := hasFinding(v.Findings, "validation point"); f == nil || f.Status != evaluator.StatusReview || f.Category != evaluator.CategoryMissingEvidence {
		t.Errorf("a validation point without verify steps is missing evidence: %+v", f)
	}
	r := stage(t, rep, "relocate")
	if !layer(r, LayerWorkload).Changed || !r.State.Relocated || hasFinding(r.Findings, "Workload relocation") == nil {
		t.Errorf("relocation: %+v %+v", r.Layers, r.Findings)
	}
	if !rep.Strategies[1].Selected || rep.Strategies[0].Selected {
		t.Errorf("recreate strategy selected: %+v", rep.Strategies)
	}
}

func TestEnrollmentDeclarationsAreChecked(t *testing.T) {
	f := fixtures.Fernhill()
	base := `schema_version: 1
name: enroll
account: "222222222227"
stages:
  - id: enroll
    title: Enroll
    placement:
      parent: %s
    governance:
      enrolled: true
      execution_role_present: %s
`
	rep, err := Run(Input{Scenario: mustParse(t, strings.Replace(strings.Replace(base, "%s", fixtures.FernhillRetailOU, 1), "%s", "false", 1)), Source: f})
	if err != nil {
		t.Fatal(err)
	}
	if p := hasFinding(rep.Stages[0].Findings, "Enrollment prerequisites"); p == nil || p.Status != evaluator.StatusNoGo || !strings.Contains(p.Detail, "declared NOT satisfied") {
		t.Errorf("a declared missing role blocks the enrollment: %+v", p)
	}
	rep, err = Run(Input{Scenario: mustParse(t, strings.Replace(strings.Replace(base, "%s", fixtures.FernhillSandboxOU, 1), "%s", "true", 1)), Source: f})
	if err != nil {
		t.Fatal(err)
	}
	if p := hasFinding(rep.Stages[0].Findings, "is not a registered OU"); p == nil || p.Status != evaluator.StatusNoGo {
		t.Errorf("enrolling into an unregistered OU is refused: %+v", p)
	}
	l := fixtures.Larkspur()
	rep, err = Run(Input{Scenario: mustParse(t, strings.Replace(strings.Replace(strings.Replace(base, "%s", "ou-lark-prod", 1), "%s", "true", 1), `"222222222227"`, `"111111111116"`, 1)), Source: l})
	if err != nil {
		t.Fatal(err)
	}
	if p := hasFinding(rep.Stages[0].Findings, "no Control Tower landing zone"); p == nil || p.Status != evaluator.StatusNoGo {
		t.Errorf("no landing zone in Larkspur: %+v", p)
	}
}

func golden(t *testing.T, name string, rep *Report) {
	t.Helper()
	got, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	got = append(got, '\n')
	path := filepath.Join("testdata", name+".golden.json")
	if *update {
		os.MkdirAll("testdata", 0o755)
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("missing golden file (run with -update): %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("report differs from %s (run go test ./internal/scenario -update after reviewing)", path)
	}
}
