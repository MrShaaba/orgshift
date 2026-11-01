package runbook

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

type scenario struct {
	name     string
	from, to *snapshot.Snapshot
	account  string
	targetOU string
}

// scenarios mirrors the evaluator's golden scenarios.
func scenarios() []scenario {
	l, f := fixtures.Larkspur(), fixtures.Fernhill()
	return []scenario{
		{"cross-org-payments-to-fernhill", l, f, fixtures.LarkspurPaymentsProd, fixtures.FernhillPaymentsOU},
		{"same-org-payments-dev-to-production", l, nil, "111111111116", "ou-lark-prod"},
		{"same-org-sandbox-to-production", l, nil, "111111111117", "ou-lark-prod"},
		{"cross-org-security-to-fernhill-core", l, f, "111111111113", "ou-fern-core"},
		{"same-org-fernhill-retail-prod-to-sandbox", f, nil, fixtures.FernhillRetailProd, fixtures.FernhillSandboxOU},
		{"cross-org-data-prod-to-fernhill-retail", l, f, "111111111118", fixtures.FernhillRetailOU},
	}
}

func buildScenario(t *testing.T, sc scenario) *Runbook {
	t.Helper()
	res, err := evaluator.Evaluate(evaluator.Input{From: sc.from, To: sc.to, AccountID: sc.account, TargetOUID: sc.targetOU})
	if err != nil {
		t.Fatal(err)
	}
	return Build(res, sc.from, sc.to)
}

func compareGolden(t *testing.T, name string, v any) {
	t.Helper()
	got, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	got = append(got, '\n')
	path := filepath.Join("testdata", name+".golden.json")
	if *update {
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("missing golden file (run with -update): %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("runbook differs from %s (run go test ./internal/runbook -update after reviewing)", path)
	}
}

func TestGolden(t *testing.T) {
	for _, sc := range scenarios() {
		t.Run(sc.name, func(t *testing.T) {
			compareGolden(t, sc.name, buildScenario(t, sc))
		})
	}
}

func stepWith(t *testing.T, rb *Runbook, phase string, want string) Step {
	t.Helper()
	for _, s := range rb.Phase(phase).Steps {
		if strings.Contains(s.Title, want) {
			return s
		}
	}
	t.Fatalf("no step in phase %s with %q in its title; have:\n%s", phase, want, titles(rb.Phase(phase)))
	return Step{}
}

func titles(p *Phase) string {
	var out []string
	for _, s := range p.Steps {
		out = append(out, "  "+s.ID+" ["+string(s.Status)+"] "+s.Title)
	}
	return strings.Join(out, "\n")
}

func TestCrossOrgRunbook(t *testing.T) {
	rb := buildScenario(t, scenarios()[0])
	if rb.Verdict != evaluator.StatusNoGo || rb.Subject.AccountID != fixtures.LarkspurPaymentsProd {
		t.Fatalf("subject or verdict wrong: %+v", rb.Subject)
	}
	if len(rb.Phases) != 5 || rb.Phases[0].ID != PhaseBefore || rb.Phases[4].ID != PhaseRollback {
		t.Fatalf("phases: %+v", rb.Phases)
	}
	for i, s := range rb.Steps() {
		if s.ID == "" || s.Title == "" || s.Kind == "" {
			t.Errorf("step %d incomplete: %+v", i, s)
		}
	}

	// Blockers come with the exact statement to review, grouped per statement.
	s := stepWith(t, rb, PhaseBefore, "SCP Fernhill-EU-Only-Regions / DenyOutsideEU denies")
	if s.Status != evaluator.StatusNoGo || s.Kind != KindPolicy || len(s.Actions) < 2 || len(s.Evidence) != 1 || s.Evidence[0].Statement != "DenyOutsideEU" {
		t.Errorf("region deny step should group the denied actions with one statement as evidence: %+v", s)
	}
	if !strings.Contains(s.Detail, "ec2:RunInstances in ap-southeast-1, us-east-1") || !strings.Contains(s.Detail, "aws:PrincipalAccount") || !strings.Contains(strings.Join(s.Commands, "\n"), "update-policy --policy-id p-fern0002") {
		t.Errorf("region deny step detail/commands: %s\n%v", s.Detail, s.Commands)
	}
	if !strings.Contains(s.Where, "222222222221") {
		t.Errorf("policy changes happen in the target management account, got %q", s.Where)
	}
	s = stepWith(t, rb, PhaseBefore, "RCP Fernhill-Block-External-Principals / EnforceOrgIdentities denies")
	if s.Status != evaluator.StatusNoGo || !strings.Contains(s.Detail, "aws:PrincipalOrgID") || !strings.Contains(s.Detail, " by 999999999999") {
		t.Errorf("RCP step: %+v", s)
	}
	s = stepWith(t, rb, PhaseBefore, "Decide whether SCP Fernhill-Payments-Controls / TerminateNeedsPlatformTag applies")
	if s.Status != evaluator.StatusReview || s.Kind != KindDecision {
		t.Errorf("undecidable condition should be a REVIEW decision: %+v", s)
	}
	s = stepWith(t, rb, PhaseBefore, "Lift the deny on organizations:LeaveOrganization in SCP Larkspur-Baseline-Guardrails / DenyLeaveOrganization")
	if s.Status != evaluator.StatusReview || len(s.Evidence) != 1 || s.Evidence[0].Side != "source" || !strings.Contains(strings.Join(s.Commands, "\n"), "remove-account-from-organization --account-id 111111111115") {
		t.Errorf("leave deny step: %+v", s)
	}
	stepWith(t, rb, PhaseBefore, "Make the account able to stand alone")
	s = stepWith(t, rb, PhaseBefore, "Re-tag before the move")
	if s.Status != evaluator.StatusReview || !strings.Contains(strings.Join(s.Commands, "\n"), "tag-resources --resource-arn-list arn:") {
		t.Errorf("tag step: %+v", s)
	}
	s = stepWith(t, rb, PhaseBefore, "Find what references the 4 AWSReservedSSO_* role(s)")
	if !strings.Contains(strings.Join(s.Commands, "\n"), "/aws-reserved/sso.amazonaws.com/us-east-1/") {
		t.Errorf("reserved role step: %+v", s)
	}
	stepWith(t, rb, PhaseBefore, "Deprovision the stale permission set(s) from the account: DataPlatformOperator")

	// Re-create: the networking share is NO-GO, owner and commands exact.
	s = stepWith(t, rb, PhaseRecreate, "Re-share larkspur-core-network with the account directly")
	if s.Status != evaluator.StatusNoGo || s.Where != "owner account 111111111112" || !strings.Contains(strings.Join(s.Commands, "\n"), "--allow-external-principals") || !strings.Contains(strings.Join(s.Commands, "\n"), "--principals 111111111115") {
		t.Errorf("share step: %+v", s)
	}
	s = stepWith(t, rb, PhaseRecreate, "Create permission set PaymentsEngineer in the target instance")
	cmds := strings.Join(s.Commands, "\n")
	if !strings.Contains(cmds, "create-permission-set --instance-arn "+fixtures.FernhillIdentityCenterInstance+" --name PaymentsEngineer") || !strings.Contains(cmds, "--session-duration PT8H") || !strings.Contains(cmds, "put-inline-policy-to-permission-set") || !strings.Contains(cmds, "Name=LarkspurPaymentsEngineer,Path=/larkspur/") {
		t.Errorf("create permission set commands:\n%s", cmds)
	}
	s = stepWith(t, rb, PhaseRecreate, "Review permission set AdministratorAccess in the target instance")
	if !strings.Contains(s.Detail, "session duration PT1H vs PT2H") {
		t.Errorf("matched permission set should carry the differences: %s", s.Detail)
	}
	stepWith(t, rb, PhaseRecreate, "Replace what StackSet larkspur-baseline-roles deploys")
	stepWith(t, rb, PhaseRecreate, "Enable trusted access in Fernhill Group")

	// The move, in order.
	move := rb.Phase(PhaseMove).Steps
	wantMove := []string{"Invite the account into Fernhill Group", "Leave Larkspur Holdings", "Accept the invitation", "Move the account from the root to OU Payments (ou-fern-pay1)"}
	if len(move) != len(wantMove) {
		t.Fatalf("move steps:\n%s", titles(rb.Phase(PhaseMove)))
	}
	for i, w := range wantMove {
		if !strings.Contains(move[i].Title, w) || move[i].Status != "" {
			t.Errorf("move step %d = %q (%s), want %q", i, move[i].Title, move[i].Status, w)
		}
	}
	if !strings.Contains(strings.Join(move[3].Commands, "\n"), "move-account --account-id 111111111115 --source-parent-id r-fern --destination-parent-id ou-fern-pay1") {
		t.Errorf("move command: %v", move[3].Commands)
	}

	// After: position first, assignments, shares, trail, re-simulate last.
	after := rb.Phase(PhaseAfter).Steps
	if !strings.HasPrefix(after[0].Title, "Confirm the account sits under OU Payments") || !strings.HasPrefix(after[len(after)-1].Title, "Collect a fresh snapshot") {
		t.Errorf("after phase order:\n%s", titles(rb.Phase(PhaseAfter)))
	}
	s = stepWith(t, rb, PhaseAfter, "Assign PaymentsEngineer to group Payments-Engineers, user oncall.payments")
	cmds = strings.Join(s.Commands, "\n")
	if !strings.Contains(cmds, "list-groups --identity-store-id d-fern0000001") || !strings.Contains(cmds, "list-users --identity-store-id d-fern0000001") || !strings.Contains(cmds, "--principal-type USER") {
		t.Errorf("assignment commands:\n%s", cmds)
	}
	stepWith(t, rb, PhaseAfter, "Accept the invitation for share larkspur-core-network")
	s = stepWith(t, rb, PhaseAfter, "Confirm CloudTrail coverage")
	if !strings.Contains(s.Detail, "larkspur-org-trail stop logging") || !strings.Contains(s.Detail, "fernhill-org-trail (bucket fernhill-log-archive)") {
		t.Errorf("trail check detail: %s", s.Detail)
	}
	s = stepWith(t, rb, PhaseAfter, "Exercise the")
	if !strings.Contains(s.Detail, "iam:CreateUser") {
		t.Errorf("flagged actions should be listed: %s", s.Detail)
	}

	// Rollback from the source chain.
	s = stepWith(t, rb, PhaseRollback, "Leave Fernhill Group (o-fernhill0001) again")
	if !strings.Contains(s.Detail, "Fernhill-Root-Guardrails / DenyLeaveOrganization") {
		t.Errorf("rollback should warn about the target's leave deny: %s", s.Detail)
	}
	stepWith(t, rb, PhaseRollback, "Re-invite the account into Larkspur Holdings (o-larkspur0001)")
	s = stepWith(t, rb, PhaseRollback, "Move the account back to OU Production (ou-lark-prod)")
	if !strings.Contains(strings.Join(s.Commands, "\n"), "--source-parent-id r-lark --destination-parent-id ou-lark-prod") {
		t.Errorf("rollback move: %v", s.Commands)
	}
	s = stepWith(t, rb, PhaseRollback, "Re-create the 4 Identity Center assignment(s) in the source instance")
	if len(s.Commands) != 4 || !strings.Contains(s.Commands[0], "--instance-arn "+fixtures.LarkspurIdentityCenterInstance) {
		t.Errorf("rollback assignments: %v", s.Commands)
	}
	s = stepWith(t, rb, PhaseRollback, "Verify the original policy chain")
	if len(s.Evidence) == 0 || s.Evidence[0].Kind != "source-chain" || !strings.Contains(s.Evidence[0].Note, "OU Workloads (ou-lark-work): FullAWSAccess (p-FullAWSAccess), Larkspur-Allowed-Regions (p-lark0002)") {
		t.Errorf("source chain evidence: %+v", s.Evidence)
	}
	if !strings.HasPrefix(rb.Summary, "4") && !strings.Contains(rb.Summary, "steps:") {
		t.Errorf("summary: %s", rb.Summary)
	}
}

func TestDelegatedAdminAndAggregatorOwner(t *testing.T) {
	rb := buildScenario(t, scenarios()[3]) // larkspur-security: delegated admin for three services, hosts the aggregator
	if rb.Verdict != evaluator.StatusNoGo {
		t.Fatalf("expected NO-GO, got %s", rb.Verdict)
	}
	// Organizations refuses to remove a delegated administrator, so the
	// hand-over is a blocker, not a decision.
	s := stepWith(t, rb, PhaseBefore, "Hand over delegated administration for guardduty.amazonaws.com")
	if s.Status != evaluator.StatusNoGo || !strings.Contains(strings.Join(s.Commands, "\n"), "deregister-delegated-administrator --account-id 111111111113 --service-principal guardduty.amazonaws.com") || !strings.Contains(s.Where, "111111111111") {
		t.Errorf("delegated admin hand-over: %+v", s)
	}
	s = stepWith(t, rb, PhaseBefore, "Move the organization Config aggregator larkspur-org-aggregator out of the account first")
	if s.Status != evaluator.StatusNoGo {
		t.Errorf("aggregator owner should be a blocker: %+v", s)
	}
	s = stepWith(t, rb, PhaseAfter, "Re-create the delegation for securityhub.amazonaws.com in Fernhill Group")
	if !strings.Contains(strings.Join(s.Commands, "\n"), "register-delegated-administrator --account-id 111111111113 --service-principal securityhub.amazonaws.com") {
		t.Errorf("re-delegation: %+v", s)
	}
	s = stepWith(t, rb, PhaseRollback, "Re-delegate administration to the account: config.amazonaws.com, guardduty.amazonaws.com, securityhub.amazonaws.com")
	if len(s.Commands) != 3 {
		t.Errorf("rollback re-delegation: %+v", s)
	}
}

func TestSameOrgRunbook(t *testing.T) {
	rb := buildScenario(t, scenarios()[1]) // payments-dev to Production: GO
	if rb.Verdict != evaluator.StatusGo {
		t.Fatalf("expected GO, got %s", rb.Verdict)
	}
	if n := len(rb.Phase(PhaseBefore).Steps); n != 0 {
		t.Errorf("a GO move should have nothing to fix, got:\n%s", titles(rb.Phase(PhaseBefore)))
	}
	move := rb.Phase(PhaseMove).Steps
	if len(move) != 1 || !strings.Contains(strings.Join(move[0].Commands, "\n"), "move-account --account-id 111111111116 --source-parent-id ou-lark-dev --destination-parent-id ou-lark-prod") {
		t.Errorf("same-org move:\n%s\n%v", titles(rb.Phase(PhaseMove)), move)
	}
	rollback := rb.Phase(PhaseRollback).Steps
	if len(rollback) != 2 || !strings.Contains(strings.Join(rollback[0].Commands, "\n"), "--source-parent-id ou-lark-prod --destination-parent-id ou-lark-dev") {
		t.Errorf("same-org rollback:\n%s", titles(rb.Phase(PhaseRollback)))
	}
	for _, s := range rb.Steps() {
		if strings.Contains(s.Title, "invitation") || strings.Contains(s.Title, "Leave ") {
			t.Errorf("same-org runbook must not mention leaving or invitations: %s", s.Title)
		}
	}

	// Sandbox to Production gains a share and a StackSet: checks only.
	rb = buildScenario(t, scenarios()[2])
	stepWith(t, rb, PhaseAfter, "Share larkspur-workload-prefix-lists becomes available")
	stepWith(t, rb, PhaseAfter, "Confirm StackSet larkspur-baseline-roles deployed")
}

func TestControlTowerRunbook(t *testing.T) {
	rb := buildScenario(t, scenarios()[4]) // fernhill-retail-prod out of its registered OU
	s := stepWith(t, rb, PhaseBefore, "Moving out of the registered OU Retail unenrolls the account")
	if s.Kind != KindDecision || s.Status != evaluator.StatusReview {
		t.Errorf("leaving a registered OU is a decision: %+v", s)
	}
	// Vended by Account Factory, inside the organization: the move goes through the product.
	move := rb.Phase(PhaseMove).Steps
	if len(move) != 1 || !strings.Contains(move[0].Title, "through Account Factory to OU Sandbox") || !strings.Contains(strings.Join(move[0].Commands, "\n"), "update-provisioned-product --provisioned-product-name") {
		t.Errorf("Control Tower move should go through Account Factory:\n%s\n%v", titles(rb.Phase(PhaseMove)), move)
	}
	stepWith(t, rb, PhaseAfter, "Check for Config rules left behind")
	stepWith(t, rb, PhaseRollback, "Move the account back to OU Retail (ou-fern-ret) through Account Factory")

	// Cross-org into a registered OU: role before, enrolment after.
	l, f := fixtures.Larkspur(), fixtures.Fernhill()
	res, err := evaluator.Evaluate(evaluator.Input{From: l, To: f, AccountID: fixtures.LarkspurPaymentsProd, TargetOUID: fixtures.FernhillPaymentsOU})
	if err != nil {
		t.Fatal(err)
	}
	rb = Build(res, l, f)
	s = stepWith(t, rb, PhaseRecreate, "Create the AWSControlTowerExecution role in the account, trusting management account 222222222221")
	if !strings.Contains(strings.Join(s.Commands, "\n"), "arn:aws:iam::222222222221:root") {
		t.Errorf("execution role trust: %v", s.Commands)
	}
	stepWith(t, rb, PhaseAfter, "Enroll the account in Control Tower from Account Factory (OU Payments)")
	// Fernhill audit account cannot move at all.
	res, err = evaluator.Evaluate(evaluator.Input{From: f, To: l, AccountID: fixtures.FernhillAuditAccount, TargetOUID: "ou-lark-sec"})
	if err != nil {
		t.Fatal(err)
	}
	rb = Build(res, f, l)
	s = stepWith(t, rb, PhaseBefore, "Stop: Account is the Control Tower audit account")
	if s.Status != evaluator.StatusNoGo || s.Kind != KindBlocker {
		t.Errorf("audit account blocker: %+v", s)
	}
}

func TestWithoutSnapshotsStillBuilds(t *testing.T) {
	l, f := fixtures.Larkspur(), fixtures.Fernhill()
	res, err := evaluator.Evaluate(evaluator.Input{From: l, To: f, AccountID: fixtures.LarkspurPaymentsProd, TargetOUID: fixtures.FernhillPaymentsOU})
	if err != nil {
		t.Fatal(err)
	}
	rb := Build(res, nil, nil)
	if len(rb.Steps()) == 0 {
		t.Fatal("runbook from a bare result should still have steps")
	}
	s := stepWith(t, rb, PhaseRecreate, "Re-share larkspur-core-network")
	if s.Where != "owner account 111111111112" {
		t.Errorf("owner should be parsed from the evidence when no snapshot is given, got %q", s.Where)
	}
	if s := stepWith(t, rb, PhaseMove, "Invite the account"); !strings.Contains(s.Where, "<management account>") {
		t.Errorf("unknown management account should be a placeholder, got %q", s.Where)
	}
	data, err := json.Marshal(rb)
	if err != nil {
		t.Fatal(err)
	}
	var back Runbook
	if err := json.Unmarshal(data, &back); err != nil || len(back.Phases) != 5 {
		t.Fatalf("json round trip: %v", err)
	}
}

type ouScenario struct {
	name     string
	from, to *snapshot.Snapshot
	ou       string
	parent   string
}

func ouScenarios() []ouScenario {
	l, f := fixtures.Larkspur(), fixtures.Fernhill()
	return []ouScenario{
		{"ou-cross-org-workloads-to-fernhill-business-units", l, f, fixtures.LarkspurWorkloadsOU, fixtures.FernhillBusinessUnitsOU},
		{"ou-same-org-production-to-root", l, nil, "ou-lark-prod", "r-lark"},
	}
}

func buildOUScenario(t *testing.T, sc ouScenario) *OURunbook {
	t.Helper()
	res, err := evaluator.EvaluateOU(evaluator.OUInput{From: sc.from, To: sc.to, OUID: sc.ou, TargetParentID: sc.parent})
	if err != nil {
		t.Fatal(err)
	}
	return BuildOU(res, sc.from, sc.to)
}

func TestGoldenOU(t *testing.T) {
	for _, sc := range ouScenarios() {
		t.Run(sc.name, func(t *testing.T) {
			compareGolden(t, sc.name, buildOUScenario(t, sc))
		})
	}
}

func ouStepWith(t *testing.T, rb *OURunbook, phase string, want string) Step {
	t.Helper()
	for _, s := range rb.Phase(phase).Steps {
		if strings.Contains(s.Title, want) {
			return s
		}
	}
	t.Fatalf("no OU step in phase %s with %q in its title; have:\n%s", phase, want, titles(rb.Phase(phase)))
	return Step{}
}

func TestOURunbooks(t *testing.T) {
	rb := buildOUScenario(t, ouScenarios()[0]) // Workloads into Fernhill Business Units
	if rb.Verdict != evaluator.StatusNoGo || len(rb.Accounts) != 3 {
		t.Fatalf("verdict %s, %d accounts", rb.Verdict, len(rb.Accounts))
	}
	s := ouStepWith(t, rb, PhaseBefore, "Clear the blockers of")
	if s.Status != evaluator.StatusNoGo || !strings.Contains(s.Detail, "larkspur-payments-prod (111111111115)") {
		t.Errorf("blocker overview: %+v", s)
	}
	s = ouStepWith(t, rb, PhaseRecreate, "Create policy Larkspur-Allowed-Regions (SCP) in Fernhill Group")
	if len(s.Evidence) != 1 || len(s.Evidence[0].StatementJSON) == 0 || !strings.Contains(strings.Join(s.Commands, "\n"), "create-policy --name Larkspur-Allowed-Regions --type SERVICE_CONTROL_POLICY") {
		t.Errorf("policy recreation should carry the document: %+v", s)
	}
	if s = ouStepWith(t, rb, PhaseRecreate, "Create policy Larkspur-Daily-Backups (BACKUP)"); !strings.Contains(s.Commands[0], "--type BACKUP_POLICY") {
		t.Errorf("backup policy type: %v", s.Commands)
	}
	rec := rb.Phase(PhaseRecreate).Steps
	var order []string
	for _, st := range rec {
		if st.Kind == KindOU {
			order = append(order, st.Title)
		}
	}
	if len(order) != 3 || !strings.HasPrefix(order[0], "Create OU Workloads under OU Business Units (ou-fern-bu)") || !strings.Contains(order[1], "under the new Workloads OU") {
		t.Errorf("OU creation order: %v", order)
	}
	s = ouStepWith(t, rb, PhaseRecreate, "Attach to the new Workloads OU: SCP Larkspur-Allowed-Regions")
	if !strings.Contains(strings.Join(s.Commands, "\n"), "attach-policy --policy-id <ID of the recreated Larkspur-Allowed-Regions> --target-id <ID of the new Workloads OU>") {
		t.Errorf("cross-org attach should use placeholders: %v", s.Commands)
	}
	ouStepWith(t, rb, PhaseMove, "Move the 3 account(s) one by one")
	s = ouStepWith(t, rb, PhaseMove, "Move larkspur-payments-prod (111111111115) from the target root into the new Production OU")
	if !strings.Contains(strings.Join(s.Commands, "\n"), "--source-parent-id r-fern --destination-parent-id <ID of the new Production OU>") {
		t.Errorf("cross-org account move: %v", s.Commands)
	}
	ouStepWith(t, rb, PhaseAfter, "The new parent Business Units is registered with Control Tower")
	s = ouStepWith(t, rb, PhaseAfter, "Delete the 3 empty source OU(s)")
	if len(s.Commands) != 3 || !strings.Contains(s.Commands[0], "ou-lark-dev") && !strings.Contains(s.Commands[0], "ou-lark-prod") || !strings.Contains(s.Commands[2], "ou-lark-work") {
		t.Errorf("source OUs should be deleted deepest first: %v", s.Commands)
	}
	ouStepWith(t, rb, PhaseRollback, "Recreate OU Workloads under root Root (r-lark) with its attachments")
	// Account runbooks are embedded and do not move on their own.
	var acct *Runbook
	for _, a := range rb.Accounts {
		if a.Subject.AccountID == fixtures.LarkspurPaymentsProd {
			acct = a
		}
	}
	if acct == nil || rb.Accounts[0].Verdict != evaluator.StatusNoGo {
		t.Fatalf("accounts should keep the rollup order (worst first) and include the payments account")
	}
	if mv := acct.Phase(PhaseMove).Steps; len(mv) != 1 || !strings.Contains(mv[0].Title, "Moved together with OU Workloads") {
		t.Errorf("embedded account runbook should not move on its own:\n%s", titles(acct.Phase(PhaseMove)))
	}
	if len(acct.Phase(PhaseBefore).Steps) == 0 || len(acct.Phase(PhaseRecreate).Steps) == 0 {
		t.Error("embedded account runbook should still carry its blockers and re-creations")
	}
	if rb.Accounts[0].Phase(PhaseRollback).Steps[0].Kind != KindRollback || len(rb.Accounts[0].Phase(PhaseRollback).Steps[0].Evidence) == 0 {
		t.Error("embedded rollback should carry the source chain")
	}

	// Same-org: real policy IDs, accounts moved by the OU, old OUs deleted.
	rb = buildOUScenario(t, ouScenarios()[1])
	s = ouStepWith(t, rb, PhaseRecreate, "Attach to the new Production OU: BACKUP Larkspur-Daily-Backups")
	if !strings.Contains(strings.Join(s.Commands, "\n"), "attach-policy --policy-id p-lark0005 --target-id <ID of the new Production OU>") {
		t.Errorf("same-org attach should reuse the policy: %v", s.Commands)
	}
	s = ouStepWith(t, rb, PhaseMove, "Move larkspur-payments-prod (111111111115) from Production (ou-lark-prod) into the new Production OU")
	if !strings.Contains(strings.Join(s.Commands, "\n"), "--source-parent-id ou-lark-prod --destination-parent-id <ID of the new Production OU>") {
		t.Errorf("same-org account move: %v", s.Commands)
	}
	ouStepWith(t, rb, PhaseRollback, "Move larkspur-payments-prod (111111111115) back into Production")
	for _, st := range rb.Steps() {
		if strings.Contains(st.Title, "invite") || strings.Contains(st.Title, "Create policy") {
			t.Errorf("same-org OU runbook must not recreate policies or invite accounts: %s", st.Title)
		}
	}
}
