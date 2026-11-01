package report

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/MrShaaba/orgshift/internal/evaluator"
	"github.com/MrShaaba/orgshift/internal/fixtures"
	"github.com/MrShaaba/orgshift/internal/runbook"
)

var update = flag.Bool("update", false, "rewrite golden files")

func compareGolden(t *testing.T, name, got string) {
	t.Helper()
	path := filepath.Join("testdata", name+".golden.md")
	if *update {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("missing golden file (run with -update): %v", err)
	}
	if !bytes.Equal([]byte(got), want) {
		t.Errorf("markdown differs from %s (run go test ./internal/report -update after reviewing)", path)
	}
}

func TestRunbookMarkdown(t *testing.T) {
	l, f := fixtures.Larkspur(), fixtures.Fernhill()
	res, err := evaluator.Evaluate(evaluator.Input{From: l, To: f, AccountID: fixtures.LarkspurPaymentsProd, TargetOUID: fixtures.FernhillPaymentsOU})
	if err != nil {
		t.Fatal(err)
	}
	rb := runbook.Build(res, l, f)
	md := RunbookMarkdown(rb)
	compareGolden(t, "runbook-cross-org-payments-to-fernhill", md)
	for _, want := range []string{
		"# orgshift runbook: larkspur-payments-prod (111111111115)",
		"**Verdict NO-GO.**",
		"> Generated from a snapshot simulation. Every command is for an operator to review and run by hand; orgshift never writes to AWS.",
		"## 1. Before the move: fix the blockers and make the decisions",
		"- [ ] **1.1** `NO-GO` SCP Fernhill-EU-Only-Regions / DenyOutsideEU denies 15 actions after the move",
		"  _Where:_ management account 222222222221 of Fernhill Group",
		"  ```sh\n  aws organizations describe-policy --policy-id p-fern0002 --query Content --output text",
		"  - Evidence (policy-statement): target, SCP `Fernhill-EU-Only-Regions` (p-fern0002), statement DenyOutsideEU, at OU Business Units (ou-fern-bu)",
		"## 3. The move",
		"- [ ] **3.1** Invite the account into Fernhill Group (o-fernhill0001)",
		"## 5. Rollback",
		"  - Evidence (source-chain): source\n    root Root (r-lark): FullAWSAccess (p-FullAWSAccess), Larkspur-Baseline-Guardrails (p-lark0001)",
	} {
		if !strings.Contains(md, want) {
			t.Errorf("runbook markdown missing %q", want)
		}
	}
	if strings.Contains(md, "\n\n\n") {
		t.Error("runbook markdown should not contain triple newlines")
	}
	data, err := RunbookJSON(rb)
	if err != nil || !strings.Contains(string(data), `"runbook_schema_version": 1`) {
		t.Fatalf("runbook json: %v", err)
	}

	same, err := evaluator.Evaluate(evaluator.Input{From: l, AccountID: "111111111116", TargetOUID: "ou-lark-prod"})
	if err != nil {
		t.Fatal(err)
	}
	md = RunbookMarkdown(runbook.Build(same, l, nil))
	if !strings.Contains(md, "## 1. Before the move: fix the blockers and make the decisions\n\nEverything here") || !strings.Contains(md, "Nothing to do in this phase.") || !strings.Contains(md, "move-account --account-id 111111111116 --source-parent-id ou-lark-dev --destination-parent-id ou-lark-prod") {
		t.Errorf("same-org runbook markdown:\n%s", md)
	}
}

func TestOURunbookMarkdown(t *testing.T) {
	l, f := fixtures.Larkspur(), fixtures.Fernhill()
	res, err := evaluator.EvaluateOU(evaluator.OUInput{From: l, To: f, OUID: fixtures.LarkspurWorkloadsOU, TargetParentID: fixtures.FernhillBusinessUnitsOU})
	if err != nil {
		t.Fatal(err)
	}
	rb := runbook.BuildOU(res, l, f)
	md := OURunbookMarkdown(rb)
	compareGolden(t, "runbook-ou-cross-org-workloads-to-fernhill-business-units", md)
	for _, want := range []string{
		"# orgshift runbook: OU Workloads (ou-lark-work)",
		"| NO-GO | larkspur-payments-prod (`111111111115`) |",
		"## 2. Before the move: create the new OU tree",
		"- [ ] **2.4** Create OU Workloads under OU Business Units (ou-fern-bu)",
		"  - Evidence (policy-document): source, SCP `Larkspur-Allowed-Regions` (p-lark0002)",
		"## Account larkspur-payments-prod (`111111111115`): NO-GO",
		"### 3. The move\n\nRun these in order.",
		"Moved together with OU Workloads",
	} {
		if !strings.Contains(md, want) {
			t.Errorf("OU runbook markdown missing %q", want)
		}
	}
	if _, err := OURunbookJSON(rb); err != nil {
		t.Fatal(err)
	}
}
