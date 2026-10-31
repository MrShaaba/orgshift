package evaluator

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/MrShaaba/orgshift/internal/fixtures"
	"github.com/MrShaaba/orgshift/internal/snapshot"
)

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

func TestGoldenOU(t *testing.T) {
	for _, sc := range ouScenarios() {
		t.Run(sc.name, func(t *testing.T) {
			res, err := EvaluateOU(OUInput{From: sc.from, To: sc.to, OUID: sc.ou, TargetParentID: sc.parent})
			if err != nil {
				t.Fatal(err)
			}
			got, err := json.MarshalIndent(res, "", "  ")
			if err != nil {
				t.Fatal(err)
			}
			got = append(got, '\n')
			path := filepath.Join("testdata", sc.name+".golden.json")
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
				t.Errorf("result differs from %s (run go test ./internal/evaluator -update after reviewing)", path)
			}
		})
	}
}

func accountRollup(t *testing.T, res *OUResult, id string) AccountRollup {
	t.Helper()
	for _, a := range res.Accounts {
		if a.AccountID == id {
			return a
		}
	}
	t.Fatalf("account %s missing from the rollup", id)
	return AccountRollup{}
}

func TestOUCrossOrgRecreatesTree(t *testing.T) {
	l, f := fixtures.Larkspur(), fixtures.Fernhill()
	res, err := EvaluateOU(OUInput{From: l, To: f, OUID: fixtures.LarkspurWorkloadsOU, TargetParentID: fixtures.FernhillBusinessUnitsOU})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Subject.CrossOrg || res.Subject.NestedOUs != 2 || res.Subject.Accounts != 3 {
		t.Fatalf("unexpected subject: %+v", res.Subject)
	}
	if res.Verdict != StatusNoGo {
		t.Fatalf("expected NO-GO, got %s: %s", res.Verdict, res.Summary)
	}
	// The OU itself: one REVIEW saying it has to be recreated, with the attachments as evidence.
	if len(res.Findings) != 1 || res.Findings[0].Status != StatusReview || !strings.Contains(res.Findings[0].Title, "must be recreated under Business Units") {
		t.Fatalf("expected one recreate finding, got %+v", res.Findings)
	}
	notes := strings.Join(func() []string {
		var out []string
		for _, ev := range res.Findings[0].Evidence {
			out = append(out, ev.Note)
		}
		return out
	}(), "\n")
	for _, want := range []string{"Larkspur-Allowed-Regions", "Larkspur-Dev-Guardrails", "Larkspur-Daily-Backups"} {
		if !strings.Contains(notes, want) {
			t.Errorf("recreate evidence should list %s, got:\n%s", want, notes)
		}
	}
	for _, at := range res.Attachments {
		if at.Fate != "recreate" {
			t.Errorf("cross-org attachments must be marked recreate, got %+v", at)
		}
	}
	// Accounts keep their place inside the subtree, under the new parent.
	pay := accountRollup(t, res, fixtures.LarkspurPaymentsProd)
	if pay.RelativePath != "Workloads / Production" || snapshot.PathString(pay.Result.Subject.TargetPath) != "Root / Business Units / Workloads / Production / larkspur-payments-prod" {
		t.Errorf("unexpected target path: %s / %s", pay.RelativePath, snapshot.PathString(pay.Result.Subject.TargetPath))
	}
	if pay.Verdict != StatusNoGo || pay.Blocking == 0 || len(pay.BlockingTitles) == 0 {
		t.Errorf("payments-prod should roll up as NO-GO with blocking titles, got %+v", pay)
	}
	// The recreated OUs carry only the AWS managed defaults: the Payments OU controls do not apply here, so CreateVpc is only a
	// region problem (denied outside the EU), not a plain deny.
	f1 := find(t, pay.Result, "scp", func(f Finding) bool { return f.Action == "ec2:CreateVpc" })
	if f1.Evidence[0].PolicyName != "Fernhill-EU-Only-Regions" {
		t.Errorf("CreateVpc under a recreated OU should only hit the region deny, got %+v", f1.Evidence[0])
	}
	// The rollup is sorted worst first and the OU verdict is the worst account verdict.
	for i := 1; i < len(res.Accounts); i++ {
		if rank(res.Accounts[i-1].Verdict) < rank(res.Accounts[i].Verdict) {
			t.Errorf("accounts are not sorted worst first: %s before %s", res.Accounts[i-1].Verdict, res.Accounts[i].Verdict)
		}
	}
	data := accountRollup(t, res, "111111111118")
	if data.Verdict != StatusNoGo {
		t.Errorf("data-prod loses the transit gateway share and must be NO-GO, got %s", data.Verdict)
	}
	// Diff at the OU position: Fernhill adds EU-only regions, Larkspur's own attachment on Workloads is gone.
	var scp Diff
	for _, d := range res.Diff {
		if d.TypeShort == "SCP" {
			scp = d
		}
	}
	names := func(refs []PolicyRef) (out []string) {
		for _, r := range refs {
			out = append(out, r.Name)
		}
		return out
	}
	if !contains(names(scp.Added), "Fernhill-EU-Only-Regions") || !contains(names(scp.Removed), "Larkspur-Allowed-Regions") {
		t.Errorf("unexpected OU diff: added=%v removed=%v", names(scp.Added), names(scp.Removed))
	}
}

func TestOUSameOrgCarriesAttachments(t *testing.T) {
	l := fixtures.Larkspur()
	res, err := EvaluateOU(OUInput{From: l, OUID: "ou-lark-prod", TargetParentID: "r-lark"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Subject.CrossOrg {
		t.Fatal("same snapshot must not be a cross-org move")
	}
	if len(res.Findings) != 1 || res.Findings[0].Status != StatusInfo || !strings.Contains(res.Findings[0].Title, "move with it") {
		t.Fatalf("expected one INFO finding about carried attachments, got %+v", res.Findings)
	}
	carried := false
	for _, at := range res.Attachments {
		if at.Fate != "carried" {
			t.Errorf("same-org attachments must be carried, got %+v", at)
		}
		if at.PolicyName == "Larkspur-Daily-Backups" {
			carried = true
		}
	}
	if !carried {
		t.Error("the backup policy attached to Production should be listed")
	}
	// Leaving Workloads loses the OU-scoped prefix list share (networking: NO-GO) and lifts the region SCP (INFO).
	pay := accountRollup(t, res, fixtures.LarkspurPaymentsProd)
	if pay.Verdict != StatusNoGo || !strings.Contains(strings.Join(pay.BlockingTitles, "\n"), "larkspur-workload-prefix-lists") {
		t.Errorf("payments-prod should be NO-GO because of the prefix list share, got %+v", pay.BlockingTitles)
	}
	if pay.Result.Subject.TargetOUID != "ou-lark-prod" || snapshot.PathString(pay.Result.Subject.TargetPath) != "Root / Production / larkspur-payments-prod" {
		t.Errorf("the account must stay inside Production, got %s", snapshot.PathString(pay.Result.Subject.TargetPath))
	}
	find(t, pay.Result, "org-services", func(f Finding) bool {
		return strings.Contains(f.Title, "larkspur-baseline-roles") && f.Status == StatusReview
	})
	if res.Verdict != StatusNoGo {
		t.Fatalf("OU verdict should be the worst account verdict, got %s", res.Verdict)
	}
}

func TestOUEmptyAndSelf(t *testing.T) {
	l := fixtures.Larkspur()
	// Infrastructure has one account; move it to its own parent: a note, not an error.
	res, err := EvaluateOU(OUInput{From: l, OUID: "ou-lark-infra", TargetParentID: "r-lark"})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Notes) == 0 || !strings.Contains(res.Notes[0], "current parent") {
		t.Errorf("expected a note about the current parent, got %v", res.Notes)
	}
	// An OU with no accounts still produces a result.
	l.OUs = append(l.OUs, snapshot.OU{ID: "ou-lark-empty", Name: "Empty", ParentID: "r-lark"})
	res, err = EvaluateOU(OUInput{From: l, OUID: "ou-lark-empty", TargetParentID: "ou-lark-sand"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Verdict != StatusGo || len(res.Accounts) != 0 || !strings.Contains(strings.Join(res.Notes, " "), "no accounts") {
		t.Errorf("empty OU should be GO with a note, got %s %v", res.Verdict, res.Notes)
	}
}

func TestOUInputErrors(t *testing.T) {
	l, f := fixtures.Larkspur(), fixtures.Fernhill()
	if _, err := EvaluateOU(OUInput{From: l, OUID: "r-lark", TargetParentID: "ou-lark-sand"}); err == nil {
		t.Fatal("a root is not a movable OU")
	}
	if _, err := EvaluateOU(OUInput{From: l, OUID: "ou-lark-work", TargetParentID: "ou-lark-prod"}); err == nil {
		t.Fatal("an OU cannot move under its own descendant")
	}
	if _, err := EvaluateOU(OUInput{From: l, OUID: "ou-lark-work", TargetParentID: "ou-lark-work"}); err == nil {
		t.Fatal("an OU cannot move under itself")
	}
	if _, err := EvaluateOU(OUInput{From: l, To: f, OUID: "ou-lark-work", TargetParentID: "222222222222"}); err == nil {
		t.Fatal("an account is not a valid parent")
	}
	if _, err := EvaluateOU(OUInput{From: l, To: f, OUID: "ou-fern-bu", TargetParentID: "r-fern"}); err == nil {
		t.Fatal("the OU must be in the source snapshot")
	}
}
