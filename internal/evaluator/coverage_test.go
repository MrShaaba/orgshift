package evaluator

import (
	"strings"
	"testing"

	"github.com/MrShaaba/orgshift/internal/fixtures"
	"github.com/MrShaaba/orgshift/internal/snapshot"
)

func gapFindings(c Check) []Finding {
	var out []Finding
	for _, f := range c.Findings {
		for _, ev := range f.Evidence {
			if ev.Kind == "coverage" {
				out = append(out, f)
				break
			}
		}
	}
	return out
}

func TestCoverageCheckIsFirstAndCompleteOnFixtures(t *testing.T) {
	res, err := Evaluate(Input{From: fixtures.Larkspur(), To: fixtures.Fernhill(), AccountID: fixtures.LarkspurPaymentsProd, TargetOUID: fixtures.FernhillPaymentsOU})
	if err != nil {
		t.Fatal(err)
	}
	if res.Checks[0].ID != "coverage" || res.Checks[0].Status != StatusGo {
		t.Fatalf("the coverage check should lead the board and be GO on complete fixtures: %+v", res.Checks[0])
	}
	if !res.Coverage.Complete || res.Coverage.SameSnapshot || len(res.Coverage.Gaps) != 0 || res.Coverage.Required == 0 {
		t.Fatalf("matrix should be complete for a cross-org move between full fixtures: %+v", res.Coverage)
	}
	for _, c := range res.Checks {
		if len(c.CoverageGaps) > 0 || len(gapFindings(c)) > 0 {
			t.Errorf("check %s should carry no coverage gap: %v", c.ID, c.CoverageGaps)
		}
	}
	if len(res.Models) != 4 || res.Models[0].ID != "rcp-applicability" || res.Models[0].Version != RCPModelVersion || res.Models[1].ID != "ram-behaviour" || res.Models[2].ID != "transfer-procedure" ||
		res.Models[3].ID != "workload-behaviour" || res.Models[3].Version != WorkloadModelVersion {
		t.Errorf("models should be listed with their versions: %+v", res.Models)
	}
	if res.ResultSchemaVersion != 4 {
		t.Errorf("result schema version should be 4, got %d", res.ResultSchemaVersion)
	}
}

func TestMissingCoverageTurnsGoIntoReview(t *testing.T) {
	l := fixtures.Larkspur()
	l.Coverage = nil // a hand-written or schema 1 snapshot
	res, err := Evaluate(Input{From: l, AccountID: "111111111116", TargetOUID: "ou-lark-prod"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Verdict != StatusReview {
		t.Fatalf("a GO move on a snapshot with unknown coverage must be REVIEW, got %s: %s", res.Verdict, res.Summary)
	}
	if res.Coverage.Complete || !res.Coverage.SameSnapshot {
		t.Fatalf("matrix: %+v", res.Coverage)
	}
	ram := check(res, "ram")
	if len(ram.CoverageGaps) != 1 || ram.CoverageGaps[0] != "resource_shares" {
		t.Errorf("the RAM check should name its gap once for a same-org move, got %v", ram.CoverageGaps)
	}
	gf := gapFindings(ram)
	if len(gf) != 1 || gf[0].Status != StatusReview || !strings.Contains(gf[0].Title, "Coverage of resource_shares is not recorded") || !strings.Contains(gf[0].Detail, "asserted_complete") {
		t.Errorf("gap finding wrong: %+v", gf)
	}
	if !strings.Contains(res.Summary, "Collection coverage is incomplete") {
		t.Errorf("summary should mention coverage: %s", res.Summary)
	}
	// Domains the move does not need are not gaps: Identity Center and
	// delegated administration are cross-organization concerns.
	for _, g := range res.Coverage.Gaps {
		if strings.Contains(g, "identity_center") || strings.Contains(g, "delegated_administrators") || strings.Contains(g, "policies.backup") {
			t.Errorf("same-org move must not require %s", g)
		}
	}
	// The coverage check itself owns the domains no other check depends on.
	cov := res.Checks[0]
	if cov.ID != "coverage" || cov.Status != StatusReview || len(gapFindings(cov)) < 2 {
		t.Errorf("coverage check should own the tree and organization gaps: %+v", cov.CoverageGaps)
	}
}

func TestAssertedCompletenessRestoresGo(t *testing.T) {
	l := fixtures.Larkspur()
	l.Coverage = &snapshot.Coverage{AssertedComplete: true, AssertedBy: "test"}
	res, err := Evaluate(Input{From: l, AccountID: "111111111116", TargetOUID: "ou-lark-prod"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Verdict != StatusGo || !res.Coverage.Complete {
		t.Fatalf("asserted completeness should allow GO, got %s: %s", res.Verdict, res.Summary)
	}
	for _, row := range res.Coverage.Rows {
		if row.Source.Required && !row.Source.Asserted {
			t.Errorf("row %s should be marked asserted: %+v", row.Domain, row.Source)
		}
	}
	if !strings.Contains(res.Summary, "GO within the assessed scope") || !strings.Contains(res.Summary, "not a guarantee") {
		t.Errorf("GO wording must scope the claim: %s", res.Summary)
	}
}

func TestPartialFixtureReportsEachGapInItsCheck(t *testing.T) {
	p := fixtures.LarkspurPartial()
	// Cross-org: still NO-GO (the SCP denies are real), and every gap sits in the check that depends on it.
	res, err := Evaluate(Input{From: p, To: fixtures.Fernhill(), AccountID: fixtures.LarkspurPaymentsProd, TargetOUID: fixtures.FernhillPaymentsOU})
	if err != nil {
		t.Fatal(err)
	}
	if res.Verdict != StatusNoGo {
		t.Fatalf("real blockers keep the verdict NO-GO: %s", res.Verdict)
	}
	want := map[string]string{
		"ram":             "resource_shares on source",
		"control-tower":   "control_tower on source",
		"identity-center": "identity_center on source",
		"org-services":    "organization_trails on source",
	}
	for id, gap := range want {
		c := check(res, id)
		if !strings.Contains(strings.Join(c.CoverageGaps, ";"), gap) {
			t.Errorf("check %s should list %q, got %v", id, gap, c.CoverageGaps)
		}
	}
	ramGap := gapFindings(check(res, "ram"))[0]
	if !strings.Contains(ramGap.Title, "denied access to resource_shares") || !strings.Contains(ramGap.Detail, "docs/permissions.md") || ramGap.Evidence[0].Reference != "resource_shares" {
		t.Errorf("access denied gap: %+v", ramGap)
	}
	ctGap := gapFindings(check(res, "control-tower"))
	found := false
	for _, f := range ctGap {
		if strings.Contains(f.Detail, "home region") {
			found = true
		}
	}
	if !found {
		t.Errorf("the wrong-region hint should reach the Control Tower gap: %+v", ctGap)
	}
	idc := gapFindings(check(res, "identity-center"))
	if len(idc) != 1 || !strings.Contains(idc[0].Title, "was skipped") || !strings.Contains(idc[0].Detail, "--skip-identity-center") {
		t.Errorf("skipped gap: %+v", idc)
	}
	// The gained-share and lost-share findings cannot be computed, and the RAM summary says so through the gap, not through "0 lost".
	if strings.Contains(check(res, "ram").Summary, "0 lost") && len(check(res, "ram").CoverageGaps) == 0 {
		t.Error("an empty share list must not read as nothing lost without a gap")
	}

	// Same-org GO move on the partial snapshot becomes REVIEW.
	res, err = Evaluate(Input{From: p, AccountID: "111111111116", TargetOUID: "ou-lark-prod"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Verdict != StatusReview {
		t.Fatalf("partial collection must not yield GO, got %s", res.Verdict)
	}
	if res.Coverage.Complete || !strings.Contains(strings.Join(res.Coverage.Gaps, ";"), "resource_shares: access_denied") {
		t.Errorf("gaps: %v", res.Coverage.Gaps)
	}
}

func TestUpgradedSnapshotGetsANote(t *testing.T) {
	l := fixtures.Larkspur()
	l.Coverage = nil
	l.UpgradedFrom = 1
	res, err := Evaluate(Input{From: l, To: fixtures.Fernhill(), AccountID: fixtures.LarkspurPaymentsProd, TargetOUID: fixtures.FernhillPaymentsOU})
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(res.Notes, " ")
	if !strings.Contains(joined, "schema version 1") {
		t.Errorf("notes should explain the upgrade: %v", res.Notes)
	}
	for _, row := range res.Coverage.Rows {
		if row.Domain == snapshot.DomainTree && !strings.Contains(row.Source.Detail, "schema version 1") {
			t.Errorf("cell detail should say why coverage is unknown: %+v", row.Source)
		}
	}
}

func TestOUMoveCarriesCoverageIntoAccounts(t *testing.T) {
	p := fixtures.LarkspurPartial()
	res, err := EvaluateOU(OUInput{From: p, OUID: "ou-lark-prod", TargetParentID: "r-lark"})
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range res.Accounts {
		if a.Result.Coverage.Complete {
			t.Errorf("account %s should inherit the incomplete coverage", a.AccountID)
		}
		if a.Verdict == StatusGo {
			t.Errorf("account %s cannot be GO on a partial snapshot", a.AccountID)
		}
	}
	if res.Verdict == StatusGo {
		t.Error("OU verdict cannot be GO on a partial snapshot")
	}
}
