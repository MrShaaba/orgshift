package report

import (
	"strings"
	"testing"

	"github.com/MrShaaba/orgshift/internal/evaluator"
	"github.com/MrShaaba/orgshift/internal/fixtures"
)

func TestCoverageRendering(t *testing.T) {
	res, err := evaluator.Evaluate(evaluator.Input{From: fixtures.LarkspurPartial(), AccountID: "111111111116", TargetOUID: "ou-lark-prod"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Verdict != evaluator.StatusReview {
		t.Fatalf("partial snapshot should be REVIEW, got %s", res.Verdict)
	}
	md := Markdown(res)
	for _, want := range []string{
		"## Collection coverage", "Coverage is incomplete: ", "Both columns describe the same snapshot.",
		"| Domain | Decides | Check | Source | Target |",
		"| `resource_shares` | RAM shares that stop or start reaching the account | ram | access_denied: resource_shares access_denied (account 111111111111, region us-east-1): AccessDeniedException",
		"| `identity_center` |", "(not required)",
		"Models used: rcp-applicability " + evaluator.RCPModelVersion, "ram-behaviour " + evaluator.RAMModelVersion,
		"## Resource shares (RAM): REVIEW", "Evidence incomplete: resource_shares.",
		"### REVIEW: The collector was denied access to resource_shares for the the snapshot",
	} {
		if !strings.Contains(md, want) {
			t.Errorf("markdown missing %q", want)
		}
	}
	txt := Text(res)
	if !strings.Contains(txt, "coverage: incomplete: ") || !strings.Contains(txt, "[evidence incomplete: resource_shares]") {
		t.Errorf("text should carry the coverage line and the check caveat:\n%s", txt)
	}
	// A complete result says so.
	full, err := evaluator.Evaluate(evaluator.Input{From: fixtures.Larkspur(), AccountID: "111111111116", TargetOUID: "ou-lark-prod"})
	if err != nil {
		t.Fatal(err)
	}
	if md := Markdown(full); !strings.Contains(md, "Coverage is complete (") || strings.Contains(md, "Evidence incomplete") {
		t.Error("complete result rendering wrong")
	}
	if txt := Text(full); !strings.Contains(txt, "coverage: complete (") || !strings.Contains(txt, "GO within the assessed scope") {
		t.Errorf("text for a complete GO:\n%s", txt)
	}
	// References render under findings.
	cross, _ := evaluator.Evaluate(evaluator.Input{From: fixtures.Larkspur(), To: fixtures.Fernhill(), AccountID: "111111111113", TargetOUID: "ou-fern-core"})
	if md := Markdown(cross); !strings.Contains(md, "Documentation: https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_accounts_remove.html") {
		t.Error("finding references should render in Markdown")
	}
}
