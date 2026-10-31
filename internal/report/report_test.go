package report

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/MrShaaba/orgshift/internal/evaluator"
	"github.com/MrShaaba/orgshift/internal/fixtures"
)

func TestRenderers(t *testing.T) {
	res, err := evaluator.Evaluate(evaluator.Input{From: fixtures.Larkspur(), To: fixtures.Fernhill(), AccountID: fixtures.LarkspurPaymentsProd, TargetOUID: fixtures.FernhillPaymentsOU})
	if err != nil {
		t.Fatal(err)
	}
	data, err := JSON(res)
	if err != nil {
		t.Fatal(err)
	}
	var back evaluator.Result
	if err := json.Unmarshal(data, &back); err != nil || back.Verdict != evaluator.StatusNoGo {
		t.Fatalf("json round trip failed: %v", err)
	}
	md := Markdown(res)
	for _, want := range []string{"# orgshift verdict: NO-GO", "Fernhill-EU-Only-Regions", "## What changes", "DenyOutsideEU", "```json"} {
		if !strings.Contains(md, want) {
			t.Errorf("markdown missing %q", want)
		}
	}
	txt := Text(res)
	if !strings.Contains(txt, "VERDICT: NO-GO") || !strings.Contains(txt, "ec2:CreateVpc") {
		t.Errorf("text summary incomplete:\n%s", txt)
	}
}

func TestOURenderers(t *testing.T) {
	res, err := evaluator.EvaluateOU(evaluator.OUInput{From: fixtures.Larkspur(), To: fixtures.Fernhill(), OUID: fixtures.LarkspurWorkloadsOU, TargetParentID: fixtures.FernhillBusinessUnitsOU})
	if err != nil {
		t.Fatal(err)
	}
	data, err := OUJSON(res)
	if err != nil {
		t.Fatal(err)
	}
	var back evaluator.OUResult
	if err := json.Unmarshal(data, &back); err != nil || back.Verdict != evaluator.StatusNoGo || len(back.Accounts) != 3 {
		t.Fatalf("json round trip failed: %v (%d accounts)", err, len(back.Accounts))
	}
	md := OUMarkdown(res)
	for _, want := range []string{"# orgshift verdict: NO-GO", "## Accounts", "| NO-GO | larkspur-payments-prod (`111111111115`) | Workloads / Production |",
		"must be recreated under Business Units", "| Workloads (`ou-lark-work`) | SCP | `Larkspur-Allowed-Regions` | recreate |",
		"## What changes at the OU", "## Account larkspur-payments-prod (`111111111115`): NO-GO", "### Service control policies: NO-GO", "#### NO-GO:"} {
		if !strings.Contains(md, want) {
			t.Errorf("OU markdown missing %q", want)
		}
	}
	txt := OUText(res)
	if !strings.Contains(txt, "VERDICT: NO-GO") || !strings.Contains(txt, "Accounts (worst first)") || !strings.Contains(txt, "larkspur-data-prod (111111111118) in Workloads / Production") {
		t.Errorf("OU text summary incomplete:\n%s", txt)
	}
}
