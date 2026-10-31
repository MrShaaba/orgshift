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
