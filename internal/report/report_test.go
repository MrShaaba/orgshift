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

func TestControlTowerRendering(t *testing.T) {
	f := fixtures.Fernhill()
	res, err := evaluator.Evaluate(evaluator.Input{From: f, AccountID: fixtures.FernhillRetailProd, TargetOUID: fixtures.FernhillSandboxOU})
	if err != nil {
		t.Fatal(err)
	}
	md := Markdown(res)
	for _, want := range []string{"| Control Tower | REVIEW |", "### REVIEW: Moving out of the registered OU Retail unenrolls the account from Control Tower",
		"- Evidence (landing-zone): source, `arn:aws:controltower:eu-west-1:222222222221:landingzone/FERNHILLLZ000001`",
		"`aws-guardrails-kjwqpf` (Control Tower guardrail)", "- `aws-guardrails-kjwqpf` (p-fern0010) at OU Business Units (ou-fern-bu), Control Tower guardrail"} {
		if !strings.Contains(md, want) {
			t.Errorf("markdown missing %q", want)
		}
	}
	txt := Text(res)
	if !strings.Contains(txt, "[REVIEW] Control Tower - 1 item(s) to settle") || !strings.Contains(txt, "unenrolls the account") {
		t.Errorf("text summary should list the Control Tower check:\n%s", txt)
	}

	ou, err := evaluator.EvaluateOU(evaluator.OUInput{From: fixtures.Larkspur(), To: f, OUID: fixtures.LarkspurWorkloadsOU, TargetParentID: fixtures.FernhillBusinessUnitsOU})
	if err != nil {
		t.Fatal(err)
	}
	if omd := OUMarkdown(ou); !strings.Contains(omd, "### INFO: The new parent Business Units is registered with Control Tower; register the moved OU too") {
		t.Errorf("OU markdown should carry the registered-parent note")
	}
	same, err := evaluator.EvaluateOU(evaluator.OUInput{From: f, OUID: fixtures.FernhillBusinessUnitsOU, TargetParentID: fixtures.FernhillSandboxOU})
	if err != nil {
		t.Fatal(err)
	}
	if omd := OUMarkdown(same); !strings.Contains(omd, "| Business Units (`ou-fern-bu`) | SCP | `aws-guardrails-kjwqpf` (Control Tower guardrail) | carried |") {
		t.Errorf("OU attachments table should label the guardrail:\n%s", omd)
	}
}

func TestIdentityCenterRendering(t *testing.T) {
	res, err := evaluator.Evaluate(evaluator.Input{From: fixtures.Larkspur(), To: fixtures.Fernhill(), AccountID: fixtures.LarkspurPaymentsProd, TargetOUID: fixtures.FernhillPaymentsOU})
	if err != nil {
		t.Fatal(err)
	}
	md := Markdown(res)
	for _, want := range []string{"| IAM Identity Center | REVIEW |", "### REVIEW: Permission set PaymentsEngineer: 2 assignment(s) removed when the account leaves (group Payments-Engineers, user oncall.payments)",
		"- Evidence (account-assignment): source, `", "user oncall.payments has permission set PaymentsEngineer in account 111111111115",
		"### REVIEW: 4 AWSReservedSSO_* role(s) are deleted from the account: AWSReservedSSO_AdministratorAccess_*", "- Evidence (reserved-role): source, `AWSReservedSSO_DataPlatformOperator_*`",
		"- Evidence (permission-set): source, `arn:aws:sso:::permissionSet/ssoins-larkspur00000001/ps-lark00000002`", `"Sid": "NoIAMChanges"`} {
		if !strings.Contains(md, want) {
			t.Errorf("markdown missing %q", want)
		}
	}
	txt := Text(res)
	if !strings.Contains(txt, "[REVIEW] IAM Identity Center - 4 assignment(s) across 3 permission set(s)") || !strings.Contains(txt, "REVIEW Permission set PaymentsEngineer") {
		t.Errorf("text summary should list the Identity Center check:\n%s", txt)
	}
}
