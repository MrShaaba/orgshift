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
	// The procedure the move was evaluated as is in the header of both, and
	// its findings are in the body.
	const direct = "direct transfer (invite, accept; no standalone interval)"
	if !strings.Contains(md, "Transfer procedure: "+direct+".") || !strings.Contains(txt, "transfer: "+direct) {
		t.Error("the reports name the transfer procedure")
	}
	for _, want := range []string{"### NO-GO: A source SCP denies organizations:LeaveOrganization, which blocks the transfer", "### REVIEW: The account lands at the destination root first: 6 policy(ies)",
		"### REVIEW: Transfer eligibility: 1 requirement(s) cannot be confirmed from the snapshots", "### INFO: Direct transfer: 222222222221 invites the account and the account accepts; it is never standalone"} {
		if !strings.Contains(md, want) {
			t.Errorf("markdown missing %q", want)
		}
	}
	same, err := evaluator.Evaluate(evaluator.Input{From: fixtures.Larkspur(), AccountID: "111111111116", TargetOUID: "ou-lark-prod"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(Markdown(same), "Transfer procedure") || strings.Contains(Text(same), "transfer:") {
		t.Error("a move inside one organization has no transfer procedure")
	}
	// The workload layer: how much was evaluated, from what, and the findings.
	for _, want := range []string{"## Workload layer: evaluated", "8 stack(s) with 37 resource(s), 14 sampled resource(s) from tagging-api", "| `workloads.resources` | observed |",
		"| How it would be redeployed | Stacks | Resources in stacks | Sampled resources outside stacks |", "| redeployable from a template or pipeline | 5 | 27 | 3 |",
		"## Workloads: NO-GO", "### NO-GO: Bucket policy of arn:aws:s3:::larkspur-payments-settlement-files denies the account's own principals after the move",
		"1 of the actions were derived from the workload inventory"} {
		if !strings.Contains(md, want) {
			t.Errorf("markdown missing %q", want)
		}
	}
	for _, want := range []string{"workload layer: evaluated (8 stack(s) with 37 resource(s)", "[NO-GO ] Workloads - Workload layer evaluated", "NO-GO  Stack payments-api sits on 2 subnets shared through larkspur-core-network"} {
		if !strings.Contains(txt, want) {
			t.Errorf("text missing %q", want)
		}
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
	if !strings.Contains(md, "Transfer procedure for each account: direct transfer") || !strings.Contains(txt, "transfer, for each account: direct transfer") {
		t.Error("the OU reports name the transfer procedure")
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
