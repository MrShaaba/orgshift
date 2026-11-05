package report

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/MrShaaba/orgshift/internal/fixtures"
	"github.com/MrShaaba/orgshift/internal/workload"
)

func TestWorkloadsRenderings(t *testing.T) {
	l := fixtures.Larkspur()
	inv := workload.Build(l, fixtures.LarkspurPaymentsProd)
	text := WorkloadsText(inv)
	for _, want := range []string{"WORKLOADS larkspur-payments-prod (111111111115)", "workload layer: evaluated", "workloads.stacks observed", "How it would be redeployed",
		"redeployable from a template or pipeline", "5 stack(s) with 27 resource(s), 3 sampled resource(s) outside any stack", "[service-managed StackSet, high confidence]",
		"auto-deployment true, retain stacks on account removal false", "imports payments-app-sg from stack payments-network (Fn::ImportValue, same account and Region)",
		"reads output LogDestinationArn of stack shared-observability in account 111111111113", "references subnet subnet-", "(parameter AppSubnetIds)",
		"[Terraform-style tag convention, medium confidence]", "[unknown, low confidence]", "Policies that reference organization identity",
		"s3-bucket-policy  arn:aws:s3:::larkspur-payments-settlement-files", "Deny DataPerimeter: StringNotEqualsIfExists aws:PrincipalOrgID o-larkspur0001, o-acquirer0001",
		"template-policy  resource AppLogSubscriptionRole of stack payments-api", "never untagged ones"} {
		if !strings.Contains(text, want) {
			t.Errorf("text should contain %q", want)
		}
	}
	md := WorkloadsMarkdown(inv)
	for _, want := range []string{"# Workloads of larkspur-payments-prod (`111111111115`)", "Workload layer: **evaluated**.", "| `workloads.policies` | observed |", "## How it would be redeployed",
		"| recreated by Control Tower or a StackSet | 3 | 10 | 0 |", "## Stacks", "| us-east-1 | `payments-api` | plain CloudFormation stack | high | 7 |", "## Sampled resources", "## Policies that reference organization identity"} {
		if !strings.Contains(md, want) {
			t.Errorf("markdown should contain %q", want)
		}
	}
	data, err := WorkloadsJSON(inv)
	if err != nil {
		t.Fatal(err)
	}
	var back workload.Inventory
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatal(err)
	}
	if len(back.Stacks) != 8 || back.Stacks[0].Provenance.Kind != workload.KindStackSetServiceManaged || len(back.Groups) != 3 || !back.Collected {
		t.Errorf("JSON round trip: %d stacks", len(back.Stacks))
	}
	// An account that was not inspected says so and nothing else.
	none := WorkloadsText(workload.Build(l, "111111111117"))
	if !strings.Contains(none, "workload layer: not-evaluated") || !strings.Contains(none, "no coverage record for this account") || strings.Contains(none, "Stacks\n") {
		t.Errorf("uninspected account: %s", none)
	}
	index := WorkloadsIndexText(l)
	if !strings.Contains(index, "3 account(s) with a workload inventory") || !strings.Contains(index, "111111111115  larkspur-payments-prod") {
		t.Errorf("index: %s", index)
	}
	if empty := WorkloadsIndexText(fixtures.LarkspurPartial()); !strings.Contains(empty, "none: name accounts under member_inspection.accounts") {
		t.Errorf("empty index: %s", empty)
	}
}
