package report

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/MrShaaba/orgshift/internal/fixtures"
	"github.com/MrShaaba/orgshift/internal/scenario"
)

func stagedReport(t *testing.T) *scenario.Report {
	t.Helper()
	sc, err := scenario.Parse([]byte(fixtures.PaymentsToFernhillStaged))
	if err != nil {
		t.Fatal(err)
	}
	rep, err := scenario.Run(scenario.Input{Scenario: sc, Source: fixtures.Larkspur(), Destination: fixtures.Fernhill(), Version: "test"})
	if err != nil {
		t.Fatal(err)
	}
	return rep
}

func TestStagesRenderings(t *testing.T) {
	rep := stagedReport(t)
	text := StagesText(rep)
	for _, want := range []string{"NO-GO", "scenario: Payments production into Fernhill, staged (transfer)", "== Stage 3: Destination organization entry at the root", "* membership:", "- workload: unchanged", "[informational]", "standalone", "== Strategies", "(selected)", "== Limitations", "critical operations declared: ec2:CreateTransitGatewayVpcAttachment", "proposed: 2 OU(s), 1 policy(ies), 1 share(s)", "(declared)"} {
		if !strings.Contains(text, want) {
			t.Errorf("text should contain %q", want)
		}
	}
	md := StagesMarkdown(rep)
	for _, want := range []string{"# orgshift staged verdict: NO-GO", "## Stages", "| 3 | Destination organization entry at the root | ", "## Declared critical operations", "## Proposed objects", "- OU **Legacy** (`ou-proposed-legacy`) under `r-fern`, policies p-fern0002", "## Stage 6: Control Tower enrollment into the Payments OU: NO-GO", "### Stage findings", "Category potential-impact, confidence medium.", "### Operator verification at this stage", "- [ ] transit gateway attachment created and routes propagated", "### Transition into this stage", "## Strategies compared", "### Transfer the account into the destination organization (selected)", "**Reversal limitations**", "## Limitations of the offline evaluation", "Models used: rcp-applicability"} {
		if !strings.Contains(md, want) {
			t.Errorf("markdown should contain %q", want)
		}
	}
	data, err := StagesJSON(rep)
	if err != nil {
		t.Fatal(err)
	}
	var back scenario.Report
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatal(err)
	}
	if len(back.Stages) != 7 || back.Stages[2].Transition == nil || back.Stages[2].Transition.Subject.CrossOrg != true || back.SchemaVersion != scenario.ReportSchemaVersion {
		t.Errorf("JSON round trip: %d stages", len(back.Stages))
	}
	if strings.Contains(string(data), `"snapshot_version"`) {
		t.Error("derived snapshots must not be exported")
	}
}

// The workload layer and the redeployment plan are part of every rendering.
func TestStagesRenderTheWorkloadLayer(t *testing.T) {
	rep := stagedReport(t)
	text := StagesText(rep)
	for _, want := range []string{"- workload: unchanged [evaluated];", "workload layer evaluated: 8 stack(s) with 37 resource(s)", "1 stack(s) are deleted by their StackSet on leaving",
		"(from the workload inventory)", "what must be redeployed (workload layer evaluated):", "redeployable from a template or pipeline: 5 stack(s) with 27 resource(s) and 3 sampled resource(s) outside any stack",
		"stack payments-api (us-east-1, 7 resource(s)) [plain CloudFormation stack, high confidence]", "function:settlement-notifier [unknown, low confidence]",
		"to:   Fernhill Group (`o-fernhill0001`) Root / Business Units / Payments"} {
		if !strings.Contains(text, want) {
			t.Errorf("text should contain %q", want)
		}
	}
	md := StagesMarkdown(rep)
	for _, want := range []string{"| Layer | Change | Evaluation |", "| workload | unchanged | **evaluated**: 8 stack(s) with 37 resource(s)", " - (evaluated) |",
		"**What must be redeployed** (workload layer evaluated; an inventory with counts, not an estimate of effort)", "| redeployable from a template or pipeline | 5 | 27 | 3 |",
		"| recreated by Control Tower or a StackSet | `StackSet-larkspur-baseline-roles-", "| manual or unknown | `arn:aws:sqs:us-east-1:111111111115:fraud-events` | us-east-1 | unknown | low |  |",
		"Workload layer: evaluated", "| `workloads.stacks` | observed |"} {
		if !strings.Contains(md, want) {
			t.Errorf("markdown should contain %q", want)
		}
	}
	// A recreate scenario keeps the account in the source organization, and
	// the header says so.
	sc, err := scenario.Parse([]byte(fixtures.PaymentsRecreatedInFernhill))
	if err != nil {
		t.Fatal(err)
	}
	rc, err := scenario.Run(scenario.Input{Scenario: sc, Source: fixtures.Larkspur(), Destination: fixtures.Fernhill(), Version: "test"})
	if err != nil {
		t.Fatal(err)
	}
	text = StagesText(rc)
	for _, want := range []string{"to:   Larkspur Holdings (`o-larkspur0001`) Root / Workloads / Production", "* workload: workloads relocate to account 222222222229", "REVIEW [potential-impact] Workload relocation: 8 stack(s) and 6 sampled resource(s) outside stacks",
		"Create destination accounts and migrate the workloads (selected)"} {
		if !strings.Contains(text, want) {
			t.Errorf("recreate text should contain %q", want)
		}
	}
	if md := StagesMarkdown(rc); !strings.Contains(md, "from Larkspur Holdings (`o-larkspur0001`) at Root / Workloads / Production / larkspur-payments-prod to Larkspur Holdings") {
		t.Error("recreate markdown should say the account stays in the source organization")
	}
}
