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
