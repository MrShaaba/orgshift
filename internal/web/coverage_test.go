package web

import (
	"strings"
	"testing"

	"github.com/MrShaaba/orgshift/internal/fixtures"
)

func TestCoverageInTheUI(t *testing.T) {
	ts := newTestServer(t, true)
	// Complete fixtures: the matrix is shown and complete.
	q := "from=" + escape(fixtures.LarkspurName) + "&to=" + escape(fixtures.FernhillName) + "&account=" + fixtures.LarkspurPaymentsProd + "&target_ou=" + fixtures.FernhillPaymentsOU
	resp, body := get(t, ts, "/simulate?"+q, nil)
	if resp.StatusCode != 200 {
		t.Fatalf("simulate: %d", resp.StatusCode)
	}
	for _, want := range []string{
		"<h2>Collection coverage <span class=\"pill go\">complete</span></h2>",
		`<table class="rollup coverage">`, "<code>resource_shares</code>", "<code>control_tower.enrolled_accounts</code>",
		"<h3>Collection coverage</h3>", "Complete: all ", "required collection domains were inspected",
		"Models used:", "rcp-applicability", "ram-behaviour",
		"Documentation: <a href=\"https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_rcps.html#rcp-supported-services\">",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("result page missing %q", want)
		}
	}
	if strings.Contains(body, "evidence incomplete") {
		t.Error("complete fixtures must not show incomplete evidence")
	}

	// The partially collected fixture: incomplete matrix, pills on the checks, gap findings and runbook steps.
	q = "from=" + escape(fixtures.LarkspurPartialName) + "&to=" + escape(fixtures.FernhillName) + "&account=" + fixtures.LarkspurPaymentsProd + "&target_ou=" + fixtures.FernhillPaymentsOU
	resp, body = get(t, ts, "/simulate?"+q, nil)
	if resp.StatusCode != 200 {
		t.Fatalf("simulate partial: %d", resp.StatusCode)
	}
	for _, want := range []string{
		`<span class="pill review">incomplete</span>`,
		`<span class="pill review" title="Not completely collected: resource_shares on source">evidence incomplete</span>`,
		`<span class="pill review" title="`, "access_denied",
		"The collector was denied access to resource_shares for the source snapshot",
		`<span class="kind">coverage</span>`,
		"Collect the missing evidence: resource_shares (source snapshot)",
		"orgshift collect --profile &lt;source management profile&gt;",
		"home region",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("partial result page missing %q", want)
		}
	}
	// The index offers the partial fixture.
	_, body = get(t, ts, "/", nil)
	if !strings.Contains(body, fixtures.LarkspurPartialName) {
		t.Error("index should list the partial fixture")
	}
	// Markdown export carries the matrix.
	_, body = get(t, ts, "/export.md?"+q, nil)
	if !strings.Contains(body, "## Collection coverage") || !strings.Contains(body, "| `resource_shares` |") || !strings.Contains(body, "access_denied") {
		t.Error("markdown export should carry the coverage matrix")
	}
	// JSON export carries the matrix and the models.
	_, body = get(t, ts, "/export.json?"+q, nil)
	for _, want := range []string{`"coverage": {`, `"same_snapshot": false`, `"complete": false`, `"gaps": [`, `"models": [`, `"id": "rcp-applicability"`, `"result_schema_version": 3`, `"coverage_gaps": [`} {
		if !strings.Contains(body, want) {
			t.Errorf("json export missing %q", want)
		}
	}
}
