package web

import (
	"net/url"
	"strings"
	"testing"

	"github.com/MrShaaba/orgshift/internal/fixtures"
)

// The result page carries the workload panel: the evaluation level, the
// redeployment groups, every stack with its provenance and evidence, the
// resource sample and the policies tied to the organization.
func TestWorkloadPanelOnTheResultPage(t *testing.T) {
	ts := newTestServer(t, true)
	q := "from=" + escape(fixtures.LarkspurName) + "&to=" + escape(fixtures.FernhillName) + "&account=111111111115&target_ou=ou-fern-pay1"
	resp, body := get(t, ts, "/simulate?"+q, nil)
	if resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	for _, want := range []string{
		`<section class="panel workload-panel" id="workloads">`, `<h2>Workloads <span class="pill go">evaluated</span></h2>`,
		"8 stack(s) with 37 resource(s), 14 sampled resource(s) from tagging-api", "The Workloads check has 8 item(s) to settle and 3 informational.",
		`<strong>workloads.stacks</strong> <span class="pill go">observed</span>`,
		"How it would be redeployed", `<td>redeployable from a template or pipeline</td><td class="num">5</td><td class="num">27</td><td class="num">3</td>`,
		`<td>recreated by Control Tower or a StackSet</td><td class="num">3</td><td class="num">10</td><td class="num">0</td>`,
		`<td>manual or unknown</td><td class="num">0</td><td class="num">0</td><td class="num">3</td>`,
		"Stacks (8)", `<span class="pill prov stackset-service-managed">service-managed StackSet</span> <span class="pill go" title="confidence of the classification">high</span>`,
		"the stack ID is listed as an instance of StackSet larkspur-baseline-roles", "auto-deployment true, retain stacks on account removal false, targets ou-lark-work",
		`<span class="pill prov stack">plain CloudFormation stack</span>`, "imports 2 exports from payments-network", "reads output LogDestinationArn of stack shared-observability in account 111111111113", "references 2 subnet",
		"Sampled resources (14) from tagging-api", `<span class="pill prov terraform">Terraform-style tag convention</span> <span class="pill review">medium</span>`,
		`<span class="pill prov unknown">unknown</span> <span class="pill info">low</span>`, "<code>Terraform</code> = true",
		"Policies that reference organization identity (3 of 17 read)", "Deny DataPerimeter: StringNotEqualsIfExists <code>aws:PrincipalOrgID</code> o-larkspur0001, o-acquirer0001",
		`<code>AppLogSubscriptionRole</code> of stack <code>payments-api</code>`,
		"(1 derived from the workload inventory)", `Workload layer: <a href="#workloads">evaluated</a>`,
		// The findings sit on the verdict board, and the page is rendered to its end.
		"<h3>Workloads</h3>", "denies the account&#39;s own principals after the move", "What changes: effective policies", "Inputs used for larkspur-payments-prod",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("result page should contain %q", want)
		}
	}
	// An account that was not inspected: the panel says so and shows no tables.
	q = "from=" + escape(fixtures.LarkspurName) + "&to=" + escape(fixtures.FernhillName) + "&account=111111111117&target_ou=ou-fern-sand"
	_, body = get(t, ts, "/simulate?"+q, nil)
	for _, want := range []string{`<h2>Workloads <span class="pill info">not-evaluated</span></h2>`, "no workload inventory for the account", `<span class="pill review">unknown</span>`, "name it under member_inspection.accounts", "What changes: effective policies"} {
		if !strings.Contains(body, want) {
			t.Errorf("uninspected account page should contain %q", want)
		}
	}
	if strings.Contains(body, "How it would be redeployed") || strings.Contains(body, "Stacks (") {
		t.Error("no inventory tables for an account that was not inspected")
	}
	// A denied inventory reads the same way, with the reason on the chips.
	q = "from=" + escape(fixtures.LarkspurPartialName) + "&to=" + escape(fixtures.FernhillName) + "&account=111111111115&target_ou=ou-fern-pay1"
	_, body = get(t, ts, "/simulate?"+q, nil)
	if !strings.Contains(body, `<span class="pill review">access_denied</span>`) || !strings.Contains(body, `<h2>Workloads <span class="pill info">not-evaluated</span></h2>`) {
		t.Error("a denied inventory shows access_denied on the workload domains")
	}
	// The OU page says the level per account.
	q = "kind=ou&from=" + escape(fixtures.LarkspurName) + "&to=" + escape(fixtures.FernhillName) + "&ou=ou-lark-work&target_ou=ou-fern-bu"
	resp, body = get(t, ts, "/simulate?"+q, nil)
	if resp.StatusCode != 200 || !strings.Contains(body, `Workload layer: <span class="pill go">evaluated</span> 8 stack(s) with 37 resource(s)`) || strings.Count(body, "Workload layer: <span") != 3 {
		t.Errorf("OU page should say the workload layer of each of the three accounts: %d", resp.StatusCode)
	}
	// The JSON export carries the layer.
	q = "from=" + escape(fixtures.LarkspurName) + "&to=" + escape(fixtures.FernhillName) + "&account=111111111115&target_ou=ou-fern-pay1"
	_, js := get(t, ts, "/export.json?"+q, nil)
	for _, want := range []string{`"workload_layer": {`, `"evaluation": "evaluated"`, `"derived_operations": 1`, `"id": "workloads"`, `"source": "workload"`} {
		if !strings.Contains(js, want) {
			t.Errorf("json export should contain %q", want)
		}
	}
}

// The stage page shows the workload layer of every stage and, on the
// recreate strategy, what must be redeployed.
func TestWorkloadPanelOnTheStagePage(t *testing.T) {
	ts := newTestServer(t, true)
	q := url.Values{"scenario": {fixtures.PaymentsToFernhillStagedName}, "from": {fixtures.LarkspurName}, "to": {fixtures.FernhillName}}
	resp, body := get(t, ts, "/stages?"+q.Encode(), nil)
	if resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	for _, want := range []string{
		`<strong>workload</strong> unchanged <span class="pill go">evaluated</span>`,
		`<details class="transition stage-workloads">`, `<span class="pill go">evaluated</span> Workload layer going into this stage: 8 stack(s), 14 sampled resource(s), 8 item(s) to settle`,
		// After entry the inventory has lost the instance its StackSet deletes.
		"Workload layer going into this stage: 7 stack(s), 12 sampled resource(s)", "1 stack(s) are deleted by their StackSet on leaving",
		`What must be redeployed <span class="pill go">evaluated</span>`, "An inventory with counts, not an estimate of effort.",
		"redeployable from a template or pipeline: 5 stack(s) with 27 resource(s) and 3 sampled resource(s) outside any stack",
		`<code>payments-ledger-db</code> <span class="muted small">us-east-1</span> <span class="pill prov stack">plain CloudFormation stack</span> <span class="pill go">high</span> <span class="muted small">3 resource(s)</span>`,
		"manual or unknown: 3 sampled resource(s) outside any stack", "Limitations of the offline evaluation",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("stages page should contain %q", want)
		}
	}
	if n := strings.Count(body, `<details class="transition stage-workloads">`); n != 7 {
		t.Errorf("every stage has its workload panel, got %d", n)
	}
	// The recreate scenario is one of the fixtures and lists the relocation.
	_, index := get(t, ts, "/", nil)
	if !strings.Contains(index, fixtures.PaymentsRecreatedInFernhillName) {
		t.Error("the recreate scenario should be offered on the index page")
	}
	q = url.Values{"scenario": {fixtures.PaymentsRecreatedInFernhillName}, "from": {fixtures.LarkspurName}, "to": {fixtures.FernhillName}}
	resp, body = get(t, ts, "/stages?"+q.Encode(), nil)
	for _, want := range []string{"staged · recreate", "Workload relocation: 8 stack(s) and 6 sampled resource(s) outside stacks to bring into the other account, 3 of unknown provenance",
		`<strong>workload</strong> workloads relocate to account 222222222229`, "workloads relocated", "Create destination accounts and migrate the workloads <span class=\"pill subject\">selected</span>", "Limitations of the offline evaluation"} {
		if !strings.Contains(body, want) {
			t.Errorf("recreate stages page should contain %q", want)
		}
	}
	if resp.StatusCode != 200 {
		t.Errorf("status %d", resp.StatusCode)
	}
	// Without an inventory the stage panel and the strategy say so.
	q = url.Values{"scenario": {fixtures.PaymentsRecreatedInFernhillName}, "from": {fixtures.LarkspurPartialName}, "to": {fixtures.FernhillName}}
	_, body = get(t, ts, "/stages?"+q.Encode(), nil)
	for _, want := range []string{`<span class="pill info">not-evaluated</span> Workload layer going into this stage`, "Workload relocation is declared, not evaluated: no workload inventory for the account", `What must be redeployed <span class="pill info">not-evaluated</span>`} {
		if !strings.Contains(body, want) {
			t.Errorf("stages page without an inventory should contain %q", want)
		}
	}
}
