package web

import (
	"bytes"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/MrShaaba/orgshift/internal/fixtures"
	"github.com/MrShaaba/orgshift/internal/snapshot"
)

func newTestServer(t *testing.T, withFixtures bool) *httptest.Server {
	t.Helper()
	store := NewStore()
	if withFixtures {
		store.LoadFixtures()
	}
	srv, err := New(store, log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return ts
}

func get(t *testing.T, ts *httptest.Server, path string, headers map[string]string) (*http.Response, string) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, ts.URL+path, nil)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp, string(body)
}

func TestIndexAndPartials(t *testing.T) {
	ts := newTestServer(t, true)
	resp, body := get(t, ts, "/", nil)
	if resp.StatusCode != 200 || !strings.Contains(body, "Plan a move") || !strings.Contains(body, fixtures.LarkspurName) {
		t.Fatalf("index: %d %s", resp.StatusCode, body[:200])
	}
	_, body = get(t, ts, "/partials/accounts?from="+escape(fixtures.LarkspurName), nil)
	if !strings.Contains(body, "larkspur-payments-prod (111111111115)") || !strings.Contains(body, `label="Root / Workloads / Production"`) {
		t.Fatalf("accounts partial: %s", body)
	}
	_, body = get(t, ts, "/partials/ous?to="+escape(fixtures.FernhillName), nil)
	if !strings.Contains(body, `value="ou-fern-pay1"`) {
		t.Fatalf("ous partial: %s", body)
	}
	resp, _ = get(t, ts, "/static/htmx.min.js", nil)
	if resp.StatusCode != 200 {
		t.Fatal("htmx must be embedded")
	}
	resp, _ = get(t, ts, "/static/style.css", nil)
	if resp.StatusCode != 200 {
		t.Fatal("stylesheet must be embedded")
	}
}

func TestSimulateHTMXAndFullPage(t *testing.T) {
	ts := newTestServer(t, true)
	q := "from=" + escape(fixtures.LarkspurName) + "&to=" + escape(fixtures.FernhillName) + "&account=111111111115&target_ou=ou-fern-pay1"
	resp, body := get(t, ts, "/simulate?"+q, map[string]string{"HX-Request": "true"})
	if resp.StatusCode != 200 || strings.Contains(body, "<html") {
		t.Fatalf("htmx response should be a partial: %d", resp.StatusCode)
	}
	for _, want := range []string{"NO-GO", "Fernhill-EU-Only-Regions", "after the move", "What changes", "Export JSON", "larkspur-core-network"} {
		if !strings.Contains(body, want) {
			t.Errorf("result missing %q", want)
		}
	}
	if resp.Header.Get("HX-Push-Url") == "" {
		t.Error("expected HX-Push-Url so the result is linkable")
	}
	resp, body = get(t, ts, "/simulate?"+q, nil)
	if resp.StatusCode != 200 || !strings.Contains(body, "<html") || !strings.Contains(body, "verdict-pill nogo") {
		t.Fatalf("full page: %d", resp.StatusCode)
	}
	// POST form (what the HTMX form sends).
	resp, err := ts.Client().Post(ts.URL+"/simulate", "application/x-www-form-urlencoded", strings.NewReader(q))
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("post simulate: %v %d", err, resp.StatusCode)
	}
	resp.Body.Close()
	// Errors.
	resp, body = get(t, ts, "/simulate?from=nope&account=1&target_ou=x", map[string]string{"HX-Request": "true"})
	if resp.StatusCode != 422 || !strings.Contains(body, "not loaded") {
		t.Fatalf("expected 422 with message, got %d %s", resp.StatusCode, body)
	}
}

func TestExports(t *testing.T) {
	ts := newTestServer(t, true)
	q := "from=" + escape(fixtures.LarkspurName) + "&to=" + escape(fixtures.FernhillName) + "&account=111111111115&target_ou=ou-fern-pay1"
	resp, body := get(t, ts, "/export.json?"+q, nil)
	if resp.StatusCode != 200 || resp.Header.Get("Content-Type") != "application/json" || !strings.Contains(body, `"verdict": "NO-GO"`) {
		t.Fatalf("json export: %d %s", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
	resp, body = get(t, ts, "/export.md?"+q, nil)
	if resp.StatusCode != 200 || !strings.HasPrefix(body, "# orgshift verdict: NO-GO") {
		t.Fatalf("markdown export: %d", resp.StatusCode)
	}
}

func TestUploadAndSameOrg(t *testing.T) {
	ts := newTestServer(t, false)
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	fw, _ := mw.CreateFormFile("source", "lark.json")
	data, _ := snapshot.Marshal(fixtures.Larkspur())
	fw.Write(data)
	mw.Close()
	client := ts.Client()
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := client.Post(ts.URL+"/snapshots", mw.FormDataContentType(), &buf)
	if err != nil || resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("upload: %v %d", err, resp.StatusCode)
	}
	resp.Body.Close()
	q := "from=" + escape(fixtures.LarkspurName) + "&to=" + escape(fixtures.LarkspurName) + "&account=111111111116&target_ou=ou-lark-prod"
	resp, body := get(t, ts, "/simulate?"+q, map[string]string{"HX-Request": "true"})
	if resp.StatusCode != 200 || !strings.Contains(body, "verdict-pill go") {
		t.Fatalf("same-org simulate: %d", resp.StatusCode)
	}
	// Bad upload.
	buf.Reset()
	mw = multipart.NewWriter(&buf)
	fw, _ = mw.CreateFormFile("source", "bad.json")
	fw.Write([]byte(`{"schema_version": 1}`))
	mw.Close()
	resp, _ = client.Post(ts.URL+"/snapshots", mw.FormDataContentType(), &buf)
	if loc := resp.Header.Get("Location"); !strings.Contains(loc, "error=") {
		t.Fatalf("invalid snapshot should redirect with an error, got %s", loc)
	}
	resp.Body.Close()
}

func escape(s string) string { return strings.ReplaceAll(s, " ", "+") }

func TestSubjectPartialAndOUSimulation(t *testing.T) {
	ts := newTestServer(t, true)
	_, body := get(t, ts, "/partials/subject?kind=ou&from="+escape(fixtures.LarkspurName)+"&ou_preselect=ou-lark-work", nil)
	if !strings.Contains(body, `name="ou"`) || !strings.Contains(body, `value="ou-lark-work" selected`) || strings.Contains(body, `value="r-lark"`) {
		t.Fatalf("ou subject partial should list OUs (not the root) with the preselection: %s", body)
	}
	if !strings.Contains(body, "Workloads (ou-lark-work) · 3 accounts") || !strings.Contains(body, "Production (ou-lark-prod) · 2 accounts") {
		t.Errorf("ou labels should carry account counts: %s", body)
	}
	_, body = get(t, ts, "/partials/subject?kind=account&from="+escape(fixtures.LarkspurName), nil)
	if !strings.Contains(body, `name="account"`) {
		t.Fatalf("account subject partial: %s", body)
	}
	_, body = get(t, ts, "/", nil)
	if !strings.Contains(body, `name="kind" value="ou"`) || !strings.Contains(body, "a whole OU") {
		t.Fatal("index should offer the whole-OU toggle")
	}

	q := "kind=ou&from=" + escape(fixtures.LarkspurName) + "&to=" + escape(fixtures.FernhillName) + "&ou=ou-lark-work&target_ou=ou-fern-bu"
	resp, body := get(t, ts, "/simulate?"+q, map[string]string{"HX-Request": "true"})
	if resp.StatusCode != 200 || strings.Contains(body, "<html") {
		t.Fatalf("htmx response should be a partial: %d", resp.StatusCode)
	}
	for _, want := range []string{"OU Workloads", "verdict-pill nogo", `class="rollup"`, "larkspur-payments-prod", "larkspur-payments-dev", "larkspur-data-prod",
		"Workloads / Production", "must be recreated under Business Units", "recreate in the target", `id="acct-111111111115"`, "Policy chain down to the OU",
		"What changes at the OU", "Larkspur-Allowed-Regions", "after the move"} {
		if !strings.Contains(body, want) {
			t.Errorf("OU result missing %q", want)
		}
	}
	if push := resp.Header.Get("HX-Push-Url"); !strings.Contains(push, "kind=ou") || !strings.Contains(push, "ou=ou-lark-work") {
		t.Errorf("HX-Push-Url should carry the OU parameters, got %q", push)
	}
	// The target tree draws the moved subtree under Business Units, with the nested OUs and accounts as ghosts.
	if !strings.Contains(body, `node ou on-path subject ghost`) || !strings.Contains(body, `node account   ghost`) {
		t.Error("target tree should contain the ghost OU subtree")
	}
	// Full page keeps the form state and the OU result.
	resp, body = get(t, ts, "/simulate?"+q, nil)
	if resp.StatusCode != 200 || !strings.Contains(body, "<html") || !strings.Contains(body, `name="kind" value="ou" checked`) || !strings.Contains(body, `name="ou_preselect" value="ou-lark-work"`) {
		t.Fatalf("full page should preselect the OU: %d", resp.StatusCode)
	}
	// Same-org move: attachments travel.
	q = "kind=ou&from=" + escape(fixtures.LarkspurName) + "&to=" + escape(fixtures.LarkspurName) + "&ou=ou-lark-prod&target_ou=r-lark"
	_, body = get(t, ts, "/simulate?"+q, map[string]string{"HX-Request": "true"})
	if !strings.Contains(body, "moves with the OU") || !strings.Contains(body, "Larkspur-Daily-Backups") {
		t.Error("same-org OU result should list carried attachments")
	}
	// Errors.
	q = "kind=ou&from=" + escape(fixtures.LarkspurName) + "&to=" + escape(fixtures.LarkspurName) + "&ou=ou-lark-work&target_ou=ou-lark-prod"
	resp, body = get(t, ts, "/simulate?"+q, map[string]string{"HX-Request": "true"})
	if resp.StatusCode != 422 || !strings.Contains(body, "under itself") {
		t.Fatalf("moving an OU under its descendant should be a 422, got %d %s", resp.StatusCode, body)
	}
}

func TestOUExports(t *testing.T) {
	ts := newTestServer(t, true)
	q := "kind=ou&from=" + escape(fixtures.LarkspurName) + "&to=" + escape(fixtures.FernhillName) + "&ou=ou-lark-work&target_ou=ou-fern-bu"
	resp, body := get(t, ts, "/export.json?"+q, nil)
	if resp.StatusCode != 200 || !strings.Contains(body, `"ou_id": "ou-lark-work"`) || !strings.Contains(resp.Header.Get("Content-Disposition"), "orgshift-ou-ou-lark-work-to-ou-fern-bu.json") {
		t.Fatalf("ou json export: %d %s", resp.StatusCode, resp.Header.Get("Content-Disposition"))
	}
	resp, body = get(t, ts, "/export.md?"+q, nil)
	if resp.StatusCode != 200 || !strings.HasPrefix(body, "# orgshift verdict: NO-GO") || !strings.Contains(body, "## Accounts") {
		t.Fatalf("ou markdown export: %d", resp.StatusCode)
	}
}

func TestControlTowerInTheUI(t *testing.T) {
	ts := newTestServer(t, true)
	q := "from=" + escape(fixtures.FernhillName) + "&to=" + escape(fixtures.FernhillName) + "&account=" + fixtures.FernhillRetailProd + "&target_ou=" + fixtures.FernhillSandboxOU
	resp, body := get(t, ts, "/simulate?"+q, nil)
	if resp.StatusCode != 200 || !strings.Contains(body, "verdict-pill review") {
		t.Fatalf("simulate: %d", resp.StatusCode)
	}
	for _, want := range []string{
		"<h3>Control Tower</h3>",
		"Moving out of the registered OU Retail unenrolls the account from Control Tower",
		"vended by Account Factory",
		`<span class="kind">landing-zone</span>`,
		`class="chip  ct"`, `<span class="ctmark">CT</span>`,
		`<span class="pill ct" title="A preventive control enforced by Control Tower`,
		`class="badge ct" title="Registered with Control Tower (baseline 4.0, SUCCEEDED); controls enabled here: AWS-GR_CLOUDTRAIL_ENABLED`,
		`aws-guardrails-kjwqpf (Control Tower guardrail)`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("result page missing %q", want)
		}
	}
	// A cross-org OU move shows the guardrail's fate.
	q = "kind=ou&from=" + escape(fixtures.FernhillName) + "&to=" + escape(fixtures.LarkspurName) + "&ou=" + fixtures.FernhillBusinessUnitsOU + "&target_ou=ou-lark-work"
	resp, body = get(t, ts, "/simulate?"+q, nil)
	if resp.StatusCode != 200 || !strings.Contains(body, "re-attached by Control Tower when the new OU is registered") || !strings.Contains(body, "registered OU(s) in the moved tree have to be deregistered") {
		t.Errorf("OU result should show the guardrail fate and the registered OU finding (%d)", resp.StatusCode)
	}
}
