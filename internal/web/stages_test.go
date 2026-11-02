package web

import (
	"bytes"
	"mime/multipart"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/MrShaaba/orgshift/internal/fixtures"
	"github.com/MrShaaba/orgshift/internal/scenario"
)

func TestStagesInTheUI(t *testing.T) {
	ts := newTestServer(t, true)
	_, index := get(t, ts, "/", nil)
	for _, want := range []string{"3. Stage a migration", fixtures.PaymentsToFernhillStagedName, fixtures.SandboxToBusinessUnitsStagedName, "Evaluate the stages"} {
		if !strings.Contains(index, want) {
			t.Errorf("index should contain %q", want)
		}
	}
	q := url.Values{"scenario": {fixtures.PaymentsToFernhillStagedName}, "from": {fixtures.LarkspurName}, "to": {fixtures.FernhillName}}
	resp, body := get(t, ts, "/stages?"+q.Encode(), nil)
	if resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	for _, want := range []string{"staged · transfer", "Current versus proposed hierarchy", `class="pill proposed"`, "Legacy", "Stage by stage", "Destination organization entry at the root", "layer-chip changed", "Enrollment prerequisites at this stage", "Transition into this stage", "Strategies compared", "Create destination accounts and migrate the workloads", "Limitations of the offline evaluation", "declared", `class="pill cat"`, "standalone"} {
		if !strings.Contains(body, want) {
			t.Errorf("stages page should contain %q", want)
		}
	}
	// HTMX returns the partial and pushes the URL.
	resp, partial := get(t, ts, "/stages?"+q.Encode(), map[string]string{"HX-Request": "true"})
	if resp.Header.Get("HX-Push-Url") == "" || strings.Contains(partial, "<html") || !strings.Contains(partial, "Stage by stage") {
		t.Errorf("htmx partial: push=%q", resp.Header.Get("HX-Push-Url"))
	}
	// Exports.
	resp, js := get(t, ts, "/stages.json?"+q.Encode(), nil)
	if resp.StatusCode != 200 || !strings.Contains(js, `"stages_schema_version": 1`) || !strings.Contains(js, `"id": "enroll"`) || strings.Contains(js, `"schema_version": 2`) {
		t.Errorf("json export: %d %s", resp.StatusCode, js[:200])
	}
	resp, md := get(t, ts, "/stages.md?"+q.Encode(), nil)
	if resp.StatusCode != 200 || !strings.HasPrefix(md, "# orgshift staged verdict") || !strings.Contains(md, "## Strategies compared") {
		t.Errorf("markdown export: %d", resp.StatusCode)
	}
	// Same-organization scenario: the destination is the source.
	q = url.Values{"scenario": {fixtures.SandboxToBusinessUnitsStagedName}, "from": {fixtures.FernhillName}, "to": {fixtures.FernhillName}}
	resp, body = get(t, ts, "/stages?"+q.Encode(), nil)
	if resp.StatusCode != 200 || !strings.Contains(body, "Transitional") || strings.Contains(body, "different organization") {
		t.Errorf("same-org stages: %d", resp.StatusCode)
	}
	// Errors: unknown scenario, wrong snapshots.
	if resp, body := get(t, ts, "/stages?scenario=nope&from="+url.QueryEscape(fixtures.LarkspurName), map[string]string{"HX-Request": "true"}); resp.StatusCode != http.StatusUnprocessableEntity || !strings.Contains(body, "not loaded") {
		t.Errorf("unknown scenario: %d %s", resp.StatusCode, body)
	}
	q = url.Values{"scenario": {fixtures.PaymentsToFernhillStagedName}, "from": {fixtures.FernhillName}, "to": {fixtures.LarkspurName}}
	if resp, body := get(t, ts, "/stages?"+q.Encode(), nil); resp.StatusCode != 200 || !strings.Contains(body, "not in the source snapshot") {
		t.Errorf("wrong source: %d", resp.StatusCode)
	}
}

func TestScenarioUpload(t *testing.T) {
	ts := newTestServer(t, true)
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	fw, _ := mw.CreateFormFile("scenario", "plan.yaml")
	fw.Write([]byte(strings.Replace(scenario.Example, "name: Payments production into Fernhill, staged", "name: Uploaded plan", 1)))
	mw.Close()
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Post(ts.URL+"/scenarios", mw.FormDataContentType(), &buf)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther || !strings.Contains(resp.Header.Get("Location"), "Uploaded+plan") {
		t.Fatalf("upload: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	q := url.Values{"scenario": {"Uploaded plan"}, "from": {fixtures.LarkspurName}, "to": {fixtures.FernhillName}}
	if resp, body := get(t, ts, "/stages?"+q.Encode(), nil); resp.StatusCode != 200 || !strings.Contains(body, "Uploaded plan") {
		t.Errorf("uploaded scenario: %d", resp.StatusCode)
	}
	// A broken file is reported.
	buf.Reset()
	mw = multipart.NewWriter(&buf)
	fw, _ = mw.CreateFormFile("scenario", "bad.yaml")
	fw.Write([]byte("schema_version: 1\nname: x\n"))
	mw.Close()
	resp, _ = client.Post(ts.URL+"/scenarios", mw.FormDataContentType(), &buf)
	resp.Body.Close()
	if !strings.Contains(resp.Header.Get("Location"), "error=") {
		t.Errorf("broken scenario should redirect with an error: %s", resp.Header.Get("Location"))
	}
}
