package report

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/MrShaaba/orgshift/internal/awsaccess"
	"github.com/MrShaaba/orgshift/internal/preflight"
)

func samplePreflight() *preflight.Result {
	return &preflight.Result{
		Tool: "orgshift preflight test", SchemaVersion: preflight.SchemaVersion, GeneratedAt: "2026-11-02T12:00:00Z", Ready: false,
		Sides: []preflight.SideResult{{
			Name:       "source",
			Identities: []preflight.IdentityCheck{{Side: "source", Access: "management", Expected: "111111111111", Actual: awsaccess.Identity{AccountID: "111111111111", ARN: "arn:aws:sts::111111111111:assumed-role/OrgshiftOrgRead/x"}, Status: preflight.Available, Via: "profile larkspur"}},
			Probes:     []preflight.Probe{{Side: "source", Access: "management", Domain: "resource_shares", Operation: "ram:GetResourceShares", Status: preflight.Denied, Detail: "AccessDeniedException: no | pipe", Millis: 12}},
			Domains:    []preflight.DomainResult{{Domain: "tree", Status: preflight.Available, Required: true}, {Domain: "resource_shares", Status: preflight.Denied, Required: true, Detail: "ram:GetResourceShares denied: AccessDeniedException"}},
			Blocking:   []string{"ram:GetResourceShares denied for management"},
			Notes:      []string{"audit account: identity verified"},
		}},
		Matrix: preflight.Matrix{SingleSide: true, Rows: []preflight.Row{
			{Domain: "tree", Why: "the OU hierarchy", Check: "coverage", Source: preflight.Cell{Status: preflight.Available, Required: true}, Target: preflight.Cell{Status: preflight.Unknown, Detail: "no destination configured"}},
			{Domain: "resource_shares", Why: "RAM shares", Check: "ram", Source: preflight.Cell{Status: preflight.Denied, Required: true, Detail: "ram:GetResourceShares denied"}, Target: preflight.Cell{Status: preflight.Unknown}},
			{Domain: "stack_sets", Why: "StackSets", Check: "org-services", Source: preflight.Cell{Status: preflight.Unknown, Required: false, Detail: "not collected by this build"}, Target: preflight.Cell{Status: preflight.Unknown}},
		}},
		Blocking: []string{"source: ram:GetResourceShares denied for management (AccessDeniedException): grant it to arn:aws:sts::111111111111:assumed-role/OrgshiftOrgRead/x"},
		Notes:    []string{"A probe reads one page."},
	}
}

func TestPreflightRenderings(t *testing.T) {
	r := samplePreflight()
	text := PreflightText(r)
	for _, want := range []string{"PREFLIGHT: NOT READY", "Identities", "source       management", "arn:aws:sts::111111111111:assumed-role/OrgshiftOrgRead/x", "(via profile larkspur)",
		"Capabilities (coverage matrix format)", "destination (none)", "resource_shares", "denied", "stack_sets", "unknown*", "Blocking", "grant it to", "Notes", "source: audit account: identity verified"} {
		if !strings.Contains(text, want) {
			t.Errorf("text should contain %q:\n%s", want, text)
		}
	}
	md := PreflightMarkdown(r)
	for _, want := range []string{"# Preflight: NOT READY", "| Side | Access | Expected account |", "| `tree` | the OU hierarchy | coverage | available | unknown (not required): no destination configured |",
		"| `resource_shares` | RAM shares | ram | denied: ram:GetResourceShares denied |", "unknown (not required): not collected by this build", "## Blocking", "## Probes", "no \\| pipe", "## Notes"} {
		if !strings.Contains(md, want) {
			t.Errorf("markdown should contain %q:\n%s", want, md)
		}
	}
	data, err := PreflightJSON(r)
	if err != nil {
		t.Fatal(err)
	}
	var back preflight.Result
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatal(err)
	}
	if back.Ready || len(back.Matrix.Rows) != 3 || back.Sides[0].Probes[0].Status != preflight.Denied || back.SchemaVersion != preflight.SchemaVersion {
		t.Errorf("JSON round trip: %+v", back)
	}
	r.Ready, r.Blocking = true, nil
	if text := PreflightText(r); !strings.HasPrefix(text, "PREFLIGHT: READY") || strings.Contains(text, "Blocking") {
		t.Errorf("ready text: %s", text)
	}
}
