package iamtemplates

import (
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/MrShaaba/orgshift/internal/collector"
	"github.com/MrShaaba/orgshift/internal/config"
)

var update = flag.Bool("update", false, "rewrite docs/iam from the generator")

func TestEveryWildcardIsJustifiedAndActionsMatchTheCatalog(t *testing.T) {
	ts, err := Generate(Input{})
	if err != nil {
		t.Fatal(err)
	}
	if len(ts) != len(collector.Responsibilities) {
		t.Fatalf("one template per responsibility, got %d", len(ts))
	}
	for _, tpl := range ts {
		var trust map[string]any
		if err := json.Unmarshal(tpl.TrustPolicy, &trust); err != nil {
			t.Errorf("%s trust policy is not JSON: %v", tpl.ID, err)
		}
		granted := map[string]bool{}
		for _, s := range tpl.Statements {
			for _, r := range s.Resource {
				if r == "*" && len(s.Justification) < 40 {
					t.Errorf("%s/%s: Resource * needs a real justification", tpl.ID, s.Sid)
				}
			}
			for _, a := range s.Actions {
				granted[a] = true
				op, ok := collector.Lookup(a)
				if !ok || !op.Used || !op.For(tpl.ID) {
					t.Errorf("%s/%s grants %s, which the catalog does not list as used by %s", tpl.ID, s.Sid, a, tpl.ID)
				}
			}
		}
		// Billable reads are never in the default permissions policy: they
		// sit in a separate opt-in statement, each with its justification.
		optIn := map[string]bool{}
		for _, s := range tpl.OptIn {
			if len(s.Justification) < 40 || !strings.Contains(s.Justification, "bills") {
				t.Errorf("%s/%s: an opt-in statement says what AWS bills", tpl.ID, s.Sid)
			}
			for _, a := range s.Actions {
				optIn[a] = true
				op, ok := collector.Lookup(a)
				if !ok || !op.Used || op.Kind != collector.KindReadBillable || op.OptIn == "" {
					t.Errorf("%s/%s: %s is not a billable read with an opt-in", tpl.ID, s.Sid, a)
				}
			}
		}
		for _, a := range collector.ActionsFor(tpl.ID, false) {
			op, _ := collector.Lookup(a)
			switch {
			case op.Kind == collector.KindReadBillable && granted[a]:
				t.Errorf("%s: billable %s must not be in the default permissions policy", tpl.ID, a)
			case op.Kind == collector.KindReadBillable && !optIn[a]:
				t.Errorf("%s: billable %s is missing from the opt-in statement", tpl.ID, a)
			case op.Kind != collector.KindReadBillable && !granted[a]:
				t.Errorf("%s: catalog action %s is not in the permissions policy", tpl.ID, a)
			}
		}
		if (tpl.OptInPolicy == nil) != (len(tpl.OptIn) == 0) {
			t.Errorf("%s: opt-in policy and statements disagree", tpl.ID)
		}
		for _, p := range tpl.Planned {
			if p.Used || granted[p.Action()] {
				t.Errorf("%s: planned %s must not be granted", tpl.ID, p.Action())
			}
		}
		if tpl.DelegatedAdministrator == "" || tpl.Account == "" || tpl.Purpose == "" || len(tpl.References) == 0 || len(tpl.Commands) == 0 {
			t.Errorf("%s is missing prose: %+v", tpl.ID, tpl)
		}
		if (tpl.PermissionsPolicy == nil) != (len(tpl.Statements) == 0) {
			t.Errorf("%s: permissions policy and statements disagree", tpl.ID)
		}
		if tpl.PermissionsPolicy != nil {
			var perm struct {
				Statement []struct {
					Effect string
					Action []string
				}
			}
			if err := json.Unmarshal(tpl.PermissionsPolicy, &perm); err != nil {
				t.Fatalf("%s permissions policy: %v", tpl.ID, err)
			}
			for _, s := range perm.Statement {
				if s.Effect != "Allow" {
					t.Errorf("%s: only Allow statements", tpl.ID)
				}
				for _, a := range s.Action {
					if collector.WriteVerb(strings.SplitN(a, ":", 2)[1]) {
						t.Errorf("%s grants a write verb: %s", tpl.ID, a)
					}
				}
			}
		}
	}
}

func TestPlaceholdersAndConfiguredValues(t *testing.T) {
	ts, err := Generate(Input{})
	if err != nil {
		t.Fatal(err)
	}
	byID := map[collector.Responsibility]Template{}
	for _, tpl := range ts {
		byID[tpl.ID] = tpl
	}
	org := byID[collector.RoleOrgManagement]
	if !strings.Contains(string(org.TrustPolicy), PlaceholderOperatorARN) || !strings.Contains(org.Account, PlaceholderManagementAccount) {
		t.Errorf("placeholders expected without a configuration: %s", org.TrustPolicy)
	}
	if !strings.Contains(string(org.PermissionsPolicy), "arn:aws:iam::*:role/OrgshiftMemberRead") || !strings.Contains(string(org.PermissionsPolicy), "aws:ResourceOrgID") {
		t.Errorf("the org role assumes the member role inside the organization only: %s", org.PermissionsPolicy)
	}
	if org.DelegationPolicy == nil || !strings.Contains(string(org.DelegationPolicy), "organizations:ListTargetsForPolicy") {
		t.Errorf("delegation policy example: %s", org.DelegationPolicy)
	}
	member := byID[collector.RoleMemberInspection]
	if !strings.Contains(string(member.TrustPolicy), "arn:aws:iam::<management-account-id>:role/OrgshiftOrgRead") {
		t.Errorf("member role trusts the org role: %s", member.TrustPolicy)
	}
	perm := string(member.PermissionsPolicy)
	for _, want := range []string{"cloudformation:DescribeStacks", "cloudformation:ListStacks", "cloudformation:GetTemplate", "tag:GetResources", "resource-explorer-2:Search", "iam:ListRoles"} {
		if !strings.Contains(perm, want) {
			t.Errorf("member permissions should grant %s: %s", want, perm)
		}
	}
	if strings.Contains(perm, "s3:") {
		t.Errorf("the S3 reads are billed and must not be in the default member policy: %s", perm)
	}
	if optIn := string(member.OptInPolicy); !strings.Contains(optIn, "s3:GetBucketPolicy") || !strings.Contains(optIn, "s3:ListAllMyBuckets") || strings.Contains(optIn, "s3:ListBuckets\"") {
		t.Errorf("the opt-in policy carries the S3 reads under their IAM names: %s", optIn)
	}
	if !strings.Contains(strings.Join(member.Commands, "\n"), "# only for the billable opt-in: aws iam put-role-policy") {
		t.Errorf("the opt-in policy is attached by a separate, commented command: %v", member.Commands)
	}
	if !strings.Contains(string(org.PermissionsPolicy), "cloudformation:ListStackSets") {
		t.Errorf("the org role reads the StackSets: %s", org.PermissionsPolicy)
	}
	if !strings.Contains(byID[collector.RoleControlTower].DelegatedAdministrator, "no delegated administrator") && !strings.Contains(byID[collector.RoleControlTower].DelegatedAdministrator, "None") {
		t.Error("control tower has no delegated administrator")
	}

	cfg, err := config.Parse([]byte(config.Example))
	if err != nil {
		t.Fatal(err)
	}
	cfg.Templates.ExternalID = "secret-handshake"
	ts, err = Generate(Input{Config: cfg})
	if err != nil {
		t.Fatal(err)
	}
	for _, tpl := range ts {
		byID[tpl.ID] = tpl
	}
	org = byID[collector.RoleOrgManagement]
	if !strings.Contains(string(org.TrustPolicy), "arn:aws:iam::111111111111:role/PlatformOperators") || !strings.Contains(string(org.TrustPolicy), "secret-handshake") || strings.Contains(string(org.TrustPolicy), "<") {
		t.Errorf("configured trust: %s", org.TrustPolicy)
	}
	if !strings.Contains(string(org.PermissionsPolicy), "arn:aws:iam::111111111120:role/OrgshiftNetworkRead") || !strings.Contains(org.Account, "111111111111") {
		t.Errorf("configured network account and management account: %s %s", org.PermissionsPolicy, org.Account)
	}
	if net := byID[collector.RoleNetwork]; !strings.Contains(string(net.TrustPolicy), "arn:aws:iam::111111111111:role/OrgshiftOrgRead") || !strings.Contains(net.Account, "111111111120") {
		t.Errorf("network role: %s %s", net.TrustPolicy, net.Account)
	}
	if m := byID[collector.RoleMemberInspection]; m.RoleName != "OrgshiftMemberRead" || strings.Contains(string(m.TrustPolicy), "sts:ExternalId") {
		t.Errorf("member role without an external id: %s", m.TrustPolicy)
	}
	md := Markdown(ts, Input{Config: cfg})
	if !strings.Contains(md, "Larkspur Holdings") || !strings.Contains(md, "## org-management") || !strings.Contains(md, "aws iam create-role --role-name OrgshiftOrgRead") || !strings.Contains(md, "Planned for later milestones") {
		t.Errorf("markdown: %s", md)
	}
	ts, err = Generate(Input{Config: cfg, Side: "destination"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(ts[0].TrustPolicy), "PlatformOperators") || !strings.Contains(ts[0].Account, "222222222222") {
		t.Errorf("destination side: %s", ts[0].Account)
	}
	if _, err := Generate(Input{Config: cfg, Side: "elsewhere"}); err == nil {
		t.Error("unknown side must fail")
	}
}

func TestWriteFiles(t *testing.T) {
	ts, err := Generate(Input{})
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	paths, err := Write(dir, ts, Input{})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"README.md", "control-tower-permissions.json", "control-tower-trust.json", "identity-center-permissions.json", "identity-center-trust.json", "member-inspection-billable-opt-in.json", "member-inspection-permissions.json", "member-inspection-trust.json", "network-permissions.json", "network-trust.json", "org-management-delegation-policy.json", "org-management-permissions.json", "org-management-trust.json"}
	if len(paths) != len(want) {
		t.Fatalf("files: %v", paths)
	}
	for i, p := range paths {
		if filepath.Base(p) != want[i] {
			t.Errorf("file %d = %s, want %s", i, filepath.Base(p), want[i])
		}
	}
}

// TestDocsIAMMatchesTheGenerator keeps docs/iam in step with the catalog
// and the generator. Run go test ./internal/iamtemplates -update after a
// reviewed change.
func TestDocsIAMMatchesTheGenerator(t *testing.T) {
	ts, err := Generate(Input{})
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join("..", "..", "docs", "iam")
	files := Files(ts, Input{})
	if *update {
		if err := os.RemoveAll(dir); err != nil {
			t.Fatal(err)
		}
		if _, err := Write(dir, ts, Input{}); err != nil {
			t.Fatal(err)
		}
	}
	for name, want := range files {
		got, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("%s: %v (run with -update)", name, err)
		}
		if string(got) != string(want) {
			t.Errorf("docs/iam/%s is out of date; run go test ./internal/iamtemplates -update", name)
		}
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if _, ok := files[e.Name()]; !ok {
			t.Errorf("docs/iam/%s is not generated; remove it or teach the generator", e.Name())
		}
	}
}

// With the opt-in on in the configuration, the S3 statement is part of the
// member role's permissions policy and no separate opt-in file is written.
func TestBucketPolicyOptInMovesIntoThePermissionsPolicy(t *testing.T) {
	cfg, err := config.Parse([]byte(config.Example))
	if err != nil {
		t.Fatal(err)
	}
	cfg.Billable.BucketPolicies = true
	ts, err := Generate(Input{Config: cfg})
	if err != nil {
		t.Fatal(err)
	}
	for _, tpl := range ts {
		if tpl.ID != collector.RoleMemberInspection {
			continue
		}
		perm := string(tpl.PermissionsPolicy)
		if !strings.Contains(perm, "s3:GetBucketPolicy") || !strings.Contains(perm, "s3:ListAllMyBuckets") || tpl.OptInPolicy != nil || len(tpl.OptIn) != 0 {
			t.Errorf("opted in, the S3 reads belong to the permissions policy: %s", perm)
		}
		if !strings.Contains(strings.Join(tpl.Notes, " "), "billable.bucket_policies is on") {
			t.Errorf("the notes should say why the S3 statement is there: %v", tpl.Notes)
		}
		if _, ok := Files(ts, Input{Config: cfg})["member-inspection-billable-opt-in.json"]; ok {
			t.Error("no separate opt-in file when the statement is in the permissions policy")
		}
	}
}
