package evaluator

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/MrShaaba/orgshift/internal/fixtures"
	"github.com/MrShaaba/orgshift/internal/snapshot"
)

var update = flag.Bool("update", false, "rewrite golden files")

type scenario struct {
	name     string
	from, to *snapshot.Snapshot
	account  string
	targetOU string
}

func scenarios() []scenario {
	l, f := fixtures.Larkspur(), fixtures.Fernhill()
	return []scenario{
		{"cross-org-payments-to-fernhill", l, f, fixtures.LarkspurPaymentsProd, fixtures.FernhillPaymentsOU},
		{"same-org-payments-dev-to-production", l, nil, "111111111116", "ou-lark-prod"},
		{"same-org-sandbox-to-production", l, nil, "111111111117", "ou-lark-prod"},
		{"cross-org-security-to-fernhill-core", l, f, "111111111113", "ou-fern-core"},
		{"same-org-fernhill-retail-prod-to-sandbox", f, nil, fixtures.FernhillRetailProd, fixtures.FernhillSandboxOU},
	}
}

func TestGolden(t *testing.T) {
	for _, sc := range scenarios() {
		t.Run(sc.name, func(t *testing.T) {
			res, err := Evaluate(Input{From: sc.from, To: sc.to, AccountID: sc.account, TargetOUID: sc.targetOU})
			if err != nil {
				t.Fatal(err)
			}
			got, err := json.MarshalIndent(res, "", "  ")
			if err != nil {
				t.Fatal(err)
			}
			got = append(got, '\n')
			path := filepath.Join("testdata", sc.name+".golden.json")
			if *update {
				if err := os.WriteFile(path, got, 0o644); err != nil {
					t.Fatal(err)
				}
			}
			want, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("missing golden file (run with -update): %v", err)
			}
			if !bytes.Equal(got, want) {
				t.Errorf("result differs from %s (run go test ./internal/evaluator -update after reviewing)", path)
			}
		})
	}
}

func find(t *testing.T, res *Result, checkID string, pred func(Finding) bool) Finding {
	t.Helper()
	for _, c := range res.Checks {
		if c.ID != checkID {
			continue
		}
		for _, f := range c.Findings {
			if pred(f) {
				return f
			}
		}
	}
	t.Fatalf("no finding matched in check %s", checkID)
	return Finding{}
}

func check(res *Result, id string) Check {
	for _, c := range res.Checks {
		if c.ID == id {
			return c
		}
	}
	return Check{}
}

func TestCrossOrgPlantedProblems(t *testing.T) {
	res, err := Evaluate(Input{From: fixtures.Larkspur(), To: fixtures.Fernhill(), AccountID: fixtures.LarkspurPaymentsProd, TargetOUID: fixtures.FernhillPaymentsOU})
	if err != nil {
		t.Fatal(err)
	}
	if res.Verdict != StatusNoGo {
		t.Fatalf("expected NO-GO, got %s: %s", res.Verdict, res.Summary)
	}
	if !res.Subject.CrossOrg {
		t.Fatal("should be a cross-org move")
	}

	// Region deny: RunInstances is denied outside the EU, allowed in eu-west-1.
	f := find(t, res, "scp", func(f Finding) bool { return f.Action == "ec2:RunInstances" && f.Status == StatusNoGo })
	if strings.Join(f.Regions, ",") != "ap-southeast-1,us-east-1" {
		t.Errorf("RunInstances should be denied in exactly ap-southeast-1 and us-east-1, got %v", f.Regions)
	}
	if len(f.Evidence) == 0 || f.Evidence[0].PolicyName != "Fernhill-EU-Only-Regions" || f.Evidence[0].Statement != "DenyOutsideEU" {
		t.Errorf("RunInstances evidence should point at the region deny, got %+v", f.Evidence)
	}
	// CreateVpc and CreateUser: plain denies.
	f = find(t, res, "scp", func(f Finding) bool {
		return f.Action == "ec2:CreateVpc" && f.Status == StatusNoGo && len(f.Regions) == 1
	})
	if f.Evidence[0].PolicyName != "Fernhill-Payments-Controls" {
		t.Errorf("CreateVpc in eu-west-1 should be denied by the payments controls, got %+v", f.Evidence[0])
	}
	f = find(t, res, "scp", func(f Finding) bool { return f.Action == "iam:CreateUser" })
	if f.Status != StatusNoGo || f.Evidence[0].PolicyName != "Fernhill-Root-Guardrails" || f.Evidence[0].Statement != "NoIAMUsers" {
		t.Errorf("CreateUser should be a NO-GO from the root guardrails, got %+v", f)
	}
	// Principal tag condition cannot be evaluated: REVIEW in the EU region.
	f = find(t, res, "scp", func(f Finding) bool { return f.Action == "ec2:TerminateInstances" && f.Status == StatusReview })
	if strings.Join(f.Regions, ",") != "eu-west-1" || !strings.Contains(f.Detail, "aws:PrincipalTag/team") {
		t.Errorf("TerminateInstances review should be about the principal tag in eu-west-1, got %+v", f)
	}
	// Allowed actions produce no finding.
	for _, c := range res.Checks {
		for _, f := range c.Findings {
			if f.Action == "iam:CreateRole" || f.Action == "organizations:DescribeOrganization" {
				t.Errorf("%s should stay allowed, got %+v", f.Action, f)
			}
		}
	}

	// RCP: the acquirer (other org) and the Larkspur sibling account are blocked; the unknown vendor is a REVIEW; CloudTrail is fine.
	f = find(t, res, "rcp", func(f Finding) bool { return f.Principal == "999999999999" && f.Action == "s3:GetObject" })
	if f.Status != StatusNoGo || f.Evidence[0].PolicyName != "Fernhill-Block-External-Principals" {
		t.Errorf("acquirer access should be a NO-GO from the RCP, got %+v", f)
	}
	f = find(t, res, "rcp", func(f Finding) bool {
		return strings.Contains(f.Principal, "111111111118") && f.Action == "sts:AssumeRole"
	})
	if f.Status != StatusNoGo {
		t.Errorf("sibling account in the old organization should be blocked, got %+v", f)
	}
	f = find(t, res, "rcp", func(f Finding) bool { return f.Principal == "888888888888" })
	if f.Status != StatusReview || !strings.Contains(f.Detail, "principal_org_id") {
		t.Errorf("unknown vendor should be a REVIEW asking for principal_org_id, got %+v", f)
	}
	for _, f := range check(res, "rcp").Findings {
		if f.Principal == "cloudtrail.amazonaws.com" {
			t.Errorf("service principals are exempt from the RCP, got %+v", f)
		}
		if f.Principal == "" && f.Status != StatusInfo {
			t.Errorf("the account's own principals are inside the target org and must pass the RCP, got %+v", f)
		}
	}

	// Tags: wrong-case key and disallowed value are REVIEW because ec2:instance and rds:db are enforced; untagged is INFO.
	f = find(t, res, "tags", func(f Finding) bool { return strings.Contains(f.Title, `"Cost-Center"`) })
	if f.Status != StatusReview {
		t.Errorf("wrong-case key should be REVIEW, got %+v", f)
	}
	f = find(t, res, "tags", func(f Finding) bool { return strings.Contains(f.Title, `"PAY-01"`) })
	if f.Status != StatusReview {
		t.Errorf("disallowed value should be REVIEW, got %+v", f)
	}
	for _, f := range check(res, "tags").Findings {
		if strings.Contains(f.Title, "CC-3001") {
			t.Errorf("CC-3001 is appended by the Payments OU policy and must be allowed, got %+v", f)
		}
	}

	// RAM: the org-scoped TGW share is a NO-GO, the Fernhill TGW becomes available.
	f = find(t, res, "ram", func(f Finding) bool { return strings.Contains(f.Title, "larkspur-core-network") })
	if f.Status != StatusNoGo {
		t.Errorf("losing the transit gateway share should be a NO-GO, got %+v", f)
	}
	f = find(t, res, "ram", func(f Finding) bool { return strings.Contains(f.Title, "fernhill-core-network") })
	if f.Status != StatusInfo {
		t.Errorf("gained share should be INFO, got %+v", f)
	}
	find(t, res, "ram", func(f Finding) bool {
		return strings.Contains(f.Title, "larkspur-license-config") && f.Status == StatusReview
	})

	// Organization services.
	find(t, res, "org-services", func(f Finding) bool {
		return strings.Contains(f.Title, "larkspur-org-trail") && f.Status == StatusReview
	})
	find(t, res, "org-services", func(f Finding) bool {
		return strings.Contains(f.Title, "larkspur-baseline-roles") && f.Status == StatusReview
	})
	find(t, res, "org-services", func(f Finding) bool {
		return strings.Contains(f.Title, "larkspur-org-aggregator") && f.Status == StatusReview
	})

	// Diff: the target chain adds the planted policies and drops the Larkspur ones.
	var scpDiff Diff
	for _, d := range res.Diff {
		if d.TypeShort == "SCP" {
			scpDiff = d
		}
	}
	names := func(refs []PolicyRef) string {
		var out []string
		for _, r := range refs {
			out = append(out, r.Name)
		}
		return strings.Join(out, ",")
	}
	if !strings.Contains(names(scpDiff.Added), "Fernhill-EU-Only-Regions") || !strings.Contains(names(scpDiff.Removed), "Larkspur-Allowed-Regions") || names(scpDiff.Unchanged) != "FullAWSAccess" {
		t.Errorf("unexpected SCP diff: added=%s removed=%s unchanged=%s", names(scpDiff.Added), names(scpDiff.Removed), names(scpDiff.Unchanged))
	}
}

func TestSameOrgMoves(t *testing.T) {
	l := fixtures.Larkspur()
	res, err := Evaluate(Input{From: l, AccountID: "111111111116", TargetOUID: "ou-lark-prod"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Subject.CrossOrg {
		t.Fatal("same snapshot must not be a cross-org move")
	}
	if res.Verdict != StatusGo {
		t.Fatalf("payments-dev to Production should be GO, got %s: %s", res.Verdict, res.Summary)
	}
	// Sandbox to Production: the sandbox restrictions are lifted (INFO), the prefix list share is gained.
	res, err = Evaluate(Input{From: l, AccountID: "111111111117", TargetOUID: "ou-lark-prod"})
	if err != nil {
		t.Fatal(err)
	}
	find(t, res, "scp", func(f Finding) bool { return f.Action == "redshift:CreateCluster" && f.Status == StatusInfo })
	find(t, res, "ram", func(f Finding) bool {
		return strings.Contains(f.Title, "larkspur-workload-prefix-lists") && f.Status == StatusInfo
	})
	find(t, res, "org-services", func(f Finding) bool {
		return strings.Contains(f.Title, "larkspur-baseline-roles") && f.Status == StatusInfo
	})
	if res.Verdict != StatusGo {
		t.Fatalf("sandbox to Production should be GO, got %s: %s", res.Verdict, res.Summary)
	}
}

func TestInputErrors(t *testing.T) {
	l, f := fixtures.Larkspur(), fixtures.Fernhill()
	if _, err := Evaluate(Input{From: l, To: f, AccountID: "000000000000", TargetOUID: fixtures.FernhillPaymentsOU}); err == nil {
		t.Fatal("unknown account should fail")
	}
	if _, err := Evaluate(Input{From: l, To: f, AccountID: fixtures.LarkspurPaymentsProd, TargetOUID: "222222222222"}); err == nil {
		t.Fatal("an account is not a valid target")
	}
	if _, err := Evaluate(Input{From: l, To: f, AccountID: fixtures.LarkspurPaymentsProd, TargetOUID: "ou-lark-prod"}); err == nil {
		t.Fatal("target OU must be in the destination snapshot")
	}
}

func TestNoUsageIsReview(t *testing.T) {
	l := fixtures.Larkspur()
	res, err := Evaluate(Input{From: l, AccountID: "111111111114", TargetOUID: "ou-lark-dev"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Verdict != StatusReview {
		t.Fatalf("an account without actions in use should be REVIEW, got %s", res.Verdict)
	}
}
