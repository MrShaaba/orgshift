package evaluator

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/MrShaaba/orgshift/internal/snapshot"
)

// twoOrgs builds two minimal organizations that share nothing but, when
// asked, a policy ID. The account 111111111112 lives in the source under one
// OU and is evaluated at the target root.
func twoOrgs(t *testing.T, srcPolicyDoc, dstPolicyDoc string, samePolicyID bool) (*snapshot.Snapshot, *snapshot.Snapshot) {
	t.Helper()
	full := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`
	org := func(id, mgmt, root, member, policyID, policyDoc string) *snapshot.Snapshot {
		s := &snapshot.Snapshot{
			SchemaVersion: snapshot.SchemaVersion, Source: "fixture",
			Organization: snapshot.Organization{ID: id, ManagementAccountID: mgmt},
			Root:         snapshot.Root{ID: root, Name: "Root", EnabledPolicyTypes: []snapshot.PolicyType{snapshot.PolicyTypeSCP}},
			Accounts: []snapshot.Account{
				{ID: mgmt, Name: "mgmt", ParentID: root, EnabledRegions: []string{"us-east-1"}},
				{ID: member, Name: "member", ParentID: root, EnabledRegions: []string{"us-east-1"}},
			},
			Policies: []snapshot.Policy{
				{ID: "p-FullAWSAccess", Name: "FullAWSAccess", Type: snapshot.PolicyTypeSCP, AWSManaged: true, Document: json.RawMessage(full), Targets: []string{root, mgmt, member}},
				{ID: policyID, Name: "Guardrails", Type: snapshot.PolicyTypeSCP, Document: json.RawMessage(policyDoc), Targets: []string{root}},
			},
			Usage:    map[string]*snapshot.AccountUsage{member: {Actions: []snapshot.ActionInUse{{Action: "ec2:RunInstances"}}}},
			Coverage: &snapshot.Coverage{AssertedComplete: true, AssertedBy: "test"},
		}
		return s
	}
	dstID := "p-target0001"
	if samePolicyID {
		// The same policy ID and name in both organizations, with different documents.
		dstID = "p-shared001"
	}
	src := org("o-source000001", "111111111111", "r-src1", "111111111112", "p-shared001", srcPolicyDoc)
	dst := org("o-target000001", "222222222221", "r-dst1", "222222222222", dstID, dstPolicyDoc)
	return src, dst
}

// TestPolicyCacheIsNamespacedPerSnapshot reproduces the audit finding that a
// parsed-policy cache keyed by policy ID alone lets the source organization's
// document stand in for a target policy with the same ID.
func TestPolicyCacheIsNamespacedPerSnapshot(t *testing.T) {
	harmless := `{"Version":"2012-10-17","Statement":[{"Sid":"Nothing","Effect":"Deny","Action":"glacier:DeleteVault","Resource":"*"}]}`
	denyRun := `{"Version":"2012-10-17","Statement":[{"Sid":"NoInstances","Effect":"Deny","Action":"ec2:RunInstances","Resource":"*"}]}`

	src, dst := twoOrgs(t, harmless, denyRun, true)
	for _, s := range []*snapshot.Snapshot{src, dst} {
		if err := s.Validate(); err != nil {
			t.Fatal(err)
		}
	}
	res, err := Evaluate(Input{From: src, To: dst, AccountID: "111111111112", TargetOUID: "r-dst1"})
	if err != nil {
		t.Fatal(err)
	}
	f := find(t, res, "scp", func(f Finding) bool { return f.Action == "ec2:RunInstances" })
	if f.Status != StatusNoGo || len(f.Evidence) == 0 || f.Evidence[0].Statement != "NoInstances" || f.Evidence[0].Side != "target" {
		t.Fatalf("the target's own document must be evaluated, got %+v", f)
	}

	// The other way round: denied today, allowed after the move.
	src, dst = twoOrgs(t, denyRun, harmless, true)
	res, err = Evaluate(Input{From: src, To: dst, AccountID: "111111111112", TargetOUID: "r-dst1"})
	if err != nil {
		t.Fatal(err)
	}
	f = find(t, res, "scp", func(f Finding) bool { return f.Action == "ec2:RunInstances" })
	if f.Status != StatusInfo || !strings.Contains(f.Title, "becomes allowed") {
		t.Fatalf("source deny must not leak into the target evaluation, got %+v", f)
	}
}

// TestUnparseablePolicyIsReviewNotPanic reproduces the audit finding that a
// policy document which is valid JSON but not a valid policy makes the
// evaluator dereference a nil statement.
func TestUnparseablePolicyIsReviewNotPanic(t *testing.T) {
	harmless := `{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"glacier:DeleteVault","Resource":"*"}]}`
	for name, broken := range map[string]string{
		"no action":               `{"Version":"2012-10-17","Statement":[{"Sid":"Broken","Effect":"Deny","Resource":"*"}]}`,
		"bad effect":              `{"Version":"2012-10-17","Statement":[{"Effect":"Maybe","Action":"*","Resource":"*"}]}`,
		"no statement":            `{"Version":"2012-10-17"}`,
		"statement is a number":   `{"Statement": 5}`,
		"condition not an object": `{"Statement":[{"Effect":"Deny","Action":"*","Resource":"*","Condition":"nope"}]}`,
	} {
		t.Run(name, func(t *testing.T) {
			src, dst := twoOrgs(t, harmless, broken, false)
			// Validate now rejects these with the parse error, which is the
			// first line of defence; the evaluator must survive them anyway
			// (fixtures and callers can build snapshots without validating).
			if err := dst.Validate(); err == nil || !strings.Contains(err.Error(), "p-target0001") {
				t.Fatalf("Validate should name the broken policy, got %v", err)
			}
			res, err := Evaluate(Input{From: src, To: dst, AccountID: "111111111112", TargetOUID: "r-dst1"})
			if err != nil {
				t.Fatal(err)
			}
			f := find(t, res, "scp", func(f Finding) bool { return f.Action == "ec2:RunInstances" })
			if f.Status != StatusReview || !strings.Contains(strings.ToLower(f.Detail), "could not be parsed") {
				t.Fatalf("a policy that cannot be parsed must come back as REVIEW with the parse error, got %+v", f)
			}
			if res.Verdict != StatusReview {
				t.Fatalf("verdict should be REVIEW, got %s", res.Verdict)
			}
		})
	}
}
