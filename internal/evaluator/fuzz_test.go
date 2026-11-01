package evaluator

import (
	"encoding/json"
	"testing"

	"github.com/MrShaaba/orgshift/internal/fixtures"
	"github.com/MrShaaba/orgshift/internal/snapshot"
)

// FuzzEvaluateWithPolicyDocument drops an arbitrary document into the target
// organization's root SCP, RCP and tag policy and checks that the evaluator
// never panics, whatever the document looks like, and that an unparseable
// SCP or RCP never produces a GO.
func FuzzEvaluateWithPolicyDocument(f *testing.F) {
	for _, p := range fixtures.Fernhill().Policies {
		f.Add(string(p.Document))
	}
	f.Add(`{"Version":"2012-10-17","Statement":[{"Sid":"Broken","Effect":"Deny","Resource":"*"}]}`)
	f.Add(`{"Statement": 5}`)
	f.Add(`{"tags":{"owner":"not an object"}}`)
	f.Add(`{"tags":{"cost-center":{"tag_value":{"@@assign":5},"enforced_for":{"@@assign":"ec2:instance"}}}}`)
	f.Add(`null`)
	f.Add(`[]`)
	f.Fuzz(func(t *testing.T, doc string) {
		if !json.Valid([]byte(doc)) {
			return // Validate rejects it before any evaluation
		}
		from := fixtures.Larkspur()
		for _, typ := range []snapshot.PolicyType{snapshot.PolicyTypeSCP, snapshot.PolicyTypeRCP, snapshot.PolicyTypeTag} {
			to := fixtures.Fernhill()
			for i := range to.Policies {
				p := &to.Policies[i]
				if p.Type == typ && !p.AWSManaged && contains(p.Targets, to.Root.ID) {
					p.Document = json.RawMessage(doc)
				}
			}
			res, err := Evaluate(Input{From: from, To: to, AccountID: fixtures.LarkspurPaymentsProd, TargetOUID: fixtures.FernhillPaymentsOU})
			if err != nil {
				t.Fatalf("evaluation failed: %v", err)
			}
			if res.Verdict != StatusGo && res.Verdict != StatusReview && res.Verdict != StatusNoGo {
				t.Fatalf("verdict out of range: %s", res.Verdict)
			}
			if typ != snapshot.PolicyTypeTag && snapshot.ValidatePolicyDocument(typ, json.RawMessage(doc)) != nil && res.Verdict == StatusGo {
				t.Fatalf("an unparseable %s at the target root must not yield GO", typ)
			}
		}
	})
}

// FuzzSnapshotParse checks that no document makes the loader panic.
func FuzzSnapshotParse(f *testing.F) {
	for _, s := range []*snapshot.Snapshot{fixtures.Larkspur(), fixtures.Fernhill(), fixtures.LarkspurPartial()} {
		data, _ := snapshot.Marshal(s)
		f.Add(data)
	}
	f.Add([]byte(`{"schema_version": 1, "organization": {"id":"o-x"}, "root": {"id":"r-x"}}`))
	f.Add([]byte(`{"schema_version": 2, "coverage": {"domains": [{"domain": "tree", "status": "maybe"}]}}`))
	f.Add([]byte(`{`))
	f.Fuzz(func(t *testing.T, data []byte) {
		s, err := snapshot.Parse(data)
		if err != nil {
			if s != nil {
				t.Fatal("an error must not come with a snapshot")
			}
			return
		}
		if s.SchemaVersion != snapshot.SchemaVersion {
			t.Fatalf("parsed snapshots are always at the current version, got %d", s.SchemaVersion)
		}
		// A parsed snapshot can always be evaluated for its accounts.
		if len(s.Accounts) > 0 {
			if _, err := Evaluate(Input{From: s, AccountID: s.Accounts[0].ID, TargetOUID: s.Root.ID}); err != nil {
				t.Fatalf("a validated snapshot must evaluate: %v", err)
			}
		}
	})
}
