package snapshot

import (
	"encoding/json"
	"strings"
	"testing"
)

// M5 defect 3. What a missing Resource means depends on the policy type.
// The SCP syntax page says "Each statement in an SCP must include a
// Resource or NotResource element" and the RCP page "Each statement must
// contain the Resource or NotResource element", so a statement without one
// is malformed there; it is not a statement about every resource.
func TestPolicyTypeRulesForMalformedStatements(t *testing.T) {
	cases := []struct {
		name string
		typ  PolicyType
		doc  string
		want string
	}{
		{"scp without resource", PolicyTypeSCP, `{"Version":"2012-10-17","Statement":[{"Sid":"NoResource","Effect":"Deny","Action":"ec2:RunInstances"}]}`, "must include a Resource or NotResource element"},
		{"scp action and notaction", PolicyTypeSCP, `{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"ec2:*","NotAction":"s3:*","Resource":"*"}]}`, "both Action and NotAction"},
		{"scp resource and notresource", PolicyTypeSCP, `{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"s3:*","Resource":"*","NotResource":"arn:aws:s3:::keep/*"}]}`, "both Resource and NotResource"},
		{"rcp without resource", PolicyTypeRCP, `{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Principal":"*","Action":"s3:*"}]}`, "must include a Resource or NotResource element"},
		{"rcp with notaction", PolicyTypeRCP, `{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Principal":"*","NotAction":"s3:*","Resource":"*"}]}`, "do not support NotAction"},
	}
	for _, c := range cases {
		err := ValidatePolicyDocument(c.typ, json.RawMessage(c.doc))
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: expected %q, got %v", c.name, c.want, err)
		}
	}
	for name, doc := range map[string]string{
		"scp with resource":    `{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"ec2:RunInstances","Resource":"*"}]}`,
		"scp with notresource": `{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"s3:*","NotResource":"arn:aws:s3:::keep/*"}]}`,
		"scp with a variable":  `{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"s3:*","Resource":"arn:aws:s3:::example/${aws:PrincipalTag/team}/*"}]}`,
	} {
		if err := ValidatePolicyDocument(PolicyTypeSCP, json.RawMessage(doc)); err != nil {
			t.Errorf("%s is well formed: %v", name, err)
		}
	}
}

// A snapshot records a malformed policy with the reason instead of being
// unusable because of it: the collector cannot fix what the organization
// holds. A malformed document without the record is still an error, so a
// slip in a hand-written file is caught on load.
func TestMalformedPolicyIsRecordedNotFatal(t *testing.T) {
	base := func() *Snapshot {
		return &Snapshot{
			SchemaVersion: SchemaVersion, Source: "fixture",
			Organization: Organization{ID: "o-example00001", ManagementAccountID: "111111111111"},
			Root:         Root{ID: "r-ex01", Name: "Root", EnabledPolicyTypes: []PolicyType{PolicyTypeSCP}},
			Accounts:     []Account{{ID: "111111111111", Name: "mgmt", ParentID: "r-ex01"}},
			Policies: []Policy{
				{ID: "p-FullAWSAccess", Name: "FullAWSAccess", Type: PolicyTypeSCP, AWSManaged: true, Document: json.RawMessage(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`), Targets: []string{"r-ex01", "111111111111"}},
				{ID: "p-broken0001", Name: "Broken", Type: PolicyTypeSCP, Document: json.RawMessage(`{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"ec2:*","NotAction":"s3:*","Resource":"*"}]}`), Targets: []string{"r-ex01"}},
			},
		}
	}
	s := base()
	if err := s.Validate(); err == nil || !strings.Contains(err.Error(), "p-broken0001") || !strings.Contains(err.Error(), "both Action and NotAction") {
		t.Fatalf("an unrecorded malformed policy is an error that names it: %v", err)
	}
	s = base()
	s.Policies[1].Malformed = "statement #1: statement has both Action and NotAction"
	if err := s.Validate(); err != nil {
		t.Fatalf("a recorded malformed policy does not make the snapshot unusable: %v", err)
	}
	if got := s.MalformedPolicies(); len(got) != 1 || got[0].ID != "p-broken0001" {
		t.Errorf("malformed policies: %+v", got)
	}
	// The record survives a save and a load.
	data, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	back, err := Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	if back.Policies[1].Malformed == "" || !strings.Contains(string(data), `"malformed":`) {
		t.Errorf("the reason is part of the snapshot: %s", back.Policies[1].Malformed)
	}
	// MarkMalformed fills the record from the document itself.
	s = base()
	if n := s.MarkMalformedPolicies(); n != 1 || !strings.Contains(s.Policies[1].Malformed, "both Action and NotAction") || s.Policies[0].Malformed != "" {
		t.Errorf("marking: %d %q", n, s.Policies[1].Malformed)
	}
}
