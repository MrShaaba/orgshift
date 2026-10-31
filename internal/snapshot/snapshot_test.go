package snapshot

import (
	"encoding/json"
	"strings"
	"testing"
)

func minimal() *Snapshot {
	return &Snapshot{
		SchemaVersion: SchemaVersion,
		Organization:  Organization{ID: "o-test00000001", ManagementAccountID: "111111111111"},
		Root:          Root{ID: "r-test", Name: "Root", EnabledPolicyTypes: []PolicyType{PolicyTypeSCP}},
		OUs: []OU{
			{ID: "ou-test-aaaa", Name: "Workloads", ParentID: "r-test"},
			{ID: "ou-test-bbbb", Name: "Prod", ParentID: "ou-test-aaaa"},
		},
		Accounts: []Account{
			{ID: "111111111111", Name: "management", ParentID: "r-test"},
			{ID: "111111111112", Name: "prod-app", ParentID: "ou-test-bbbb"},
		},
		Policies: []Policy{
			{ID: "p-FullAWSAccess", Name: "FullAWSAccess", Type: PolicyTypeSCP, AWSManaged: true,
				Document: json.RawMessage(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`),
				Targets:  []string{"r-test", "ou-test-aaaa", "ou-test-bbbb", "111111111111", "111111111112"}},
		},
	}
}

func TestRoundTrip(t *testing.T) {
	s := minimal()
	data, err := Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	back, err := Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	if back.Organization.ID != s.Organization.ID || len(back.Accounts) != 2 {
		t.Fatalf("round trip lost data: %+v", back)
	}
}

func TestPath(t *testing.T) {
	ix := minimal().Index()
	p := ix.PathTo("111111111112")
	if got := PathString(p); got != "Root / Workloads / Prod / prod-app" {
		t.Fatalf("unexpected path %q", got)
	}
	if ids := OUPath(p); len(ids) != 3 || ids[2] != "ou-test-bbbb" {
		t.Fatalf("unexpected ou path %v", ids)
	}
	if ix.PathTo("nope") != nil {
		t.Fatal("unknown id should have no path")
	}
	acct, _ := ix.Node("111111111112")
	under := ix.PathUnder("ou-test-aaaa", acct)
	if got := PathString(under); got != "Root / Workloads / prod-app" {
		t.Fatalf("unexpected hypothetical path %q", got)
	}
}

func TestValidateRejectsBrokenReferences(t *testing.T) {
	cases := map[string]func(*Snapshot){
		"missing parent":    func(s *Snapshot) { s.Accounts[1].ParentID = "ou-missing" },
		"bad account id":    func(s *Snapshot) { s.Accounts[1].ID = "12345" },
		"dangling target":   func(s *Snapshot) { s.Policies[0].Targets = append(s.Policies[0].Targets, "ou-nope") },
		"bad policy json":   func(s *Snapshot) { s.Policies[0].Document = json.RawMessage(`{`) },
		"unknown type":      func(s *Snapshot) { s.Policies[0].Type = "FANCY_POLICY" },
		"usage non-account": func(s *Snapshot) { s.Usage = map[string]*AccountUsage{"ou-test-aaaa": {}} },
		"ou cycle": func(s *Snapshot) {
			s.OUs[0].ParentID = "ou-test-bbbb"
		},
	}
	for name, mutate := range cases {
		s := minimal()
		mutate(s)
		if err := s.Validate(); err == nil {
			t.Errorf("%s: expected a validation error", name)
		}
	}
}

func TestParseRejectsNewerSchemaAndUnknownFields(t *testing.T) {
	if _, err := Parse([]byte(`{"schema_version": 99}`)); err == nil || !strings.Contains(err.Error(), "newer") {
		t.Fatalf("expected newer-version error, got %v", err)
	}
	if _, err := Parse([]byte(`{"schema_version": 1, "organization": {"id":"o-x"}, "root": {"id":"r-x"}, "bogus": 1}`)); err == nil {
		t.Fatal("expected unknown field error")
	}
	if _, err := Parse([]byte(`{}`)); err == nil {
		t.Fatal("expected missing schema version error")
	}
}
