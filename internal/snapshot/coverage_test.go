package snapshot

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestDomainStatusAggregatesWorstRecord(t *testing.T) {
	s := minimal()
	if got := s.DomainStatus(DomainResourceShares, ""); got != CoverageUnknown {
		t.Fatalf("no coverage block must read as unknown, got %s", got)
	}
	s.Coverage = &Coverage{Domains: []DomainCoverage{
		{Domain: DomainResourceShares, Status: CoverageObserved, AccountID: "111111111111", Items: 2},
		{Domain: DomainResourceShares, Status: CoverageAccessDenied, AccountID: "111111111112", Error: "AccessDeniedException: no"},
		{Domain: DomainEnabledRegions, Status: CoverageObserved},
		{Domain: DomainEnabledRegions, Status: CoverageError, AccountID: "111111111112", Error: "boom"},
		{Domain: DomainControlTower, Status: CoverageEmpty, Region: "us-east-1", Reason: "no landing zone"},
	}}
	if got := s.DomainStatus(DomainResourceShares, ""); got != CoverageAccessDenied {
		t.Errorf("worst record should win across accounts, got %s", got)
	}
	if got := s.DomainStatus(DomainResourceShares, "111111111111"); got != CoverageObserved {
		t.Errorf("scoping to the observed account should read observed, got %s", got)
	}
	if got := s.DomainStatus(DomainEnabledRegions, "111111111111"); got != CoverageObserved {
		t.Errorf("an organization-wide observed record applies to every account, got %s", got)
	}
	if got := s.DomainStatus(DomainEnabledRegions, "111111111112"); got != CoverageError {
		t.Errorf("the failing account's own record must win for that account, got %s", got)
	}
	if !s.DomainStatus(DomainControlTower, "").Complete() {
		t.Error("empty is complete")
	}
	if got := s.DomainStatus(DomainIdentityCenter, ""); got != CoverageUnknown {
		t.Errorf("a domain without a record is unknown, got %s", got)
	}
	gaps := s.CoverageGaps()
	if !strings.Contains(strings.Join(gaps, ","), DomainResourceShares) || !strings.Contains(strings.Join(gaps, ","), DomainIdentityCenter) {
		t.Errorf("gaps should list the denied domain and the unrecorded ones: %v", gaps)
	}
	if err := s.Validate(); err != nil {
		t.Fatalf("coverage block should validate: %v", err)
	}
	if got := s.Coverage.Domains[1].Label(); !strings.Contains(got, "resource_shares access_denied (account 111111111112): AccessDeniedException: no") {
		t.Errorf("label: %s", got)
	}
}

func TestAssertedCompleteStandsInForRecords(t *testing.T) {
	s := minimal()
	s.Coverage = &Coverage{AssertedComplete: true, AssertedBy: "hand-written for a test", Domains: []DomainCoverage{
		{Domain: DomainResourceShares, Status: CoverageSkipped, Reason: "--skip-ram"},
	}}
	if got := s.DomainStatus(DomainIdentityCenter, ""); got != CoverageObserved || !s.CoverageAsserted(DomainIdentityCenter) {
		t.Errorf("asserted completeness covers domains without a record, got %s", got)
	}
	if got := s.DomainStatus(DomainResourceShares, ""); got != CoverageSkipped || s.CoverageAsserted(DomainResourceShares) {
		t.Errorf("an explicit record beats the assertion, got %s", got)
	}
	if err := s.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestCoverageValidation(t *testing.T) {
	cases := map[string]*Coverage{
		"unknown status":           {Domains: []DomainCoverage{{Domain: DomainTree, Status: "maybe"}}},
		"stored unknown":           {Domains: []DomainCoverage{{Domain: DomainTree, Status: CoverageUnknown}}},
		"denied without error":     {Domains: []DomainCoverage{{Domain: DomainTree, Status: CoverageAccessDenied}}},
		"missing domain":           {Domains: []DomainCoverage{{Status: CoverageObserved}}},
		"bad account":              {Domains: []DomainCoverage{{Domain: DomainTree, Status: CoverageObserved, AccountID: "abc"}}},
		"asserted_by without flag": {AssertedBy: "me"},
		"partial needs error too":  {Domains: []DomainCoverage{{Domain: DomainTree, Status: CoveragePartial}}},
	}
	for name, cov := range cases {
		s := minimal()
		s.Coverage = cov
		if err := s.Validate(); err == nil {
			t.Errorf("%s: expected a validation error", name)
		}
	}
}

func TestParseUpgradesSchemaVersionOne(t *testing.T) {
	s := minimal()
	s.SchemaVersion = 1
	data, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	back, err := Parse(data)
	if err != nil {
		t.Fatalf("a version 1 document must still load: %v", err)
	}
	if back.SchemaVersion != SchemaVersion || back.UpgradedFrom != 1 || back.Coverage != nil {
		t.Fatalf("upgrade wrong: version %d from %d coverage %v", back.SchemaVersion, back.UpgradedFrom, back.Coverage)
	}
	if got := back.DomainStatus(DomainResourceShares, ""); got != CoverageUnknown {
		t.Fatalf("an upgraded document has unknown coverage, got %s", got)
	}
	out, _ := Marshal(back)
	if strings.Contains(string(out), "upgraded_from") || !strings.Contains(string(out), `"schema_version": 2`) {
		t.Fatalf("the upgrade marker must not be written; the new version must: %s", out[:120])
	}
}

func TestValidatePolicyDocuments(t *testing.T) {
	good := map[PolicyType]string{
		PolicyTypeSCP:    `{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"ec2:*","Resource":"*"}]}`,
		PolicyTypeRCP:    `{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Principal":"*","Action":"s3:*","Resource":"*"}]}`,
		PolicyTypeTag:    `{"tags":{"owner":{"tag_key":{"@@assign":"owner"}}}}`,
		PolicyTypeBackup: `{"plans":{"p":{"regions":{"@@assign":["us-east-1"]}}}}`,
	}
	for t2, doc := range good {
		if err := ValidatePolicyDocument(t2, json.RawMessage(doc)); err != nil {
			t.Errorf("%s: valid document rejected: %v", t2, err)
		}
	}
	bad := map[string]struct {
		t    PolicyType
		doc  string
		want string
	}{
		"scp without action":       {PolicyTypeSCP, `{"Statement":[{"Effect":"Deny","Resource":"*"}]}`, "neither Action nor NotAction"},
		"scp with principal":       {PolicyTypeSCP, `{"Statement":[{"Effect":"Deny","Principal":"*","Action":"*","Resource":"*"}]}`, "cannot carry a Principal"},
		"scp bad effect":           {PolicyTypeSCP, `{"Statement":[{"Effect":"Maybe","Action":"*"}]}`, "effect must be Allow or Deny"},
		"rcp without principal":    {PolicyTypeRCP, `{"Statement":[{"Effect":"Deny","Action":"s3:*","Resource":"*"}]}`, "require a Principal"},
		"rcp narrow principal":     {PolicyTypeRCP, `{"Statement":[{"Effect":"Deny","Principal":{"AWS":"111111111111"},"Action":"s3:*","Resource":"*"}]}`, `must be "*"`},
		"rcp notprincipal":         {PolicyTypeRCP, `{"Statement":[{"Effect":"Deny","NotPrincipal":"*","Action":"s3:*","Resource":"*"}]}`, "NotPrincipal"},
		"tag policy not an object": {PolicyTypeTag, `[]`, "tag policy must be an object"},
		"tag policy no tags":       {PolicyTypeTag, `{"nope":1}`, "no tags element"},
		"tag spec not object":      {PolicyTypeTag, `{"tags":{"owner":"x"}}`, "must be an object"},
		"backup no plans":          {PolicyTypeBackup, `{"x":1}`, "no plans element"},
		"statement is a number":    {PolicyTypeSCP, `{"Statement":5}`, "statement #1"},
	}
	for name, c := range bad {
		err := ValidatePolicyDocument(c.t, json.RawMessage(c.doc))
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: expected error containing %q, got %v", name, c.want, err)
		}
	}
	// Validate names the policy.
	s := minimal()
	s.Policies = append(s.Policies, Policy{ID: "p-bad", Name: "Broken", Type: PolicyTypeSCP, Document: json.RawMessage(`{"Statement":[{"Effect":"Deny","Resource":"*"}]}`), Targets: []string{"r-test"}})
	if err := s.Validate(); err == nil || !strings.Contains(err.Error(), "p-bad (Broken): statement #1") {
		t.Fatalf("Validate should name the broken policy and statement, got %v", err)
	}
	s = minimal()
	s.Accounts[0].JoinedAt = "yesterday"
	if err := s.Validate(); err == nil || !strings.Contains(err.Error(), "joined_at") {
		t.Fatalf("bad joined_at should be rejected, got %v", err)
	}
}

func TestPolicyFingerprintAndKey(t *testing.T) {
	a := &Policy{ID: "p-1", Document: json.RawMessage(`{"Statement": [ {"Effect":"Deny","Action":"*","Resource":"*"} ]}`)}
	b := &Policy{ID: "p-1", Document: json.RawMessage(`{"Statement":[{"Effect":"Deny","Action":"*","Resource":"*"}]}`)}
	c := &Policy{ID: "p-1", Document: json.RawMessage(`{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`)}
	if a.Fingerprint() != b.Fingerprint() {
		t.Error("whitespace must not change the fingerprint")
	}
	if a.Fingerprint() == c.Fingerprint() {
		t.Error("different documents must have different fingerprints")
	}
	s1, s2 := minimal(), minimal()
	s2.Organization.ID = "o-other0000001"
	if s1.PolicyKey(a) == s2.PolicyKey(a) || !strings.HasPrefix(s1.PolicyKey(a), "o-test00000001|p-1|") {
		t.Errorf("policy keys must be namespaced by organization: %s vs %s", s1.PolicyKey(a), s2.PolicyKey(a))
	}
}

func TestEnrolledAccountProvenance(t *testing.T) {
	cases := map[bool]*EnrolledAccount{
		true:  {AccountID: "111111111112", Source: EnrolledManual},
		false: {AccountID: "111111111112", Source: EnrolledFromBaseline},
	}
	for want, e := range cases {
		if got := e.ProvenanceKnown(); got != want {
			t.Errorf("%+v: ProvenanceKnown = %v want %v", e, got, want)
		}
	}
	withProduct := &EnrolledAccount{Source: EnrolledFromBaseline, ProvisionedProduct: "x"}
	if !withProduct.ProvenanceKnown() {
		t.Error("a product name makes the provenance known")
	}
	var nilRecord *EnrolledAccount
	if nilRecord.ProvenanceKnown() {
		t.Error("nil is unknown")
	}
	s := minimal()
	s.ControlTower = &ControlTower{AutoEnrollment: "sometimes", RegisteredOUs: []RegisteredOU{{OUID: "ou-test-aaaa"}},
		EnrolledAccounts: []EnrolledAccount{{AccountID: "111111111112", Source: "guess"}, {AccountID: "111111111112"}}}
	err := s.Validate()
	if err == nil {
		t.Fatal("expected validation errors")
	}
	for _, want := range []string{"auto_enrollment", "unknown source", "listed twice"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("validation error should mention %q, got:\n%v", want, err)
		}
	}
}
