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
	if strings.Contains(string(out), "upgraded_from") || !strings.Contains(string(out), `"schema_version": 3`) {
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

func TestParseUpgradesSchemaVersionTwo(t *testing.T) {
	s := minimal()
	s.SchemaVersion = 2
	s.Coverage = &Coverage{AssertedComplete: true, AssertedBy: "written by hand"}
	data, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	back, err := Parse(data)
	if err != nil {
		t.Fatalf("a version 2 document must still load: %v", err)
	}
	if back.SchemaVersion != SchemaVersion || back.UpgradedFrom != 2 || back.Workloads != nil {
		t.Fatalf("upgrade wrong: version %d from %d", back.SchemaVersion, back.UpgradedFrom)
	}
	// The assertion covers what existed when it was made, not the workload
	// inventory that schema version 3 added.
	if got := back.DomainStatus(DomainResourceShares, ""); got != CoverageObserved {
		t.Errorf("asserted domains stay asserted, got %s", got)
	}
	for _, d := range WorkloadDomains {
		if got := back.DomainStatus(d, "111111111112"); got != CoverageUnknown {
			t.Errorf("%s must be unknown in an upgraded document, got %s", d, got)
		}
		if back.CoverageAsserted(d) {
			t.Errorf("%s must not count as asserted", d)
		}
	}
	// A document written at version 3 with the same assertion does cover them.
	s.SchemaVersion = 3
	data, _ = json.Marshal(s)
	if back, err = Parse(data); err != nil || back.DomainStatus(DomainWorkloadStacks, "") != CoverageObserved {
		t.Errorf("a version 3 assertion covers the workload domains: %v", err)
	}
}

func TestWorkloadsValidationAndHelpers(t *testing.T) {
	s := minimal()
	policyDoc := json.RawMessage(`{"Version":"2012-10-17","Statement":[{"Sid":"Org","Effect":"Deny","Principal":"*","Action":"s3:*","Resource":"*","Condition":{"StringNotEquals":{"aws:PrincipalOrgID":"o-test00000001"}}}]}`)
	conds, err := ExtractOrgConditions(policyDoc)
	if err != nil || len(conds) != 1 || conds[0].Key != "aws:PrincipalOrgID" || conds[0].Operator != "StringNotEquals" || conds[0].Effect != "Deny" || conds[0].Sid != "Org" {
		t.Fatalf("extracted conditions: %+v %v", conds, err)
	}
	if c, _ := ExtractOrgConditions(json.RawMessage(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"*"}]}`)); len(c) != 0 {
		t.Errorf("a policy without organization keys yields nothing: %+v", c)
	}
	if _, err := ExtractOrgConditions(json.RawMessage(`{"Statement": 5}`)); err == nil {
		t.Error("an unparseable policy is an error")
	}
	s.StackSets = []StackSet{{Name: "baseline", PermissionModel: "SERVICE_MANAGED", Instances: []StackInstance{{AccountID: "111111111112", Region: "us-east-1", StackID: "arn:stack/1"}}}}
	s.Workloads = map[string]*AccountWorkloads{"111111111112": {
		Regions: []string{"us-east-1"},
		Stacks: []Stack{
			{Name: "StackSet-baseline-0a1b", ID: "arn:stack/1", Region: "us-east-1", ResourceTypes: map[string]int{"AWS::IAM::Role": 2}},
			{Name: "StackSet-baseline-extra-9z", Region: "us-east-1", ResourceTypes: map[string]int{}},
			{Name: "app", Region: "us-east-1", ResourceTypes: map[string]int{"AWS::S3::Bucket": 1, "AWS::IAM::Role": 1}, StackSet: nil},
		},
		Resources:        []WorkloadResource{{ARN: "arn:aws:s3:::bucket", Type: "s3:bucket", Tags: map[string]string{}}},
		ResourcePolicies: []ResourcePolicy{{Kind: PolicyKindBucket, ResourceARN: "arn:aws:s3:::bucket", Document: policyDoc, Conditions: conds}},
	}}
	if err := s.Validate(); err != nil {
		t.Fatalf("a valid workloads block: %v", err)
	}
	w := s.WorkloadsFor("111111111112")
	if w == nil || s.WorkloadsFor("111111111111") != nil || w.Stacks[2].ResourceCount() != 2 {
		t.Error("lookups")
	}
	if ss, byInstance := s.StackSetOfStack("111111111112", w.Stacks[0]); ss == nil || !byInstance {
		t.Error("a stack whose ID is in the instance list matches by instance")
	}
	if ss, byInstance := s.StackSetOfStack("111111111112", w.Stacks[1]); ss == nil || byInstance || ss.Name != "baseline" {
		t.Error("a stack named StackSet-<name>-<id> matches the StackSet by name only")
	}
	if ss, _ := s.StackSetOfStack("111111111112", w.Stacks[2]); ss != nil {
		t.Error("a plain stack matches no StackSet")
	}
	for arn, want := range map[string]string{
		"arn:aws:ec2:us-east-1:111111111112:instance/i-1": "ec2:instance", "arn:aws:s3:::bucket": "s3:bucket", "arn:aws:rds:us-east-1:111111111112:db:name": "rds:db",
		"arn:aws:lambda:us-east-1:111111111112:function:f": "lambda:function", "arn:aws:sqs:us-east-1:111111111112:queue": "sqs:queue", "not-an-arn": "",
	} {
		if got := TypeFromARN(arn); got != want {
			t.Errorf("TypeFromARN(%s) = %q want %q", arn, got, want)
		}
	}
	if RegionFromARN("arn:aws:ec2:eu-west-1:111111111112:instance/i-1") != "eu-west-1" || AccountFromARN("arn:aws:s3:::bucket") != "" || AccountFromARN("arn:aws:iam::111111111112:role/x") != "111111111112" {
		t.Error("ARN helpers")
	}
	if !IsOrgConditionKey("AWS:principalorgid") || IsOrgConditionKey("aws:PrincipalAccount") || !IsWorkloadDomain(DomainWorkloadPolicies) || IsWorkloadDomain(DomainTree) {
		t.Error("key and domain helpers")
	}
	broken := map[string]func(*Snapshot){
		"unknown account":      func(s *Snapshot) { s.Workloads["999999999999"] = &AccountWorkloads{} },
		"stack without region": func(s *Snapshot) { s.Workloads["111111111112"].Stacks[0].Region = "" },
		"duplicate stack": func(s *Snapshot) {
			s.Workloads["111111111112"].Stacks[1].Name = "app"
			s.Workloads["111111111112"].Stacks[2].Name = "app"
		},
		"resource without arn": func(s *Snapshot) { s.Workloads["111111111112"].Resources[0].ARN = "" },
		"policy kind":          func(s *Snapshot) { s.Workloads["111111111112"].ResourcePolicies[0].Kind = "weird" },
		"policy not json": func(s *Snapshot) {
			s.Workloads["111111111112"].ResourcePolicies[0].Document = json.RawMessage(`{"Statement": 5}`)
		},
		"empty kept policy": func(s *Snapshot) {
			s.Workloads["111111111112"].ResourcePolicies[0] = ResourcePolicy{Kind: PolicyKindTemplate, Resource: "X"}
		},
		"non-org condition": func(s *Snapshot) { s.Workloads["111111111112"].ResourcePolicies[0].Conditions[0].Key = "aws:SourceIp" },
		"resource source":   func(s *Snapshot) { s.Workloads["111111111112"].ResourceSource = "guess" },
		"stackset evidence": func(s *Snapshot) {
			s.Workloads["111111111112"].Stacks[0].StackSet = &StackSetRef{Name: "x", Evidence: "rumour"}
		},
		"instance account": func(s *Snapshot) { s.StackSets[0].Instances[0].AccountID = "abc" },
	}
	for name, mutate := range broken {
		data, _ := json.Marshal(s)
		var c Snapshot
		if err := json.Unmarshal(data, &c); err != nil {
			t.Fatal(err)
		}
		mutate(&c)
		if err := c.Validate(); err == nil {
			t.Errorf("%s: expected a validation error", name)
		}
	}
}
