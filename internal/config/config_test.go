package config

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestExampleParsesAndValidates(t *testing.T) {
	c, err := Parse([]byte(Example))
	if err != nil {
		t.Fatal(err)
	}
	if c.Source.Name != "Larkspur Holdings" || c.Source.Management.AccountID != "111111111111" || c.Source.Management.Profile != "larkspur-mgmt" || len(c.Source.Management.AssumeRole) != 1 {
		t.Errorf("source: %+v", c.Source.Management)
	}
	if c.Destination == nil || c.Destination.Management.SSOSession != "fernhill" || c.Destination.Management.SSORoleName != "OrgshiftOrgRead" || c.Destination.Management.SSOAccount() != "222222222222" {
		t.Errorf("destination: %+v", c.Destination)
	}
	if !c.Source.ControlTowerEnabled() || c.Source.ControlTowerRegion() != "us-east-1" || c.Destination.IdentityCenterRegion() != "eu-west-1" || !c.Destination.IdentityCenterEnabled() {
		t.Error("regions and switches")
	}
	if len(c.Source.Network) != 1 || c.Source.Network[0].From != "management" || c.Source.Network[0].Region != "us-east-1" || c.Source.Network[0].Label != "network account" {
		t.Errorf("network defaults: %+v", c.Source.Network)
	}
	if c.Source.Security[0].Region != "us-east-1" || c.Source.Management.Label != "management" {
		t.Errorf("defaults not applied: %+v", c.Source.Security[0])
	}
	if c.Collection.Concurrency != 4 || c.Collection.RetryAttempts != 8 || time.Duration(c.Collection.Timeout) != 10*time.Minute || !c.Collection.Checkpointing() {
		t.Errorf("collection: %+v", c.Collection)
	}
	if c.Source.MemberInspection.MemberSample() != 5 || c.Source.MemberInspection.RoleName != "OrgshiftMemberRead" {
		t.Errorf("member inspection: %+v", c.Source.MemberInspection)
	}
	if c.Templates.RolePrefix != "Orgshift" || len(c.Templates.TrustedPrincipalARNs) != 1 {
		t.Errorf("templates: %+v", c.Templates)
	}
	if got := c.Source.Management.Describe(); got != "profile larkspur-mgmt, then assume arn:aws:iam::111111111111:role/OrgshiftOrgRead" {
		t.Errorf("Describe: %s", got)
	}
	if got := c.Destination.Management.Describe(); !strings.Contains(got, "Identity Center session fernhill") {
		t.Errorf("Describe SSO: %s", got)
	}
	if got := c.Source.Network[0].Describe(); got != "the management credentials, then assume arn:aws:iam::111111111120:role/OrgshiftNetworkRead" {
		t.Errorf("Describe from management: %s", got)
	}
	ic := c.Source.IdentityCenterAccess()
	if ic.Profile != "larkspur-mgmt" || ic.Region != "us-east-1" {
		t.Errorf("identity center access defaults to management: %+v", ic)
	}
	sides := c.Sides()
	if len(sides) != 2 || sides[0].Name != "source" || sides[1].Name != "destination" {
		t.Errorf("sides: %+v", sides)
	}
	if _, err := c.Side("nowhere"); err == nil {
		t.Error("unknown side must fail")
	}
	// The JSON rendering is itself a valid configuration (JSON is YAML).
	data, err := c.JSON()
	if err != nil {
		t.Fatal(err)
	}
	again, err := Parse(data)
	if err != nil {
		t.Fatalf("JSON round trip: %v\n%s", err, data)
	}
	if again.Collection.Timeout != c.Collection.Timeout || again.Destination.Management.SSOSession != "fernhill" {
		t.Errorf("round trip lost fields: %+v", again.Collection)
	}
}

func TestJSONInputAndDefaults(t *testing.T) {
	c, err := Parse([]byte(`{"schema_version": 1, "source": {"name": "One", "management": {"account_id": "123456789012", "region": "us-west-2"}}}`))
	if err != nil {
		t.Fatal(err)
	}
	if c.Destination != nil || c.Source.Management.Describe() != "the default credential chain" || c.Collection.Concurrency != DefaultConcurrency || c.Templates.RolePrefix != DefaultRolePrefix {
		t.Errorf("defaults: %+v", c)
	}
	if !c.Source.ControlTowerEnabled() || c.Source.ControlTowerRegion() != "us-west-2" || c.Source.IdentityCenterRegion() != "us-west-2" {
		t.Error("control tower and identity center default to the management region")
	}
	if _, err := c.Side("destination"); err == nil || !strings.Contains(err.Error(), "no destination") {
		t.Errorf("destination lookup: %v", err)
	}
	off := false
	c.Source.ControlTower = &ControlTower{Enabled: &off}
	c.Source.Skip = []string{"identity_center"}
	if c.Source.ControlTowerEnabled() || c.Source.IdentityCenterEnabled() || !c.Source.Skipped("identity_center") {
		t.Error("switches off")
	}
}

func TestValidationErrors(t *testing.T) {
	base := `schema_version: 1
source:
  name: One
  management:
    account_id: "123456789012"
    region: us-west-2
`
	cases := map[string]struct {
		doc  string
		want string
	}{
		"missing version": {`source: {name: x, management: {account_id: "123456789012", region: us-east-1}}`, "schema_version is required"},
		"newer version":   {`schema_version: 2` + base[len("schema_version: 1"):], "schema_version 2 is not supported"},
		"unknown field":   {base + `sourc: {}`, "field sourc not found"},
		"bad account":     {strings.Replace(base, `"123456789012"`, `"12345"`, 1), "is not a 12-digit account ID"},
		"bad region":      {strings.Replace(base, "us-west-2", "mars", 1), `region "mars" is not a region`},
		"two sources":     {base + "    profile: a\n    sso_session: b\n    sso_role_name: r\n    sso_region: us-east-1\n", "mutually exclusive"},
		"sso needs role":  {strings.Replace(base, "region: us-west-2", "region: us-west-2\n    sso_session: b\n    sso_region: us-east-1", 1), "sso_role_name is required"},
		"sso fields":      {strings.Replace(base, "region: us-west-2", "region: us-west-2\n    sso_role_name: r", 1), "sso_* fields need sso_session"},
		"from on mgmt":    {strings.Replace(base, "region: us-west-2", "region: us-west-2\n    from: management\n    assume_role: [{role_arn: arn:aws:iam::123456789012:role/X}]", 1), "from is only for network"},
		"from no hop":     {base + "  network:\n    - account_id: \"123456789013\"\n      from: management\n", "needs at least one assume_role hop"},
		"from other":      {base + "  network:\n    - account_id: \"123456789013\"\n      from: elsewhere\n      assume_role: [{role_arn: arn:aws:iam::123456789013:role/X}]\n", `from must be "management"`},
		"bad role arn":    {base + "  network:\n    - account_id: \"123456789013\"\n      from: management\n      assume_role: [{role_arn: not-an-arn}]\n", "is not an IAM role ARN"},
		"bad duration":    {base + "  network:\n    - account_id: \"123456789013\"\n      from: management\n      assume_role: [{role_arn: arn:aws:iam::123456789013:role/X, duration: 1m}]\n", "duration must be between 15m and 12h"},
		"member role":     {base + "  member_inspection:\n    role_name: \"bad role name\"\n", "is not a valid IAM role name"},
		"member account":  {base + "  member_inspection:\n    role_name: Ok\n    accounts: [abc]\n", "is not a 12-digit account ID"},
		"member sample":   {base + "  member_inspection:\n    role_name: Ok\n    sample: -2\n", "sample must be -1"},
		"skip":            {base + "  skip: [tree]\n", `skip: "tree" is not one of`},
		"workload region": {base + "  workload_regions: [EU]\n", `"EU" is not a region`},
		"ct region":       {base + "  control_tower:\n    home_region: nope\n", `home_region "nope" is not a region`},
		"same account":    {base + "destination:\n  name: Two\n  management:\n    account_id: \"123456789012\"\n    region: us-west-2\n", "equals the source's"},
		"concurrency":     {base + "collection:\n  concurrency: 64\n", "concurrency must be between 1 and 32"},
		"retries":         {base + "collection:\n  retry_attempts: 0\n", ""},
		"timeout":         {base + "collection:\n  timeout: 10s\n", "timeout must be at least 1m"},
		"prefix":          {base + "templates:\n  role_prefix: \"a b\"\n", "is not a valid IAM role name prefix"},
		"trusted":         {base + "templates:\n  trusted_principal_arns: [bob]\n", "is not an IAM role, user or account root ARN"},
		"no name":         {strings.Replace(base, "  name: One\n", "", 1), "source.name is required"},
		"no region":       {strings.Replace(base, "    region: us-west-2\n", "", 1), "management.region is required"},
	}
	for name, c := range cases {
		_, err := Parse([]byte(c.doc))
		if c.want == "" {
			if err != nil {
				t.Errorf("%s: unexpected error %v", name, err)
			}
			continue
		}
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: want error containing %q, got %v", name, c.want, err)
		}
	}
}

func TestLoadMissingFile(t *testing.T) {
	if _, err := Load("/nonexistent/orgshift.yaml"); err == nil {
		t.Fatal("expected an error")
	}
}

func TestDurationsDecodeFromStringsInYAMLAndJSON(t *testing.T) {
	yamlDoc := `schema_version: 1
source:
  name: One
  management:
    account_id: "123456789012"
    region: us-west-2
    assume_role:
      - role_arn: arn:aws:iam::123456789012:role/X
        duration: 1h
collection:
  timeout: 90m
`
	c, err := Parse([]byte(yamlDoc))
	if err != nil {
		t.Fatal(err)
	}
	if time.Duration(c.Source.Management.AssumeRole[0].Duration) != time.Hour || time.Duration(c.Collection.Timeout) != 90*time.Minute {
		t.Errorf("durations: %+v %v", c.Source.Management.AssumeRole, c.Collection.Timeout)
	}
	var generic map[string]any
	if err := json.Unmarshal([]byte(`{"schema_version":1,"source":{"name":"One","management":{"account_id":"123456789012","region":"us-west-2"}},"collection":{"timeout":"2h"}}`), &generic); err != nil {
		t.Fatal(err)
	}
	c, err = Parse([]byte(`{"schema_version":1,"source":{"name":"One","management":{"account_id":"123456789012","region":"us-west-2"}},"collection":{"timeout":"2h"}}`))
	if err != nil {
		t.Fatal(err)
	}
	if time.Duration(c.Collection.Timeout) != 2*time.Hour {
		t.Errorf("JSON duration: %v", c.Collection.Timeout)
	}
}
