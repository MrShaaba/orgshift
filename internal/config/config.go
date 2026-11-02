// Package config reads the onboarding configuration: one YAML or JSON file
// that says how orgshift reaches the source and destination organizations
// (profiles, Identity Center sessions, assume-role chains), which account
// each credential is expected to belong to, where Control Tower and Identity
// Center live, which regions the workloads use, and how collection should
// behave. Nothing in it is a secret: it names profiles and roles, never
// keys.
package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// SchemaVersion is the configuration file version this build reads.
const SchemaVersion = 1

// Config is the whole onboarding file.
type Config struct {
	SchemaVersion int `yaml:"schema_version" json:"schema_version"`
	// Source is the organization the account leaves; always present.
	Source Side `yaml:"source" json:"source"`
	// Destination is the organization the account joins. Omit it for a move
	// inside one organization.
	Destination *Side      `yaml:"destination,omitempty" json:"destination,omitempty"`
	Collection  Collection `yaml:"collection" json:"collection"`
	Billable    Billable   `yaml:"billable" json:"billable"`
	Templates   Templates  `yaml:"templates" json:"templates"`
}

// Side describes the access to one organization.
type Side struct {
	// Name is the friendly organization name stored in snapshots.
	Name string `yaml:"name" json:"name"`
	// Management reaches the management account (or an Organizations
	// delegated administrator) for Organizations, Account Management and
	// the management account's own RAM shares.
	Management Access `yaml:"management" json:"management"`
	// MemberInspection names the role assumed in member accounts.
	MemberInspection *MemberInspection `yaml:"member_inspection,omitempty" json:"member_inspection,omitempty"`
	// Network reaches the accounts that own the shared networking (RAM
	// only lists the caller's own shares).
	Network []Access `yaml:"network,omitempty" json:"network,omitempty"`
	// Security reaches the audit and log archive accounts. Not used by this
	// build's collector; preflight verifies the identity.
	Security []Access `yaml:"security,omitempty" json:"security,omitempty"`
	// ControlTower says where the landing zone lives. Nil means "read it in
	// the management region"; Enabled false turns the domain off.
	ControlTower *ControlTower `yaml:"control_tower,omitempty" json:"control_tower,omitempty"`
	// IdentityCenter says where the instance lives and, optionally, which
	// credentials read it (the delegated administrator).
	IdentityCenter *IdentityCenter `yaml:"identity_center,omitempty" json:"identity_center,omitempty"`
	// WorkloadRegions are the regions the workloads run in; later
	// milestones scope network-path reasoning to them.
	WorkloadRegions []string `yaml:"workload_regions,omitempty" json:"workload_regions,omitempty"`
	// Skip lists coverage domains not to collect: enabled_regions,
	// resource_shares, control_tower, identity_center.
	Skip []string `yaml:"skip,omitempty" json:"skip,omitempty"`
}

// Access says how one credential is obtained and which account it must
// belong to. Exactly one of profile, sso_session and from (or none, for the
// default credential chain) selects the base credentials; assume_role hops
// are applied on top, in order.
type Access struct {
	// Label names the access in messages ("network account").
	Label string `yaml:"label,omitempty" json:"label,omitempty"`
	// AccountID is the account the final credentials must belong to.
	// sts:GetCallerIdentity is checked against it before anything is read.
	AccountID string `yaml:"account_id" json:"account_id"`
	// Region is the endpoint region; defaults to the side's management
	// region.
	Region string `yaml:"region,omitempty" json:"region,omitempty"`
	// Profile is a shared configuration profile (which may itself be an SSO
	// or assume-role profile).
	Profile string `yaml:"profile,omitempty" json:"profile,omitempty"`
	// SSOSession is an sso-session name from the shared configuration whose
	// cached token (aws sso login --sso-session NAME) is used to fetch role
	// credentials for SSORoleName in SSOAccountID.
	SSOSession   string `yaml:"sso_session,omitempty" json:"sso_session,omitempty"`
	SSORegion    string `yaml:"sso_region,omitempty" json:"sso_region,omitempty"`
	SSOStartURL  string `yaml:"sso_start_url,omitempty" json:"sso_start_url,omitempty"`
	SSORoleName  string `yaml:"sso_role_name,omitempty" json:"sso_role_name,omitempty"`
	SSOAccountID string `yaml:"sso_account_id,omitempty" json:"sso_account_id,omitempty"`
	// From is "management": start from the side's management credentials,
	// then assume the roles below. Only for network, security and Identity
	// Center access.
	From string `yaml:"from,omitempty" json:"from,omitempty"`
	// AssumeRole is the chain of roles to assume, in order.
	AssumeRole []RoleHop `yaml:"assume_role,omitempty" json:"assume_role,omitempty"`
}

// RoleHop is one sts:AssumeRole in a chain.
type RoleHop struct {
	RoleARN     string   `yaml:"role_arn" json:"role_arn"`
	ExternalID  string   `yaml:"external_id,omitempty" json:"external_id,omitempty"`
	SessionName string   `yaml:"session_name,omitempty" json:"session_name,omitempty"`
	Duration    Duration `yaml:"duration,omitempty" json:"duration,omitempty"`
}

// Duration is a time.Duration written as "10m" or "1h30m" in YAML and JSON
// (a bare integer is read as nanoseconds, as Go would).
type Duration time.Duration

func (d Duration) String() string { return time.Duration(d).String() }

// MarshalJSON writes the duration as a string.
func (d Duration) MarshalJSON() ([]byte, error) { return json.Marshal(d.String()) }

// UnmarshalJSON reads a string or a number of nanoseconds.
func (d *Duration) UnmarshalJSON(b []byte) error {
	var v any
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	switch x := v.(type) {
	case string:
		parsed, err := time.ParseDuration(x)
		if err != nil {
			return err
		}
		*d = Duration(parsed)
	case float64:
		*d = Duration(time.Duration(x))
	default:
		return fmt.Errorf("duration must be a string like \"10m\", got %v", v)
	}
	return nil
}

// MarshalYAML writes the duration as a string.
func (d Duration) MarshalYAML() (any, error) { return d.String(), nil }

// UnmarshalYAML reads a string or an integer number of nanoseconds.
func (d *Duration) UnmarshalYAML(n *yaml.Node) error {
	if n.Tag == "!!int" {
		var ns int64
		if err := n.Decode(&ns); err != nil {
			return err
		}
		*d = Duration(ns)
		return nil
	}
	parsed, err := time.ParseDuration(n.Value)
	if err != nil {
		return fmt.Errorf("duration %q: %w", n.Value, err)
	}
	*d = Duration(parsed)
	return nil
}

// MemberInspection names the role the collector assumes in member accounts.
type MemberInspection struct {
	// RoleName is the role present in every member account (the IAM
	// template "member-inspection" creates it).
	RoleName   string `yaml:"role_name" json:"role_name"`
	ExternalID string `yaml:"external_id,omitempty" json:"external_id,omitempty"`
	// Accounts are always probed by preflight; Sample says how many more
	// accounts are probed (default 5, 0 for none, -1 for all).
	Accounts []string `yaml:"accounts,omitempty" json:"accounts,omitempty"`
	Sample   *int     `yaml:"sample,omitempty" json:"sample,omitempty"`
}

// ControlTower locates the landing zone.
type ControlTower struct {
	Enabled *bool `yaml:"enabled,omitempty" json:"enabled,omitempty"`
	// HomeRegion is where the landing zone APIs answer.
	HomeRegion string `yaml:"home_region,omitempty" json:"home_region,omitempty"`
}

// IdentityCenter locates the instance.
type IdentityCenter struct {
	Enabled *bool  `yaml:"enabled,omitempty" json:"enabled,omitempty"`
	Region  string `yaml:"region,omitempty" json:"region,omitempty"`
	// Access overrides the management credentials for the Identity Center
	// reads, for example a role in the delegated administrator account.
	Access *Access `yaml:"access,omitempty" json:"access,omitempty"`
}

// Collection tunes the collector.
type Collection struct {
	// Concurrency bounds parallel per-item calls (default 4).
	Concurrency int `yaml:"concurrency,omitempty" json:"concurrency,omitempty"`
	// RetryAttempts is the SDK's maximum attempts per call (default 8).
	RetryAttempts int `yaml:"retry_attempts,omitempty" json:"retry_attempts,omitempty"`
	// Timeout bounds a whole collection run (default 10m).
	Timeout Duration `yaml:"timeout,omitempty" json:"timeout,omitempty"`
	// Checkpoint writes <out>.checkpoint.json after every completed step and
	// resumes from it (default true).
	Checkpoint *bool `yaml:"checkpoint,omitempty" json:"checkpoint,omitempty"`
}

// Billable are the opt-ins for reads AWS bills. Everything is off by
// default and refused until implemented.
type Billable struct {
	CloudTrailLake bool `yaml:"cloudtrail_lake" json:"cloudtrail_lake"`
	ConfigQueries  bool `yaml:"config_queries" json:"config_queries"`
}

// Templates tunes the generated IAM templates.
type Templates struct {
	// RolePrefix prefixes the generated role names (default "Orgshift").
	RolePrefix string `yaml:"role_prefix,omitempty" json:"role_prefix,omitempty"`
	// TrustedPrincipalARNs may assume the management-account roles: the
	// operator role or user that runs orgshift.
	TrustedPrincipalARNs []string `yaml:"trusted_principal_arns,omitempty" json:"trusted_principal_arns,omitempty"`
	// ExternalID is required in the trust policies when set.
	ExternalID string `yaml:"external_id,omitempty" json:"external_id,omitempty"`
}

// Defaults.
const (
	DefaultConcurrency   = 4
	DefaultRetryAttempts = 8
	DefaultTimeout       = 10 * time.Minute
	DefaultMemberSample  = 5
	DefaultRolePrefix    = "Orgshift"
)

// SkippableDomains are the coverage domains Side.Skip may name.
var SkippableDomains = []string{"enabled_regions", "resource_shares", "control_tower", "identity_center"}

// Load reads and validates a configuration file (YAML or JSON).
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	c, err := Parse(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return c, nil
}

// Parse decodes and validates a configuration document. Unknown fields are
// errors, so a typo never silently disables something.
func Parse(data []byte) (*Config, error) {
	var c Config
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}
	c.applyDefaults()
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

// applyDefaults fills the defaults that Validate relies on.
func (c *Config) applyDefaults() {
	if c.Collection.Concurrency == 0 {
		c.Collection.Concurrency = DefaultConcurrency
	}
	if c.Collection.RetryAttempts == 0 {
		c.Collection.RetryAttempts = DefaultRetryAttempts
	}
	if c.Collection.Timeout == 0 {
		c.Collection.Timeout = Duration(DefaultTimeout)
	}
	if c.Templates.RolePrefix == "" {
		c.Templates.RolePrefix = DefaultRolePrefix
	}
	for _, s := range c.sides() {
		s.side.applyDefaults()
	}
}

func (s *Side) applyDefaults() {
	region := s.Management.Region
	if s.Management.Label == "" {
		s.Management.Label = "management"
	}
	for i := range s.Network {
		if s.Network[i].Region == "" {
			s.Network[i].Region = region
		}
		if s.Network[i].Label == "" {
			s.Network[i].Label = fmt.Sprintf("network %d", i+1)
		}
	}
	for i := range s.Security {
		if s.Security[i].Region == "" {
			s.Security[i].Region = region
		}
		if s.Security[i].Label == "" {
			s.Security[i].Label = fmt.Sprintf("security %d", i+1)
		}
	}
	if s.IdentityCenter != nil && s.IdentityCenter.Access != nil {
		if s.IdentityCenter.Access.Label == "" {
			s.IdentityCenter.Access.Label = "identity center"
		}
		if s.IdentityCenter.Access.Region == "" {
			s.IdentityCenter.Access.Region = s.IdentityCenterRegion()
		}
	}
	if s.MemberInspection != nil && s.MemberInspection.Sample == nil {
		n := DefaultMemberSample
		s.MemberInspection.Sample = &n
	}
}

var (
	accountIDRe = regexp.MustCompile(`^\d{12}$`)
	regionRe    = regexp.MustCompile(`^[a-z]{2}(-[a-z]+)+-\d$`)
	roleARNRe   = regexp.MustCompile(`^arn:aws(-[a-z]+)*:iam::\d{12}:role/[\w+=,.@/-]+$`)
	roleNameRe  = regexp.MustCompile(`^[\w+=,.@-]{1,64}$`)
	anyARNRe    = regexp.MustCompile(`^arn:aws(-[a-z]+)*:iam::\d{12}:(role|user|root)(/[\w+=,.@/-]+)?$`)
)

// Validate checks the configuration without touching AWS.
func (c *Config) Validate() error {
	var errs []string
	fail := func(format string, args ...any) { errs = append(errs, fmt.Sprintf(format, args...)) }
	switch {
	case c.SchemaVersion == 0:
		fail("schema_version is required (this build reads %d)", SchemaVersion)
	case c.SchemaVersion != SchemaVersion:
		fail("schema_version %d is not supported (this build reads %d)", c.SchemaVersion, SchemaVersion)
	}
	for _, s := range c.sides() {
		s.side.validate(s.name, fail)
	}
	if c.Destination != nil && c.Destination.Management.AccountID == c.Source.Management.AccountID {
		fail("destination.management.account_id equals the source's; omit destination for a move inside one organization")
	}
	if c.Collection.Concurrency < 1 || c.Collection.Concurrency > 32 {
		fail("collection.concurrency must be between 1 and 32")
	}
	if c.Collection.RetryAttempts < 1 || c.Collection.RetryAttempts > 20 {
		fail("collection.retry_attempts must be between 1 and 20")
	}
	if time.Duration(c.Collection.Timeout) < time.Minute {
		fail("collection.timeout must be at least 1m")
	}
	if !roleNameRe.MatchString(c.Templates.RolePrefix) {
		fail("templates.role_prefix %q is not a valid IAM role name prefix", c.Templates.RolePrefix)
	}
	for _, p := range c.Templates.TrustedPrincipalARNs {
		if !anyARNRe.MatchString(p) {
			fail("templates.trusted_principal_arns: %q is not an IAM role, user or account root ARN", p)
		}
	}
	if len(errs) == 0 {
		return nil
	}
	sort.Strings(errs)
	return fmt.Errorf("invalid configuration:\n  - %s", strings.Join(errs, "\n  - "))
}

func (s *Side) validate(prefix string, fail func(string, ...any)) {
	if s.Name == "" {
		fail("%s.name is required", prefix)
	}
	s.Management.validate(prefix+".management", false, fail)
	if s.Management.Region == "" {
		fail("%s.management.region is required", prefix)
	}
	for i := range s.Network {
		s.Network[i].validate(fmt.Sprintf("%s.network[%d]", prefix, i), true, fail)
	}
	for i := range s.Security {
		s.Security[i].validate(fmt.Sprintf("%s.security[%d]", prefix, i), true, fail)
	}
	if ct := s.ControlTower; ct != nil && ct.HomeRegion != "" && !regionRe.MatchString(ct.HomeRegion) {
		fail("%s.control_tower.home_region %q is not a region", prefix, ct.HomeRegion)
	}
	if ic := s.IdentityCenter; ic != nil {
		if ic.Region != "" && !regionRe.MatchString(ic.Region) {
			fail("%s.identity_center.region %q is not a region", prefix, ic.Region)
		}
		if ic.Access != nil {
			ic.Access.validate(prefix+".identity_center.access", true, fail)
		}
	}
	if m := s.MemberInspection; m != nil {
		if !roleNameRe.MatchString(m.RoleName) {
			fail("%s.member_inspection.role_name %q is not a valid IAM role name", prefix, m.RoleName)
		}
		for _, a := range m.Accounts {
			if !accountIDRe.MatchString(a) {
				fail("%s.member_inspection.accounts: %q is not a 12-digit account ID", prefix, a)
			}
		}
		if m.Sample != nil && *m.Sample < -1 {
			fail("%s.member_inspection.sample must be -1 (all), 0 (none) or a count", prefix)
		}
	}
	for _, r := range s.WorkloadRegions {
		if !regionRe.MatchString(r) {
			fail("%s.workload_regions: %q is not a region", prefix, r)
		}
	}
	for _, d := range s.Skip {
		if !contains(SkippableDomains, d) {
			fail("%s.skip: %q is not one of %s", prefix, d, strings.Join(SkippableDomains, ", "))
		}
	}
}

func (a *Access) validate(prefix string, fromAllowed bool, fail func(string, ...any)) {
	if !accountIDRe.MatchString(a.AccountID) {
		fail("%s.account_id %q is not a 12-digit account ID", prefix, a.AccountID)
	}
	if a.Region != "" && !regionRe.MatchString(a.Region) {
		fail("%s.region %q is not a region", prefix, a.Region)
	}
	sources := 0
	for _, set := range []bool{a.Profile != "", a.SSOSession != "", a.From != ""} {
		if set {
			sources++
		}
	}
	if sources > 1 {
		fail("%s: profile, sso_session and from are mutually exclusive", prefix)
	}
	if a.From != "" {
		switch {
		case !fromAllowed:
			fail("%s.from is only for network, security and identity_center access", prefix)
		case a.From != "management":
			fail("%s.from must be \"management\", got %q", prefix, a.From)
		case len(a.AssumeRole) == 0:
			fail("%s: from management needs at least one assume_role hop, otherwise it is the management account itself", prefix)
		}
	}
	if a.SSOSession != "" {
		if a.SSORoleName == "" {
			fail("%s.sso_role_name is required with sso_session", prefix)
		}
		if a.SSORegion == "" {
			fail("%s.sso_region is required with sso_session", prefix)
		} else if !regionRe.MatchString(a.SSORegion) {
			fail("%s.sso_region %q is not a region", prefix, a.SSORegion)
		}
		if a.SSOAccountID != "" && !accountIDRe.MatchString(a.SSOAccountID) {
			fail("%s.sso_account_id %q is not a 12-digit account ID", prefix, a.SSOAccountID)
		}
	} else if a.SSORoleName != "" || a.SSORegion != "" || a.SSOStartURL != "" || a.SSOAccountID != "" {
		fail("%s: sso_* fields need sso_session", prefix)
	}
	for i, h := range a.AssumeRole {
		if !roleARNRe.MatchString(h.RoleARN) {
			fail("%s.assume_role[%d].role_arn %q is not an IAM role ARN", prefix, i, h.RoleARN)
		}
		if d := time.Duration(h.Duration); d != 0 && (d < 15*time.Minute || d > 12*time.Hour) {
			fail("%s.assume_role[%d].duration must be between 15m and 12h", prefix, i)
		}
		if h.SessionName != "" && !regexp.MustCompile(`^[\w+=,.@-]{2,64}$`).MatchString(h.SessionName) {
			fail("%s.assume_role[%d].session_name %q is not a valid session name", prefix, i, h.SessionName)
		}
	}
}

// NamedSide pairs a side with its name ("source", "destination").
type NamedSide struct {
	Name string
	Side *Side
}

// Sides returns the source and, when present, the destination.
func (c *Config) Sides() []NamedSide {
	var out []NamedSide
	for _, s := range c.sides() {
		out = append(out, NamedSide{Name: s.name, Side: s.side})
	}
	return out
}

type namedSide struct {
	name string
	side *Side
}

func (c *Config) sides() []namedSide {
	out := []namedSide{{"source", &c.Source}}
	if c.Destination != nil {
		out = append(out, namedSide{"destination", c.Destination})
	}
	return out
}

// Side returns the side by name.
func (c *Config) Side(name string) (*Side, error) {
	for _, s := range c.Sides() {
		if s.Name == name {
			return s.Side, nil
		}
	}
	if name == "destination" {
		return nil, fmt.Errorf("the configuration has no destination")
	}
	return nil, fmt.Errorf("unknown side %q (source or destination)", name)
}

// ControlTowerEnabled reports whether the landing zone is read.
func (s *Side) ControlTowerEnabled() bool {
	if contains(s.Skip, "control_tower") {
		return false
	}
	return s.ControlTower == nil || s.ControlTower.Enabled == nil || *s.ControlTower.Enabled
}

// ControlTowerRegion is the landing zone's home region, or the management
// region when none is configured.
func (s *Side) ControlTowerRegion() string {
	if s.ControlTower != nil && s.ControlTower.HomeRegion != "" {
		return s.ControlTower.HomeRegion
	}
	return s.Management.Region
}

// IdentityCenterEnabled reports whether the instance is read.
func (s *Side) IdentityCenterEnabled() bool {
	if contains(s.Skip, "identity_center") {
		return false
	}
	return s.IdentityCenter == nil || s.IdentityCenter.Enabled == nil || *s.IdentityCenter.Enabled
}

// IdentityCenterRegion is the instance's region, or the management region.
func (s *Side) IdentityCenterRegion() string {
	if s.IdentityCenter != nil && s.IdentityCenter.Region != "" {
		return s.IdentityCenter.Region
	}
	return s.Management.Region
}

// IdentityCenterAccess returns the credentials that read Identity Center:
// the override when configured, else the management access with the
// instance's region.
func (s *Side) IdentityCenterAccess() Access {
	if s.IdentityCenter != nil && s.IdentityCenter.Access != nil {
		return *s.IdentityCenter.Access
	}
	a := s.Management
	a.Region = s.IdentityCenterRegion()
	return a
}

// Skipped reports whether a coverage domain is turned off for the side.
func (s *Side) Skipped(domain string) bool { return contains(s.Skip, domain) }

// Checkpointing reports whether checkpoints are on (default true).
func (c Collection) Checkpointing() bool { return c.Checkpoint == nil || *c.Checkpoint }

// MemberSample returns how many extra member accounts preflight probes.
func (m *MemberInspection) MemberSample() int {
	if m == nil || m.Sample == nil {
		return DefaultMemberSample
	}
	return *m.Sample
}

// Describe says how the credentials are obtained, for messages.
func (a Access) Describe() string {
	var parts []string
	switch {
	case a.Profile != "":
		parts = append(parts, "profile "+a.Profile)
	case a.SSOSession != "":
		parts = append(parts, fmt.Sprintf("Identity Center session %s (role %s in %s)", a.SSOSession, a.SSORoleName, a.ssoAccount()))
	case a.From == "management":
		parts = append(parts, "the management credentials")
	default:
		parts = append(parts, "the default credential chain")
	}
	for _, h := range a.AssumeRole {
		parts = append(parts, "assume "+h.RoleARN)
	}
	return strings.Join(parts, ", then ")
}

func (a Access) ssoAccount() string {
	if a.SSOAccountID != "" {
		return a.SSOAccountID
	}
	return a.AccountID
}

// SSOAccount is the account the SSO role is fetched for.
func (a Access) SSOAccount() string { return a.ssoAccount() }

// JSON renders the configuration as indented JSON, for `config check`.
func (c *Config) JSON() ([]byte, error) {
	return json.MarshalIndent(c, "", "  ")
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}
