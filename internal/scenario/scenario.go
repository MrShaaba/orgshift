// Package scenario is the staged migration model: a scenario overlay file,
// kept apart from the immutable snapshots, describes a migration as a
// sequence of proposed states across five layers (organization membership,
// OU placement, Control Tower governance, network connectivity, workload
// relocation), and the package derives the state after every stage,
// evaluates each transition with the evaluator and compares strategies.
//
// Nothing here changes a snapshot on disk or in memory: every derived state
// is a copy with the proposed objects added, and proposed OUs, policies and
// shares are listed in the result so a reader can tell them from collected
// ones.
package scenario

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/MrShaaba/orgshift/internal/evaluator"
	"github.com/MrShaaba/orgshift/internal/snapshot"
)

// SchemaVersion is the scenario file version this build reads.
const SchemaVersion = 1

// Layers of a migration, kept separate in every stage and every report.
const (
	LayerMembership = "membership"
	LayerPlacement  = "placement"
	LayerGovernance = "governance"
	LayerNetwork    = "network"
	LayerWorkload   = "workload"
)

// Layers lists the five layers in report order.
var Layers = []string{LayerMembership, LayerPlacement, LayerGovernance, LayerNetwork, LayerWorkload}

// Strategies the comparison knows.
const (
	// StrategyTransfer moves the account itself between organizations.
	StrategyTransfer = "transfer"
	// StrategyRecreate creates destination accounts and migrates the
	// workloads into them, leaving the source account where it is.
	StrategyRecreate = "recreate"
)

// Organization sides a stage can place the account in.
const (
	OrgSource      = "source"
	OrgDestination = "destination"
)

// Scenario is the overlay file.
type Scenario struct {
	SchemaVersion int    `yaml:"schema_version" json:"schema_version"`
	Name          string `yaml:"name" json:"name"`
	Description   string `yaml:"description,omitempty" json:"description,omitempty"`
	// AccountID is the account that moves.
	AccountID string `yaml:"account" json:"account"`
	// Strategy is transfer (default) or recreate; the comparison always
	// describes both.
	Strategy string `yaml:"strategy,omitempty" json:"strategy,omitempty"`
	// Source and Destination are optional snapshot file paths, relative to
	// the scenario file; the CLI flags override them.
	Source      string `yaml:"source,omitempty" json:"source,omitempty"`
	Destination string `yaml:"destination,omitempty" json:"destination,omitempty"`
	// CriticalOperations are operations the operator declares the account
	// must keep performing, evaluated at every stage alongside the observed
	// usage.
	CriticalOperations []CriticalOperation `yaml:"critical_operations,omitempty" json:"critical_operations,omitempty"`
	// Proposed objects do not exist in the destination snapshot yet.
	Proposed Proposed `yaml:"proposed,omitempty" json:"proposed,omitempty"`
	Stages   []Stage  `yaml:"stages" json:"stages"`
}

// CriticalOperation is a user-declared operation.
type CriticalOperation struct {
	Action        string            `yaml:"action" json:"action"`
	Resource      string            `yaml:"resource,omitempty" json:"resource,omitempty"`
	Regions       []string          `yaml:"regions,omitempty" json:"regions,omitempty"`
	PrincipalARN  string            `yaml:"principal_arn,omitempty" json:"principal_arn,omitempty"`
	PrincipalTags map[string]string `yaml:"principal_tags,omitempty" json:"principal_tags,omitempty"`
	// Reason says why the operation matters (a deployment, a recovery
	// procedure, scaling).
	Reason string `yaml:"reason" json:"reason"`
}

// ActionInUse converts the declaration into the evaluator's input.
func (c CriticalOperation) ActionInUse() snapshot.ActionInUse {
	return snapshot.ActionInUse{Action: c.Action, Resource: c.Resource, Regions: c.Regions, PrincipalArn: c.PrincipalARN, PrincipalTags: c.PrincipalTags, Note: c.Reason}
}

// Proposed are the objects the scenario adds to the destination
// organization (or to the source, for a move inside one organization).
type Proposed struct {
	OUs            []ProposedOU     `yaml:"organizational_units,omitempty" json:"organizational_units,omitempty"`
	Policies       []ProposedPolicy `yaml:"policies,omitempty" json:"policies,omitempty"`
	ResourceShares []ProposedShare  `yaml:"resource_shares,omitempty" json:"resource_shares,omitempty"`
}

// ProposedOU is an OU to create.
type ProposedOU struct {
	// ID is a synthetic identifier used by the stages; it must not exist in
	// the snapshot. Organizations assigns the real one at creation.
	ID       string `yaml:"id" json:"id"`
	Name     string `yaml:"name" json:"name"`
	ParentID string `yaml:"parent" json:"parent"`
	// Policies are existing or proposed policy IDs attached to the OU from
	// its creation. Organizations attaches the AWS managed defaults itself.
	Policies []string `yaml:"policies,omitempty" json:"policies,omitempty"`
	// Register says the OU is registered with Control Tower when it is
	// created (a stage's governance.register_ou does the same later).
	Register bool `yaml:"register,omitempty" json:"register,omitempty"`
}

// ProposedPolicy is a policy to create.
type ProposedPolicy struct {
	ID          string              `yaml:"id" json:"id"`
	Name        string              `yaml:"name" json:"name"`
	Type        snapshot.PolicyType `yaml:"type" json:"type"`
	Description string              `yaml:"description,omitempty" json:"description,omitempty"`
	// Document is the policy document: a YAML mapping or a JSON string.
	Document yaml.Node `yaml:"document" json:"-"`
	// DocumentJSON is the document as JSON, filled by Parse.
	DocumentJSON json.RawMessage `yaml:"-" json:"document"`
}

// ProposedShare is a RAM share to create, usually re-creating in the
// destination a share the account loses by leaving the source.
type ProposedShare struct {
	Name           string   `yaml:"name" json:"name"`
	OwnerAccountID string   `yaml:"owner_account" json:"owner_account"`
	Principals     []string `yaml:"principals" json:"principals"`
	Resources      []struct {
		ARN  string `yaml:"arn" json:"arn"`
		Type string `yaml:"type" json:"type"`
	} `yaml:"resources" json:"resources"`
	AllowExternalPrincipals bool `yaml:"allow_external_principals,omitempty" json:"allow_external_principals,omitempty"`
	RetainOnLeave           bool `yaml:"retain_sharing_on_account_leave_organization,omitempty" json:"retain_sharing_on_account_leave_organization,omitempty"`
}

// Stage is one proposed state. Every layer is optional; a stage that
// changes nothing is a verification point.
type Stage struct {
	ID          string      `yaml:"id" json:"id"`
	Title       string      `yaml:"title" json:"title"`
	Description string      `yaml:"description,omitempty" json:"description,omitempty"`
	Membership  *Membership `yaml:"membership,omitempty" json:"membership,omitempty"`
	Placement   *Placement  `yaml:"placement,omitempty" json:"placement,omitempty"`
	Governance  *Governance `yaml:"governance,omitempty" json:"governance,omitempty"`
	Network     *Network    `yaml:"network,omitempty" json:"network,omitempty"`
	Workload    *Workload   `yaml:"workload,omitempty" json:"workload,omitempty"`
	// Policies attaches or detaches policies at this stage (progressive
	// tightening).
	Policies *PolicyChange `yaml:"policies,omitempty" json:"policies,omitempty"`
	// Verify lists the checks the operator performs at this stage; they are
	// reported, not performed.
	Verify []string `yaml:"verify,omitempty" json:"verify,omitempty"`
}

// Membership changes the organization the account belongs to.
type Membership struct {
	Organization string `yaml:"organization" json:"organization"`
	// Method is how the account changes organization: "direct" (the
	// default: the other organization invites, the account accepts, and it
	// is never standalone) or "leave-and-rejoin" (it leaves or is removed,
	// runs standalone, then accepts). A management account has neither: its
	// organization has to be emptied and deleted first, and the stage says
	// so whatever is written here.
	Method string `yaml:"method,omitempty" json:"method,omitempty"`
}

// Placement changes the account's parent (a root, an existing OU or a
// proposed OU of the current organization).
type Placement struct {
	ParentID string `yaml:"parent" json:"parent"`
}

// Governance changes the Control Tower state.
type Governance struct {
	// Enrolled enrolls (true) or unenrolls (false) the account.
	Enrolled *bool `yaml:"enrolled,omitempty" json:"enrolled,omitempty"`
	// RegisterOU registers an OU with Control Tower at this stage.
	RegisterOU string `yaml:"register_ou,omitempty" json:"register_ou,omitempty"`
	// Declarations about the enrollment prerequisites, which the collector
	// cannot see. Unset means unknown.
	ExecutionRolePresent   *bool `yaml:"execution_role_present,omitempty" json:"execution_role_present,omitempty"`
	ConfigResourcesRemoved *bool `yaml:"config_resources_removed,omitempty" json:"config_resources_removed,omitempty"`
}

// Network changes the shares that reach the account.
type Network struct {
	// RecreateShares names proposed shares that exist from this stage on.
	RecreateShares []string `yaml:"recreate_shares,omitempty" json:"recreate_shares,omitempty"`
	// RemoveShares names existing shares (by name) the owner withdraws.
	RemoveShares []string `yaml:"remove_shares,omitempty" json:"remove_shares,omitempty"`
	// Validated marks the stage as the network validation point.
	Validated bool   `yaml:"validated,omitempty" json:"validated,omitempty"`
	Note      string `yaml:"note,omitempty" json:"note,omitempty"`
}

// Workload describes workload relocation (the recreate strategy).
type Workload struct {
	Relocate        bool   `yaml:"relocate,omitempty" json:"relocate,omitempty"`
	TargetAccountID string `yaml:"target_account,omitempty" json:"target_account,omitempty"`
	Note            string `yaml:"note,omitempty" json:"note,omitempty"`
}

// PolicyChange attaches or detaches policies.
type PolicyChange struct {
	Attach []Attachment `yaml:"attach,omitempty" json:"attach,omitempty"`
	Detach []Attachment `yaml:"detach,omitempty" json:"detach,omitempty"`
}

// Attachment is one policy on one target.
type Attachment struct {
	PolicyID string `yaml:"policy" json:"policy"`
	TargetID string `yaml:"target" json:"target"`
}

// Load reads and validates a scenario file (YAML or JSON).
func Load(path string) (*Scenario, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	sc, err := Parse(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return sc, nil
}

// Parse decodes and validates a scenario. Unknown fields are errors.
func Parse(data []byte) (*Scenario, error) {
	var sc Scenario
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&sc); err != nil {
		return nil, fmt.Errorf("invalid scenario: %w", err)
	}
	if sc.Strategy == "" {
		sc.Strategy = StrategyTransfer
	}
	for i := range sc.Proposed.Policies {
		p := &sc.Proposed.Policies[i]
		doc, err := documentJSON(p.Document)
		if err != nil {
			return nil, fmt.Errorf("invalid scenario: proposed policy %s: %w", p.ID, err)
		}
		p.DocumentJSON = doc
	}
	if err := sc.Validate(); err != nil {
		return nil, err
	}
	return &sc, nil
}

// documentJSON turns a YAML mapping or a JSON string into compact JSON.
func documentJSON(n yaml.Node) (json.RawMessage, error) {
	if n.Kind == 0 {
		return nil, fmt.Errorf("document is required")
	}
	if n.Kind == yaml.ScalarNode {
		if !json.Valid([]byte(n.Value)) {
			return nil, fmt.Errorf("document string is not valid JSON")
		}
		var buf bytes.Buffer
		if err := json.Compact(&buf, []byte(n.Value)); err != nil {
			return nil, err
		}
		return buf.Bytes(), nil
	}
	var v any
	if err := n.Decode(&v); err != nil {
		return nil, err
	}
	data, err := json.Marshal(normalize(v))
	if err != nil {
		return nil, err
	}
	return data, nil
}

// normalize turns yaml.v3's map[string]any (already string-keyed) and nested
// slices into JSON-marshalable values.
func normalize(v any) any {
	switch x := v.(type) {
	case map[string]any:
		out := map[string]any{}
		for k, val := range x {
			out[k] = normalize(val)
		}
		return out
	case map[any]any:
		out := map[string]any{}
		for k, val := range x {
			out[fmt.Sprint(k)] = normalize(val)
		}
		return out
	case []any:
		for i := range x {
			x[i] = normalize(x[i])
		}
		return x
	}
	return v
}

var (
	accountIDRe = regexp.MustCompile(`^\d{12}$`)
	actionRe    = regexp.MustCompile(`^[a-z0-9-]+:[A-Za-z0-9*]+$`)
	idRe        = regexp.MustCompile(`^[A-Za-z0-9_.:-]+$`)
)

// Validate checks the scenario's shape. References to snapshot objects are
// checked when the scenario is run against snapshots.
func (sc *Scenario) Validate() error {
	var errs []string
	fail := func(format string, args ...any) { errs = append(errs, fmt.Sprintf(format, args...)) }
	switch {
	case sc.SchemaVersion == 0:
		fail("schema_version is required (this build reads %d)", SchemaVersion)
	case sc.SchemaVersion != SchemaVersion:
		fail("schema_version %d is not supported (this build reads %d)", sc.SchemaVersion, SchemaVersion)
	}
	if sc.Name == "" {
		fail("name is required")
	}
	if !accountIDRe.MatchString(sc.AccountID) {
		fail("account %q is not a 12-digit account ID", sc.AccountID)
	}
	if sc.Strategy != StrategyTransfer && sc.Strategy != StrategyRecreate {
		fail("strategy must be %s or %s, got %q", StrategyTransfer, StrategyRecreate, sc.Strategy)
	}
	for i, op := range sc.CriticalOperations {
		if !actionRe.MatchString(op.Action) {
			fail("critical_operations[%d].action %q is not service:Action", i, op.Action)
		}
		if op.Reason == "" {
			fail("critical_operations[%d] (%s) needs a reason", i, op.Action)
		}
	}
	ids := map[string]string{}
	for i, ou := range sc.Proposed.OUs {
		switch {
		case ou.ID == "" || !idRe.MatchString(ou.ID):
			fail("proposed.organizational_units[%d].id %q is not a valid identifier", i, ou.ID)
		case ids[ou.ID] != "":
			fail("proposed.organizational_units[%d].id %s is used twice", i, ou.ID)
		default:
			ids[ou.ID] = "ou"
		}
		if ou.Name == "" {
			fail("proposed.organizational_units[%d] (%s) needs a name", i, ou.ID)
		}
		if ou.ParentID == "" {
			fail("proposed.organizational_units[%d] (%s) needs a parent", i, ou.ID)
		}
	}
	for i, p := range sc.Proposed.Policies {
		switch {
		case p.ID == "" || !idRe.MatchString(p.ID):
			fail("proposed.policies[%d].id %q is not a valid identifier", i, p.ID)
		case ids[p.ID] != "":
			fail("proposed.policies[%d].id %s is used twice", i, p.ID)
		default:
			ids[p.ID] = "policy"
		}
		if p.Name == "" {
			fail("proposed.policies[%d] (%s) needs a name", i, p.ID)
		}
		valid := false
		for _, t := range snapshot.AllPolicyTypes {
			if p.Type == t {
				valid = true
			}
		}
		if !valid {
			fail("proposed.policies[%d] (%s) has unknown type %q", i, p.ID, p.Type)
		} else if err := snapshot.ValidatePolicyDocument(p.Type, p.DocumentJSON); err != nil {
			fail("proposed.policies[%d] (%s): %v", i, p.ID, err)
		}
	}
	shares := map[string]bool{}
	for i, sh := range sc.Proposed.ResourceShares {
		if sh.Name == "" || shares[sh.Name] {
			fail("proposed.resource_shares[%d] needs a unique name", i)
		}
		shares[sh.Name] = true
		if !accountIDRe.MatchString(sh.OwnerAccountID) {
			fail("proposed.resource_shares[%d] (%s): owner_account %q is not a 12-digit account ID", i, sh.Name, sh.OwnerAccountID)
		}
		if len(sh.Principals) == 0 || len(sh.Resources) == 0 {
			fail("proposed.resource_shares[%d] (%s) needs principals and resources", i, sh.Name)
		}
	}
	if len(sc.Stages) == 0 {
		fail("at least one stage is required")
	}
	seen := map[string]bool{}
	for i, st := range sc.Stages {
		where := fmt.Sprintf("stages[%d]", i)
		if st.ID == "" || !idRe.MatchString(st.ID) {
			fail("%s.id %q is not a valid identifier", where, st.ID)
		} else if seen[st.ID] {
			fail("%s.id %s is used twice", where, st.ID)
		}
		seen[st.ID] = true
		if st.Title == "" {
			fail("%s (%s) needs a title", where, st.ID)
		}
		if m := st.Membership; m != nil {
			if err := evaluator.ValidTransferMethod(m.Method); err != nil {
				fail("%s.membership.method: %v", where, err)
			}
		}
		if m := st.Membership; m != nil && m.Organization != OrgSource && m.Organization != OrgDestination {
			fail("%s.membership.organization must be %s or %s, got %q", where, OrgSource, OrgDestination, m.Organization)
		}
		if p := st.Placement; p != nil && p.ParentID == "" {
			fail("%s.placement.parent is required", where)
		}
		if n := st.Network; n != nil {
			for _, name := range n.RecreateShares {
				if !shares[name] {
					fail("%s.network.recreate_shares: %q is not a proposed resource share", where, name)
				}
			}
		}
		if w := st.Workload; w != nil && w.TargetAccountID != "" && !accountIDRe.MatchString(w.TargetAccountID) {
			fail("%s.workload.target_account %q is not a 12-digit account ID", where, w.TargetAccountID)
		}
		if pc := st.Policies; pc != nil {
			for j, a := range append(append([]Attachment(nil), pc.Attach...), pc.Detach...) {
				if a.PolicyID == "" || a.TargetID == "" {
					fail("%s.policies[%d] needs policy and target", where, j)
				}
			}
		}
	}
	if len(errs) == 0 {
		return nil
	}
	sort.Strings(errs)
	return fmt.Errorf("invalid scenario:\n  - %s", strings.Join(errs, "\n  - "))
}

// Declared converts the critical operations for the evaluator.
func (sc *Scenario) Declared() []snapshot.ActionInUse {
	var out []snapshot.ActionInUse
	for _, op := range sc.CriticalOperations {
		out = append(out, op.ActionInUse())
	}
	return out
}

// JSON renders the scenario as JSON (documents included).
func (sc *Scenario) JSON() ([]byte, error) {
	return json.MarshalIndent(sc, "", "  ")
}

// LoadCriticalOperations reads a file holding critical operations: either a
// list, or a mapping with a critical_operations key (a whole scenario file
// works too).
func LoadCriticalOperations(path string) ([]CriticalOperation, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var list []CriticalOperation
	if err := yaml.Unmarshal(data, &list); err == nil && len(list) > 0 {
		return checkOperations(path, list)
	}
	var wrapped struct {
		CriticalOperations []CriticalOperation `yaml:"critical_operations"`
	}
	if err := yaml.Unmarshal(data, &wrapped); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if len(wrapped.CriticalOperations) == 0 {
		return nil, fmt.Errorf("%s: no critical operations found (expected a list of {action, regions, reason} or a critical_operations key)", path)
	}
	return checkOperations(path, wrapped.CriticalOperations)
}

func checkOperations(path string, ops []CriticalOperation) ([]CriticalOperation, error) {
	for i, op := range ops {
		if !actionRe.MatchString(op.Action) {
			return nil, fmt.Errorf("%s: critical operation %d: action %q is not service:Action", path, i, op.Action)
		}
		if op.Reason == "" {
			return nil, fmt.Errorf("%s: critical operation %d (%s) needs a reason", path, i, op.Action)
		}
	}
	return ops, nil
}
