// Package evaluator simulates moving an account to a different OU or
// organization and produces a GO / REVIEW / NO-GO verdict with evidence.
package evaluator

import (
	"encoding/json"

	"github.com/MrShaaba/orgshift/internal/snapshot"
)

// Status is a verdict level. INFO findings never change a verdict.
type Status string

// Status values.
const (
	StatusGo     Status = "GO"
	StatusReview Status = "REVIEW"
	StatusNoGo   Status = "NO-GO"
	StatusInfo   Status = "INFO"
)

func rank(s Status) int {
	switch s {
	case StatusReview:
		return 1
	case StatusNoGo:
		return 2
	}
	return 0
}

// Worst returns the more severe of two statuses.
func Worst(a, b Status) Status {
	if rank(b) > rank(a) {
		return b
	}
	if rank(a) == 0 {
		return StatusGo
	}
	return a
}

// ResultSchemaVersion is bumped when the exported result shape changes.
//
// Version 2 added the coverage matrix, the list of versioned models the
// evaluation used, documentation references on findings and the
// coverage_gaps list on checks. Version 3 added the impact category,
// confidence and source on every finding, the declared critical operations
// on the subject, the category counts and the standing limitations of the
// offline evaluation. Version 4 added the workloads check, the workload
// layer block (how much of the layer was evaluated and what the inventory
// holds), operations derived from the workload inventory (source
// "workload") and their count on the subject.
const ResultSchemaVersion = 4

// Impact categories (Section 7 of the brief). Every finding carries one so
// a reader can tell a restriction that exists from one that hits something
// the account does, and a limitation of the evaluator from missing input.
const (
	// CategoryKnownRestriction: a policy or control restricts something, and
	// nothing declared or observed depends on it (or it is restricted today
	// already).
	CategoryKnownRestriction = "known-restriction"
	// CategoryDeclaredImpact: a restriction or change hits an operation the
	// account performs (observed usage) or the operator declared as
	// critical, or hits the migration operation itself.
	CategoryDeclaredImpact = "declared-impact"
	// CategoryPotentialImpact: an operation may be affected, but deciding it
	// needs context the snapshot does not carry (a condition on a request
	// value, a behaviour AWS does not document, an operator decision).
	CategoryPotentialImpact = "potential-impact"
	// CategoryUnsupported: the offline evaluator does not model this (an
	// operator, a policy type, a resource owned outside both snapshots).
	CategoryUnsupported = "unsupported-evaluation"
	// CategoryMissingEvidence: the input lacks what the check needs (no usage
	// list, no resource sample, an incompletely collected domain).
	CategoryMissingEvidence = "missing-evidence"
	// CategoryInformational: a change that is neither a restriction nor a
	// problem (a share that becomes available, a trail that starts covering
	// the account).
	CategoryInformational = "informational"
)

// Confidence levels on findings.
const (
	ConfidenceHigh   = "high"
	ConfidenceMedium = "medium"
	ConfidenceLow    = "low"
)

// Finding sources: where the operation a finding is about came from.
// SourceWorkload (workloads.go) marks what the workload inventory shows.
const (
	SourceObserved = "observed"
	SourceDeclared = "declared"
)

// Result is the complete outcome of one simulated move.
type Result struct {
	Tool                string  `json:"tool"`
	ResultSchemaVersion int     `json:"result_schema_version"`
	Subject             Subject `json:"subject"`
	Verdict             Status  `json:"verdict"`
	Summary             string  `json:"summary"`
	// Coverage says which collection domains the verdict rests on and
	// whether each was completely collected on each side.
	Coverage CoverageMatrix `json:"coverage"`
	Checks   []Check        `json:"checks"`
	// WorkloadLayer says how much of the workload layer was evaluated and
	// what the account's inventory holds.
	WorkloadLayer *WorkloadLayer `json:"workload_layer"`
	Diff          []Diff         `json:"diff"`
	// Models lists the versioned AWS behaviour models the evaluation used,
	// with the documentation they were verified against.
	Models []ModelRef `json:"models"`
	// Categories counts the findings per impact category.
	Categories map[string]int `json:"categories"`
	// Limitations are the standing limits of the offline evaluation: what it
	// does not decide, whatever the snapshots contain.
	Limitations []string `json:"limitations"`
	Notes       []string `json:"notes,omitempty"`
}

// ModelRef names one versioned model of AWS behaviour the evaluator relies
// on, so a reader can tell how current the assumptions are.
type ModelRef struct {
	ID        string `json:"id"`
	Version   string `json:"version"`
	Reference string `json:"reference"`
	Note      string `json:"note,omitempty"`
}

// OrgRef identifies an organization.
type OrgRef struct {
	ID   string `json:"id"`
	Name string `json:"name,omitempty"`
}

// Subject describes what is being moved where.
type Subject struct {
	AccountID    string          `json:"account_id"`
	AccountName  string          `json:"account_name"`
	SourceOrg    OrgRef          `json:"source_org"`
	TargetOrg    OrgRef          `json:"target_org"`
	CrossOrg     bool            `json:"cross_org"`
	SourcePath   []snapshot.Node `json:"source_path"`
	TargetPath   []snapshot.Node `json:"target_path"`
	SourcePathID string          `json:"source_parent_id"`
	TargetOUID   string          `json:"target_ou_id"`
	// Counts of what was evaluated, so a GO on an empty list is visible.
	ActionsInUse    int      `json:"actions_in_use"`
	InboundAccess   int      `json:"inbound_access"`
	TaggedResources int      `json:"tagged_resources"`
	RegionsAssumed  []string `json:"regions_assumed"`
	// DeclaredOperations counts the critical operations the operator
	// declared on top of the observed usage.
	DeclaredOperations int `json:"declared_operations"`
	// DerivedOperations counts the operations derived from the workload
	// inventory (a role CloudFormation assumes to read another account's
	// stack output), evaluated like observed ones.
	DerivedOperations int `json:"derived_operations"`
	// OrgPaths are the aws:PrincipalOrgPaths values of the account before
	// and after the move, as evaluated.
	SourceOrgPath string `json:"source_org_path"`
	TargetOrgPath string `json:"target_org_path"`
	// TransferMethod is the procedure evaluated for a move between
	// organizations: direct, leave-and-rejoin or management-account.
	TransferMethod string `json:"transfer_method,omitempty"`
}

// Check is one area of the verdict board.
type Check struct {
	ID      string `json:"id"`
	Title   string `json:"title"`
	Status  Status `json:"status"`
	Summary string `json:"summary"`
	// CoverageGaps lists the collection domains this check depends on that
	// were not completely collected ("resource_shares on source"), so an
	// empty finding list is read with that caveat.
	CoverageGaps []string  `json:"coverage_gaps,omitempty"`
	Findings     []Finding `json:"findings"`
}

// Finding is one explained observation with evidence.
type Finding struct {
	Status Status `json:"status"`
	// Category is the impact category (Category* constants).
	Category string `json:"category"`
	// Confidence says how sure the evaluator is of the finding.
	Confidence string `json:"confidence"`
	// Source is observed, declared or workload for findings about an
	// operation or a resource of the account.
	Source    string     `json:"source,omitempty"`
	Title     string     `json:"title"`
	Detail    string     `json:"detail"`
	Action    string     `json:"action,omitempty"`
	Resource  string     `json:"resource,omitempty"`
	Principal string     `json:"principal,omitempty"`
	Regions   []string   `json:"regions,omitempty"`
	Evidence  []Evidence `json:"evidence,omitempty"`
	// References are the official documentation pages the finding's claim
	// about AWS behaviour was verified against.
	References []string `json:"references,omitempty"`
}

// Evidence points at the exact policy statement, share or setting that
// produced a finding.
type Evidence struct {
	Kind          string          `json:"kind"`
	Side          string          `json:"side,omitempty"`
	Level         string          `json:"level,omitempty"`
	PolicyID      string          `json:"policy_id,omitempty"`
	PolicyName    string          `json:"policy_name,omitempty"`
	PolicyType    string          `json:"policy_type,omitempty"`
	Statement     string          `json:"statement,omitempty"`
	StatementJSON json.RawMessage `json:"statement_json,omitempty"`
	Reference     string          `json:"reference,omitempty"`
	Note          string          `json:"note,omitempty"`
}

// Diff is the "what changes" view for one policy type.
type Diff struct {
	Type          string      `json:"type"`
	TypeShort     string      `json:"type_short"`
	EnabledSource bool        `json:"enabled_at_source"`
	EnabledTarget bool        `json:"enabled_at_target"`
	SourceChain   []ChainLink `json:"source_chain"`
	TargetChain   []ChainLink `json:"target_chain"`
	Added         []PolicyRef `json:"added"`
	Removed       []PolicyRef `json:"removed"`
	Changed       []PolicyRef `json:"changed"`
	Unchanged     []PolicyRef `json:"unchanged"`
}

// ChainLink is one node of a policy chain with the policies attached there.
type ChainLink struct {
	Node     snapshot.Node `json:"node"`
	Policies []PolicyRef   `json:"policies"`
}

// PolicyRef is a compact description of a policy for diffs and chains.
type PolicyRef struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	AWSManaged  bool   `json:"aws_managed"`
	// ControlTowerManaged marks the aws-guardrails-* SCPs that implement
	// Control Tower's preventive controls.
	ControlTowerManaged bool   `json:"control_tower_managed,omitempty"`
	Level               string `json:"level,omitempty"`
	// Malformed is the reason the document is not a well-formed policy of
	// its type; such a policy is unknown in both directions.
	Malformed  string             `json:"malformed,omitempty"`
	Statements []StatementSummary `json:"statements,omitempty"`
	Document   json.RawMessage    `json:"document,omitempty"`
}

// StatementSummary is a one-line view of an SCP or RCP statement.
type StatementSummary struct {
	Sid          string   `json:"sid,omitempty"`
	Effect       string   `json:"effect"`
	Actions      []string `json:"actions,omitempty"`
	NotActions   []string `json:"not_actions,omitempty"`
	HasCondition bool     `json:"has_condition"`
	Conditions   []string `json:"conditions,omitempty"`
}

func (c *Check) add(f Finding) {
	c.Findings = append(c.Findings, f)
	c.Status = Worst(c.Status, f.Status)
}

// Counts returns how many findings carry each status.
func (c Check) Counts() map[Status]int {
	m := map[Status]int{}
	for _, f := range c.Findings {
		m[f.Status]++
	}
	return m
}
