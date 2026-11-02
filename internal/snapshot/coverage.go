package snapshot

import (
	"fmt"
	"sort"
	"strings"
)

// CoverageStatus says what the collector knows about one collection domain.
// An empty list in a snapshot means "nothing exists" only when the domain's
// status is observed or empty; every other status (or no record at all)
// means the list may be incomplete.
type CoverageStatus string

// Coverage statuses, from complete to broken.
const (
	// CoverageObserved: the calls succeeded and returned at least one item.
	CoverageObserved CoverageStatus = "observed"
	// CoverageEmpty: the calls succeeded and confirmed there is nothing.
	CoverageEmpty CoverageStatus = "empty"
	// CoverageSkipped: the operator turned the domain off (a --skip flag).
	CoverageSkipped CoverageStatus = "skipped"
	// CoverageUnsupported: this collector version does not read the domain,
	// or the API does not exist for this account or partition.
	CoverageUnsupported CoverageStatus = "unsupported"
	// CoveragePartial: some pages or sub-resources were read before a call
	// failed; the lists are incomplete.
	CoveragePartial CoverageStatus = "partial"
	// CoverageAccessDenied: the credentials lack the permission.
	CoverageAccessDenied CoverageStatus = "access_denied"
	// CoverageError: any other failure, including a lookup in a region where
	// the service does not answer.
	CoverageError CoverageStatus = "error"
	// CoverageUnknown is never stored. DomainStatus returns it when a
	// snapshot carries no record for a domain and no completeness assertion.
	CoverageUnknown CoverageStatus = "unknown"
)

// Complete reports whether the lists of a domain can be trusted.
func (s CoverageStatus) Complete() bool { return s == CoverageObserved || s == CoverageEmpty }

// severity orders statuses so the worst record wins when a domain has
// several (one per account or region).
func (s CoverageStatus) severity() int {
	switch s {
	case CoverageObserved, CoverageEmpty:
		return 0
	case CoverageSkipped:
		return 1
	case CoverageUnsupported:
		return 2
	case CoveragePartial:
		return 3
	case CoverageAccessDenied:
		return 4
	case CoverageError:
		return 5
	}
	return 6
}

// Valid reports whether s is a status a snapshot may store.
func (s CoverageStatus) Valid() bool {
	switch s {
	case CoverageObserved, CoverageEmpty, CoverageSkipped, CoverageUnsupported, CoveragePartial, CoverageAccessDenied, CoverageError:
		return true
	}
	return false
}

// Collection domains. Each names one group of lists in the snapshot and the
// API calls that fill it.
const (
	DomainOrganization     = "organization"
	DomainTree             = "tree"
	DomainAccountTags      = "account_tags"
	DomainEnabledRegions   = "enabled_regions"
	DomainPoliciesSCP      = "policies.scp"
	DomainPoliciesRCP      = "policies.rcp"
	DomainPoliciesTag      = "policies.tag"
	DomainPoliciesBackup   = "policies.backup"
	DomainDelegatedAdmins  = "delegated_administrators"
	DomainTrustedAccess    = "trusted_access"
	DomainResourceShares   = "resource_shares"
	DomainOrgTrails        = "organization_trails"
	DomainConfigAggregator = "config_aggregators"
	DomainStackSets        = "stack_sets"
	DomainControlTower     = "control_tower"
	DomainEnrolledAccounts = "control_tower.enrolled_accounts"
	DomainIdentityCenter   = "identity_center"
)

// AllDomains lists every domain in display order.
var AllDomains = []string{
	DomainOrganization, DomainTree, DomainAccountTags, DomainEnabledRegions,
	DomainPoliciesSCP, DomainPoliciesRCP, DomainPoliciesTag, DomainPoliciesBackup,
	DomainDelegatedAdmins, DomainTrustedAccess, DomainResourceShares,
	DomainOrgTrails, DomainConfigAggregator, DomainStackSets,
	DomainControlTower, DomainEnrolledAccounts, DomainIdentityCenter,
}

// PolicyDomain returns the coverage domain of a policy type.
func PolicyDomain(t PolicyType) string {
	switch t {
	case PolicyTypeSCP:
		return DomainPoliciesSCP
	case PolicyTypeRCP:
		return DomainPoliciesRCP
	case PolicyTypeTag:
		return DomainPoliciesTag
	case PolicyTypeBackup:
		return DomainPoliciesBackup
	}
	return "policies." + strings.ToLower(string(t))
}

// Coverage records what the collector inspected to produce the snapshot.
// Without it, an evaluator cannot tell an empty list from one that was never
// read, so it must treat every domain as unknown.
type Coverage struct {
	// CollectorVersion is the orgshift build (or "fixture", "manual") that
	// wrote the records.
	CollectorVersion string `json:"collector_version,omitempty"`
	// AssertedComplete is for hand-written snapshots: the author confirms
	// that every list is complete and every empty list is confirmed empty.
	// It stands in for records on every domain that has none.
	AssertedComplete bool `json:"asserted_complete,omitempty"`
	// AssertedBy says who or what asserted completeness.
	AssertedBy string           `json:"asserted_by,omitempty"`
	Domains    []DomainCoverage `json:"domains"`
}

// DomainCoverage is one observation about one domain: which calls were made
// from which account against which region, and how they ended.
type DomainCoverage struct {
	Domain string         `json:"domain"`
	Status CoverageStatus `json:"status"`
	// AccountID is the account the calls were made from (shares, policies)
	// or about (regions, tags); empty for organization-wide calls.
	AccountID string `json:"account_id,omitempty"`
	// Region is the endpoint region, when the domain is regional.
	Region      string   `json:"region,omitempty"`
	CollectedAt string   `json:"collected_at,omitempty"`
	Operations  []string `json:"operations,omitempty"`
	// Items counts the observations recorded; Pages the API pages read.
	Items int `json:"items,omitempty"`
	Pages int `json:"pages,omitempty"`
	// Retries counts the throttling retries the collector performed for the
	// domain beyond what the SDK retried itself.
	Retries int `json:"retries,omitempty"`
	// Error carries the API error for partial, access_denied and error.
	Error string `json:"error,omitempty"`
	// Reason explains skipped, unsupported and empty records.
	Reason string `json:"reason,omitempty"`
}

// Label renders the record for messages.
func (d DomainCoverage) Label() string {
	var parts []string
	if d.AccountID != "" {
		parts = append(parts, "account "+d.AccountID)
	}
	if d.Region != "" {
		parts = append(parts, "region "+d.Region)
	}
	where := ""
	if len(parts) > 0 {
		where = " (" + strings.Join(parts, ", ") + ")"
	}
	why := d.Error
	if why == "" {
		why = d.Reason
	}
	if why != "" {
		why = ": " + why
	}
	return fmt.Sprintf("%s %s%s%s", d.Domain, d.Status, where, why)
}

// DomainRecords returns the coverage records for a domain, in snapshot order.
func (s *Snapshot) DomainRecords(domain string) []DomainCoverage {
	if s == nil || s.Coverage == nil {
		return nil
	}
	var out []DomainCoverage
	for _, d := range s.Coverage.Domains {
		if d.Domain == domain {
			out = append(out, d)
		}
	}
	return out
}

// DomainStatus aggregates the records of a domain: the worst status wins.
// Records about a specific account are only considered when accountID is
// empty (every account) or matches; organization-wide records always count.
// A domain with no record is CoverageObserved when the coverage block
// asserts completeness, otherwise CoverageUnknown.
func (s *Snapshot) DomainStatus(domain, accountID string) CoverageStatus {
	if s == nil || s.Coverage == nil {
		return CoverageUnknown
	}
	status, found := CoverageUnknown, false
	for _, d := range s.Coverage.Domains {
		if d.Domain != domain {
			continue
		}
		if accountID != "" && d.AccountID != "" && d.AccountID != accountID {
			continue
		}
		if !found || d.Status.severity() > status.severity() {
			status = d.Status
		}
		found = true
	}
	if !found && s.Coverage.AssertedComplete {
		return CoverageObserved
	}
	return status
}

// CoverageAsserted reports whether a domain's completeness rests on the
// author's assertion rather than on a record.
func (s *Snapshot) CoverageAsserted(domain string) bool {
	return s != nil && s.Coverage != nil && s.Coverage.AssertedComplete && len(s.DomainRecords(domain)) == 0
}

// CoverageGaps lists the domains whose aggregated status is not complete,
// in AllDomains order, followed by any domain the snapshot names that
// AllDomains does not know.
func (s *Snapshot) CoverageGaps() []string {
	var out []string
	seen := map[string]bool{}
	for _, d := range AllDomains {
		seen[d] = true
		if !s.DomainStatus(d, "").Complete() {
			out = append(out, d)
		}
	}
	if s != nil && s.Coverage != nil {
		var extra []string
		for _, d := range s.Coverage.Domains {
			if !seen[d.Domain] {
				seen[d.Domain] = true
				if !s.DomainStatus(d.Domain, "").Complete() {
					extra = append(extra, d.Domain)
				}
			}
		}
		sort.Strings(extra)
		out = append(out, extra...)
	}
	return out
}

// validateCoverage checks the coverage block.
func (s *Snapshot) validateCoverage(seen map[string]string, fail func(string, ...any)) {
	c := s.Coverage
	if c == nil {
		return
	}
	if c.AssertedBy != "" && !c.AssertedComplete {
		fail("coverage: asserted_by is set but asserted_complete is false")
	}
	for i, d := range c.Domains {
		if d.Domain == "" {
			fail("coverage.domains[%d]: domain is required", i)
		}
		if !d.Status.Valid() {
			fail("coverage.domains[%d] (%s): status %q is not one of observed, empty, skipped, unsupported, partial, access_denied, error", i, d.Domain, d.Status)
		}
		if d.AccountID != "" && !accountIDRe.MatchString(d.AccountID) {
			fail("coverage.domains[%d] (%s): account_id %q is not a 12 digit account id", i, d.Domain, d.AccountID)
		}
		switch d.Status {
		case CoveragePartial, CoverageAccessDenied, CoverageError:
			if d.Error == "" {
				fail("coverage.domains[%d] (%s): status %s needs an error message", i, d.Domain, d.Status)
			}
		}
	}
}
