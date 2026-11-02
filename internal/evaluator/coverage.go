package evaluator

import (
	"fmt"
	"strings"

	"github.com/MrShaaba/orgshift/internal/snapshot"
)

// CoverageMatrix says, for every collection domain, whether the snapshots
// behind a verdict were completely collected and whether the move needs the
// domain at all. A verdict rests on the required rows; a GO with an
// incomplete required row is not issued.
type CoverageMatrix struct {
	// SameSnapshot is true for a move inside one organization, where the
	// source and target columns describe the same snapshot.
	SameSnapshot bool `json:"same_snapshot"`
	// Complete is true when every required cell is observed or empty.
	Complete bool `json:"complete"`
	// Required counts the required cells; Gaps lists the incomplete ones as
	// "domain on side: status".
	Required int           `json:"required"`
	Gaps     []string      `json:"gaps,omitempty"`
	Rows     []CoverageRow `json:"rows"`
}

// CoverageRow is one domain across both sides.
type CoverageRow struct {
	Domain string `json:"domain"`
	// Why says what the domain decides in this evaluation.
	Why string `json:"why,omitempty"`
	// Check is the verdict board check that depends on the domain.
	Check  string       `json:"check,omitempty"`
	Source CoverageCell `json:"source"`
	Target CoverageCell `json:"target"`
}

// CoverageCell is one domain on one side.
type CoverageCell struct {
	Status   snapshot.CoverageStatus `json:"status"`
	Required bool                    `json:"required"`
	// Asserted is true when the status rests on the snapshot author's
	// completeness assertion rather than on a collector record.
	Asserted bool `json:"asserted,omitempty"`
	// Detail carries the error or reason of the worst record.
	Detail string `json:"detail,omitempty"`
}

// Complete reports whether a required cell can be trusted; cells that are
// not required are always complete.
func (c CoverageCell) Complete() bool { return !c.Required || c.Status.Complete() }

// coverageCheckID is the verdict board check that owns domains no other
// check depends on.
const coverageCheckID = "coverage"

type coverageRequirement struct {
	domain   string
	why      string
	check    string
	src, dst bool
	// accountScoped records are filtered to the moving account.
	accountScoped bool
}

// DomainDescription says what a collection domain decides and which verdict
// board check depends on it. The preflight uses it to label its matrix with
// the same words as the evaluation.
type DomainDescription struct {
	Domain string `json:"domain"`
	Why    string `json:"why"`
	Check  string `json:"check,omitempty"`
}

// domainDescriptions is the single list of domains, in matrix order.
var domainDescriptions = []DomainDescription{
	{snapshot.DomainOrganization, "the organization identity that decides whether this is a cross-organization move", coverageCheckID},
	{snapshot.DomainTree, "the OU hierarchy, the account's position and the policy attachment targets", coverageCheckID},
	{snapshot.DomainPoliciesSCP, "the SCP chains evaluated against the actions in use", "scp"},
	{snapshot.DomainPoliciesRCP, "the RCP chains evaluated against inbound access and the account's own actions", "rcp"},
	{snapshot.DomainPoliciesTag, "the effective tag policy at the target and the one it replaces", "tags"},
	{snapshot.DomainPoliciesBackup, "backup policies are shown in the diff only", ""},
	{snapshot.DomainEnabledRegions, "the regions an action is evaluated in when it names none", "scp"},
	{snapshot.DomainAccountTags, "account tags are shown for context only", ""},
	{snapshot.DomainResourceShares, "RAM shares that stop or start reaching the account", "ram"},
	{snapshot.DomainStackSets, "service-managed StackSets that target the account's OUs", "org-services"},
	{snapshot.DomainDelegatedAdmins, "delegated administration, which blocks leaving the organization", "org-services"},
	{snapshot.DomainTrustedAccess, "trusted access the target needs for the integrations in use", "org-services"},
	{snapshot.DomainOrgTrails, "organization trails that stop or start covering the account", "org-services"},
	{snapshot.DomainConfigAggregator, "organization Config aggregators that stop or start receiving the account", "org-services"},
	{snapshot.DomainControlTower, "the landing zone, its registered OUs and the controls that apply", "control-tower"},
	{snapshot.DomainEnrolledAccounts, "which accounts are enrolled rather than merely placed in a registered OU", "control-tower"},
	{snapshot.DomainIdentityCenter, "the assignments and roles that are removed when the account leaves", "identity-center"},
}

// DescribeDomains returns every collection domain with what it decides and
// the check that depends on it, in matrix order.
func DescribeDomains() []DomainDescription {
	return append([]DomainDescription(nil), domainDescriptions...)
}

// coverageRequirements defines which domains this move needs from which
// side. Policy types count only where they are enabled; cross-organization
// moves need the organization services and Identity Center on both sides.
func (e *evaluation) coverageRequirements() []coverageRequirement {
	cross := e.crossOrg
	from, to := e.from, e.to
	enabled := func(s *snapshot.Snapshot, t snapshot.PolicyType) bool { return s.PolicyTypeEnabled(t) }
	sides := map[string]struct {
		src, dst, accountScoped bool
	}{
		snapshot.DomainOrganization:     {src: true, dst: true},
		snapshot.DomainTree:             {src: true, dst: true},
		snapshot.DomainPoliciesSCP:      {src: enabled(from, snapshot.PolicyTypeSCP), dst: enabled(to, snapshot.PolicyTypeSCP)},
		snapshot.DomainPoliciesRCP:      {src: enabled(from, snapshot.PolicyTypeRCP), dst: enabled(to, snapshot.PolicyTypeRCP)},
		snapshot.DomainPoliciesTag:      {src: enabled(from, snapshot.PolicyTypeTag), dst: enabled(to, snapshot.PolicyTypeTag)},
		snapshot.DomainEnabledRegions:   {src: true, accountScoped: true},
		snapshot.DomainAccountTags:      {accountScoped: true},
		snapshot.DomainResourceShares:   {src: true, dst: true},
		snapshot.DomainStackSets:        {src: true, dst: true},
		snapshot.DomainDelegatedAdmins:  {src: cross},
		snapshot.DomainTrustedAccess:    {src: cross, dst: cross},
		snapshot.DomainOrgTrails:        {src: cross, dst: cross},
		snapshot.DomainConfigAggregator: {src: cross, dst: cross},
		snapshot.DomainControlTower:     {src: true, dst: true},
		snapshot.DomainEnrolledAccounts: {src: from.ControlTower != nil},
		snapshot.DomainIdentityCenter:   {src: cross, dst: cross},
	}
	var out []coverageRequirement
	for _, d := range domainDescriptions {
		s := sides[d.Domain]
		out = append(out, coverageRequirement{domain: d.Domain, why: d.Why, check: d.Check, src: s.src, dst: s.dst, accountScoped: s.accountScoped})
	}
	return out
}

// coverageCell reads one domain on one snapshot.
func coverageCell(s *snapshot.Snapshot, domain, accountID string, required bool) CoverageCell {
	status := s.DomainStatus(domain, accountID)
	cell := CoverageCell{Status: status, Required: required, Asserted: s.CoverageAsserted(domain)}
	var details []string
	for _, r := range s.DomainRecords(domain) {
		if accountID != "" && r.AccountID != "" && r.AccountID != accountID {
			continue
		}
		if r.Status.Complete() {
			continue
		}
		details = append(details, r.Label())
	}
	if len(details) > 0 {
		cell.Detail = strings.Join(details, "; ")
	} else if status == snapshot.CoverageUnknown {
		cell.Detail = "no coverage record"
		if s.UpgradedFrom == 1 {
			cell.Detail = "no coverage record (snapshot written with schema version 1)"
		}
	}
	return cell
}

// applyCoverage builds the coverage matrix, adds a REVIEW finding for every
// required domain that is not complete to the check that depends on it, and
// prepends the coverage check to the board.
func (e *evaluation) applyCoverage(res *Result) {
	m := CoverageMatrix{SameSnapshot: e.from == e.to || e.from.Organization.ID == e.to.Organization.ID, Complete: true}
	cov := Check{ID: coverageCheckID, Title: "Collection coverage", Status: StatusGo, Findings: []Finding{}}
	byID := map[string]*Check{}
	for i := range res.Checks {
		byID[res.Checks[i].ID] = &res.Checks[i]
	}
	gaps := 0
	for _, req := range e.coverageRequirements() {
		scope := ""
		if req.accountScoped {
			scope = e.accountID
		}
		row := CoverageRow{Domain: req.domain, Why: req.why, Check: req.check}
		row.Source = coverageCell(e.from, req.domain, scope, req.src)
		if m.SameSnapshot {
			row.Target = coverageCell(e.from, req.domain, scope, req.src || req.dst)
			row.Source.Required = row.Target.Required
		} else {
			row.Target = coverageCell(e.to, req.domain, scope, req.dst)
		}
		for _, sideCell := range []struct {
			name string
			cell CoverageCell
			snap *snapshot.Snapshot
		}{{"source", row.Source, e.from}, {"target", row.Target, e.to}} {
			if !sideCell.cell.Required {
				continue
			}
			m.Required++
			if m.SameSnapshot && sideCell.name == "target" {
				// One snapshot, counted once.
				m.Required--
				continue
			}
			if sideCell.cell.Complete() {
				continue
			}
			gaps++
			m.Complete = false
			sideLabel, gap := sideCell.name, req.domain+" on "+sideCell.name
			if m.SameSnapshot {
				sideLabel, gap = "the", req.domain
			}
			m.Gaps = append(m.Gaps, fmt.Sprintf("%s: %s", gap, sideCell.cell.Status))
			f := gapFinding(req, sideLabel, sideCell.cell, sideCell.snap)
			owner := byID[req.check]
			if owner == nil {
				owner = &cov
			}
			owner.add(f)
			owner.CoverageGaps = append(owner.CoverageGaps, gap)
		}
		m.Rows = append(m.Rows, row)
	}
	for i := range res.Checks {
		if len(res.Checks[i].CoverageGaps) > 0 {
			sortFindings(res.Checks[i].Findings)
		}
	}
	sortFindings(cov.Findings)
	switch {
	case gaps == 0 && m.Required > 0:
		cov.Summary = fmt.Sprintf("Complete: all %d required collection domains were inspected.", m.Required)
	case gaps == 0:
		cov.Summary = "Nothing is required of the snapshots for this move."
	default:
		// The gaps are reported by the checks they affect; the coverage
		// check itself still reads REVIEW so the board does not show a GO
		// next to a summary that lists missing evidence.
		cov.Status = Worst(cov.Status, StatusReview)
		cov.Summary = fmt.Sprintf("%d of %d required collection domains are incomplete: %s. The checks that depend on them carry a REVIEW finding each; a GO is not issued on incomplete evidence.", gaps, m.Required, strings.Join(m.Gaps, "; "))
	}
	if e.from.UpgradedFrom == 1 || (e.to != e.from && e.to.UpgradedFrom == 1) {
		res.Notes = append(res.Notes, "A snapshot written with schema version 1 carries no coverage records; collect it again with this version so empty lists can be told from uncollected ones.")
	}
	res.Coverage = m
	res.Checks = append([]Check{cov}, res.Checks...)
}

// gapFinding describes one incomplete required domain.
func gapFinding(req coverageRequirement, sideLabel string, cell CoverageCell, s *snapshot.Snapshot) Finding {
	domain := req.domain
	where := sideLabel + " snapshot"
	ev := Evidence{Kind: "coverage", Side: strings.TrimPrefix(sideLabel, "the"), Reference: domain, Note: cell.Detail}
	if ev.Side == "" {
		ev.Side = "source"
	}
	var lines []string
	for _, r := range s.DomainRecords(domain) {
		lines = append(lines, r.Label())
	}
	if len(lines) > 0 {
		ev.Note = strings.Join(lines, "\n")
	}
	f := Finding{Status: StatusReview, Evidence: []Evidence{ev}}
	fix := " Collect the snapshot again with this version of orgshift once the cause is fixed, or add the entries by hand and record them under coverage.domains; for a hand-written snapshot, set coverage.asserted_complete once every list is confirmed."
	switch cell.Status {
	case snapshot.CoverageUnknown:
		f.Title = fmt.Sprintf("Coverage of %s is not recorded in the %s", domain, where)
		f.Detail = fmt.Sprintf("Nothing says whether %s was inspected, so an empty list there cannot be told from one that was never read. It decides %s.", domain, req.why)
		if s.UpgradedFrom == 1 {
			f.Detail += " The snapshot was written with schema version 1, which had no coverage records."
		}
		f.Detail += fix
	case snapshot.CoverageSkipped:
		f.Title = fmt.Sprintf("Collection of %s was skipped for the %s", domain, where)
		f.Detail = fmt.Sprintf("The collector was told not to read %s (%s). It decides %s, so the lists may be incomplete.%s", domain, cell.Detail, req.why, fix)
	case snapshot.CoverageUnsupported:
		f.Title = fmt.Sprintf("%s is not collected for the %s", domain, where)
		f.Detail = fmt.Sprintf("This collector does not read %s (%s). It decides %s. Add the entries by hand (docs/snapshot.md) and record them under coverage.domains, or treat the lists as unknown.", domain, cell.Detail, req.why)
	case snapshot.CoveragePartial:
		f.Title = fmt.Sprintf("Collection of %s was cut short for the %s", domain, where)
		f.Detail = fmt.Sprintf("Some of %s was read before a call failed (%s), so the lists are incomplete. It decides %s.%s", domain, cell.Detail, req.why, fix)
	case snapshot.CoverageAccessDenied:
		f.Title = fmt.Sprintf("The collector was denied access to %s for the %s", domain, where)
		f.Detail = fmt.Sprintf("The credentials used for the %s lack a permission for %s (%s). It decides %s. Grant the permission listed in docs/permissions.md and collect again.", where, domain, cell.Detail, req.why)
	default:
		f.Title = fmt.Sprintf("%s could not be collected for the %s", domain, where)
		f.Detail = fmt.Sprintf("The calls for %s failed (%s). It decides %s.%s", domain, cell.Detail, req.why, fix)
	}
	return f
}

// Line summarizes the matrix in one line for reports.
func (m CoverageMatrix) Line() string {
	if m.Complete {
		return fmt.Sprintf("complete (%d required domains inspected)", m.Required)
	}
	return fmt.Sprintf("incomplete: %s", strings.Join(m.Gaps, "; "))
}
