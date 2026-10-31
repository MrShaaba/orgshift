package evaluator

import (
	"fmt"
	"sort"

	"github.com/MrShaaba/orgshift/internal/snapshot"
)

// Input describes one simulated move.
type Input struct {
	From *snapshot.Snapshot
	// To is the destination organization; nil means the same organization.
	To         *snapshot.Snapshot
	AccountID  string
	TargetOUID string
}

type evaluation struct {
	from, to  *snapshot.Snapshot
	accountID string
	account   *snapshot.Account
	crossOrg  bool
	src, dst  side
	docs      map[string]parsedDoc
}

// Evaluate runs every check and returns the verdict.
func Evaluate(in Input) (*Result, error) {
	if in.From == nil {
		return nil, fmt.Errorf("a source snapshot is required")
	}
	to := in.To
	if to == nil {
		to = in.From
	}
	fromIx, toIx := in.From.Index(), to.Index()
	acct, ok := fromIx.AccountByID[in.AccountID]
	if !ok {
		return nil, fmt.Errorf("account %s is not in the source snapshot (%s)", in.AccountID, in.From.Organization.ID)
	}
	targetNode, ok := toIx.Node(in.TargetOUID)
	if !ok || targetNode.Kind == snapshot.KindAccount {
		return nil, fmt.Errorf("target %q is not a root or OU in the destination snapshot (%s)", in.TargetOUID, to.Organization.ID)
	}
	e := &evaluation{
		from: in.From, to: to, accountID: in.AccountID, account: acct,
		crossOrg: in.From.Organization.ID != to.Organization.ID,
		docs:     map[string]parsedDoc{},
	}
	acctNode := snapshot.Node{ID: acct.ID, Name: acct.Name, Kind: snapshot.KindAccount}
	e.src = side{name: "source", snap: in.From, ix: fromIx, orgID: in.From.Organization.ID, path: fromIx.PathTo(acct.ID), direct: true}
	e.dst = side{name: "target", snap: to, ix: toIx, orgID: to.Organization.ID, path: toIx.PathUnder(in.TargetOUID, acctNode), direct: !e.crossOrg}
	if e.src.path == nil || e.dst.path == nil {
		return nil, fmt.Errorf("could not resolve the account's path in one of the snapshots")
	}

	usage := in.From.UsageFor(acct.ID)
	res := &Result{
		Tool: "orgshift", ResultSchemaVersion: ResultSchemaVersion,
		Subject: Subject{
			AccountID: acct.ID, AccountName: acct.Name,
			SourceOrg: OrgRef{ID: in.From.Organization.ID, Name: in.From.Organization.Name},
			TargetOrg: OrgRef{ID: to.Organization.ID, Name: to.Organization.Name},
			CrossOrg:  e.crossOrg, SourcePath: e.src.path, TargetPath: e.dst.path,
			SourcePathID: acct.ParentID, TargetOUID: in.TargetOUID,
			ActionsInUse: len(usage.Actions), InboundAccess: len(usage.InboundAccess), TaggedResources: len(usage.TaggedResources),
			RegionsAssumed: append([]string(nil), acct.EnabledRegions...),
		},
	}
	sort.Strings(res.Subject.RegionsAssumed)
	if !e.crossOrg && acct.ParentID == in.TargetOUID {
		res.Notes = append(res.Notes, "The target OU is the account's current parent; the simulation compares the account with itself.")
	}
	if len(acct.EnabledRegions) == 0 {
		res.Notes = append(res.Notes, "The account lists no enabled regions, so region conditions cannot be evaluated unless actions carry explicit regions.")
	}

	newCheck := func(id, title string) Check {
		return Check{ID: id, Title: title, Status: StatusGo, Findings: []Finding{}}
	}
	scp := newCheck("scp", "Service control policies")
	e.evaluateOwnActions(&scp, snapshot.PolicyTypeSCP)
	rcp := newCheck("rcp", "Resource control policies")
	e.evaluateOwnActions(&rcp, snapshot.PolicyTypeRCP)
	e.evaluateInbound(&rcp)
	tags := newCheck("tags", "Tag policies")
	e.evaluateTags(&tags)
	shares := newCheck("ram", "Resource shares (RAM)")
	e.evaluateShares(&shares)
	services := newCheck("org-services", "Organization services")
	e.evaluateOrgServices(&services)
	res.Checks = []Check{scp, rcp, tags, shares, services}

	for _, t := range snapshot.AllPolicyTypes {
		res.Diff = append(res.Diff, e.diff(t))
	}

	res.Verdict = StatusGo
	for _, c := range res.Checks {
		res.Verdict = Worst(res.Verdict, c.Status)
	}
	res.Summary = summarize(res)
	return res, nil
}

func summarize(r *Result) string {
	noGo, review := 0, 0
	for _, c := range r.Checks {
		for _, f := range c.Findings {
			switch f.Status {
			case StatusNoGo:
				noGo++
			case StatusReview:
				review++
			}
		}
	}
	move := fmt.Sprintf("Moving %s (%s) from %s to %s", r.Subject.AccountName, r.Subject.AccountID,
		snapshot.PathString(r.Subject.SourcePath[:len(r.Subject.SourcePath)-1]), snapshot.PathString(r.Subject.TargetPath[:len(r.Subject.TargetPath)-1]))
	if r.Subject.CrossOrg {
		move += fmt.Sprintf(" (organization %s to %s)", r.Subject.SourceOrg.ID, r.Subject.TargetOrg.ID)
	}
	switch r.Verdict {
	case StatusNoGo:
		return fmt.Sprintf("%s: NO-GO. %d blocking finding(s) and %d to review.", move, noGo, review)
	case StatusReview:
		return fmt.Sprintf("%s: REVIEW. Nothing blocks the move outright, but %d finding(s) could not be decided offline or need a decision.", move, review)
	}
	return move + ": GO. Every evaluated action stays allowed, no networking share is lost and nothing needs review."
}
