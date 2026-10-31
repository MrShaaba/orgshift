package evaluator

import (
	"fmt"
	"sort"

	"github.com/MrShaaba/orgshift/internal/snapshot"
)

// Input describes one simulated account move.
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

// move is the resolved description of one account move: where the account
// ends up and which nodes on that path are new to the target organization.
type move struct {
	from, to   *snapshot.Snapshot
	fromIx     *snapshot.Index
	toIx       *snapshot.Index
	account    *snapshot.Account
	targetPath []snapshot.Node // root ... parent, account
	fresh      map[string]bool
}

// Evaluate runs every check for one account and returns the verdict.
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
	m := move{from: in.From, to: to, fromIx: fromIx, toIx: toIx, account: acct,
		targetPath: toIx.PathUnder(in.TargetOUID, snapshot.Node{ID: acct.ID, Name: acct.Name, Kind: snapshot.KindAccount}),
		fresh:      map[string]bool{}}
	if in.From.Organization.ID != to.Organization.ID {
		m.fresh[acct.ID] = true
	}
	return evaluateMove(m)
}

// evaluateMove runs every check for one resolved move.
func evaluateMove(m move) (*Result, error) {
	acct := m.account
	e := &evaluation{
		from: m.from, to: m.to, accountID: acct.ID, account: acct,
		crossOrg: m.from.Organization.ID != m.to.Organization.ID,
		docs:     map[string]parsedDoc{},
	}
	e.src = side{name: "source", snap: m.from, ix: m.fromIx, orgID: m.from.Organization.ID, path: m.fromIx.PathTo(acct.ID), fresh: map[string]bool{}}
	e.dst = side{name: "target", snap: m.to, ix: m.toIx, orgID: m.to.Organization.ID, path: m.targetPath, fresh: m.fresh}
	if e.src.path == nil || len(e.dst.path) < 2 {
		return nil, fmt.Errorf("could not resolve the account's path in one of the snapshots")
	}
	targetOUID := e.dst.path[len(e.dst.path)-2].ID

	usage := m.from.UsageFor(acct.ID)
	res := &Result{
		Tool: "orgshift", ResultSchemaVersion: ResultSchemaVersion,
		Subject: Subject{
			AccountID: acct.ID, AccountName: acct.Name,
			SourceOrg: OrgRef{ID: m.from.Organization.ID, Name: m.from.Organization.Name},
			TargetOrg: OrgRef{ID: m.to.Organization.ID, Name: m.to.Organization.Name},
			CrossOrg:  e.crossOrg, SourcePath: e.src.path, TargetPath: e.dst.path,
			SourcePathID: acct.ParentID, TargetOUID: targetOUID,
			ActionsInUse: len(usage.Actions), InboundAccess: len(usage.InboundAccess), TaggedResources: len(usage.TaggedResources),
			RegionsAssumed: append([]string(nil), acct.EnabledRegions...),
		},
	}
	sort.Strings(res.Subject.RegionsAssumed)
	if !e.crossOrg && samePath(e.src.path, e.dst.path) {
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
	controlTower := newCheck("control-tower", "Control Tower")
	e.evaluateControlTower(&controlTower)
	res.Checks = []Check{scp, rcp, tags, shares, services, controlTower}

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

func samePath(a, b []snapshot.Node) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].ID != b[i].ID {
			return false
		}
	}
	return true
}

// countFindings returns how many findings of a result are NO-GO and REVIEW.
func countFindings(r *Result) (noGo, review int) {
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
	return noGo, review
}

func summarize(r *Result) string {
	noGo, review := countFindings(r)
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
