package evaluator

import (
	"fmt"
	"sort"
	"strings"

	"github.com/MrShaaba/orgshift/internal/snapshot"
)

// Input describes one simulated account move.
type Input struct {
	From *snapshot.Snapshot
	// To is the destination organization; nil means the same organization.
	To         *snapshot.Snapshot
	AccountID  string
	TargetOUID string
	// Declared are critical operations the operator declares on top of the
	// observed usage: future deployments, recovery, scaling and rarely used
	// operations that history alone does not show. They are evaluated like
	// observed actions and their findings carry source "declared".
	Declared []snapshot.ActionInUse
	// TransferMethod is how the account changes organization: "direct"
	// (the default: the destination invites and the account accepts, with
	// no standalone interval) or "leave-and-rejoin". It is ignored inside
	// one organization and for a management account, whose only way out is
	// the management-account sequence.
	TransferMethod string
}

type evaluation struct {
	from, to  *snapshot.Snapshot
	accountID string
	account   *snapshot.Account
	crossOrg  bool
	src, dst  side
	docs      map[string]parsedDoc
	// usage is the account's usage merged with the declared operations.
	usage *snapshot.AccountUsage
	// method is the transfer method the operator chose for a move between
	// organizations.
	method string
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
	declared   []snapshot.ActionInUse
	method     string
}

// Models lists the versioned AWS behaviour models every evaluation uses.
func Models() []ModelRef {
	return []ModelRef{RCPModel(), RAMModel(), TransferModel(), WorkloadModel()}
}

// Limitations are the standing limits of the offline evaluation. They are
// repeated on every result so a GO is never read as more than it is.
func Limitations() []string {
	return []string{
		"An SCP or RCP that allows an action is not a grant: IAM identity policies, resource policies, permissions boundaries and session policies decide the request and are not evaluated here. The governance-policy evaluation says what the organization forbids, not what the account can do.",
		"Condition keys evaluated with explicit context: aws:RequestedRegion, aws:PrincipalOrgID, aws:PrincipalOrgPaths, aws:PrincipalAccount, aws:PrincipalArn, aws:PrincipalTag/*, aws:PrincipalIsAWSService, aws:ResourceAccount, aws:ResourceOrgID and aws:ResourceOrgPaths, with the organization IDs and paths before and after the move. Other keys, policy variables and unsupported operators are reported as unsupported, never as an allow.",
		"Tag policies: compliance is checked on the sampled resources (existing-resource compliance), enforcement only for the resource types listed in enforced_for (enforcement on supported operations); whether tags are required at creation depends on separate controls (SCP conditions, Config rules) that are not modelled. A tag policy alone never rejects an untagged resource.",
		"RAM: a share that stops reaching the account is a control-plane change; what happens to traffic already flowing is taken from the per-resource-type behaviour model, and data-plane continuity is not tested.",
		"Observed usage comes from the actions the snapshot lists; declared critical operations are evaluated the same way. Anything the account will do that is in neither list is not covered by the verdict.",
		"Workload layer: evaluated from the inventory of the account alone (stacks, a resource sample, the policies read). Resources created outside CloudFormation appear only if the sample returned them; the Tagging API never returns untagged resources and the sample is capped. Of resource policies, bucket policies and role trust policies are read and only for conditions on organization identity; identity policies, KMS key policies and other resource policies are not. Templates are read for references and conditions, not executed, so a value computed at deployment is reported as unknown.",
	}
}

// Evaluate runs every check for one account and returns the verdict.
func Evaluate(in Input) (*Result, error) {
	if in.From == nil {
		return nil, fmt.Errorf("a source snapshot is required")
	}
	if err := ValidTransferMethod(in.TransferMethod); err != nil {
		return nil, err
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
		fresh:      map[string]bool{}, declared: in.Declared, method: in.TransferMethod}
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
		method:   m.method,
	}
	e.src = side{name: "source", snap: m.from, ix: m.fromIx, orgID: m.from.Organization.ID, path: m.fromIx.PathTo(acct.ID), fresh: map[string]bool{}}
	e.dst = side{name: "target", snap: m.to, ix: m.toIx, orgID: m.to.Organization.ID, path: m.targetPath, fresh: m.fresh}
	if len(e.src.path) == 0 || len(e.dst.path) < 2 {
		return nil, fmt.Errorf("could not resolve the account's path in one of the snapshots")
	}
	targetOUID := e.dst.path[len(e.dst.path)-2].ID

	usage := withDeclared(m.from.UsageFor(acct.ID), m.declared)
	derived := e.derivedOperations()
	usage.Actions = append(usage.Actions, derived...)
	usage.TaggedResources = e.taggedSample()
	e.usage = usage
	res := &Result{
		Tool: "orgshift", ResultSchemaVersion: ResultSchemaVersion,
		Subject: Subject{
			AccountID: acct.ID, AccountName: acct.Name,
			SourceOrg: OrgRef{ID: m.from.Organization.ID, Name: m.from.Organization.Name},
			TargetOrg: OrgRef{ID: m.to.Organization.ID, Name: m.to.Organization.Name},
			CrossOrg:  e.crossOrg, SourcePath: e.src.path, TargetPath: e.dst.path,
			SourcePathID: acct.ParentID, TargetOUID: targetOUID,
			ActionsInUse: len(usage.Actions), InboundAccess: len(usage.InboundAccess), TaggedResources: len(usage.TaggedResources),
			RegionsAssumed: append([]string(nil), acct.EnabledRegions...), DeclaredOperations: len(m.declared), DerivedOperations: len(derived),
			SourceOrgPath: orgPath(e.src.orgID, e.src.path), TargetOrgPath: orgPath(e.dst.orgID, e.dst.path),
		},
		Models: Models(), Limitations: Limitations(),
	}
	sort.Strings(res.Subject.RegionsAssumed)
	if e.crossOrg {
		res.Subject.TransferMethod = e.transferMethod()
	}
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
	identity := newCheck("identity-center", "IAM Identity Center")
	e.evaluateIdentityCenter(&identity)
	workloads := newCheck("workloads", "Workloads")
	res.WorkloadLayer = e.evaluateWorkloads(&workloads)
	res.Checks = []Check{scp, rcp, tags, shares, services, controlTower, identity, workloads}
	e.applyCoverage(res)

	for _, t := range snapshot.AllPolicyTypes {
		res.Diff = append(res.Diff, e.diff(t))
	}

	res.Verdict = StatusGo
	for _, c := range res.Checks {
		res.Verdict = Worst(res.Verdict, c.Status)
	}
	categorize(res)
	res.Summary = summarize(res)
	return res, nil
}

// withDeclared merges the declared critical operations into a copy of the
// account's usage, marking them so their findings say where they came from.
func withDeclared(u *snapshot.AccountUsage, declared []snapshot.ActionInUse) *snapshot.AccountUsage {
	out := &snapshot.AccountUsage{}
	if u != nil {
		out.Actions = append(out.Actions, u.Actions...)
		out.InboundAccess = u.InboundAccess
		out.TaggedResources = u.TaggedResources
	}
	for _, d := range declared {
		d.Source = SourceDeclared
		out.Actions = append(out.Actions, d)
	}
	return out
}

// categorize fills the impact category and confidence of every finding
// that its check did not set, from the status: a NO-GO hits something the
// account does, a REVIEW needs context, an INFO describes a change. It then
// counts the categories.
func categorize(res *Result) {
	res.Categories = map[string]int{}
	for i := range res.Checks {
		c := &res.Checks[i]
		for j := range c.Findings {
			f := &c.Findings[j]
			if f.Category == "" {
				switch f.Status {
				case StatusNoGo:
					f.Category = CategoryDeclaredImpact
				case StatusReview:
					f.Category = CategoryPotentialImpact
				default:
					f.Category = CategoryInformational
				}
			}
			if f.Confidence == "" {
				switch f.Category {
				case CategoryMissingEvidence:
					f.Confidence = ConfidenceLow
				case CategoryPotentialImpact, CategoryUnsupported:
					f.Confidence = ConfidenceMedium
				default:
					f.Confidence = ConfidenceHigh
				}
			}
			res.Categories[f.Category]++
		}
	}
}

// orgPath renders the aws:PrincipalOrgPaths value of a position: the
// organization ID, the root and every OU down to the account's parent,
// each followed by a slash.
func orgPath(orgID string, path []snapshot.Node) string {
	var b strings.Builder
	b.WriteString(orgID + "/")
	for _, n := range path {
		if n.Kind == snapshot.KindAccount {
			continue
		}
		b.WriteString(n.ID + "/")
	}
	return b.String()
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
	coverage := ""
	if !r.Coverage.Complete {
		coverage = " Collection coverage is incomplete (" + r.Coverage.Line() + ")."
	}
	switch r.Verdict {
	case StatusNoGo:
		return fmt.Sprintf("%s: NO-GO. %d blocking finding(s) and %d to review.%s", move, noGo, review, coverage)
	case StatusReview:
		return fmt.Sprintf("%s: REVIEW. Nothing blocks the move outright, but %d finding(s) could not be decided offline or need a decision.%s", move, review, coverage)
	}
	declared := ""
	if r.Subject.DeclaredOperations > 0 {
		declared = fmt.Sprintf(" (%d of them declared critical operations)", r.Subject.DeclaredOperations)
	}
	return fmt.Sprintf("%s: GO within the assessed scope. No blocker was found among the %d actions%s, %d inbound requests, the shares, services and controls evaluated, and every required collection domain was inspected. This is not a guarantee of zero downtime or of compatibility with everything the account does; only what the snapshots and the usage list describe was checked, and an organization policy that allows an action is not an IAM grant.",
		move, r.Subject.ActionsInUse, declared, r.Subject.InboundAccess)
}
