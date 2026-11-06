package evaluator

import (
	"fmt"
	"sort"
	"strings"

	"github.com/MrShaaba/orgshift/internal/policy"
	"github.com/MrShaaba/orgshift/internal/snapshot"
)

// link is one level of a policy chain: a node, the policies attached to it
// and the snapshot they come from (so parsed documents are cached per
// organization, never by policy ID alone).
type link struct {
	node     snapshot.Node
	policies []*snapshot.Policy
	snap     *snapshot.Snapshot
}

// chain builds the policy chain of one type along a side's path.
func (e *evaluation) chain(s *side, t snapshot.PolicyType) []link {
	var out []link
	for _, n := range s.path {
		var pols []*snapshot.Policy
		if s.fresh[n.ID] {
			// The node joins the organization fresh: it only carries the
			// AWS managed defaults that Organizations attaches automatically.
			for i := range s.snap.Policies {
				p := &s.snap.Policies[i]
				if p.Type == t && p.AWSManaged {
					pols = append(pols, p)
				}
			}
		} else {
			pols = s.ix.Attached(n.ID, t)
		}
		out = append(out, link{node: n, policies: pols, snap: s.snap})
	}
	return out
}

func levelLabel(n snapshot.Node) string {
	switch n.Kind {
	case snapshot.KindRoot:
		return fmt.Sprintf("root %s (%s)", n.Name, n.ID)
	case snapshot.KindOU:
		return fmt.Sprintf("OU %s (%s)", n.Name, n.ID)
	}
	return fmt.Sprintf("account %s (%s)", n.Name, n.ID)
}

// parsed returns the parsed document for a policy, caching the result. The
// cache key is the snapshot's organization, the policy ID and a fingerprint
// of the document: two organizations can use the same policy ID (the AWS
// managed defaults always do, hand-written snapshots may), and the
// documents behind them must never stand in for each other.
func (e *evaluation) parsed(snap *snapshot.Snapshot, p *snapshot.Policy) (*policy.Document, error) {
	key := snap.PolicyKey(p)
	if d, ok := e.docs[key]; ok {
		return d.doc, d.err
	}
	d, err := policy.Parse(p.Document)
	e.docs[key] = parsedDoc{doc: d, err: err}
	return d, err
}

type parsedDoc struct {
	doc *policy.Document
	err error
}

type decisionKind int

const (
	allowed decisionKind = iota
	denied
	implicitDenied
	unknown
)

// decision is the outcome of evaluating one request against a chain.
type decision struct {
	kind      decisionKind
	node      snapshot.Node
	policy    *snapshot.Policy
	statement *policy.Statement
	reason    string
	// attached lists the policies at the level of an implicit deny.
	attached []*snapshot.Policy
}

// cause renders what decided a request, tolerating a decision without a
// statement (a policy that could not be parsed) or without a policy.
func (d decision) cause() string {
	switch {
	case d.policy == nil:
		return d.reason
	case d.statement == nil:
		return fmt.Sprintf("%s (%s, attached at %s)", d.reason, d.policy.Name, levelLabel(d.node))
	case d.reason != "":
		return fmt.Sprintf("%s (%s, %s, attached at %s)", d.reason, d.policy.Name, d.statement.Label(), levelLabel(d.node))
	}
	return fmt.Sprintf("%s, %s, attached at %s", d.policy.Name, d.statement.Label(), levelLabel(d.node))
}

// evalChain decides a request against every level of a chain. A level allows
// the request when one of its Allow statements matches and no Deny statement
// matches; the request is allowed only if every level allows it. A policy
// that cannot be parsed is treated as unknown in both directions: it might
// hold the Allow the level needs or a Deny that applies, so the request is
// neither allowed nor implicitly denied but reported for review.
func (e *evaluation) evalChain(ch []link, req policy.Request) decision {
	var pending []decision
	for _, lvl := range ch {
		allowMatched := false
		var allowUnknown, denyUnknown *decision
		for _, p := range lvl.policies {
			doc, err := e.parsed(lvl.snap, p)
			if err != nil {
				d := decision{kind: unknown, node: lvl.node, policy: p, reason: "policy could not be parsed: " + err.Error()}
				if denyUnknown == nil {
					denyUnknown = &d
				}
				if allowUnknown == nil {
					allowUnknown = &d
				}
				continue
			}
			for i := range doc.Statements {
				st := &doc.Statements[i]
				m := st.Applies(req)
				if m.Outcome == policy.No {
					continue
				}
				d := decision{node: lvl.node, policy: p, statement: st, reason: m.Reason}
				switch {
				case st.IsAllow() && m.Outcome == policy.Yes:
					allowMatched = true
				case st.IsAllow():
					d.kind = unknown
					if allowUnknown == nil {
						allowUnknown = &d
					}
				case m.Outcome == policy.Yes:
					d.kind = denied
					return d
				default:
					d.kind = unknown
					if denyUnknown == nil {
						denyUnknown = &d
					}
				}
			}
		}
		if denyUnknown != nil {
			pending = append(pending, *denyUnknown)
		}
		if !allowMatched {
			if allowUnknown != nil {
				if denyUnknown == nil || denyUnknown != allowUnknown {
					pending = append(pending, *allowUnknown)
				}
				continue
			}
			return decision{kind: implicitDenied, node: lvl.node, attached: lvl.policies,
				reason: fmt.Sprintf("no policy attached at %s allows %s", levelLabel(lvl.node), req.Action)}
		}
	}
	if len(pending) > 0 {
		return pending[0]
	}
	return decision{kind: allowed}
}

// evidence renders a decision as evidence for a finding.
func (d decision) evidence(side string, t snapshot.PolicyType) []Evidence {
	switch d.kind {
	case denied, unknown:
		if d.policy == nil {
			return nil
		}
		ev := Evidence{Kind: "policy-statement", Side: side, Level: levelLabel(d.node),
			PolicyID: d.policy.ID, PolicyName: d.policy.Name, PolicyType: t.Short(), Note: d.reason}
		if d.policy.ControlTowerManaged() {
			ev.Note = "Control Tower guardrail (a preventive control; change it by disabling the control, not by editing the SCP). " + d.reason
		}
		if d.statement != nil {
			ev.Statement = d.statement.Label()
			ev.StatementJSON = d.statement.Raw
		} else {
			ev.Kind = "policy-unparseable"
			ev.StatementJSON = d.policy.Document
		}
		return []Evidence{ev}
	case implicitDenied:
		names := make([]string, 0, len(d.attached))
		for _, p := range d.attached {
			names = append(names, p.Name)
		}
		note := "attached here: " + strings.Join(names, ", ")
		if len(names) == 0 {
			note = "no policies attached here"
		}
		return []Evidence{{Kind: "implicit-deny", Side: side, Level: levelLabel(d.node), PolicyType: t.Short(), Note: d.reason + "; " + note}}
	}
	return nil
}

// groupKey identifies findings that should be merged across regions.
func (d decision) groupKey() string {
	k := fmt.Sprint(d.kind)
	if d.policy != nil {
		k += "|" + d.policy.ID + "|" + d.policy.Name
	}
	if d.statement != nil {
		k += "|" + d.statement.Label()
	}
	k += "|" + d.node.ID + "|" + d.reason
	return k
}

type outcomePair struct {
	src, dst decision
}

// compare turns a source/target pair into a finding status, title, detail
// and impact category.
func compare(p outcomePair, what string) (Status, string, string, string) {
	switch p.dst.kind {
	case denied, implicitDenied:
		cause := p.dst.reason
		if p.dst.kind == denied {
			cause = "denied by " + p.dst.cause()
		}
		switch p.src.kind {
		case allowed:
			return StatusNoGo, what + " becomes denied after the move", "Allowed today; after the move it is " + cause + ".", CategoryDeclaredImpact
		case unknown:
			return StatusNoGo, what + " is denied after the move", "Cannot be fully evaluated today (" + p.src.cause() + "); after the move it is " + cause + ".", CategoryDeclaredImpact
		default:
			return StatusInfo, what + " is already denied today", "Denied today (" + p.src.cause() + ") and still denied after the move (" + cause + "). The actions-in-use list may be stale.", CategoryKnownRestriction
		}
	case unknown:
		category := CategoryPotentialImpact
		if unsupportedReason(p.dst.reason) {
			category = CategoryUnsupported
		}
		return StatusReview, what + " needs review after the move", "Cannot decide offline: " + p.dst.cause() + ".", category
	default:
		if p.src.kind == denied || p.src.kind == implicitDenied {
			return StatusInfo, what + " becomes allowed after the move", "Denied today (" + p.src.cause() + ") and allowed after the move.", CategoryInformational
		}
		return StatusGo, "", "", ""
	}
}

// unsupportedReason reports whether an unknown decision comes from a limit
// of the evaluator (an operator or construct it does not model) rather than
// from context the snapshot lacks.
func unsupportedReason(reason string) bool {
	return strings.Contains(reason, "not supported by the offline evaluator") || strings.Contains(reason, "policy variable") || strings.Contains(reason, "could not be parsed")
}

// sourceOf returns the finding source for an action in use.
func sourceOf(a snapshot.ActionInUse) string {
	switch a.Source {
	case SourceDeclared, SourceWorkload:
		return a.Source
	}
	return SourceObserved
}

// chainsFor picks the chains and the context sides for one of the account's
// own actions. For SCPs they are the account's own chains. For RCPs the
// policies that apply are those of the organization that owns the resource:
// when the resource names another account, that account's chain is used on
// both sides and only the caller's organization changes; when the owner is
// unknown to both snapshots, or is a management account (whose resources
// RCPs do not restrict), ok is false and note says why.
type routedRequest struct {
	srcChain, dstChain     []link
	srcEnabled, dstEnabled bool
	// evidenceSide names the snapshot the policies come from, for evidence.
	evidenceSide string
	// owner is the account that owns the resource when it is not the moving
	// account.
	owner string
}

func (e *evaluation) chainsFor(t snapshot.PolicyType, a snapshot.ActionInUse, src, dst []link) (routedRequest, string, bool) {
	r := routedRequest{srcChain: src, dstChain: dst, srcEnabled: e.from.PolicyTypeEnabled(t), dstEnabled: e.to.PolicyTypeEnabled(t), evidenceSide: "target"}
	if t != snapshot.PolicyTypeRCP {
		return r, "", true
	}
	owner := policy.AccountFromPrincipal(a.Resource)
	if owner == "" || owner == e.accountID {
		return r, "", true
	}
	ownerSide := e.sideOfAccount(owner)
	if ownerSide == nil {
		return r, fmt.Sprintf("resource %s belongs to account %s, which is in neither snapshot; the RCPs of its organization cannot be evaluated offline", a.Resource, owner), false
	}
	if ownerSide.snap.Organization.ManagementAccountID == owner {
		return r, fmt.Sprintf("resource %s belongs to %s, the management account of %s; RCPs do not restrict resources in a management account", a.Resource, owner, ownerSide.orgID), false
	}
	ch := e.chain(ownerSide, t)
	enabled := ownerSide.snap.PolicyTypeEnabled(t)
	return routedRequest{srcChain: ch, dstChain: ch, srcEnabled: enabled, dstEnabled: enabled, evidenceSide: ownerSide.name, owner: owner}, "", true
}

// sideOfAccount locates an account in either snapshot and returns a side
// positioned at its real place, or nil.
func (e *evaluation) sideOfAccount(accountID string) *side {
	for _, s := range []*side{&e.src, &e.dst} {
		if _, ok := s.ix.AccountByID[accountID]; ok {
			if path := s.ix.PathTo(accountID); path != nil {
				return &side{name: s.name, snap: s.snap, ix: s.ix, orgID: s.orgID, path: path, fresh: map[string]bool{}}
			}
		}
	}
	return nil
}

// evaluateOwnActions runs the account's actions in use through the SCP chains
// (or the RCP chains when t is RCP) and fills the check.
func (e *evaluation) evaluateOwnActions(c *Check, t snapshot.PolicyType) {
	src, dst := e.chain(&e.src, t), e.chain(&e.dst, t)
	if !e.to.PolicyTypeEnabled(t) {
		c.add(Finding{Status: StatusInfo, Title: t.Short() + "s are not enabled in the target organization",
			Detail: "The policy type is not enabled at the target root, so nothing of this type restricts the account after the move."})
	}
	usage := e.usage
	if len(usage.Actions) == 0 {
		c.add(Finding{Status: StatusReview, Category: CategoryMissingEvidence, Title: "No actions in use were provided for this account",
			Detail: "Add usage.actions to the source snapshot, pass --actions or --critical-operations, or import an IAM last-accessed export. Without them nothing can be checked against the policies."})
		c.Summary = "No actions in use to evaluate against the " + t.Short() + " chain."
		return
	}
	total, flagged := 0, 0
	var notGoverned, exempt, elsewhere, serviceLinked []string
	skipped := map[string]bool{}
	for _, a := range usage.Actions {
		// Neither SCPs nor RCPs restrict a call made by a service-linked
		// role, on either side.
		if isServiceLinkedRole(a.PrincipalArn) {
			serviceLinked = append(serviceLinked, a.Action+" by "+a.PrincipalArn)
			continue
		}
		if t == snapshot.PolicyTypeRCP {
			switch applies, why := rcpApplies(a.Action); applies {
			case false:
				if why == rcpExemptReason {
					exempt = append(exempt, a.Action)
				} else {
					notGoverned = append(notGoverned, a.Action)
				}
				continue
			}
		}
		routed, note, ok := e.chainsFor(t, a, src, dst)
		if !ok {
			if !skipped[note] {
				skipped[note] = true
				status, category := StatusReview, CategoryUnsupported
				if strings.Contains(note, "management account") {
					status, category = StatusInfo, CategoryKnownRestriction
				}
				c.add(Finding{Status: status, Category: category, Source: sourceOf(a), Title: "RCP evaluation skipped for " + a.Action + " on a resource owned by another account", Detail: note + ".",
					Action: a.Action, Resource: a.Resource, References: []string{RCPModelReference}})
			}
			continue
		}
		if routed.owner != "" {
			elsewhere = append(elsewhere, a.Action+" on a resource of account "+routed.owner)
		}
		total++
		regions := regionsFor(a.Action, a.Regions, e.account.EnabledRegions)
		// Each side is asked on its own whether the policy type applies to
		// the account there: a management account is exempt in the
		// organization it manages and nowhere else.
		srcExempt, dstExempt := e.exemptOn(&e.src, t, routed.owner == ""), e.exemptOn(&e.dst, t, routed.owner == "")
		groups := map[string]*regionGroup{}
		var order []string
		for _, r := range regions.regions {
			var sd, dd decision
			if routed.srcEnabled && !srcExempt {
				sd = e.evalChain(routed.srcChain, e.ownRequest(&e.src, a, r))
			}
			if routed.dstEnabled && !dstExempt {
				dd = e.evalChain(routed.dstChain, e.ownRequest(&e.dst, a, r))
			}
			key := sd.groupKey() + "||" + dd.groupKey()
			g, ok := groups[key]
			if !ok {
				g = &regionGroup{pair: outcomePair{src: sd, dst: dd}}
				groups[key] = g
				order = append(order, key)
			}
			g.regions = append(g.regions, r)
		}
		for _, key := range order {
			g := groups[key]
			status, title, detail, category := compare(g.pair, a.Action)
			if status == StatusGo {
				continue
			}
			flagged++
			f := Finding{Status: status, Category: category, Source: sourceOf(a), Title: title, Detail: detail, Action: a.Action, Resource: a.Resource}
			if a.Source == SourceDeclared {
				f.Detail += " This operation was declared critical by the operator rather than observed."
			}
			f.Detail += e.exemptionNote(t, srcExempt, dstExempt)
			if routed.owner != "" {
				f.Detail += fmt.Sprintf(" The resource belongs to account %s, so the RCPs of that account's organization apply; what changes is that the caller's organization becomes %s.", routed.owner, e.dst.orgID)
			}
			if regions.known() && !globalServices[serviceOf(a.Action)] {
				f.Regions = g.regions
			}
			e.regionNote(&f, regions, a.Action, g.pair)
			switch {
			case a.Source == SourceWorkload:
				f.Detail += " This operation was derived from the workload inventory: " + a.Note + "."
			case a.Note != "":
				f.Detail += " Note from the usage list: " + a.Note + "."
			}
			f.Evidence = append(f.Evidence, g.pair.dst.evidence(routed.evidenceSide, t)...)
			if status == StatusInfo || g.pair.src.kind == unknown {
				srcSide := "source"
				if routed.owner != "" {
					srcSide = routed.evidenceSide
				}
				f.Evidence = append(f.Evidence, g.pair.src.evidence(srcSide, t)...)
			}
			c.add(f)
		}
	}
	if t == snapshot.PolicyTypeRCP {
		e.rcpModelFindings(c, notGoverned, exempt)
	}
	e.exemptionFindings(c, t, serviceLinked)
	sortFindings(c.Findings)
	c.Summary = fmt.Sprintf("%d actions evaluated against the %s chain; %d flagged.", total, t.Short(), flagged)
	if len(serviceLinked) > 0 {
		c.Summary += fmt.Sprintf(" %d call(s) by service-linked roles are not restricted by %ss and were not evaluated.", len(serviceLinked), t.Short())
	}
	if t == snapshot.PolicyTypeRCP {
		c.Summary += fmt.Sprintf(" RCP applicability model %s: %d action(s) on services RCPs do not govern were not evaluated, %d exempt.", RCPModelVersion, len(notGoverned), len(exempt))
		if len(elsewhere) > 0 {
			c.Summary += fmt.Sprintf(" %d action(s) target resources in other accounts and were evaluated against the owner's RCPs.", len(elsewhere))
		}
	}
}

type regionGroup struct {
	pair    outcomePair
	regions []string
}

// regionNote says where a finding's Region comes from when the service has
// more than one kind of endpoint. A decision that could not be made because
// the endpoint is not known is missing evidence: the usage entry can supply
// it.
func (e *evaluation) regionNote(f *Finding, regions regionSet, action string, pair outcomePair) {
	note := regions.note(action)
	if note == "" {
		return
	}
	if regions.endpointUnknown {
		undecided := (pair.dst.kind == unknown && strings.Contains(pair.dst.reason, "aws:RequestedRegion")) ||
			(pair.src.kind == unknown && strings.Contains(pair.src.reason, "aws:RequestedRegion"))
		if !undecided {
			return // the policies decide the call whatever its endpoint
		}
		if f.Status == StatusReview {
			f.Category = CategoryMissingEvidence
		}
	}
	f.Detail += note
	f.References = append(f.References, refSTSRegions)
}

// evaluateInbound runs inbound access entries through the RCP chains of the
// account (the resource owner).
func (e *evaluation) evaluateInbound(c *Check) {
	t := snapshot.PolicyTypeRCP
	src, dst := e.chain(&e.src, t), e.chain(&e.dst, t)
	enabledSrc, enabledDst := e.from.PolicyTypeEnabled(t), e.to.PolicyTypeEnabled(t)
	usage := e.usage
	total, flagged := 0, 0
	var notGoverned []string
	for _, in := range usage.InboundAccess {
		for _, action := range in.Actions {
			if applies, _ := rcpApplies(action); !applies {
				notGoverned = append(notGoverned, action+" by "+in.Principal)
				continue
			}
			total++
			explicit := in.Regions
			if len(explicit) == 0 {
				if r := regionFromARN(in.Resource); r != "" {
					explicit = []string{r}
				}
			}
			regions := regionsFor(action, explicit, e.account.EnabledRegions)
			groups := map[string]*regionGroup{}
			var order []string
			// The resource is the account's own: RCPs do not restrict it on
			// a side where the account is the management account.
			srcExempt, dstExempt := e.exemptOn(&e.src, t, true), e.exemptOn(&e.dst, t, true)
			for _, r := range regions.regions {
				var sd, dd decision
				if enabledSrc && !srcExempt {
					sd = e.evalChain(src, e.inboundRequest(&e.src, in, action, r))
				}
				if enabledDst && !dstExempt {
					dd = e.evalChain(dst, e.inboundRequest(&e.dst, in, action, r))
				}
				key := sd.groupKey() + "||" + dd.groupKey()
				g, ok := groups[key]
				if !ok {
					g = &regionGroup{pair: outcomePair{src: sd, dst: dd}}
					groups[key] = g
					order = append(order, key)
				}
				g.regions = append(g.regions, r)
			}
			for _, key := range order {
				g := groups[key]
				what := fmt.Sprintf("%s by %s", action, in.Principal)
				status, title, detail, category := compare(g.pair, what)
				if status == StatusGo {
					continue
				}
				flagged++
				f := Finding{Status: status, Category: category, Source: SourceObserved, Title: title, Detail: detail, Action: action, Resource: in.Resource, Principal: in.Principal}
				if regions.known() && !globalServices[serviceOf(action)] {
					f.Regions = g.regions
				}
				e.regionNote(&f, regions, action, g.pair)
				if in.Note != "" {
					f.Detail += " Note from the usage list: " + in.Note + "."
				}
				f.Detail += e.exemptionNote(t, srcExempt, dstExempt)
				if status == StatusReview && in.PrincipalOrgID == "" {
					if _, known := e.orgOfAccount(policy.AccountFromPrincipal(in.Principal)); !known && !strings.HasSuffix(in.Principal, ".amazonaws.com") {
						f.Detail += " Set principal_org_id on this inbound_access entry if the caller's organization is known."
					}
				}
				f.Evidence = append(f.Evidence, g.pair.dst.evidence("target", t)...)
				if status == StatusInfo || g.pair.src.kind == unknown {
					f.Evidence = append(f.Evidence, g.pair.src.evidence("source", t)...)
				}
				c.add(f)
			}
		}
	}
	if len(notGoverned) > 0 {
		sort.Strings(notGoverned)
		c.add(Finding{Status: StatusInfo, Title: fmt.Sprintf("%d inbound request(s) use services RCPs do not govern and were not evaluated", len(notGoverned)),
			Detail:     "RCPs apply to a fixed list of services (applicability model " + RCPModelVersion + "). Requests for other services are not restricted by RCPs at either position, so nothing changes for them: " + strings.Join(notGoverned, "; ") + ". Services added to RCPs after the model date are not covered.",
			References: []string{RCPModelReference}})
	}
	if total > 0 || len(notGoverned) > 0 {
		c.Summary += fmt.Sprintf(" %d inbound requests evaluated; %d flagged.", total, flagged)
	}
	sortFindings(c.Findings)
}

func sortFindings(fs []Finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		if rank(fs[i].Status) != rank(fs[j].Status) {
			return rank(fs[i].Status) > rank(fs[j].Status)
		}
		if fs[i].Status != fs[j].Status { // REVIEW before INFO within rank 0 is impossible; keep GO/INFO stable
			return fs[i].Status < fs[j].Status
		}
		if fs[i].Action != fs[j].Action {
			return fs[i].Action < fs[j].Action
		}
		return fs[i].Title < fs[j].Title
	})
}
