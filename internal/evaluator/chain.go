package evaluator

import (
	"fmt"
	"sort"
	"strings"

	"github.com/MrShaaba/orgshift/internal/policy"
	"github.com/MrShaaba/orgshift/internal/snapshot"
)

// link is one level of a policy chain: a node and the policies attached to it.
type link struct {
	node     snapshot.Node
	policies []*snapshot.Policy
}

// chain builds the policy chain of one type along a side's path.
func (e *evaluation) chain(s *side, t snapshot.PolicyType) []link {
	var out []link
	for _, n := range s.path {
		var pols []*snapshot.Policy
		if n.Kind == snapshot.KindAccount && !s.direct {
			// The account joins the organization fresh: it only carries the
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
		out = append(out, link{node: n, policies: pols})
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

// parsed returns the parsed document for a policy, caching the result.
func (e *evaluation) parsed(p *snapshot.Policy) (*policy.Document, error) {
	if d, ok := e.docs[p.ID+"|"+p.Name]; ok {
		return d.doc, d.err
	}
	d, err := policy.Parse(p.Document)
	e.docs[p.ID+"|"+p.Name] = parsedDoc{doc: d, err: err}
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

// evalChain decides a request against every level of a chain. A level allows
// the request when one of its Allow statements matches and no Deny statement
// matches; the request is allowed only if every level allows it.
func (e *evaluation) evalChain(ch []link, req policy.Request) decision {
	var pending []decision
	for _, lvl := range ch {
		allowMatched := false
		var allowUnknown, denyUnknown *decision
		for _, p := range lvl.policies {
			doc, err := e.parsed(p)
			if err != nil {
				d := decision{kind: unknown, node: lvl.node, policy: p, reason: "policy could not be parsed: " + err.Error()}
				denyUnknown = &d
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
				pending = append(pending, *allowUnknown)
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
		if d.statement != nil {
			ev.Statement = d.statement.Label()
			ev.StatementJSON = d.statement.Raw
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

// compare turns a source/target pair into a finding status and title.
func compare(p outcomePair, what string) (Status, string, string) {
	switch p.dst.kind {
	case denied, implicitDenied:
		cause := p.dst.reason
		if p.dst.kind == denied {
			cause = fmt.Sprintf("denied by %s, %s, attached at %s", p.dst.policy.Name, p.dst.statement.Label(), levelLabel(p.dst.node))
		}
		switch p.src.kind {
		case allowed:
			return StatusNoGo, what + " becomes denied after the move", "Allowed today; after the move it is " + cause + "."
		case unknown:
			return StatusNoGo, what + " is denied after the move", "Cannot be fully evaluated today (" + p.src.reason + "); after the move it is " + cause + "."
		default:
			return StatusInfo, what + " is already denied today", "Denied today (" + p.src.reason + ") and still denied after the move (" + cause + "). The actions-in-use list may be stale."
		}
	case unknown:
		return StatusReview, what + " needs review after the move",
			fmt.Sprintf("Cannot decide offline: %s (%s, %s, attached at %s).", p.dst.reason, p.dst.policy.Name, p.dst.statement.Label(), levelLabel(p.dst.node))
	default:
		if p.src.kind == denied || p.src.kind == implicitDenied {
			return StatusInfo, what + " becomes allowed after the move", "Denied today (" + p.src.reason + ") and allowed after the move."
		}
		return StatusGo, "", ""
	}
}

// evaluateActions runs the account's actions in use through the SCP chains
// (or the RCP chains when t is RCP) and fills the check.
func (e *evaluation) evaluateOwnActions(c *Check, t snapshot.PolicyType) {
	src, dst := e.chain(&e.src, t), e.chain(&e.dst, t)
	enabledSrc, enabledDst := e.from.PolicyTypeEnabled(t), e.to.PolicyTypeEnabled(t)
	if !enabledDst {
		c.add(Finding{Status: StatusInfo, Title: t.Short() + "s are not enabled in the target organization",
			Detail: "The policy type is not enabled at the target root, so nothing of this type restricts the account after the move."})
	}
	usage := e.from.UsageFor(e.accountID)
	if len(usage.Actions) == 0 {
		c.add(Finding{Status: StatusReview, Title: "No actions in use were provided for this account",
			Detail: "Add usage.actions to the source snapshot, pass --actions, or import an IAM last-accessed export. Without them nothing can be checked against the policies."})
		return
	}
	total, flagged := 0, 0
	for _, a := range usage.Actions {
		if t == snapshot.PolicyTypeRCP && !rcpServices[serviceOf(a.Action)] {
			continue
		}
		total++
		regions := regionsFor(a.Action, a.Regions, e.account.EnabledRegions)
		groups := map[string]*regionGroup{}
		var order []string
		for _, r := range regions {
			var sd, dd decision
			if enabledSrc {
				sd = e.evalChain(src, e.ownRequest(&e.src, a, r))
			}
			if enabledDst {
				dd = e.evalChain(dst, e.ownRequest(&e.dst, a, r))
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
			status, title, detail := compare(g.pair, a.Action)
			if status == StatusGo {
				continue
			}
			flagged++
			f := Finding{Status: status, Title: title, Detail: detail, Action: a.Action, Resource: a.Resource}
			if !(len(g.regions) == 1 && g.regions[0] == "") && !globalServices[serviceOf(a.Action)] {
				f.Regions = g.regions
			}
			if a.Note != "" {
				f.Detail += " Note from the usage list: " + a.Note + "."
			}
			f.Evidence = append(f.Evidence, g.pair.dst.evidence("target", t)...)
			if status == StatusInfo || g.pair.src.kind == unknown {
				f.Evidence = append(f.Evidence, g.pair.src.evidence("source", t)...)
			}
			c.add(f)
		}
	}
	sortFindings(c.Findings)
	c.Summary = fmt.Sprintf("%d actions evaluated against the %s chain; %d flagged.", total, t.Short(), flagged)
}

type regionGroup struct {
	pair    outcomePair
	regions []string
}

// evaluateInbound runs inbound access entries through the RCP chains.
func (e *evaluation) evaluateInbound(c *Check) {
	t := snapshot.PolicyTypeRCP
	src, dst := e.chain(&e.src, t), e.chain(&e.dst, t)
	enabledSrc, enabledDst := e.from.PolicyTypeEnabled(t), e.to.PolicyTypeEnabled(t)
	usage := e.from.UsageFor(e.accountID)
	total, flagged := 0, 0
	for _, in := range usage.InboundAccess {
		for _, action := range in.Actions {
			if !rcpServices[serviceOf(action)] {
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
			for _, r := range regions {
				var sd, dd decision
				if enabledSrc {
					sd = e.evalChain(src, e.inboundRequest(&e.src, in, action, r))
				}
				if enabledDst {
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
				status, title, detail := compare(g.pair, what)
				if status == StatusGo {
					continue
				}
				flagged++
				f := Finding{Status: status, Title: title, Detail: detail, Action: action, Resource: in.Resource, Principal: in.Principal}
				if !(len(g.regions) == 1 && g.regions[0] == "") && !globalServices[serviceOf(action)] {
					f.Regions = g.regions
				}
				if in.Note != "" {
					f.Detail += " Note from the usage list: " + in.Note + "."
				}
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
	if total > 0 {
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
