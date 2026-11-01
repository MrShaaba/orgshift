package web

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html/template"
	"strings"

	"github.com/MrShaaba/orgshift/internal/evaluator"
	"github.com/MrShaaba/orgshift/internal/runbook"
	"github.com/MrShaaba/orgshift/internal/snapshot"
)

// treeNode is a root, OU or account rendered in the side-by-side tree.
type treeNode struct {
	Node      snapshot.Node
	Badges    []badge
	Children  []*treeNode
	Accounts  []*treeNode
	OnPath    bool
	IsSubject bool
	Ghost     bool
}

type badge struct {
	Type  string
	Names string
	Count int
	// Label replaces "Type Count" when set.
	Label string
}

func badgesFor(ix *snapshot.Index, id string) []badge {
	var out []badge
	for _, t := range snapshot.AllPolicyTypes {
		pols := ix.Attached(id, t)
		if len(pols) == 0 {
			continue
		}
		names := make([]string, 0, len(pols))
		for _, p := range pols {
			if p.ControlTowerManaged() {
				names = append(names, p.Name+" (Control Tower guardrail)")
			} else {
				names = append(names, p.Name)
			}
		}
		out = append(out, badge{Type: t.Short(), Names: strings.Join(names, ", "), Count: len(pols)})
	}
	if ct := ix.Snapshot.ControlTower; ct != nil {
		if r := ct.RegisteredOU(id); r != nil {
			controls := ct.ControlsOn(id)
			names := make([]string, 0, len(controls))
			for _, c := range controls {
				names = append(names, c.Label())
			}
			title := fmt.Sprintf("Registered with Control Tower (baseline %s, %s)", r.BaselineVersion, r.Status)
			if len(names) > 0 {
				title += "; controls enabled here: " + strings.Join(names, ", ")
			}
			out = append(out, badge{Type: "CT", Names: title, Count: len(controls), Label: "CT"})
		}
	}
	if ic := ix.Snapshot.IdentityCenter; ic != nil {
		if labels := assignmentLabels(ic, id); len(labels) > 0 {
			out = append(out, badge{Type: "IdC", Names: "Identity Center assignments: " + strings.Join(labels, ", "), Count: len(labels)})
		}
	}
	return out
}

// assignmentLabels renders the Identity Center assignments on an account as
// "group Name → PermissionSet".
func assignmentLabels(ic *snapshot.IdentityCenter, accountID string) []string {
	var out []string
	for _, a := range ic.AssignmentsFor(accountID) {
		name := a.PermissionSetARN
		if ps := ic.PermissionSet(a.PermissionSetARN); ps != nil {
			name = ps.Name
		}
		out = append(out, a.Label()+" → "+name)
	}
	return out
}

// reservedRoles renders the AWSReservedSSO_* role patterns provisioned in an
// account.
func reservedRoles(ic *snapshot.IdentityCenter, accountID string) []string {
	var out []string
	for _, ps := range ic.ProvisionedIn(accountID) {
		out = append(out, ps.ReservedRolePattern())
	}
	return out
}

// buildTree renders a snapshot as a tree, marking the path to a position.
// When ghostParent is set, the subject is removed from its original place
// and the ghost subtree is drawn under ghostParent as if it had already
// moved.
func buildTree(s *snapshot.Snapshot, path []snapshot.Node, subject snapshot.Node, ghostParent string, ghost *treeNode) *treeNode {
	ix := s.Index()
	onPath := map[string]bool{}
	for _, n := range path {
		onPath[n.ID] = true
	}
	var build func(n snapshot.Node) *treeNode
	build = func(n snapshot.Node) *treeNode {
		tn := &treeNode{Node: n, Badges: badgesFor(ix, n.ID), OnPath: onPath[n.ID], IsSubject: n.ID == subject.ID}
		for _, ou := range ix.ChildOUs(n.ID) {
			if ghostParent != "" && ou.ID == subject.ID {
				continue
			}
			tn.Children = append(tn.Children, build(snapshot.Node{ID: ou.ID, Name: ou.Name, Kind: snapshot.KindOU}))
		}
		for _, a := range ix.AccountsIn(n.ID) {
			if ghostParent != "" && a.ID == subject.ID {
				continue
			}
			an := &treeNode{Node: snapshot.Node{ID: a.ID, Name: a.Name, Kind: snapshot.KindAccount}, Badges: badgesFor(ix, a.ID), OnPath: onPath[a.ID]}
			an.IsSubject = a.ID == subject.ID
			tn.Accounts = append(tn.Accounts, an)
		}
		if ghostParent != "" && n.ID == ghostParent && ghost != nil {
			if ghost.Node.Kind == snapshot.KindAccount {
				tn.Accounts = append([]*treeNode{ghost}, tn.Accounts...)
			} else {
				tn.Children = append([]*treeNode{ghost}, tn.Children...)
			}
		}
		return tn
	}
	return build(snapshot.Node{ID: s.Root.ID, Name: s.Root.Name, Kind: snapshot.KindRoot})
}

// ghostSubtree copies an OU and everything under it from the source
// snapshot, marked as ghosts. Badges are kept only when the attachments
// travel with the OU (a move inside one organization).
func ghostSubtree(ix *snapshot.Index, ou snapshot.Node, withBadges bool) *treeNode {
	var build func(n snapshot.Node) *treeNode
	build = func(n snapshot.Node) *treeNode {
		tn := &treeNode{Node: n, Ghost: true}
		if withBadges {
			tn.Badges = badgesFor(ix, n.ID)
		}
		for _, child := range ix.ChildOUs(n.ID) {
			tn.Children = append(tn.Children, build(snapshot.Node{ID: child.ID, Name: child.Name, Kind: snapshot.KindOU}))
		}
		for _, a := range ix.AccountsIn(n.ID) {
			tn.Accounts = append(tn.Accounts, build(snapshot.Node{ID: a.ID, Name: a.Name, Kind: snapshot.KindAccount}))
		}
		return tn
	}
	root := build(ou)
	root.OnPath, root.IsSubject = true, true
	return root
}

// resultView is what the account result template renders.
type resultView struct {
	Result     *evaluator.Result
	SourceName string
	TargetName string
	SourceTree *treeNode
	TargetTree *treeNode
	// ExportQuery is the encoded query that reproduces this result. It is
	// a template.URL so html/template keeps its & and = intact in links.
	ExportQuery template.URL
	Account     *snapshot.Account
	Usage       *snapshot.AccountUsage
	// Assignments and ReservedRoles describe the account in the source
	// Identity Center instance, when there is one.
	Assignments   []string
	ReservedRoles []string
	// Runbook is the migration checklist built from the result.
	Runbook *runbook.Runbook
}

func newResultView(res *evaluator.Result, fromName, toName string, from, to *snapshot.Snapshot, query string) *resultView {
	subject := snapshot.Node{ID: res.Subject.AccountID, Name: res.Subject.AccountName, Kind: snapshot.KindAccount}
	v := &resultView{Result: res, SourceName: fromName, TargetName: toName, ExportQuery: template.URL(query)}
	v.SourceTree = buildTree(from, res.Subject.SourcePath, subject, "", nil)
	ghost := &treeNode{Node: subject, OnPath: true, IsSubject: true, Ghost: true}
	v.TargetTree = buildTree(to, res.Subject.TargetPath, subject, res.Subject.TargetOUID, ghost)
	ix := from.Index()
	v.Account = ix.AccountByID[subject.ID]
	v.Usage = from.UsageFor(subject.ID)
	if ic := from.IdentityCenter; ic != nil {
		v.Assignments = assignmentLabels(ic, subject.ID)
		v.ReservedRoles = reservedRoles(ic, subject.ID)
	}
	v.Runbook = runbook.Build(res, from, to)
	return v
}

// ouResultView is what the OU result template renders.
type ouResultView struct {
	Result      *evaluator.OUResult
	SourceName  string
	TargetName  string
	SourceTree  *treeNode
	TargetTree  *treeNode
	ExportQuery template.URL
	Runbook     *runbook.OURunbook
	// AccountRunbooks maps account IDs to their part of the OU runbook.
	AccountRunbooks map[string]*runbook.Runbook
}

func newOUResultView(res *evaluator.OUResult, fromName, toName string, from, to *snapshot.Snapshot, query string) *ouResultView {
	subject := snapshot.Node{ID: res.Subject.OUID, Name: res.Subject.OUName, Kind: snapshot.KindOU}
	v := &ouResultView{Result: res, SourceName: fromName, TargetName: toName, ExportQuery: template.URL(query)}
	v.SourceTree = buildTree(from, res.Subject.SourcePath, subject, "", nil)
	ghost := ghostSubtree(from.Index(), subject, !res.Subject.CrossOrg)
	v.TargetTree = buildTree(to, res.Subject.TargetPath, subject, res.Subject.TargetParentID, ghost)
	v.Runbook = runbook.BuildOU(res, from, to)
	v.AccountRunbooks = map[string]*runbook.Runbook{}
	for _, rb := range v.Runbook.Accounts {
		v.AccountRunbooks[rb.Subject.AccountID] = rb
	}
	return v
}

func statusClass(s evaluator.Status) string {
	switch s {
	case evaluator.StatusGo:
		return "go"
	case evaluator.StatusReview:
		return "review"
	case evaluator.StatusNoGo:
		return "nogo"
	}
	return "info"
}

func prettyJSON(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var out bytes.Buffer
	if err := json.Indent(&out, raw, "", "  "); err != nil {
		return string(raw)
	}
	return out.String()
}

func countStatus(c evaluator.Check, s evaluator.Status) int { return c.Counts()[s] }

func pathLabel(path []snapshot.Node) string { return snapshot.PathString(path) }

func parentPath(path []snapshot.Node) string {
	if len(path) == 0 {
		return ""
	}
	return snapshot.PathString(path[:len(path)-1])
}

func plural(n int, singular, pluralForm string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, singular)
	}
	return fmt.Sprintf("%d %s", n, pluralForm)
}

// firstN returns at most the first n strings.
func firstN(list []string, n int) []string {
	if len(list) <= n {
		return list
	}
	return list[:n]
}

// leftOver returns how many strings firstN would leave out.
func leftOver(list []string, n int) int {
	if len(list) <= n {
		return 0
	}
	return len(list) - n
}

// stepNumber renders "phase.step" for a checklist item.
func stepNumber(phase, step int) string { return fmt.Sprintf("%d.%d", phase+1, step+1) }

// doneKey is the localStorage key under which the browser remembers a
// ticked step: the export query identifies the move, the step ID the item.
func doneKey(query template.URL, prefix, stepID string) string {
	return "orgshift-runbook:" + string(query) + ":" + prefix + stepID
}

// dict builds a map for templates that take several named arguments.
func dict(pairs ...any) (map[string]any, error) {
	if len(pairs)%2 != 0 {
		return nil, fmt.Errorf("dict needs key/value pairs")
	}
	m := map[string]any{}
	for i := 0; i < len(pairs); i += 2 {
		k, ok := pairs[i].(string)
		if !ok {
			return nil, fmt.Errorf("dict keys must be strings")
		}
		m[k] = pairs[i+1]
	}
	return m, nil
}
