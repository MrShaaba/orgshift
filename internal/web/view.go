package web

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/MrShaaba/orgshift/internal/evaluator"
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
			names = append(names, p.Name)
		}
		out = append(out, badge{Type: t.Short(), Names: strings.Join(names, ", "), Count: len(pols)})
	}
	return out
}

// buildTree renders a snapshot as a tree, marking the path to a position.
// When ghost is set, the subject account is drawn under targetParent as if
// it had already moved.
func buildTree(s *snapshot.Snapshot, path []snapshot.Node, subject snapshot.Node, ghostParent string) *treeNode {
	ix := s.Index()
	onPath := map[string]bool{}
	for _, n := range path {
		onPath[n.ID] = true
	}
	var build func(n snapshot.Node) *treeNode
	build = func(n snapshot.Node) *treeNode {
		tn := &treeNode{Node: n, Badges: badgesFor(ix, n.ID), OnPath: onPath[n.ID]}
		for _, ou := range ix.ChildOUs(n.ID) {
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
		if ghostParent != "" && n.ID == ghostParent {
			tn.Accounts = append([]*treeNode{{Node: subject, OnPath: true, IsSubject: true, Ghost: true}}, tn.Accounts...)
		}
		return tn
	}
	return build(snapshot.Node{ID: s.Root.ID, Name: s.Root.Name, Kind: snapshot.KindRoot})
}

// resultView is what the result template renders.
type resultView struct {
	Result      *evaluator.Result
	SourceName  string
	TargetName  string
	SourceTree  *treeNode
	TargetTree  *treeNode
	ExportQuery string
	Account     *snapshot.Account
	Usage       *snapshot.AccountUsage
}

func newResultView(res *evaluator.Result, fromName, toName string, from, to *snapshot.Snapshot, query string) *resultView {
	subject := snapshot.Node{ID: res.Subject.AccountID, Name: res.Subject.AccountName, Kind: snapshot.KindAccount}
	v := &resultView{Result: res, SourceName: fromName, TargetName: toName, ExportQuery: query}
	v.SourceTree = buildTree(from, res.Subject.SourcePath, subject, "")
	ghostParent := res.Subject.TargetOUID
	v.TargetTree = buildTree(to, res.Subject.TargetPath, subject, ghostParent)
	ix := from.Index()
	v.Account = ix.AccountByID[subject.ID]
	v.Usage = from.UsageFor(subject.ID)
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
