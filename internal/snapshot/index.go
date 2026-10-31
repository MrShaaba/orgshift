package snapshot

import (
	"sort"
	"strings"
)

// NodeKind distinguishes the three kinds of organization tree nodes.
type NodeKind string

// Node kinds.
const (
	KindRoot    NodeKind = "root"
	KindOU      NodeKind = "ou"
	KindAccount NodeKind = "account"
)

// Node is a root, OU or account seen as a tree node.
type Node struct {
	ID   string   `json:"id"`
	Name string   `json:"name"`
	Kind NodeKind `json:"kind"`
}

// Index gives fast lookups over a snapshot. Build it once with s.Index().
type Index struct {
	Snapshot    *Snapshot
	OUByID      map[string]*OU
	AccountByID map[string]*Account
	PolicyByID  map[string]*Policy
	parentOf    map[string]string
	childOUs    map[string][]*OU
	accountsIn  map[string][]*Account
	attached    map[string][]*Policy // target ID -> policies, all types
}

// Index builds the lookup structure.
func (s *Snapshot) Index() *Index {
	ix := &Index{
		Snapshot:    s,
		OUByID:      map[string]*OU{},
		AccountByID: map[string]*Account{},
		PolicyByID:  map[string]*Policy{},
		parentOf:    map[string]string{},
		childOUs:    map[string][]*OU{},
		accountsIn:  map[string][]*Account{},
		attached:    map[string][]*Policy{},
	}
	for i := range s.OUs {
		ou := &s.OUs[i]
		ix.OUByID[ou.ID] = ou
		ix.parentOf[ou.ID] = ou.ParentID
		ix.childOUs[ou.ParentID] = append(ix.childOUs[ou.ParentID], ou)
	}
	for i := range s.Accounts {
		a := &s.Accounts[i]
		ix.AccountByID[a.ID] = a
		ix.parentOf[a.ID] = a.ParentID
		ix.accountsIn[a.ParentID] = append(ix.accountsIn[a.ParentID], a)
	}
	for i := range s.Policies {
		p := &s.Policies[i]
		ix.PolicyByID[p.ID] = p
		for _, t := range p.Targets {
			ix.attached[t] = append(ix.attached[t], p)
		}
	}
	for k := range ix.childOUs {
		sort.Slice(ix.childOUs[k], func(i, j int) bool { return ix.childOUs[k][i].Name < ix.childOUs[k][j].Name })
	}
	for k := range ix.accountsIn {
		sort.Slice(ix.accountsIn[k], func(i, j int) bool { return ix.accountsIn[k][i].Name < ix.accountsIn[k][j].Name })
	}
	for k := range ix.attached {
		sort.Slice(ix.attached[k], func(i, j int) bool {
			if ix.attached[k][i].Type != ix.attached[k][j].Type {
				return ix.attached[k][i].Type < ix.attached[k][j].Type
			}
			return ix.attached[k][i].Name < ix.attached[k][j].Name
		})
	}
	return ix
}

// Node returns the tree node for an ID, or false if it is unknown.
func (ix *Index) Node(id string) (Node, bool) {
	if id == ix.Snapshot.Root.ID {
		return Node{ID: id, Name: ix.Snapshot.Root.Name, Kind: KindRoot}, true
	}
	if ou, ok := ix.OUByID[id]; ok {
		return Node{ID: id, Name: ou.Name, Kind: KindOU}, true
	}
	if a, ok := ix.AccountByID[id]; ok {
		return Node{ID: id, Name: a.Name, Kind: KindAccount}, true
	}
	return Node{}, false
}

// ParentOf returns the parent ID of an OU or account ("" for the root).
func (ix *Index) ParentOf(id string) string { return ix.parentOf[id] }

// ChildOUs returns the OUs directly under a root or OU, sorted by name.
func (ix *Index) ChildOUs(parentID string) []*OU { return ix.childOUs[parentID] }

// AccountsIn returns the accounts directly under a root or OU, sorted by name.
func (ix *Index) AccountsIn(parentID string) []*Account { return ix.accountsIn[parentID] }

// Attached returns the policies of one type attached directly to a target.
func (ix *Index) Attached(targetID string, t PolicyType) []*Policy {
	var out []*Policy
	for _, p := range ix.attached[targetID] {
		if p.Type == t {
			out = append(out, p)
		}
	}
	return out
}

// AttachedAll returns every policy attached directly to a target.
func (ix *Index) AttachedAll(targetID string) []*Policy { return ix.attached[targetID] }

// PathTo returns the chain of nodes from the root down to and including the
// given root, OU or account. It returns nil when the ID is unknown or the
// chain does not end at the root (which Validate rejects).
func (ix *Index) PathTo(id string) []Node {
	var rev []Node
	cur := id
	for i := 0; i < 64 && cur != ""; i++ {
		n, ok := ix.Node(cur)
		if !ok {
			return nil
		}
		rev = append(rev, n)
		if n.Kind == KindRoot {
			break
		}
		cur = ix.parentOf[cur]
	}
	if len(rev) == 0 || rev[len(rev)-1].Kind != KindRoot {
		return nil
	}
	out := make([]Node, 0, len(rev))
	for i := len(rev) - 1; i >= 0; i-- {
		out = append(out, rev[i])
	}
	return out
}

// PathUnder returns the chain of nodes from the root down to parentID with
// the given account appended, as if the account lived under that parent.
func (ix *Index) PathUnder(parentID string, account Node) []Node {
	p := ix.PathTo(parentID)
	if p == nil {
		return nil
	}
	return append(p, account)
}

// PathString renders a path as "Root / OU / Account".
func PathString(path []Node) string {
	parts := make([]string, 0, len(path))
	for _, n := range path {
		parts = append(parts, n.Name)
	}
	return strings.Join(parts, " / ")
}

// OUPath returns the IDs of the OUs (and root) in a path, excluding accounts.
func OUPath(path []Node) []string {
	var ids []string
	for _, n := range path {
		if n.Kind != KindAccount {
			ids = append(ids, n.ID)
		}
	}
	return ids
}

// AccountOrg finds which snapshot (if any) an account belongs to and returns
// that snapshot's organization ID.
func AccountOrg(accountID string, snaps ...*Snapshot) (string, bool) {
	for _, s := range snaps {
		if s == nil {
			continue
		}
		for _, a := range s.Accounts {
			if a.ID == accountID {
				return s.Organization.ID, true
			}
		}
	}
	return "", false
}

// Subtree returns every OU below (and including) the given OU in depth-first
// order, followed by every account under any of them, sorted by name within
// each parent. It returns nil, nil when the ID is not an OU.
func (ix *Index) Subtree(ouID string) (ous []*OU, accounts []*Account) {
	root, ok := ix.OUByID[ouID]
	if !ok {
		return nil, nil
	}
	var walk func(ou *OU)
	walk = func(ou *OU) {
		ous = append(ous, ou)
		accounts = append(accounts, ix.accountsIn[ou.ID]...)
		for _, child := range ix.childOUs[ou.ID] {
			walk(child)
		}
	}
	walk(root)
	return ous, accounts
}

// IsUnder reports whether id is ancestorID itself or sits anywhere below it.
func (ix *Index) IsUnder(id, ancestorID string) bool {
	for _, n := range ix.PathTo(id) {
		if n.ID == ancestorID {
			return true
		}
	}
	return false
}
