package scenario

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/MrShaaba/orgshift/internal/evaluator"
	"github.com/MrShaaba/orgshift/internal/snapshot"
	"github.com/MrShaaba/orgshift/internal/workload"
)

// ReportSchemaVersion is bumped when the exported staged report changes.
// Version 2 added the evaluation level and detail of the workload layer at
// every stage and the redeployment plan on the recreate strategy.
const ReportSchemaVersion = 2

// Documentation the stage findings refer to.
const (
	refRemoveAccount  = "https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_accounts_remove.html"
	refInvitations    = "https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_accounts_invites.html"
	refInheritance    = "https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_inheritance_auth.html"
	refCTEnroll       = "https://docs.aws.amazon.com/controltower/latest/userguide/enroll-account.html"
	refCTRegisterOU   = "https://docs.aws.amazon.com/controltower/latest/userguide/importing-existing.html"
	refRAMSharing     = "https://docs.aws.amazon.com/ram/latest/userguide/getting-started-sharing.html"
	refAccountFactory = "https://docs.aws.amazon.com/controltower/latest/userguide/account-factory.html"
)

// Input runs a scenario against snapshots.
type Input struct {
	Scenario *Scenario
	Source   *snapshot.Snapshot
	// Destination is nil for a move inside one organization.
	Destination *snapshot.Snapshot
	Version     string
}

// Report is the staged result.
type Report struct {
	Tool          string           `json:"tool"`
	SchemaVersion int              `json:"stages_schema_version"`
	Name          string           `json:"name"`
	Description   string           `json:"description,omitempty"`
	Strategy      string           `json:"strategy"`
	Subject       Subject          `json:"subject"`
	Verdict       evaluator.Status `json:"verdict"`
	Summary       string           `json:"summary"`
	Stages        []StageResult    `json:"stages"`
	// Proposed lists what the scenario adds, so collected and proposed
	// objects are never confused.
	Proposed           ProposedSummary      `json:"proposed"`
	CriticalOperations []CriticalOperation  `json:"critical_operations"`
	Strategies         []StrategyComparison `json:"strategies"`
	Models             []evaluator.ModelRef `json:"models"`
	Limitations        []string             `json:"limitations"`
	Notes              []string             `json:"notes,omitempty"`
}

// Subject names the account and the organizations.
type Subject struct {
	AccountID      string           `json:"account_id"`
	AccountName    string           `json:"account_name"`
	SourceOrg      evaluator.OrgRef `json:"source_org"`
	DestinationOrg evaluator.OrgRef `json:"destination_org"`
	CrossOrg       bool             `json:"cross_org"`
	CurrentPath    []snapshot.Node  `json:"current_path"`
	FinalPath      []snapshot.Node  `json:"final_path"`
}

// StageResult is one stage: the state after it, what changed per layer,
// the evaluation of the transition into it and the stage's own findings.
type StageResult struct {
	Index       int              `json:"index"`
	ID          string           `json:"id"`
	Title       string           `json:"title"`
	Description string           `json:"description,omitempty"`
	Layers      []LayerChange    `json:"layers"`
	State       StateView        `json:"state"`
	Verdict     evaluator.Status `json:"verdict"`
	Summary     string           `json:"summary"`
	// Findings are the scenario layer's own: procedure constraints,
	// declarations, inheritance notes, proposed objects to create.
	Findings []evaluator.Finding `json:"findings"`
	// Transition is the evaluation of moving from the previous state into
	// this one, with every check of the verdict board.
	Transition *evaluator.Result `json:"transition,omitempty"`
	Verify     []string          `json:"verify,omitempty"`
	// Snapshot is the derived snapshot of this state, for the UI. It is
	// never exported: it is a copy with proposed objects added.
	Snapshot *snapshot.Snapshot `json:"-"`
}

// LayerChange says what one layer does at a stage.
type LayerChange struct {
	Layer   string `json:"layer"`
	Changed bool   `json:"changed"`
	Summary string `json:"summary"`
	// Evaluation is set on the workload layer: evaluated,
	// partially-evaluated or not-evaluated, according to the coverage of
	// the account's workload inventory. Detail says what the evaluation
	// found at this stage.
	Evaluation string `json:"evaluation,omitempty"`
	Detail     string `json:"detail,omitempty"`
}

// StateView is the account's position after a stage.
type StateView struct {
	Organization evaluator.OrgRef `json:"organization"`
	Path         []snapshot.Node  `json:"path"`
	ParentID     string           `json:"parent_id"`
	// Enrolled says the state has the account enrolled with Control Tower
	// (collected or proposed); Governed says its parent OU is registered.
	Enrolled bool `json:"enrolled"`
	Governed bool `json:"governed"`
	// Shares names the proposed shares present in this state.
	Shares    []string `json:"proposed_shares_present,omitempty"`
	Relocated bool     `json:"workload_relocated,omitempty"`
	// Proposed marks the nodes on the path that do not exist yet.
	ProposedOnPath []string `json:"proposed_on_path,omitempty"`
}

// ProposedSummary lists the scenario's proposed objects.
type ProposedSummary struct {
	OUs            []ProposedOU `json:"organizational_units"`
	Policies       []PolicyRef  `json:"policies"`
	ResourceShares []string     `json:"resource_shares"`
}

// PolicyRef names a proposed policy.
type PolicyRef struct {
	ID   string              `json:"id"`
	Name string              `json:"name"`
	Type snapshot.PolicyType `json:"type"`
}

// StrategyComparison describes one strategy with its prerequisites, risks,
// unknowns and reversal limits. The lists are built from the staged
// findings where the data exists and from the transfer-procedure model
// otherwise.
type StrategyComparison struct {
	Strategy      string   `json:"strategy"`
	Title         string   `json:"title"`
	Selected      bool     `json:"selected"`
	Prerequisites []string `json:"prerequisites"`
	Risks         []string `json:"risks"`
	Unknowns      []string `json:"unknowns"`
	Reversal      []string `json:"reversal"`
	// Redeploy is set on the recreate strategy: what has to be brought into
	// the new account, grouped by deployment provenance, with counts.
	Redeploy *workload.RedeployPlan `json:"redeploy,omitempty"`
}

// mods are the accumulated proposed changes to one organization.
type mods struct {
	shares     map[string]bool // proposed shares present
	removed    map[string]bool // existing shares withdrawn
	attach     []Attachment
	detach     []Attachment
	registered map[string]bool
	enrolled   *bool
}

func newMods() *mods {
	return &mods{shares: map[string]bool{}, removed: map[string]bool{}, registered: map[string]bool{}}
}

// state is the account's position after a stage.
type state struct {
	org       string
	snap      *snapshot.Snapshot
	parent    string
	relocated bool
}

type runner struct {
	in       Input
	sc       *Scenario
	account  *snapshot.Account
	usage    *snapshot.AccountUsage
	mods     map[string]*mods // per organization side
	crossOrg bool
	// targetOrg is the side proposed objects belong to.
	targetOrg   string
	proposedIDs map[string]bool
}

// Run derives the state after every stage, evaluates each transition and
// compares the strategies.
func Run(in Input) (*Report, error) {
	sc := in.Scenario
	if sc == nil || in.Source == nil {
		return nil, fmt.Errorf("a scenario and a source snapshot are required")
	}
	if err := sc.Validate(); err != nil {
		return nil, err
	}
	srcIx := in.Source.Index()
	acct, ok := srcIx.AccountByID[sc.AccountID]
	if !ok {
		return nil, fmt.Errorf("account %s is not in the source snapshot (%s)", sc.AccountID, in.Source.Organization.ID)
	}
	r := &runner{in: in, sc: sc, account: acct, usage: in.Source.UsageFor(acct.ID), mods: map[string]*mods{OrgSource: newMods(), OrgDestination: newMods()},
		crossOrg: in.Destination != nil && in.Destination.Organization.ID != in.Source.Organization.ID, targetOrg: OrgSource, proposedIDs: map[string]bool{}}
	if r.crossOrg {
		r.targetOrg = OrgDestination
	}
	for _, ou := range sc.Proposed.OUs {
		r.proposedIDs[ou.ID] = true
	}
	for _, p := range sc.Proposed.Policies {
		r.proposedIDs[p.ID] = true
	}
	if err := r.checkReferences(); err != nil {
		return nil, err
	}

	rep := &Report{Tool: "orgshift stages " + in.Version, SchemaVersion: ReportSchemaVersion, Name: sc.Name, Description: sc.Description, Strategy: sc.Strategy,
		CriticalOperations: sc.CriticalOperations, Models: evaluator.Models(), Limitations: evaluator.Limitations(), Verdict: evaluator.StatusGo}
	rep.Subject = Subject{AccountID: acct.ID, AccountName: acct.Name, SourceOrg: evaluator.OrgRef{ID: in.Source.Organization.ID, Name: in.Source.Organization.Name}, CrossOrg: r.crossOrg, CurrentPath: srcIx.PathTo(acct.ID)}
	if r.crossOrg {
		rep.Subject.DestinationOrg = evaluator.OrgRef{ID: in.Destination.Organization.ID, Name: in.Destination.Organization.Name}
	} else {
		rep.Subject.DestinationOrg = rep.Subject.SourceOrg
	}
	rep.Proposed.OUs = append(rep.Proposed.OUs, sc.Proposed.OUs...)
	for _, p := range sc.Proposed.Policies {
		rep.Proposed.Policies = append(rep.Proposed.Policies, PolicyRef{ID: p.ID, Name: p.Name, Type: p.Type})
	}
	for _, sh := range sc.Proposed.ResourceShares {
		rep.Proposed.ResourceShares = append(rep.Proposed.ResourceShares, sh.Name)
	}
	if rep.Proposed.OUs == nil {
		rep.Proposed.OUs = []ProposedOU{}
	}
	if rep.Proposed.Policies == nil {
		rep.Proposed.Policies = []PolicyRef{}
	}
	if rep.Proposed.ResourceShares == nil {
		rep.Proposed.ResourceShares = []string{}
	}
	if rep.CriticalOperations == nil {
		rep.CriticalOperations = []CriticalOperation{}
	}

	// The initial state: the account where the source snapshot has it,
	// with the proposed objects of a same-organization scenario present.
	cur, err := r.derive(OrgSource, acct.ParentID)
	if err != nil {
		return nil, fmt.Errorf("initial state: %w", err)
	}
	for i, st := range sc.Stages {
		next, layers, findings, err := r.apply(cur, st)
		if err != nil {
			return nil, fmt.Errorf("stage %s: %w", st.ID, err)
		}
		res, err := evaluator.Evaluate(evaluator.Input{From: cur.snap, To: next.snap, AccountID: acct.ID, TargetOUID: next.parent, Declared: sc.Declared()})
		if err != nil {
			return nil, fmt.Errorf("stage %s: %w", st.ID, err)
		}
		findings = append(findings, r.inheritanceFindings(next, res)...)
		for li := range layers {
			if layers[li].Layer == LayerWorkload {
				layers[li].Evaluation, layers[li].Detail = workloadLayerNote(res, cur, next, r)
			}
		}
		for i := range findings {
			if findings[i].Confidence == "" {
				switch findings[i].Category {
				case evaluator.CategoryMissingEvidence:
					findings[i].Confidence = evaluator.ConfidenceLow
				case evaluator.CategoryPotentialImpact, evaluator.CategoryUnsupported:
					findings[i].Confidence = evaluator.ConfidenceMedium
				default:
					findings[i].Confidence = evaluator.ConfidenceHigh
				}
			}
		}
		sr := StageResult{Index: i + 1, ID: st.ID, Title: st.Title, Description: st.Description, Layers: layers, Transition: res, Verify: st.Verify, Snapshot: next.snap}
		sr.State = r.stateView(next)
		sr.Findings = findings
		if sr.Findings == nil {
			sr.Findings = []evaluator.Finding{}
		}
		sr.Verdict = res.Verdict
		for _, f := range sr.Findings {
			sr.Verdict = evaluator.Worst(sr.Verdict, f.Status)
		}
		sr.Summary = stageSummary(sr)
		rep.Stages = append(rep.Stages, sr)
		rep.Verdict = evaluator.Worst(rep.Verdict, sr.Verdict)
		cur = next
	}
	rep.Subject.FinalPath = cur.snap.Index().PathTo(acct.ID)
	rep.Strategies = r.compare(rep)
	rep.Summary = reportSummary(rep)
	if r.crossOrg {
		rep.Notes = append(rep.Notes, "A cross-organization migration transfers the account and recreates the OU arrangement around it; an OU is never transferred intact. Proposed OUs and policies in this report are to be created in the destination before the stage that uses them.")
	}
	rep.Notes = append(rep.Notes, "Every stage is evaluated as a move from the previous state into this one with the same checks as a single simulation; the five layers are reported separately so a change in one is never read as a change in another.")
	return rep, nil
}

// checkReferences makes sure every ID the scenario uses exists in the
// snapshots or among the proposed objects.
func (r *runner) checkReferences() error {
	target := r.in.Source
	if r.crossOrg {
		target = r.in.Destination
	}
	tix := target.Index()
	var errs []string
	known := func(ix *snapshot.Index, id string) bool {
		if r.proposedIDs[id] {
			return true
		}
		_, ok := ix.Node(id)
		return ok
	}
	for _, ou := range r.sc.Proposed.OUs {
		if _, exists := tix.Node(ou.ID); exists {
			errs = append(errs, fmt.Sprintf("proposed OU %s already exists in %s", ou.ID, target.Organization.ID))
		}
		if !known(tix, ou.ParentID) {
			errs = append(errs, fmt.Sprintf("proposed OU %s: parent %s is neither in %s nor proposed", ou.ID, ou.ParentID, target.Organization.ID))
		}
		for _, p := range ou.Policies {
			if _, ok := tix.PolicyByID[p]; !ok && !r.proposedIDs[p] {
				errs = append(errs, fmt.Sprintf("proposed OU %s: policy %s is neither in %s nor proposed", ou.ID, p, target.Organization.ID))
			}
		}
	}
	for _, p := range r.sc.Proposed.Policies {
		if _, exists := tix.PolicyByID[p.ID]; exists {
			errs = append(errs, fmt.Sprintf("proposed policy %s already exists in %s", p.ID, target.Organization.ID))
		}
	}
	for _, st := range r.sc.Stages {
		if m := st.Membership; m != nil && m.Organization == OrgDestination && !r.crossOrg {
			errs = append(errs, fmt.Sprintf("stage %s moves to the destination organization but the scenario has no destination snapshot", st.ID))
		}
		if p := st.Placement; p != nil {
			ix := tix
			if m := st.Membership; (m == nil && !r.crossOrg) || (m != nil && m.Organization == OrgSource) {
				ix = r.in.Source.Index()
			}
			if n, ok := ix.Node(p.ParentID); (!ok || n.Kind == snapshot.KindAccount) && !r.proposedIDs[p.ParentID] {
				errs = append(errs, fmt.Sprintf("stage %s: parent %s is not a root or OU of the organization the account is in at that stage, nor a proposed OU", st.ID, p.ParentID))
			}
		}
		if g := st.Governance; g != nil && g.RegisterOU != "" && !known(tix, g.RegisterOU) {
			errs = append(errs, fmt.Sprintf("stage %s: register_ou %s is neither an OU nor proposed", st.ID, g.RegisterOU))
		}
		if pc := st.Policies; pc != nil {
			for _, a := range append(append([]Attachment(nil), pc.Attach...), pc.Detach...) {
				if _, ok := tix.PolicyByID[a.PolicyID]; !ok && !r.proposedIDs[a.PolicyID] {
					errs = append(errs, fmt.Sprintf("stage %s: policy %s is neither in %s nor proposed", st.ID, a.PolicyID, target.Organization.ID))
				}
				if !known(tix, a.TargetID) && a.TargetID != r.account.ID {
					errs = append(errs, fmt.Sprintf("stage %s: attachment target %s is neither in %s nor proposed", st.ID, a.TargetID, target.Organization.ID))
				}
			}
		}
	}
	if len(errs) > 0 {
		sort.Strings(errs)
		return fmt.Errorf("scenario does not match the snapshots:\n  - %s", strings.Join(errs, "\n  - "))
	}
	return nil
}

// copySnapshot deep-copies a snapshot through JSON.
func copySnapshot(s *snapshot.Snapshot) (*snapshot.Snapshot, error) {
	data, err := json.Marshal(s)
	if err != nil {
		return nil, err
	}
	var out snapshot.Snapshot
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, err
	}
	out.UpgradedFrom = s.UpgradedFrom
	return &out, nil
}

// derive builds the snapshot of one organization side with the proposed
// objects and the accumulated modifications applied, and the account
// placed under parent.
func (r *runner) derive(org, parent string) (state, error) {
	base := r.in.Source
	if org == OrgDestination {
		base = r.in.Destination
	}
	snap, err := copySnapshot(base)
	if err != nil {
		return state{}, err
	}
	snap.Source = "scenario"
	m := r.mods[org]
	if org == r.targetOrg {
		r.addProposed(snap, m)
	}
	// Shares the owner withdrew.
	if len(m.removed) > 0 {
		var kept []snapshot.ResourceShare
		for _, sh := range snap.ResourceShares {
			if !m.removed[sh.Name] {
				kept = append(kept, sh)
			}
		}
		snap.ResourceShares = kept
		if snap.ResourceShares == nil {
			snap.ResourceShares = []snapshot.ResourceShare{}
		}
	}
	// The account itself.
	ix := snap.Index()
	if _, present := ix.AccountByID[r.account.ID]; !present {
		a := *r.account
		a.ParentID = parent
		a.Tags = nil // Organizations deletes the account's tags when it leaves
		a.JoinedMethod = "INVITED"
		a.JoinedAt = ""
		a.ARN = ""
		snap.Accounts = append(snap.Accounts, a)
		for i := range snap.Policies {
			if snap.Policies[i].AWSManaged {
				snap.Policies[i].Targets = appendUnique(snap.Policies[i].Targets, a.ID)
			}
		}
		if snap.Usage == nil {
			snap.Usage = map[string]*snapshot.AccountUsage{}
		}
		if r.usage != nil {
			u := *r.usage
			snap.Usage[a.ID] = &u
		}
		// The workload inventory travels with the account, less the stacks
		// a service-managed StackSet deletes when the account leaves; its
		// coverage records travel with it.
		if w, _ := workload.Departed(r.in.Source, a.ID); w != nil {
			if snap.Workloads == nil {
				snap.Workloads = map[string]*snapshot.AccountWorkloads{}
			}
			snap.Workloads[a.ID] = w
		}
		if src := r.in.Source.Coverage; src != nil && snap.Coverage != nil {
			for _, d := range src.Domains {
				if snapshot.IsWorkloadDomain(d.Domain) && (d.AccountID == "" || d.AccountID == a.ID) {
					d.AccountID = a.ID
					snap.Coverage.Domains = append(snap.Coverage.Domains, d)
				}
			}
		}
	} else {
		for i := range snap.Accounts {
			if snap.Accounts[i].ID == r.account.ID {
				snap.Accounts[i].ParentID = parent
			}
		}
	}
	// Attachments.
	for _, a := range m.attach {
		for i := range snap.Policies {
			if snap.Policies[i].ID == a.PolicyID {
				snap.Policies[i].Targets = appendUnique(snap.Policies[i].Targets, a.TargetID)
			}
		}
	}
	for _, a := range m.detach {
		for i := range snap.Policies {
			if snap.Policies[i].ID == a.PolicyID {
				snap.Policies[i].Targets = remove(snap.Policies[i].Targets, a.TargetID)
			}
		}
	}
	// Governance.
	if snap.ControlTower != nil {
		for ou := range m.registered {
			if snap.ControlTower.RegisteredOU(ou) == nil {
				snap.ControlTower.RegisteredOUs = append(snap.ControlTower.RegisteredOUs, snapshot.RegisteredOU{OUID: ou, Status: "PROPOSED"})
			}
		}
		if m.enrolled != nil {
			var kept []snapshot.EnrolledAccount
			for _, e := range snap.ControlTower.EnrolledAccounts {
				if e.AccountID != r.account.ID {
					kept = append(kept, e)
				}
			}
			snap.ControlTower.EnrolledAccounts = kept
			if *m.enrolled {
				e := snapshot.EnrolledAccount{AccountID: r.account.ID, Status: "PROPOSED", Source: snapshot.EnrolledManual}
				if n, ok := ix.Node(parent); ok && n.Kind == snapshot.KindOU {
					e.ParentOUID = parent
				}
				snap.ControlTower.EnrolledAccounts = append(snap.ControlTower.EnrolledAccounts, e)
			}
		}
	}
	if err := snap.Validate(); err != nil {
		return state{}, fmt.Errorf("derived snapshot is not valid: %w", err)
	}
	return state{org: org, snap: snap, parent: parent}, nil
}

// addProposed adds the proposed OUs, policies and the present shares to a
// derived snapshot. Organizations attaches the AWS managed defaults to new
// OUs itself, so the proposed OUs get them too.
func (r *runner) addProposed(snap *snapshot.Snapshot, m *mods) {
	for _, p := range r.sc.Proposed.Policies {
		snap.Policies = append(snap.Policies, snapshot.Policy{ID: p.ID, Name: p.Name, Description: p.Description, Type: p.Type, Document: p.DocumentJSON, Targets: []string{}})
	}
	for _, ou := range r.sc.Proposed.OUs {
		snap.OUs = append(snap.OUs, snapshot.OU{ID: ou.ID, Name: ou.Name, ParentID: ou.ParentID})
		for i := range snap.Policies {
			p := &snap.Policies[i]
			if p.AWSManaged {
				p.Targets = appendUnique(p.Targets, ou.ID)
			}
			for _, id := range ou.Policies {
				if p.ID == id {
					p.Targets = appendUnique(p.Targets, ou.ID)
				}
			}
		}
		if ou.Register && snap.ControlTower != nil {
			m.registered[ou.ID] = true
		}
	}
	for _, sh := range r.sc.Proposed.ResourceShares {
		if !m.shares[sh.Name] {
			continue
		}
		s := snapshot.ResourceShare{ARN: "arn:aws:ram::" + sh.OwnerAccountID + ":resource-share/proposed-" + sh.Name, Name: sh.Name, OwnerAccountID: sh.OwnerAccountID, Status: "PROPOSED",
			AllowExternalPrincipals: sh.AllowExternalPrincipals, RetainSharingOnAccountLeave: sh.RetainOnLeave, Principals: append([]string(nil), sh.Principals...), Resources: []snapshot.SharedResource{}}
		for _, res := range sh.Resources {
			s.Resources = append(s.Resources, snapshot.SharedResource{ARN: res.ARN, Type: res.Type})
		}
		snap.ResourceShares = append(snap.ResourceShares, s)
	}
}

// apply computes the state after a stage and the layer changes.
func (r *runner) apply(prev state, st Stage) (state, []LayerChange, []evaluator.Finding, error) {
	org, parent := prev.org, prev.parent
	var findings []evaluator.Finding
	layers := map[string]*LayerChange{}
	for _, l := range Layers {
		layers[l] = &LayerChange{Layer: l, Summary: "unchanged"}
	}
	note := func(layer, summary string) {
		layers[layer].Changed = true
		layers[layer].Summary = summary
	}
	changedOrg := false
	if m := st.Membership; m != nil && m.Organization != org {
		changedOrg = true
		org = m.Organization
		var base *snapshot.Snapshot
		if org == OrgDestination {
			base = r.in.Destination
		} else {
			base = r.in.Source
		}
		parent = base.Root.ID
		if st.Placement == nil {
			note(LayerPlacement, "lands at the root of "+base.Organization.ID+" (no placement given)")
		}
		note(LayerMembership, fmt.Sprintf("joins organization %s (%s)", base.Organization.ID, orgLabel(base)))
		findings = append(findings, r.membershipFindings(org, base)...)
	}
	target := r.mods[org]
	if p := st.Placement; p != nil {
		parent = p.ParentID
		label := parent
		if r.proposedIDs[parent] {
			label += " (proposed)"
		}
		note(LayerPlacement, "placed under "+label)
	}
	if pc := st.Policies; pc != nil {
		target.attach = append(target.attach, pc.Attach...)
		target.detach = append(target.detach, pc.Detach...)
		var parts []string
		for _, a := range pc.Attach {
			parts = append(parts, "attach "+a.PolicyID+" to "+a.TargetID)
		}
		for _, a := range pc.Detach {
			parts = append(parts, "detach "+a.PolicyID+" from "+a.TargetID)
		}
		summary := strings.Join(parts, "; ")
		if layers[LayerPlacement].Changed {
			summary = layers[LayerPlacement].Summary + "; " + summary
		}
		note(LayerPlacement, summary)
	}
	if g := st.Governance; g != nil {
		var parts []string
		if g.RegisterOU != "" {
			target.registered[g.RegisterOU] = true
			parts = append(parts, "register OU "+g.RegisterOU)
		}
		if g.Enrolled != nil {
			e := *g.Enrolled
			target.enrolled = &e
			if e {
				parts = append(parts, "enroll the account")
			} else {
				parts = append(parts, "unenroll the account")
			}
		}
		if len(parts) > 0 {
			note(LayerGovernance, strings.Join(parts, "; "))
		}
	}
	if n := st.Network; n != nil {
		var parts []string
		for _, name := range n.RecreateShares {
			r.mods[r.targetOrg].shares[name] = true
			parts = append(parts, "re-create share "+name)
		}
		for _, name := range n.RemoveShares {
			target.removed[name] = true
			parts = append(parts, "withdraw share "+name)
		}
		if n.Validated {
			parts = append(parts, "network validation point")
		}
		if n.Note != "" {
			parts = append(parts, n.Note)
		}
		if len(parts) > 0 {
			note(LayerNetwork, strings.Join(parts, "; "))
		}
		findings = append(findings, r.networkFindings(st, org)...)
	}
	relocated := prev.relocated
	if w := st.Workload; w != nil && w.Relocate {
		relocated = true
		summary := "workloads relocate"
		if w.TargetAccountID != "" {
			summary += " to account " + w.TargetAccountID
		}
		if w.Note != "" {
			summary += ": " + w.Note
		}
		note(LayerWorkload, summary)
		findings = append(findings, relocationFinding(workload.Build(prev.snap, r.account.ID), w))
	}
	next, err := r.derive(org, parent)
	if err != nil {
		return state{}, nil, nil, err
	}
	next.relocated = relocated
	if g := st.Governance; g != nil {
		findings = append(findings, r.governanceFindings(st, next)...)
	}
	anyChange := false
	for _, l := range Layers {
		if layers[l].Changed {
			anyChange = true
		}
	}
	if !anyChange {
		findings = append(findings, evaluator.Finding{Status: evaluator.StatusInfo, Category: evaluator.CategoryInformational, Title: "Verification point: nothing changes in the five layers",
			Detail: "Membership, placement, governance, network and workload are as in the previous stage. The transition below compares the state with itself and inventories what applies to the account there; the checks listed under verify are the operator's."})
	}
	if changedOrg && st.Placement == nil {
		findings = append(findings, evaluator.Finding{Status: evaluator.StatusInfo, Category: evaluator.CategoryInformational, Title: "The account lands at the root until it is placed",
			Detail: "An invited account that accepts joins at the root of the organization. Only the policies attached to the root apply there; the stage that places it into an OU adds that OU's chain."})
	}
	var out []LayerChange
	for _, l := range Layers {
		out = append(out, *layers[l])
	}
	return next, out, findings, nil
}

func orgLabel(s *snapshot.Snapshot) string {
	if s.Organization.Name != "" {
		return s.Organization.Name
	}
	return s.Organization.ID
}

// membershipFindings describe the standalone window and the invitation.
func (r *runner) membershipFindings(org string, base *snapshot.Snapshot) []evaluator.Finding {
	if org != OrgDestination {
		return []evaluator.Finding{{Status: evaluator.StatusInfo, Category: evaluator.CategoryInformational, Title: "The account returns to the source organization",
			Detail: "Returning means leaving the destination (standalone-account information again) and accepting a new invitation from the source management account; the tags, assignments and shares it had in the destination are lost the same way.", References: []string{refRemoveAccount, refInvitations}}}
	}
	return []evaluator.Finding{{Status: evaluator.StatusInfo, Category: evaluator.CategoryInformational, Title: "Between leaving the source and accepting the invitation the account is standalone",
		Detail: fmt.Sprintf("An account belongs to one organization at a time, so it leaves %s before it accepts the invitation from %s (valid 15 days). In between no SCP, RCP, tag or backup policy applies, the account pays its own bill, organization shares and Identity Center access are gone and the former management account's role in it is still there. Keep the window short and do not run changes during it. On acceptance the policies attached to the destination root (and the OU it lands in) apply at once, the destination's organization trail covers it, and Config, GuardDuty or Security Hub may enable automatically for new members.",
			r.in.Source.Organization.ID, base.Organization.ManagementAccountID),
		References: []string{refRemoveAccount, refInvitations}}}
}

// networkFindings describe re-created and withdrawn shares and the
// validation point.
func (r *runner) networkFindings(st Stage, org string) []evaluator.Finding {
	var out []evaluator.Finding
	n := st.Network
	for _, name := range n.RecreateShares {
		for _, sh := range r.sc.Proposed.ResourceShares {
			if sh.Name != name {
				continue
			}
			var types []string
			for _, res := range sh.Resources {
				types = append(types, res.Type)
			}
			out = append(out, evaluator.Finding{Status: evaluator.StatusInfo, Category: evaluator.CategoryInformational, Title: "Share " + name + " is created in the destination at this stage",
				Detail: fmt.Sprintf("Owner %s shares %s with %s. From this stage the evaluation treats the share as existing; the owner has to create it (aws ram create-resource-share) and, for an account principal outside its organization, allow external principals. Attachments and associations on the account side are made by hand after the account can see the share.",
					sh.OwnerAccountID, strings.Join(types, ", "), strings.Join(sh.Principals, ", ")),
				References: []string{refRAMSharing}})
		}
	}
	for _, name := range n.RemoveShares {
		out = append(out, evaluator.Finding{Status: evaluator.StatusInfo, Category: evaluator.CategoryInformational, Title: "Share " + name + " is withdrawn by its owner at this stage",
			Detail: "From this stage the share no longer exists in the derived state; the RAM check of the transition reports what its loss means for the account.", References: []string{refRAMSharing}})
	}
	if n.Validated {
		category, status := evaluator.CategoryInformational, evaluator.StatusInfo
		detail := "The operator validates network, identity, logging and shared-service connectivity at this stage. orgshift evaluates control-plane state (shares, policies, trusted access, Identity Center) and does not test data paths or runtime behaviour; the checks declared under verify are to be run by hand and their results recorded outside the snapshots."
		if len(st.Verify) == 0 {
			category, status = evaluator.CategoryMissingEvidence, evaluator.StatusReview
			detail += " No verification steps are declared for this stage; list them under verify so the plan says what is checked."
		}
		out = append(out, evaluator.Finding{Status: status, Category: category, Title: "Network and shared-service validation point", Detail: detail})
	}
	return out
}

// governanceFindings check the enrollment declarations against the
// procedure model.
func (r *runner) governanceFindings(st Stage, next state) []evaluator.Finding {
	g := st.Governance
	var out []evaluator.Finding
	ct := next.snap.ControlTower
	if g.RegisterOU != "" {
		if ct == nil {
			out = append(out, evaluator.Finding{Status: evaluator.StatusNoGo, Category: evaluator.CategoryDeclaredImpact, Title: "No Control Tower landing zone to register OU " + g.RegisterOU + " with",
				Detail: "The organization the account is in at this stage has no landing zone in its snapshot, so the OU cannot be registered and the account cannot be enrolled.", References: []string{refCTRegisterOU}})
		} else {
			out = append(out, evaluator.Finding{Status: evaluator.StatusInfo, Category: evaluator.CategoryInformational, Title: "OU " + g.RegisterOU + " is registered with Control Tower at this stage",
				Detail: "Registering an OU (Extend governance) deploys the landing zone baseline to it and enrolls the accounts already in it; every account in the OU must meet the enrollment prerequisites or the registration reports them as failed. The derived state marks the OU registered with no controls of its own beyond the mandatory baseline; elective controls are enabled afterwards.", References: []string{refCTRegisterOU}})
		}
	}
	if g.Enrolled == nil {
		return out
	}
	if !*g.Enrolled {
		out = append(out, evaluator.Finding{Status: evaluator.StatusInfo, Category: evaluator.CategoryInformational, Title: "The account is unenrolled from Control Tower at this stage",
			Detail: "Unenrolling (Unmanage in Account Factory) removes the resources Control Tower provisioned, including the AWSControlTowerExecution role and the baseline stacks, and moves the account to the root of the landing zone's organization. The transition reports the controls that stop applying.", References: []string{refCTEnroll}})
		return out
	}
	if ct == nil {
		out = append(out, evaluator.Finding{Status: evaluator.StatusNoGo, Category: evaluator.CategoryDeclaredImpact, Title: "Enrollment declared but the organization has no Control Tower landing zone",
			Detail: "The snapshot of the organization the account is in at this stage records no landing zone, so there is nothing to enroll into.", References: []string{refCTEnroll}})
		return out
	}
	ix := next.snap.Index()
	parentNode, _ := ix.Node(next.parent)
	registered := parentNode.Kind == snapshot.KindOU && ct.RegisteredOU(next.parent) != nil
	if !registered {
		out = append(out, evaluator.Finding{Status: evaluator.StatusNoGo, Category: evaluator.CategoryDeclaredImpact, Title: fmt.Sprintf("Enrollment declared while %s (%s) is not a registered OU", parentNode.Name, next.parent),
			Detail: "Control Tower enrolls an account into an OU that is already governed (registered); the root is never governed. Register the OU first (governance.register_ou) or place the account into a registered OU at this stage.", References: []string{refCTEnroll}})
	}
	declared := func(v *bool, what string) (string, evaluator.Status) {
		switch {
		case v == nil:
			return what + ": not declared (unknown)", evaluator.StatusReview
		case *v:
			return what + ": declared satisfied", evaluator.StatusInfo
		default:
			return what + ": declared NOT satisfied", evaluator.StatusNoGo
		}
	}
	roleText, roleStatus := declared(g.ExecutionRolePresent, "AWSControlTowerExecution role trusting management account "+next.snap.Organization.ManagementAccountID)
	configText, configStatus := declared(g.ConfigResourcesRemoved, "no AWS Config recorder or delivery channel of the account's own in the governed regions ("+strings.Join(ct.GovernedRegions, ", ")+")")
	status := evaluator.Worst(roleStatus, configStatus)
	if status == evaluator.StatusGo {
		status = evaluator.StatusInfo
	}
	category := evaluator.CategoryPotentialImpact
	switch status {
	case evaluator.StatusNoGo:
		category = evaluator.CategoryDeclaredImpact
	case evaluator.StatusInfo:
		category = evaluator.CategoryInformational
	}
	out = append(out, evaluator.Finding{Status: status, Category: category, Title: "Enrollment prerequisites at this stage",
		Detail:     fmt.Sprintf("Enrolling deploys the baseline StackSets (CloudTrail, CloudWatch, Config, roles), enables AWS Config to record every resource, adds the detective Config rules and applies the OU's SCPs; existing VPCs are left alone. Prerequisites the collector cannot see and the operator declares in the scenario: %s; %s. An account-level CloudTrail trail duplicates the organization trail's charges once enrolled. Transfer procedure model %s.", roleText, configText, evaluator.TransferModelVersion),
		References: []string{refCTEnroll}})
	return out
}

// inheritanceFindings explain what a proposed OU inherits from above it
// and that an inherited explicit deny cannot be overridden.
func (r *runner) inheritanceFindings(next state, res *evaluator.Result) []evaluator.Finding {
	if !r.proposedIDs[next.parent] {
		return nil
	}
	var out []evaluator.Finding
	ix := next.snap.Index()
	parent, _ := ix.Node(next.parent)
	for _, d := range res.Diff {
		if d.Type != string(snapshot.PolicyTypeSCP) || !d.EnabledTarget {
			continue
		}
		var inherited, denies []string
		for _, l := range d.TargetChain {
			if l.Node.ID == next.parent || l.Node.Kind == snapshot.KindAccount {
				continue
			}
			for _, p := range l.Policies {
				inherited = append(inherited, fmt.Sprintf("%s (at %s)", p.Name, l.Node.Name))
				for _, st := range p.Statements {
					if strings.EqualFold(st.Effect, "Deny") {
						denies = append(denies, p.Name+" / "+orSid(st.Sid))
						break
					}
				}
			}
		}
		registered := "unregistered"
		if ct := next.snap.ControlTower; ct != nil && ct.RegisteredOU(next.parent) != nil {
			registered = "registered"
		}
		detail := fmt.Sprintf("The %s OU %s (%s) does not exist yet; create it under %s before this stage. Organizations attaches the AWS managed defaults to a new OU; the scenario's own attachments are listed in the SCP diff. The OU inherits every policy attached above it: %s. %d of them carry an explicit Deny (%s); nothing attached to the OU or the account can override an inherited explicit deny, and an allow in a child only matters where every level above allows too.",
			registered, parent.Name, parent.ID, parentPathLabel(ix, next.parent), orNone(strings.Join(inherited, ", ")), len(denies), orNone(strings.Join(denies, "; ")))
		out = append(out, evaluator.Finding{Status: evaluator.StatusInfo, Category: evaluator.CategoryKnownRestriction, Title: fmt.Sprintf("Proposed OU %s inherits %d policy attachment(s) from above", parent.Name, len(inherited)),
			Detail: detail, References: []string{refInheritance}})
	}
	return out
}

func orSid(s string) string {
	if s == "" {
		return "(no Sid)"
	}
	return s
}

func orNone(s string) string {
	if s == "" {
		return "none"
	}
	return s
}

func parentPathLabel(ix *snapshot.Index, id string) string {
	path := ix.PathTo(id)
	if len(path) < 2 {
		return "the root"
	}
	return snapshot.PathString(path[:len(path)-1])
}

func (r *runner) stateView(s state) StateView {
	ix := s.snap.Index()
	v := StateView{Organization: evaluator.OrgRef{ID: s.snap.Organization.ID, Name: s.snap.Organization.Name}, Path: ix.PathTo(r.account.ID), ParentID: s.parent, Relocated: s.relocated}
	if ct := s.snap.ControlTower; ct != nil {
		v.Enrolled = ct.Enrolled(r.account.ID) != nil
		v.Governed = ct.RegisteredOU(s.parent) != nil
	}
	for _, sh := range r.sc.Proposed.ResourceShares {
		// Shares created so far, wherever the account is at this stage.
		if r.mods[r.targetOrg].shares[sh.Name] || r.mods[s.org].shares[sh.Name] {
			v.Shares = appendUnique(v.Shares, sh.Name)
		}
	}
	for _, n := range v.Path {
		if r.proposedIDs[n.ID] {
			v.ProposedOnPath = append(v.ProposedOnPath, n.ID)
		}
	}
	return v
}

func stageSummary(sr StageResult) string {
	var changed []string
	for _, l := range sr.Layers {
		if l.Changed {
			changed = append(changed, l.Layer)
		}
	}
	noGo, review := 0, 0
	for _, f := range sr.Findings {
		switch f.Status {
		case evaluator.StatusNoGo:
			noGo++
		case evaluator.StatusReview:
			review++
		}
	}
	if sr.Transition != nil {
		for _, c := range sr.Transition.Checks {
			for _, f := range c.Findings {
				switch f.Status {
				case evaluator.StatusNoGo:
					noGo++
				case evaluator.StatusReview:
					review++
				}
			}
		}
	}
	layers := "no layer changes"
	if len(changed) > 0 {
		layers = "changes: " + strings.Join(changed, ", ")
	}
	return fmt.Sprintf("%s; %s; %d blocking, %d to review", sr.Verdict, layers, noGo, review)
}

func reportSummary(rep *Report) string {
	worst := ""
	for _, st := range rep.Stages {
		if st.Verdict == rep.Verdict && worst == "" {
			worst = st.Title
		}
	}
	path := snapshot.PathString(rep.Subject.CurrentPath[:len(rep.Subject.CurrentPath)-1]) + " to " + snapshot.PathString(rep.Subject.FinalPath[:len(rep.Subject.FinalPath)-1])
	switch rep.Verdict {
	case evaluator.StatusNoGo:
		return fmt.Sprintf("%s: NO-GO across %d stages (%s); the first blocking stage is %q. Blockers are listed per stage with the layer they belong to.", path, len(rep.Stages), rep.Strategy, worst)
	case evaluator.StatusReview:
		return fmt.Sprintf("%s: REVIEW across %d stages (%s); no stage blocks the plan outright, the first stage needing decisions is %q.", path, len(rep.Stages), rep.Strategy, worst)
	}
	return fmt.Sprintf("%s: GO within the assessed scope across %d stages (%s). Every transition was evaluated with the same checks as a single move; this is not a guarantee of zero downtime, and declared verification steps are the operator's to run.", path, len(rep.Stages), rep.Strategy)
}

// compare builds the two strategies from the staged findings and the
// procedure model.
func (r *runner) compare(rep *Report) []StrategyComparison {
	var entry *StageResult
	for i := range rep.Stages {
		for _, l := range rep.Stages[i].Layers {
			if l.Layer == LayerMembership && l.Changed {
				entry = &rep.Stages[i]
				break
			}
		}
		if entry != nil {
			break
		}
	}
	titles := func(st *StageResult, checks map[string]bool, statuses ...evaluator.Status) []string {
		var out []string
		seen := map[string]bool{}
		if st == nil || st.Transition == nil {
			return out
		}
		for _, c := range st.Transition.Checks {
			if !checks[c.ID] {
				continue
			}
			for _, f := range c.Findings {
				for _, s := range statuses {
					if f.Status == s && !seen[f.Title] {
						seen[f.Title] = true
						out = append(out, f.Title)
					}
				}
			}
		}
		return out
	}
	count := func(category string) int {
		n := 0
		for _, st := range rep.Stages {
			for _, f := range st.Findings {
				if f.Category == category {
					n++
				}
			}
			if st.Transition != nil {
				n += st.Transition.Categories[category]
			}
		}
		return n
	}
	transfer := StrategyComparison{Strategy: StrategyTransfer, Title: "Transfer the account into the destination organization", Selected: rep.Strategy == StrategyTransfer}
	transfer.Prerequisites = titles(entry, map[string]bool{"org-services": true, "control-tower": true}, evaluator.StatusNoGo, evaluator.StatusReview)
	if len(transfer.Prerequisites) == 0 {
		transfer.Prerequisites = []string{"Standalone-account information, a destination invitation and no delegated-administrator role (transfer procedure model " + evaluator.TransferModelVersion + ")"}
	}
	transfer.Risks = titles(entry, map[string]bool{"scp": true, "rcp": true, "ram": true, "identity-center": true, "tags": true, "workloads": true}, evaluator.StatusNoGo, evaluator.StatusReview)
	if len(transfer.Risks) == 0 {
		transfer.Risks = []string{"No policy, share or identity impact was found at the entry stage within the assessed scope"}
	}
	transfer.Unknowns = []string{
		fmt.Sprintf("%d finding(s) need context the snapshots do not carry (potential impact) and %d rest on missing evidence across the stages", count(evaluator.CategoryPotentialImpact), count(evaluator.CategoryMissingEvidence)),
		fmt.Sprintf("%d evaluation(s) are outside what the offline evaluator models", count(evaluator.CategoryUnsupported)),
		"Data-plane continuity of shared networking is modelled per resource type, not tested",
	}
	transfer.Reversal = []string{
		"Moving back is another transfer: the account needs the standalone-account information again, a new invitation from the source, and loses the destination's tags, assignments and shares on the way out",
		"Control Tower unenrollment removes the baseline resources from the account and cannot be partially undone; re-enrollment redeploys them",
		"Organization policies deleted or detached in the source during the move are not restored by the account's return",
		"Invited accounts are not subject to the four-day rule, so the return itself is not delayed by it",
	}

	recreate := StrategyComparison{Strategy: StrategyRecreate, Title: "Create destination accounts and migrate the workloads", Selected: rep.Strategy == StrategyRecreate}
	assignments, inbound := 0, 0
	if ic := r.in.Source.IdentityCenter; ic != nil {
		assignments = len(ic.AssignmentsFor(r.account.ID))
	}
	if r.usage != nil {
		inbound = len(r.usage.InboundAccess)
	}
	recreate.Prerequisites = []string{
		"Create the destination account with Account Factory in the target OU (enrolled and baselined from creation; no transfer prerequisites, no standalone window)",
		fmt.Sprintf("Re-create access: %d Identity Center assignment(s) on the source account have to be granted in the destination instance", assignments),
		fmt.Sprintf("Re-point %d inbound principal(s) and every resource policy, trust policy and share principal that names account %s at the new account ID", inbound, r.account.ID),
		"A migration plan per workload: data, secrets, DNS and endpoint cutover",
	}
	recreate.Risks = []string{
		"The account ID changes: ARNs, resource policies, cross-account trusts, RAM principals and hard-coded identifiers in deployments all change",
		"Dual running: two accounts bill and have to be kept consistent until cutover",
		"Cutover of DNS, endpoints and data has its own downtime, outside what orgshift evaluates",
	}
	plan := workload.Build(r.in.Source, r.account.ID).Redeploy()
	recreate.Redeploy = plan
	for _, g := range plan.Groups {
		if g.Stacks+g.SampledResources == 0 {
			continue
		}
		verb := "Redeploy from templates or pipelines"
		switch g.Group {
		case workload.GroupPlatform:
			verb = "Have the destination's Control Tower and StackSets recreate"
		case workload.GroupManual:
			verb = "Rebuild by hand, once it is known how they were made"
		}
		line := fmt.Sprintf("%s: %s", verb, g.Line())
		if names := g.StackNames(); len(names) > 0 {
			line += " (" + strings.Join(names, ", ") + ")"
		}
		recreate.Prerequisites = append(recreate.Prerequisites, line)
	}
	recreate.Risks = append(recreate.Risks, plan.Dependencies...)
	recreate.Unknowns = append([]string{fmt.Sprintf("Workload layer %s for account %s; the redeployment list is an inventory with counts, not an estimate of effort", plan.Evaluation, r.account.ID)}, plan.Unknowns...)
	recreate.Reversal = []string{
		"The source account is untouched until it is closed: rollback is a cutover back",
		"An abandoned destination account is closed and stays in the 90-day post-closure period before it disappears",
		"No four-day rule and no standalone-account prerequisites apply",
	}
	return []StrategyComparison{transfer, recreate}
}

// relocationFinding says what a declared workload relocation has to bring
// into the other account, from the inventory of the account as it is at
// that stage.
func relocationFinding(inv *workload.Inventory, w *Workload) evaluator.Finding {
	if !inv.Collected {
		return evaluator.Finding{Status: evaluator.StatusReview, Category: evaluator.CategoryMissingEvidence, Title: "Workload relocation is declared, not evaluated: no workload inventory for the account",
			Detail:     "The stage moves workloads to another account, and the snapshot holds no stacks, resource sample or resource policies for this one, so what has to be redeployed is unknown. Name the account under member_inspection.accounts and collect again; `orgshift workloads` then lists the inventory and how each item was deployed.",
			References: []string{refAccountFactory}}
	}
	plan := inv.Redeploy()
	var parts, counts []string
	unknown := 0
	for _, g := range plan.Groups {
		if g.Stacks+g.SampledResources == 0 {
			continue
		}
		counts = append(counts, fmt.Sprintf("%s: %s", g.Title, g.Line()))
		parts = append(parts, fmt.Sprintf("%s (%s): %s.", strings.ToUpper(g.Title[:1])+g.Title[1:], g.Line(), strings.Join(g.Names(), ", ")))
		if g.Group == workload.GroupManual {
			unknown = g.Stacks + g.SampledResources
		}
	}
	f := evaluator.Finding{Status: evaluator.StatusReview, Category: evaluator.CategoryPotentialImpact, Confidence: evaluator.ConfidenceHigh, Source: evaluator.SourceWorkload,
		Title:      fmt.Sprintf("Workload relocation: %d stack(s) and %d sampled resource(s) outside stacks to bring into the other account, %d of unknown provenance", len(inv.Stacks), outsideStacks(plan), unknown),
		References: []string{refAccountFactory}}
	if len(counts) == 0 {
		f.Status, f.Category = evaluator.StatusInfo, evaluator.CategoryInformational
		f.Title = "Workload relocation: the inventory of the account is empty"
		f.Detail = "The snapshot records no stacks and no sampled resources for the account, so nothing is listed to redeploy. " + strings.Join(plan.Unknowns, " ")
		return f
	}
	if plan.Evaluation != workload.Evaluated {
		f.Confidence = evaluator.ConfidenceMedium
	}
	target := "the other account"
	if w != nil && w.TargetAccountID != "" {
		target = "account " + w.TargetAccountID
	}
	f.Detail = fmt.Sprintf("The stage moves the workloads to %s. From the inventory of the account (workload layer %s): %s", target, plan.Evaluation, strings.Join(parts, " "))
	if len(plan.Dependencies) > 0 {
		f.Detail += " What constrains the redeployment: " + strings.Join(plan.Dependencies, " ")
	}
	f.Detail += " Not known: " + strings.Join(plan.Unknowns, " ")
	return f
}

func outsideStacks(plan *workload.RedeployPlan) int {
	n := 0
	for _, g := range plan.Groups {
		n += g.SampledResources
	}
	return n
}

// workloadLayerNote reads the workload layer of a transition: how much of
// it was evaluated and what the workloads check found at this stage.
func workloadLayerNote(res *evaluator.Result, cur, next state, r *runner) (evaluation, detail string) {
	wl := res.WorkloadLayer
	if wl == nil {
		return workload.NotEvaluated, ""
	}
	settle, info := 0, 0
	for _, c := range res.Checks {
		if c.ID != "workloads" {
			continue
		}
		for _, f := range c.Findings {
			switch f.Status {
			case evaluator.StatusNoGo, evaluator.StatusReview:
				settle++
			case evaluator.StatusInfo:
				info++
			}
		}
	}
	detail = wl.Detail
	if wl.Evaluation != workload.NotEvaluated {
		detail = fmt.Sprintf("%s; at this stage %d item(s) to settle and %d informational in the workloads check", wl.Detail, settle, info)
	}
	if cur.org != next.org && next.org == OrgDestination {
		if _, deleted := workload.Departed(r.in.Source, r.account.ID); len(deleted) > 0 {
			detail += fmt.Sprintf("; %d stack(s) are deleted by their StackSet on leaving and are not in the inventory of the later stages (%s)", len(deleted), strings.Join(deleted, ", "))
		}
	}
	return wl.Evaluation, detail
}

func appendUnique(list []string, s string) []string {
	for _, x := range list {
		if x == s {
			return list
		}
	}
	return append(list, s)
}

func remove(list []string, s string) []string {
	var out []string
	for _, x := range list {
		if x != s {
			out = append(out, x)
		}
	}
	if out == nil {
		out = []string{}
	}
	return out
}
