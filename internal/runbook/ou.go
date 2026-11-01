package runbook

import (
	"fmt"
	"strings"

	"github.com/MrShaaba/orgshift/internal/evaluator"
	"github.com/MrShaaba/orgshift/internal/snapshot"
)

// OURunbook is the checklist for moving a whole OU: the steps that belong
// to the OU tree (Organizations never moves an OU, so it is recreated and
// the accounts are moved one by one) followed by one runbook per account.
type OURunbook struct {
	Tool          string              `json:"tool"`
	SchemaVersion int                 `json:"runbook_schema_version"`
	Subject       evaluator.OUSubject `json:"subject"`
	Verdict       evaluator.Status    `json:"verdict"`
	Summary       string              `json:"summary"`
	Phases        []Phase             `json:"phases"`
	Accounts      []*Runbook          `json:"accounts"`
	Notes         []string            `json:"notes,omitempty"`
}

// Steps returns every OU-level step in order.
func (rb *OURunbook) Steps() []Step {
	var out []Step
	for _, p := range rb.Phases {
		out = append(out, p.Steps...)
	}
	return out
}

// Phase returns the OU-level phase with the given ID, or nil.
func (rb *OURunbook) Phase(id string) *Phase {
	for i := range rb.Phases {
		if rb.Phases[i].ID == id {
			return &rb.Phases[i]
		}
	}
	return nil
}

// BuildOU turns an OU result into a runbook. from is required for the OU
// tree and the policy documents; to may be nil for a move inside one
// organization.
func BuildOU(res *evaluator.OUResult, from, to *snapshot.Snapshot) *OURunbook {
	if to == nil {
		to = from
	}
	s := res.Subject
	cross := s.CrossOrg
	ob := &ouBuilder{res: res, from: from, to: to, cross: cross, phases: map[string]*Phase{}}
	ob.srcMgmt = mgmtWhere(from, s.SourceOrg)
	ob.dstMgmt = mgmtWhere(to, s.TargetOrg)
	for _, id := range phaseOrder {
		title, intro := ob.phaseText(id)
		ob.phases[id] = &Phase{ID: id, Title: title, Intro: intro, Steps: []Step{}}
	}
	ob.collectTree()
	ob.beforeSteps()
	ob.recreateSteps()
	ob.moveSteps()
	ob.afterSteps()
	ob.rollbackSteps()

	rb := &OURunbook{Tool: "orgshift", SchemaVersion: SchemaVersion, Subject: s, Verdict: res.Verdict}
	for _, id := range phaseOrder {
		p := ob.phases[id]
		for i := range p.Steps {
			p.Steps[i].ID = fmt.Sprintf("ou-%s-%d", id, i+1)
		}
		rb.Phases = append(rb.Phases, *p)
	}
	for _, a := range res.Accounts {
		rb.Accounts = append(rb.Accounts, build(a.Result, from, to, s.OUName))
	}
	rb.Notes = append(rb.Notes, "Generated from a snapshot simulation. Every command is for an operator to review and run by hand; orgshift never writes to AWS.")
	rb.Notes = append(rb.Notes, "Organizations has no call that moves an OU. The OU tree is created again under the new parent, the policies are attached to the new OUs and the accounts are moved one by one; new OU IDs are placeholders in angle brackets until they exist.")
	rb.Notes = append(rb.Notes, res.Notes...)
	counts := map[evaluator.Status]int{}
	for _, a := range rb.Accounts {
		counts[a.Verdict]++
	}
	rb.Summary = fmt.Sprintf("%d OU-level steps and %d account runbook(s): %d NO-GO, %d REVIEW, %d GO. Clear every account's blockers before the OU tree is recreated.",
		len(rb.Steps()), len(rb.Accounts), counts[evaluator.StatusNoGo], counts[evaluator.StatusReview], counts[evaluator.StatusGo])
	return rb
}

type ouBuilder struct {
	res      *evaluator.OUResult
	from, to *snapshot.Snapshot
	cross    bool
	phases   map[string]*Phase
	srcMgmt  string
	dstMgmt  string
	// ous is the moved tree, parent before child; parentOf maps each OU to
	// its parent inside the tree (or "" for the moved OU itself).
	ous      []*snapshot.OU
	parentOf map[string]string
	accounts []*snapshot.Account
	// attachments by OU, customer-managed only; guardrails separately.
	attached   map[string][]evaluator.OUAttachment
	guardrails map[string]bool
	policies   []evaluator.OUAttachment // unique customer-managed policies (cross-org)
	registered []string                 // names of registered OUs in the tree
}

func (ob *ouBuilder) phaseText(id string) (title, intro string) {
	switch id {
	case PhaseBefore:
		return "Before the move: the OU tree", "What has to be settled for the OUs themselves. Every account's own blockers are in its runbook below and have to be cleared first."
	case PhaseRecreate:
		return "Before the move: create the new OU tree", "Organizations cannot move an OU, so the tree is built again under the new parent with the same attachments before any account moves."
	case PhaseMove:
		if ob.cross {
			return "The move", "Each account leaves on its own and joins the target organization; its runbook has the exact sequence. Once it has accepted the invitation, move it into its new OU."
		}
		return "The move", "Move the accounts one by one into the new OUs. Each account's runbook lists what changes for it."
	case PhaseAfter:
		return "After the move: checks", "Confirm the tree, register it where Control Tower is involved and remove what is left behind."
	}
	return "Rollback", "Puts the OU tree back where it was. Built from the source attachments of the simulation."
}

func (ob *ouBuilder) add(phase string, s Step) {
	p := ob.phases[phase]
	p.Steps = append(p.Steps, s)
}

func (ob *ouBuilder) collectTree() {
	ob.parentOf = map[string]string{}
	ob.attached = map[string][]evaluator.OUAttachment{}
	ob.guardrails = map[string]bool{}
	if ob.from == nil {
		return
	}
	ix := ob.from.Index()
	var walk func(ou *snapshot.OU, parent string)
	walk = func(ou *snapshot.OU, parent string) {
		ob.ous = append(ob.ous, ou)
		ob.parentOf[ou.ID] = parent
		ob.accounts = append(ob.accounts, ix.AccountsIn(ou.ID)...)
		for _, child := range ix.ChildOUs(ou.ID) {
			walk(child, ou.ID)
		}
	}
	if root := ix.OUByID[ob.res.Subject.OUID]; root != nil {
		walk(root, "")
	}
	seen := map[string]bool{}
	for _, at := range ob.res.Attachments {
		switch {
		case at.ControlTowerManaged:
			ob.guardrails[at.OUID] = true
		case at.AWSManaged:
		default:
			ob.attached[at.OUID] = append(ob.attached[at.OUID], at)
			if !seen[at.PolicyID] {
				seen[at.PolicyID] = true
				ob.policies = append(ob.policies, at)
			}
		}
	}
	for _, f := range ob.res.Findings {
		if strings.Contains(f.Title, "registered OU(s) in the moved tree") {
			if i := strings.LastIndex(f.Title, ": "); i >= 0 {
				ob.registered = strings.Split(f.Title[i+2:], ", ")
			}
		}
	}
}

// newID is the placeholder for an OU that does not exist yet.
func newID(ou *snapshot.OU) string { return fmt.Sprintf("<ID of the new %s OU>", ou.Name) }

func (ob *ouBuilder) ouLabel(ou *snapshot.OU) string { return fmt.Sprintf("%s (%s)", ou.Name, ou.ID) }

func (ob *ouBuilder) beforeSteps() {
	s := ob.res.Subject
	var blocking []string
	for _, a := range ob.res.Accounts {
		if a.Verdict == evaluator.StatusNoGo {
			blocking = append(blocking, fmt.Sprintf("%s (%s): %s", a.AccountName, a.AccountID, strings.Join(a.BlockingTitles, "; ")))
		}
	}
	if len(blocking) > 0 {
		ob.add(PhaseBefore, Step{Kind: KindBlocker, Status: evaluator.StatusNoGo, Title: fmt.Sprintf("Clear the blockers of %d account(s) first", len(blocking)),
			Detail: "The OU verdict is the worst account verdict. Work through the first phase of each account runbook below: " + strings.Join(blocking, " | ") + "."})
	}
	for _, f := range ob.res.Findings {
		switch {
		case strings.Contains(f.Title, "registered OU(s) in the moved tree"):
			var cmds []string
			for _, name := range ob.registered {
				cmds = append(cmds, fmt.Sprintf("# Control Tower console → Organization → %s → Deregister OU (unenrolls its accounts; the guardrail SCPs are detached)", name))
			}
			ob.add(PhaseBefore, Step{Kind: KindControlTower, Status: f.Status, Title: "Deregister the registered OU(s) from Control Tower: " + strings.Join(ob.registered, ", "), Finding: f.Title, Where: ob.srcMgmt + " (Control Tower)",
				Detail: f.Detail, Commands: cmds, Evidence: f.Evidence})
		case ob.cross && strings.Contains(f.Title, "cannot move between organizations"):
			ob.add(PhaseBefore, Step{Kind: KindDecision, Status: f.Status, Title: fmt.Sprintf("Agree the target layout: OU %s with %d nested OU(s) under %s", s.OUName, s.NestedOUs, nodeLabel(s.TargetPath, s.TargetParentID)), Finding: f.Title, Where: ob.dstMgmt,
				Detail: f.Detail + " Decide which of the customer-managed policies are recreated as they are, merged into the target's own policies, or dropped on purpose; the steps below assume they are recreated unchanged.", Evidence: f.Evidence})
		}
	}
}

func (ob *ouBuilder) recreateSteps() {
	s := ob.res.Subject
	if ob.cross {
		for _, p := range ob.policies {
			var doc []byte
			if ob.from != nil {
				if pol := ob.from.Index().PolicyByID[p.PolicyID]; pol != nil {
					doc = pol.Document
				}
			}
			ob.add(PhaseRecreate, Step{Kind: KindPolicy, Status: evaluator.StatusReview, Title: fmt.Sprintf("Create policy %s (%s) in %s", p.PolicyName, p.PolicyType, orgLabel(s.TargetOrg)), Where: ob.dstMgmt,
				Detail:   fmt.Sprintf("Attached to %s in the source tree. Policies do not travel between organizations; the document is in the evidence. The target root must have the %s type enabled.", p.OUName, p.PolicyType),
				Commands: []string{fmt.Sprintf("aws organizations create-policy --name %s --type %s --description \"recreated from %s\" --content file://%s.json", p.PolicyName, policyTypeName(p.PolicyType), orgLabel(s.SourceOrg), p.PolicyName)},
				Evidence: []evaluator.Evidence{{Kind: "policy-document", Side: "source", PolicyID: p.PolicyID, PolicyName: p.PolicyName, PolicyType: p.PolicyType, StatementJSON: doc}}})
		}
	}
	for _, ou := range ob.ous {
		parent := ob.parentOf[ou.ID]
		parentID, parentLabel := s.TargetParentID, nodeLabel(s.TargetPath, s.TargetParentID)
		if parent != "" {
			if p := ob.ouByID(parent); p != nil {
				parentID, parentLabel = newID(p), "the new "+p.Name+" OU"
			}
		}
		ob.add(PhaseRecreate, Step{Kind: KindOU, Title: fmt.Sprintf("Create OU %s under %s", ou.Name, parentLabel), Where: ob.dstMgmt,
			Detail:   fmt.Sprintf("The source OU %s keeps existing until its accounts have moved. Note the new ID; the later steps refer to it as %s.", ob.ouLabel(ou), newID(ou)),
			Commands: []string{fmt.Sprintf("aws organizations create-organizational-unit --parent-id %s --name \"%s\"", parentID, ou.Name)}})
		if list := ob.attached[ou.ID]; len(list) > 0 {
			var names, cmds []string
			for _, at := range list {
				names = append(names, at.PolicyType+" "+at.PolicyName)
				id := at.PolicyID
				if ob.cross {
					id = fmt.Sprintf("<ID of the recreated %s>", at.PolicyName)
				}
				cmds = append(cmds, fmt.Sprintf("aws organizations attach-policy --policy-id %s --target-id %s", id, newID(ou)))
			}
			ob.add(PhaseRecreate, Step{Kind: KindPolicy, Title: fmt.Sprintf("Attach to the new %s OU: %s", ou.Name, strings.Join(names, ", ")), Where: ob.dstMgmt,
				Detail: "Same attachments as the source OU, so the accounts see the same chain below the moved OU once they arrive. The AWS managed defaults are attached automatically.", Commands: cmds})
		}
		if ob.guardrails[ou.ID] && !ob.cross {
			ob.add(PhaseRecreate, Step{Kind: KindControlTower, Status: evaluator.StatusReview, Title: fmt.Sprintf("Register the new %s OU with Control Tower", ou.Name), Where: ob.srcMgmt + " (Control Tower)",
				Detail:   "The source OU was registered; registration does not follow the name. Registering the new OU attaches the guardrail SCPs again and enables the same controls, so do it before the accounts move in.",
				Commands: []string{fmt.Sprintf("# Control Tower console → Organization → %s → Register OU", ou.Name)}})
		}
	}
}

func (ob *ouBuilder) ouByID(id string) *snapshot.OU {
	for _, ou := range ob.ous {
		if ou.ID == id {
			return ou
		}
	}
	return nil
}

func (ob *ouBuilder) moveSteps() {
	if ob.cross {
		var names []string
		for _, a := range ob.res.Accounts {
			names = append(names, fmt.Sprintf("%s (%s)", a.AccountName, a.AccountID))
		}
		ob.add(PhaseMove, Step{Kind: KindMove, Title: fmt.Sprintf("Move the %d account(s) one by one: invite, leave, accept", len(ob.res.Accounts)), Where: ob.dstMgmt + ", then each account",
			Detail:   "Follow the move phase of each account runbook below, in whatever order limits the standalone time. Accounts: " + orNone(strings.Join(names, ", ")) + ".",
			Commands: []string{"aws organizations invite-account-to-organization --target Id=<account ID>,Type=ACCOUNT", "aws organizations leave-organization   # inside each account, or remove-account-from-organization from the source management account", "aws organizations accept-handshake --handshake-id <handshake ID>   # inside each account"}})
		for _, a := range ob.accounts {
			ou := ob.ouByID(a.ParentID)
			if ou == nil {
				continue
			}
			ob.add(PhaseMove, Step{Kind: KindMove, Title: fmt.Sprintf("Move %s (%s) from the target root into the new %s OU", a.Name, a.ID, ou.Name), Where: ob.dstMgmt,
				Detail:   "After accepting the invitation the account sits at the target root.",
				Commands: []string{fmt.Sprintf("aws organizations move-account --account-id %s --source-parent-id %s --destination-parent-id %s", a.ID, ob.res.Subject.TargetPath[0].ID, newID(ou))}})
		}
		return
	}
	for _, a := range ob.accounts {
		ou := ob.ouByID(a.ParentID)
		if ou == nil {
			continue
		}
		detail := "Policies attached directly to the account stay with it; from the new OU upwards the chain is the one the simulation evaluated."
		if ob.guardrails[ou.ID] {
			detail += " The OU is governed by Control Tower: move enrolled accounts with Account Factory's update-account flow so the baseline follows them."
		}
		ob.add(PhaseMove, Step{Kind: KindMove, Title: fmt.Sprintf("Move %s (%s) from %s into the new %s OU", a.Name, a.ID, ob.ouLabel(ou), ou.Name), Where: ob.srcMgmt,
			Detail:   detail,
			Commands: []string{fmt.Sprintf("aws organizations move-account --account-id %s --source-parent-id %s --destination-parent-id %s", a.ID, ou.ID, newID(ou))}})
	}
	if len(ob.accounts) == 0 {
		ob.add(PhaseMove, Step{Kind: KindMove, Title: "No accounts to move", Detail: "The OU tree is empty; creating the new OUs and deleting the old ones is the whole move."})
	}
}

func (ob *ouBuilder) afterSteps() {
	s := ob.res.Subject
	var cmds []string
	for _, a := range ob.accounts {
		cmds = append(cmds, fmt.Sprintf("aws organizations list-parents --child-id %s", a.ID))
	}
	cmds = append(cmds, fmt.Sprintf("aws organizations list-organizational-units-for-parent --parent-id %s", s.TargetParentID))
	ob.add(PhaseAfter, Step{Kind: KindCheck, Title: fmt.Sprintf("Confirm the new tree under %s and every account's parent", nodeLabel(s.TargetPath, s.TargetParentID)), Where: ob.dstMgmt,
		Detail: "Every account should list its new OU as parent and the new OUs should carry the attachments from the steps above.", Commands: cmds})
	if len(ob.registered) > 0 || ob.hasGuardrails() {
		ob.add(PhaseAfter, Step{Kind: KindControlTower, Status: evaluator.StatusReview, Title: "Register the new OU(s) with Control Tower and re-enroll their accounts", Where: ob.targetCTWhere(),
			Detail:   "Registration attaches the guardrail SCPs and enables the controls; enrolment deploys the baseline into each account. Both are Account Factory operations.",
			Commands: []string{"# Control Tower console → Organization → the new OU → Register OU", "# Control Tower console → Account Factory → Enroll account, for each account"}})
	}
	for _, f := range ob.res.Findings {
		if strings.HasPrefix(f.Title, "The new parent ") && strings.Contains(f.Title, "register the moved OU too") {
			ob.add(PhaseAfter, Step{Kind: KindControlTower, Status: f.Status, Title: f.Title, Finding: f.Title, Where: ob.targetCTWhere(), Detail: f.Detail, Evidence: f.Evidence,
				Commands: []string{fmt.Sprintf("# Control Tower console → Organization → the new %s OU → Register OU", s.OUName)}})
		}
	}
	var del []string
	for i := len(ob.ous) - 1; i >= 0; i-- {
		del = append(del, fmt.Sprintf("aws organizations delete-organizational-unit --organizational-unit-id %s", ob.ous[i].ID))
	}
	detail := "An OU can only be deleted when it is empty, so delete the deepest ones first. Detach nothing by hand: deleting the OU drops its attachments."
	if ob.cross {
		detail = "Once every account has left, the source OUs are empty. Delete the deepest ones first; their policy attachments go with them (the policies themselves stay in the source organization)."
	}
	ob.add(PhaseAfter, Step{Kind: KindOU, Title: fmt.Sprintf("Delete the %d empty source OU(s)", len(ob.ous)), Where: ob.srcMgmt, Detail: detail, Commands: del})
	ob.add(PhaseAfter, Step{Kind: KindCheck, Title: "Collect a fresh snapshot and simulate the new OU against its own parent", Where: ob.dstMgmt,
		Detail:   "With the tree in place, a simulation of the new OU against its current parent compares it with itself and should come back GO.",
		Commands: []string{"orgshift collect --profile <target management profile> --out <target snapshot>", fmt.Sprintf("orgshift simulate --from <target snapshot> --ou %s --target-ou %s", newID(ob.ous[0]), s.TargetParentID)}})
}

func (ob *ouBuilder) hasGuardrails() bool { return len(ob.guardrails) > 0 }

func (ob *ouBuilder) targetCTWhere() string {
	if ob.cross {
		return ob.dstMgmt + " (Control Tower)"
	}
	return ob.srcMgmt + " (Control Tower)"
}

func (ob *ouBuilder) rollbackSteps() {
	s := ob.res.Subject
	if ob.cross {
		ob.add(PhaseRollback, Step{Kind: KindRollback, Title: "Move every account back: follow the rollback of each account runbook", Where: "each account, then " + ob.srcMgmt,
			Detail: "Each account leaves the target organization, is re-invited into the source and moved under the recreated source OUs below."})
	}
	for _, ou := range ob.ous {
		parent := ob.parentOf[ou.ID]
		parentID, parentLabel := s.SourceParentID, nodeLabel(s.SourcePath, s.SourceParentID)
		if parent != "" {
			if p := ob.ouByID(parent); p != nil {
				parentID, parentLabel = newID(p), "the recreated "+p.Name+" OU"
			}
		}
		var cmds []string
		cmds = append(cmds, fmt.Sprintf("aws organizations create-organizational-unit --parent-id %s --name \"%s\"   # only if %s was already deleted", parentID, ou.Name, ob.ouLabel(ou)))
		for _, at := range ob.attached[ou.ID] {
			cmds = append(cmds, fmt.Sprintf("aws organizations attach-policy --policy-id %s --target-id %s", at.PolicyID, newID(ou)))
		}
		ob.add(PhaseRollback, Step{Kind: KindRollback, Title: fmt.Sprintf("Recreate OU %s under %s with its attachments", ou.Name, parentLabel), Where: ob.srcMgmt,
			Detail:   fmt.Sprintf("If the source OU %s still exists, skip the creation and reuse it. The policies still exist in the source organization.", ob.ouLabel(ou)),
			Commands: cmds})
	}
	if !ob.cross {
		for _, a := range ob.accounts {
			ou := ob.ouByID(a.ParentID)
			if ou == nil {
				continue
			}
			ob.add(PhaseRollback, Step{Kind: KindRollback, Title: fmt.Sprintf("Move %s (%s) back into %s", a.Name, a.ID, ou.Name), Where: ob.srcMgmt,
				Commands: []string{fmt.Sprintf("aws organizations move-account --account-id %s --source-parent-id %s --destination-parent-id %s", a.ID, newID(ou), ou.ID)},
				Detail:   "Reverse of the move; the original chain applies again."})
		}
	}
	if len(ob.registered) > 0 {
		ob.add(PhaseRollback, Step{Kind: KindRollback, Title: "Register the recreated OU(s) with Control Tower again and re-enroll the accounts", Where: ob.srcMgmt + " (Control Tower)",
			Detail: "Registration and enrolment were undone by the deregistration before the move.", Commands: []string{"# Control Tower console → Organization → the OU → Register OU; Account Factory → Enroll account"}})
	}
	ob.add(PhaseRollback, Step{Kind: KindRollback, Title: "Delete the new OUs once they are empty", Where: ob.dstMgmt,
		Detail:   "Deepest first; the attachments go with them.",
		Commands: []string{"aws organizations delete-organizational-unit --organizational-unit-id <new OU ID>"}})
}
