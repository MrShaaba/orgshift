// Package runbook turns a simulation result into an ordered migration
// runbook: what to fix before the move, what to re-create because it does
// not travel with the account, the move itself, the checks afterwards and
// how to roll back.
//
// A runbook is a document. Every command in it is written for an operator
// to review and run by hand; orgshift never executes any of them and never
// writes to AWS.
package runbook

import (
	"fmt"
	"sort"
	"strings"

	"github.com/MrShaaba/orgshift/internal/evaluator"
	"github.com/MrShaaba/orgshift/internal/snapshot"
)

// SchemaVersion is bumped when the exported runbook shape changes.
const SchemaVersion = 1

// Phase IDs, in the order the phases are carried out.
const (
	PhaseBefore   = "before"
	PhaseRecreate = "recreate"
	PhaseMove     = "move"
	PhaseAfter    = "after"
	PhaseRollback = "rollback"
)

var phaseOrder = []string{PhaseBefore, PhaseRecreate, PhaseMove, PhaseAfter, PhaseRollback}

// Step kinds, so renderers and tests can tell what a step is about.
const (
	KindBlocker        = "blocker"
	KindPolicy         = "policy-change"
	KindDecision       = "decision"
	KindInput          = "input"
	KindTags           = "tags"
	KindShare          = "resource-share"
	KindDelegatedAdmin = "delegated-admin"
	KindLogging        = "logging"
	KindStackSet       = "stackset"
	KindTrustedAccess  = "trusted-access"
	KindPrerequisite   = "prerequisite"
	KindControlTower   = "control-tower"
	KindIdentityCenter = "identity-center"
	KindOU             = "organizational-unit"
	KindMove           = "move"
	KindCheck          = "check"
	KindRollback       = "rollback"
)

// Runbook is the ordered checklist for one account move.
type Runbook struct {
	Tool          string            `json:"tool"`
	SchemaVersion int               `json:"runbook_schema_version"`
	Subject       evaluator.Subject `json:"subject"`
	Verdict       evaluator.Status  `json:"verdict"`
	Summary       string            `json:"summary"`
	Phases        []Phase           `json:"phases"`
	Notes         []string          `json:"notes,omitempty"`
}

// Phase is one stage of the runbook.
type Phase struct {
	ID    string `json:"id"`
	Title string `json:"title"`
	Intro string `json:"intro,omitempty"`
	Steps []Step `json:"steps"`
}

// Step is one checklist item.
type Step struct {
	ID     string `json:"id"`
	Title  string `json:"title"`
	Detail string `json:"detail"`
	// Status is the status of the finding the step comes from: NO-GO steps
	// block the move, REVIEW steps need a decision or a check by hand, INFO
	// steps are optional. Routine steps carry none.
	Status evaluator.Status `json:"status,omitempty"`
	Kind   string           `json:"kind"`
	// Where names the account or console the step is performed in.
	Where string `json:"where,omitempty"`
	// Check and Finding point back at the verdict board entry the step was
	// derived from.
	Check     string   `json:"check,omitempty"`
	Finding   string   `json:"finding,omitempty"`
	Actions   []string `json:"actions,omitempty"`
	Principal string   `json:"principal,omitempty"`
	Resource  string   `json:"resource,omitempty"`
	Regions   []string `json:"regions,omitempty"`
	// Commands are AWS CLI calls for the operator to review and run by hand.
	// Lines starting with # are comments. Angle brackets mark values the
	// operator has to fill in.
	Commands []string             `json:"commands,omitempty"`
	Evidence []evaluator.Evidence `json:"evidence,omitempty"`
}

// Steps returns every step of the runbook in order.
func (rb *Runbook) Steps() []Step {
	var out []Step
	for _, p := range rb.Phases {
		out = append(out, p.Steps...)
	}
	return out
}

// Phase returns the phase with the given ID, or nil.
func (rb *Runbook) Phase(id string) *Phase {
	for i := range rb.Phases {
		if rb.Phases[i].ID == id {
			return &rb.Phases[i]
		}
	}
	return nil
}

// Build turns an account result into a runbook. from and to are the
// snapshots the result was computed from; to may be nil for a move inside
// one organization. They supply management accounts, share owners and
// Identity Center instances for exact commands; without them the runbook
// still builds, with placeholders.
func Build(res *evaluator.Result, from, to *snapshot.Snapshot) *Runbook {
	return build(res, from, to, "")
}

type builder struct {
	res      *evaluator.Result
	from, to *snapshot.Snapshot
	cross    bool
	acct     string
	phases   map[string]*Phase
	// partOfOU names the OU the account moves with, when the runbook is
	// part of an OU runbook; the account then has no move steps of its own.
	partOfOU string
	// viaAccountFactory is set when Control Tower requires the move to go
	// through Account Factory; product is the provisioned product, if known.
	viaAccountFactory bool
	accountFactory    evaluator.Finding
	product           string
	// governed is set when the account is enrolled in the source landing zone.
	governed bool
	// flagged lists the requests to exercise after the move.
	flagged []string
	// delegated lists the service principals the account administers.
	delegated []string
	// directPolicies are the customer-managed policies attached directly
	// to the account at the source, which a cross-organization move drops.
	directPolicies []evaluator.PolicyRef
}

func build(res *evaluator.Result, from, to *snapshot.Snapshot, partOfOU string) *Runbook {
	if to == nil {
		to = from
	}
	b := &builder{res: res, from: from, to: to, cross: res.Subject.CrossOrg, acct: res.Subject.AccountID, phases: map[string]*Phase{}, partOfOU: partOfOU}
	for _, id := range phaseOrder {
		title, intro := b.phaseText(id)
		b.phases[id] = &Phase{ID: id, Title: title, Intro: intro, Steps: []Step{}}
	}
	b.directPolicies = b.directAttachments()
	b.positionCheck()
	b.coverageSteps()
	for _, c := range res.Checks {
		switch c.ID {
		case "scp", "rcp":
			b.policySteps(c)
		case "tags":
			b.tagSteps(c)
		case "ram":
			b.shareSteps(c)
		case "org-services":
			b.orgServiceSteps(c)
		case "control-tower":
			b.controlTowerSteps(c)
		case "identity-center":
			b.identityCenterSteps(c)
		}
	}
	b.moveSteps()
	b.exerciseStep()
	b.resimulateStep()
	b.rollbackSteps()

	rb := &Runbook{Tool: "orgshift", SchemaVersion: SchemaVersion, Subject: res.Subject, Verdict: res.Verdict}
	for _, id := range phaseOrder {
		p := b.phases[id]
		for i := range p.Steps {
			p.Steps[i].ID = fmt.Sprintf("%s-%d", id, i+1)
		}
		rb.Phases = append(rb.Phases, *p)
	}
	rb.Notes = append(rb.Notes, "Generated from a snapshot simulation. Every command is for an operator to review and run by hand; orgshift never writes to AWS.")
	rb.Notes = append(rb.Notes, res.Notes...)
	rb.Summary = b.summary(rb)
	return rb
}

func (b *builder) phaseText(id string) (title, intro string) {
	switch id {
	case PhaseBefore:
		return "Before the move: fix the blockers and make the decisions",
			"Everything here is settled while the account is still at its current position. NO-GO steps block the move; REVIEW steps need a decision or a check by hand."
	case PhaseRecreate:
		return "Before the move: re-create what does not travel",
			"Shares, delegations, permission sets and stacks that are scoped to the account's current position do not follow it. Prepare the replacements now so nothing is interrupted."
	case PhaseMove:
		if b.cross {
			return "The move", "Run these in order. Between leaving and accepting the invitation the account is standalone, with no SCPs and no organization features; keep that window short."
		}
		return "The move", "One Organizations call, or the Account Factory flow when Control Tower governs the account."
	case PhaseAfter:
		return "After the move: checks", "Confirm what the simulation predicted and finish what could only be done once the account is at its new position."
	}
	return "Rollback", "If something breaks, this puts the account back where it was. Built from the source policy chain of the simulation."
}

func (b *builder) add(phase string, s Step) *Step {
	p := b.phases[phase]
	p.Steps = append(p.Steps, s)
	return &p.Steps[len(p.Steps)-1]
}

func (b *builder) summary(rb *Runbook) string {
	count := func(id string) int { return len(rb.Phase(id).Steps) }
	blockers := 0
	for _, s := range rb.Phase(PhaseBefore).Steps {
		if s.Status == evaluator.StatusNoGo {
			blockers++
		}
	}
	total := len(rb.Steps())
	return fmt.Sprintf("%d steps: %d before the move (%d blocking), %d to re-create, %d for the move itself, %d checks afterwards and %d to roll back.",
		total, count(PhaseBefore), blockers, count(PhaseRecreate), count(PhaseMove), count(PhaseAfter), count(PhaseRollback))
}

// Where labels.

func (b *builder) sourceMgmt() string { return mgmtWhere(b.from, b.res.Subject.SourceOrg) }
func (b *builder) targetMgmt() string { return mgmtWhere(b.to, b.res.Subject.TargetOrg) }
func (b *builder) targetMgmtID() string {
	return mgmtID(b.to)
}
func (b *builder) accountWhere() string {
	return fmt.Sprintf("account %s (%s)", b.res.Subject.AccountName, b.acct)
}

func mgmtID(s *snapshot.Snapshot) string {
	if s != nil && s.Organization.ManagementAccountID != "" {
		return s.Organization.ManagementAccountID
	}
	return "<management account>"
}

func mgmtWhere(s *snapshot.Snapshot, org evaluator.OrgRef) string {
	label := org.Name
	if label == "" {
		label = org.ID
	}
	return fmt.Sprintf("management account %s of %s", mgmtID(s), label)
}

func orgLabel(o evaluator.OrgRef) string {
	if o.Name != "" {
		return fmt.Sprintf("%s (%s)", o.Name, o.ID)
	}
	return o.ID
}

// directAttachments returns the customer-managed policies attached directly
// to the account at the source, from the source chains of the diff.
func (b *builder) directAttachments() []evaluator.PolicyRef {
	var out []evaluator.PolicyRef
	for _, d := range b.res.Diff {
		if len(d.SourceChain) == 0 {
			continue
		}
		last := d.SourceChain[len(d.SourceChain)-1]
		if last.Node.Kind != snapshot.KindAccount {
			continue
		}
		for _, p := range last.Policies {
			if !p.AWSManaged {
				p := p
				p.Level = d.TypeShort
				out = append(out, p)
			}
		}
	}
	return out
}

// coverageSteps turns every collection gap on the board into one step: the
// verdict rests on evidence that is missing, so collecting it comes before
// anything else.
func (b *builder) coverageSteps() {
	seen := map[string]bool{}
	for _, c := range b.res.Checks {
		for _, f := range c.Findings {
			ev := firstEvidence(f, "coverage")
			if ev == nil {
				continue
			}
			key := ev.Side + "|" + ev.Reference
			if seen[key] {
				continue
			}
			seen[key] = true
			which := "source"
			profile := "<source management profile>"
			if ev.Side == "target" {
				which, profile = "target", "<target management profile>"
			}
			cmds := []string{fmt.Sprintf("orgshift collect --profile %s --name \"%s\" --out <%s snapshot>   # records coverage for every domain", profile, orgNameFor(b, which), which)}
			switch ev.Reference {
			case "resource_shares":
				cmds = append(cmds, "# shares are listed per owning account: add --ram-profiles <network account profile> for the accounts that own the shares")
			case "control_tower", "control_tower.enrolled_accounts":
				cmds = append(cmds, "# the landing zone APIs answer only in the home region: pass --region <home region>")
			case "identity_center":
				cmds = append(cmds, "# the Identity Center APIs answer only in the instance's region: pass --region <instance region>")
			case "organization_trails", "config_aggregators", "stack_sets":
				cmds = append(cmds, "# not read by this collector version: add the entries by hand (docs/snapshot.md) and record them under coverage.domains")
			}
			b.add(PhaseBefore, Step{Kind: KindInput, Status: f.Status, Title: fmt.Sprintf("Collect the missing evidence: %s (%s snapshot)", ev.Reference, which), Check: c.ID, Finding: f.Title,
				Detail:   f.Detail + " Until it is collected the verdict rests on incomplete evidence and a GO is not issued.",
				Commands: cmds, Evidence: f.Evidence})
		}
	}
}

func orgNameFor(b *builder, which string) string {
	org := b.res.Subject.SourceOrg
	if which == "target" {
		org = b.res.Subject.TargetOrg
	}
	if org.Name != "" {
		return org.Name
	}
	return org.ID
}

// positionCheck is the first check after the move.
func (b *builder) positionCheck() {
	if b.partOfOU != "" {
		return
	}
	s := b.res.Subject
	cmds := []string{fmt.Sprintf("aws organizations list-parents --child-id %s", b.acct)}
	for _, d := range b.res.Diff {
		if d.EnabledTarget {
			cmds = append(cmds, fmt.Sprintf("aws organizations list-policies-for-target --target-id %s --filter %s", b.acct, d.Type))
		}
	}
	b.add(PhaseAfter, Step{Kind: KindCheck, Title: fmt.Sprintf("Confirm the account sits under %s and the expected policies reach it", nodeLabel(s.TargetPath, s.TargetOUID)),
		Detail: fmt.Sprintf("The parent must be %s. The policies listed for the account should match the target chain of the simulation (added: %s).", s.TargetOUID, orNone(strings.Join(b.addedPolicyNames(), ", "))),
		Where:  b.targetMgmt(), Commands: cmds})
}

func (b *builder) addedPolicyNames() []string {
	var out []string
	for _, d := range b.res.Diff {
		for _, p := range d.Added {
			out = append(out, d.TypeShort+" "+p.Name)
		}
	}
	return out
}

// exerciseStep lists the flagged requests to try after the move.
func (b *builder) exerciseStep() {
	if len(b.flagged) == 0 {
		return
	}
	b.add(PhaseAfter, Step{Kind: KindCheck, Title: fmt.Sprintf("Exercise the %d flagged request(s) from the account", len(b.flagged)),
		Detail: "These were denied or undecidable in the simulation. After the policy changes above and the move, confirm each one works (a dry run or a read of the resource is enough): " + strings.Join(b.flagged, "; ") + ".",
		Where:  b.accountWhere(), Commands: []string{"# for each action, run the real call once from the principal that uses it, or check CloudTrail for AccessDenied events after a day"}})
}

// resimulateStep closes the checks.
func (b *builder) resimulateStep() {
	if b.partOfOU != "" {
		return
	}
	target := "--from <target snapshot>"
	b.add(PhaseAfter, Step{Kind: KindCheck, Title: "Collect a fresh snapshot and simulate the account at its new position",
		Detail: "With the account inside the target organization, a simulation of the account against its own parent compares it with itself and should come back GO, which closes the runbook.",
		Where:  b.targetMgmt(),
		Commands: []string{
			"orgshift collect --profile <target management profile> --out <target snapshot>",
			fmt.Sprintf("orgshift simulate %s --account %s --target-ou %s", target, b.acct, b.res.Subject.TargetOUID),
		}})
}

// moveSteps writes the move phase.
func (b *builder) moveSteps() {
	s := b.res.Subject
	if b.partOfOU != "" {
		b.add(PhaseMove, Step{Kind: KindMove, Title: "Moved together with OU " + b.partOfOU,
			Detail: "The account does not move on its own; the move steps are in the OU part of the runbook."})
		return
	}
	srcParent, dst := s.SourcePathID, s.TargetOUID
	if !b.cross {
		switch {
		case srcParent == dst:
			b.add(PhaseMove, Step{Kind: KindMove, Title: "Nothing to move", Detail: "The target OU is the account's current parent; the simulation compared the account with itself."})
		case b.viaAccountFactory:
			b.add(PhaseMove, b.accountFactoryMove(dst))
		default:
			b.add(PhaseMove, Step{Kind: KindMove, Title: fmt.Sprintf("Move the account from %s to %s", nodeLabel(s.SourcePath, srcParent), nodeLabel(s.TargetPath, dst)),
				Detail:   "A single call; the new chain of policies applies immediately. Policies attached directly to the account stay attached.",
				Where:    b.sourceMgmt(),
				Commands: []string{fmt.Sprintf("aws organizations move-account --account-id %s --source-parent-id %s --destination-parent-id %s", b.acct, srcParent, dst)}})
		}
		return
	}
	targetRoot := s.TargetPath[0].ID
	dropped := ""
	if len(b.directPolicies) > 0 {
		var names []string
		for _, p := range b.directPolicies {
			names = append(names, p.Level+" "+p.Name)
		}
		dropped = " Policies attached directly to the account are detached when it leaves: " + strings.Join(names, ", ") + " (re-attaching them is part of the rollback)."
	}
	b.add(PhaseMove, Step{Kind: KindMove, Title: fmt.Sprintf("Invite the account into %s", orgLabel(s.TargetOrg)),
		Detail:   "The invitation (a handshake) is valid for 15 days. Send it before the account leaves so the standalone window is short.",
		Where:    b.targetMgmt(),
		Commands: []string{fmt.Sprintf("aws organizations invite-account-to-organization --target Id=%s,Type=ACCOUNT --notes \"Move of %s planned with orgshift\"", b.acct, s.AccountName)}})
	b.add(PhaseMove, Step{Kind: KindMove, Title: fmt.Sprintf("Leave %s", orgLabel(s.SourceOrg)),
		Detail: "Run leave-organization from inside the account, or remove it from the management account (which SCPs do not restrict). Both need the standalone prerequisites to be in place. From this moment no SCP, RCP or tag policy of the source applies, organization-scoped shares stop reaching the account and Identity Center deletes its assignments and roles." + dropped,
		Where:  fmt.Sprintf("%s, or %s", b.accountWhere(), b.sourceMgmt()),
		Commands: []string{
			"aws organizations leave-organization   # run inside the account",
			fmt.Sprintf("aws organizations remove-account-from-organization --account-id %s   # alternative, run by the management account", b.acct),
		}})
	b.add(PhaseMove, Step{Kind: KindMove, Title: "Accept the invitation",
		Detail: fmt.Sprintf("The account joins %s at its root with the AWS managed default policies attached. Everything on the verdict board that applies at the target position applies from the next step on.", orgLabel(s.TargetOrg)),
		Where:  b.accountWhere(),
		Commands: []string{
			"aws organizations list-handshakes-for-account --query \"Handshakes[?State=='OPEN'].[Id,Action]\" --output table",
			"aws organizations accept-handshake --handshake-id <handshake ID from the previous command>",
		}})
	if dst != targetRoot {
		b.add(PhaseMove, Step{Kind: KindMove, Title: fmt.Sprintf("Move the account from the root to %s", nodeLabel(s.TargetPath, dst)),
			Detail:   "Until this call the account sits at the target root with only the policies attached there.",
			Where:    b.targetMgmt(),
			Commands: []string{fmt.Sprintf("aws organizations move-account --account-id %s --source-parent-id %s --destination-parent-id %s", b.acct, targetRoot, dst)}})
	}
}

func (b *builder) accountFactoryMove(dst string) Step {
	s := b.res.Subject
	detail := "Control Tower expects the move to go through Account Factory so the baseline follows the account; moving it with Organizations directly leaves the landing zone in drift. " + b.accountFactory.Detail
	cmds := []string{fmt.Sprintf("# Control Tower console → Account Factory → %s → Update account → Organizational unit: %s", s.AccountName, nodeLabel(s.TargetPath, dst))}
	product := b.product
	if product == "" {
		product = "<provisioned product name>"
	}
	cmds = append(cmds, fmt.Sprintf("aws servicecatalog update-provisioned-product --provisioned-product-name %s --product-name \"AWS Control Tower Account Factory\" --provisioning-artifact-name <current version> --provisioning-parameters Key=ManagedOrganizationalUnit,Value=\"%s (%s)\",UsePreviousValue=false Key=AccountName,UsePreviousValue=true Key=AccountEmail,UsePreviousValue=true Key=SSOUserEmail,UsePreviousValue=true Key=SSOUserFirstName,UsePreviousValue=true Key=SSOUserLastName,UsePreviousValue=true",
		product, nodeName(s.TargetPath, dst), dst))
	return Step{Kind: KindMove, Title: fmt.Sprintf("Move the account through Account Factory to %s", nodeLabel(s.TargetPath, dst)),
		Detail: detail, Where: b.sourceMgmt() + " (Account Factory)", Commands: cmds, Check: "control-tower", Finding: b.accountFactory.Title, Evidence: b.accountFactory.Evidence}
}

// rollbackSteps writes the rollback phase from the source side of the result.
func (b *builder) rollbackSteps() {
	s := b.res.Subject
	if b.partOfOU != "" {
		b.add(PhaseRollback, Step{Kind: KindRollback, Title: "Rolled back together with OU " + b.partOfOU,
			Detail: "The rollback of the OU recreates the original OUs and moves every account back; the account's own policies to re-attach are listed below.", Evidence: b.chainEvidence()})
		return
	}
	srcParent, dst := s.SourcePathID, s.TargetOUID
	if !b.cross {
		switch {
		case srcParent == dst:
			b.add(PhaseRollback, Step{Kind: KindRollback, Title: "Nothing to roll back", Detail: "The account did not change parent."})
		case b.viaAccountFactory:
			b.add(PhaseRollback, Step{Kind: KindRollback, Title: fmt.Sprintf("Move the account back to %s through Account Factory", nodeLabel(s.SourcePath, srcParent)),
				Detail:   "Update the account in Account Factory again, with the original OU, so the baseline follows it back.",
				Where:    b.sourceMgmt() + " (Account Factory)",
				Commands: []string{fmt.Sprintf("# Control Tower console → Account Factory → %s → Update account → Organizational unit: %s", s.AccountName, nodeLabel(s.SourcePath, srcParent))}})
		default:
			b.add(PhaseRollback, Step{Kind: KindRollback, Title: fmt.Sprintf("Move the account back to %s", nodeLabel(s.SourcePath, srcParent)),
				Detail:   "The reverse of the move; the original chain applies again immediately.",
				Where:    b.sourceMgmt(),
				Commands: []string{fmt.Sprintf("aws organizations move-account --account-id %s --source-parent-id %s --destination-parent-id %s", b.acct, dst, srcParent)}})
		}
		b.add(PhaseRollback, b.chainStep())
		return
	}
	leaveDetail := "Leave the target organization the same way the account left the source, or have the target management account remove it."
	if denies := b.leaveDenies(false); len(denies) > 0 {
		var names []string
		for _, d := range denies {
			names = append(names, fmt.Sprintf("%s / %s at %s", d.PolicyName, d.Statement, d.Level))
		}
		leaveDetail += " The target chain denies organizations:LeaveOrganization (" + strings.Join(names, "; ") + "), so use remove-account-from-organization from the target management account."
	}
	b.add(PhaseRollback, Step{Kind: KindRollback, Title: fmt.Sprintf("Leave %s again", orgLabel(s.TargetOrg)), Detail: leaveDetail,
		Where: fmt.Sprintf("%s, or %s", b.accountWhere(), b.targetMgmt()),
		Commands: []string{"aws organizations leave-organization   # run inside the account",
			fmt.Sprintf("aws organizations remove-account-from-organization --account-id %s   # alternative, run by the target management account", b.acct)}})
	b.add(PhaseRollback, Step{Kind: KindRollback, Title: fmt.Sprintf("Re-invite the account into %s and accept", orgLabel(s.SourceOrg)),
		Detail: "The account comes back at the source root with the AWS managed defaults only.",
		Where:  fmt.Sprintf("%s, then %s", b.sourceMgmt(), b.accountWhere()),
		Commands: []string{fmt.Sprintf("aws organizations invite-account-to-organization --target Id=%s,Type=ACCOUNT", b.acct),
			"aws organizations list-handshakes-for-account --query \"Handshakes[?State=='OPEN'].[Id,Action]\" --output table",
			"aws organizations accept-handshake --handshake-id <handshake ID>"}})
	if srcRoot := s.SourcePath[0].ID; srcParent != srcRoot {
		b.add(PhaseRollback, Step{Kind: KindRollback, Title: fmt.Sprintf("Move the account back to %s", nodeLabel(s.SourcePath, srcParent)),
			Detail: "Restores the original chain of OU attachments.", Where: b.sourceMgmt(),
			Commands: []string{fmt.Sprintf("aws organizations move-account --account-id %s --source-parent-id %s --destination-parent-id %s", b.acct, srcRoot, srcParent)}})
	}
	if len(b.directPolicies) > 0 {
		var cmds []string
		var names []string
		for _, p := range b.directPolicies {
			names = append(names, p.Level+" "+p.Name)
			cmds = append(cmds, fmt.Sprintf("aws organizations attach-policy --policy-id %s --target-id %s", p.ID, b.acct))
		}
		b.add(PhaseRollback, Step{Kind: KindRollback, Title: fmt.Sprintf("Re-attach the %d policy(ies) that were attached directly to the account", len(b.directPolicies)),
			Detail: "Leaving an organization detaches everything attached to the account itself; the policies still exist in the source organization. Re-attach: " + strings.Join(names, ", ") + ".",
			Where:  b.sourceMgmt(), Commands: cmds})
	}
	if ic := b.sourceIdC(); ic != nil {
		if assignments := ic.AssignmentsFor(b.acct); len(assignments) > 0 {
			var cmds []string
			for _, a := range assignments {
				cmds = append(cmds, fmt.Sprintf("aws sso-admin create-account-assignment --instance-arn %s --target-id %s --target-type AWS_ACCOUNT --permission-set-arn %s --principal-type %s --principal-id %s   # %s",
					ic.InstanceARN, b.acct, a.PermissionSetARN, a.PrincipalType, a.PrincipalID, a.Label()))
			}
			b.add(PhaseRollback, Step{Kind: KindRollback, Title: fmt.Sprintf("Re-create the %d Identity Center assignment(s) in the source instance", len(assignments)),
				Detail: "The source identity store still has the users and groups; the principal IDs below come from the snapshot. New AWSReservedSSO_* roles are provisioned with new suffixes, so references to the old ARNs do not come back by themselves.",
				Where:  fmt.Sprintf("Identity Center of %s (account %s, %s)", orgLabel(s.SourceOrg), orUnknown(ic.OwnerAccountID), orUnknown(ic.Region)), Commands: cmds})
		}
	}
	if len(b.delegated) > 0 {
		var cmds []string
		for _, svc := range b.delegated {
			cmds = append(cmds, fmt.Sprintf("aws organizations register-delegated-administrator --account-id %s --service-principal %s", b.acct, svc))
		}
		b.add(PhaseRollback, Step{Kind: KindRollback, Title: "Re-delegate administration to the account: " + strings.Join(b.delegated, ", "),
			Detail: "Only if the hand-over before the move is to be reversed; deregister the stand-in first.", Where: b.sourceMgmt(), Commands: cmds})
	}
	if b.governed {
		b.add(PhaseRollback, Step{Kind: KindRollback, Title: "Re-enroll the account in the source Control Tower landing zone",
			Detail: "Enroll it from Account Factory into its original OU once it is back in the organization; the baseline and the detective controls are deployed again.",
			Where:  b.sourceMgmt() + " (Account Factory)", Commands: []string{"# Control Tower console → Account Factory → Enroll account → OU " + nodeLabel(s.SourcePath, srcParent)}})
	}
	b.add(PhaseRollback, Step{Kind: KindRollback, Title: "Organization-scoped shares and the organization trail cover the account again on their own",
		Detail: "Shares offered to the source organization or its OUs, the organization trail, the Config aggregator and service-managed StackSets follow membership and need no action. Shares that owners narrowed to the account ID keep working as well."})
	b.add(PhaseRollback, b.chainStep())
}

// chainStep verifies the original policy chain.
func (b *builder) chainStep() Step {
	var cmds []string
	for _, d := range b.res.Diff {
		if d.EnabledSource {
			cmds = append(cmds, fmt.Sprintf("aws organizations list-policies-for-target --target-id %s --filter %s", b.acct, d.Type))
		}
	}
	return Step{Kind: KindRollback, Title: "Verify the original policy chain reaches the account again", Where: b.sourceMgmt(),
		Detail: "Compare with the source chain recorded by the simulation, root to account.", Commands: cmds, Evidence: b.chainEvidence()}
}

// chainEvidence renders the source chain of every policy type as evidence.
func (b *builder) chainEvidence() []evaluator.Evidence {
	var out []evaluator.Evidence
	for _, d := range b.res.Diff {
		if !d.EnabledSource {
			continue
		}
		var lines []string
		for _, l := range d.SourceChain {
			var names []string
			for _, p := range l.Policies {
				n := p.Name + " (" + p.ID + ")"
				if p.ControlTowerManaged {
					n += " Control Tower guardrail"
				}
				names = append(names, n)
			}
			lines = append(lines, fmt.Sprintf("%s: %s", levelLabel(l.Node), orNone(strings.Join(names, ", "))))
		}
		out = append(out, evaluator.Evidence{Kind: "source-chain", Side: "source", PolicyType: d.TypeShort, Note: strings.Join(lines, "\n")})
	}
	return out
}

// leaveDenies finds unconditional Deny statements on organizations:
// LeaveOrganization in the source chain (or the target chain when target is
// set).
func (b *builder) leaveDenies(source bool) []evaluator.Evidence {
	var out []evaluator.Evidence
	for _, d := range b.res.Diff {
		if d.TypeShort != "SCP" {
			continue
		}
		chain := d.TargetChain
		side := "target"
		if source {
			chain, side = d.SourceChain, "source"
		}
		for _, l := range chain {
			for _, p := range l.Policies {
				for _, st := range p.Statements {
					if !strings.EqualFold(st.Effect, "Deny") || st.HasCondition || !deniesLeave(st) {
						continue
					}
					label := st.Sid
					if label == "" {
						label = "(unnamed statement)"
					}
					what := "Deny " + strings.Join(st.Actions, ", ")
					if len(st.NotActions) > 0 {
						what = "Deny NotAction " + strings.Join(st.NotActions, ", ")
					}
					out = append(out, evaluator.Evidence{Kind: "policy-statement", Side: side, Level: levelLabel(l.Node), PolicyID: p.ID, PolicyName: p.Name, PolicyType: "SCP", Statement: label, Note: what})
				}
			}
		}
	}
	return out
}

func deniesLeave(st evaluator.StatementSummary) bool {
	const action = "organizations:LeaveOrganization"
	if len(st.NotActions) > 0 {
		return !actionMatches(st.NotActions, action)
	}
	return actionMatches(st.Actions, action)
}

// Helpers.

func levelLabel(n snapshot.Node) string {
	switch n.Kind {
	case snapshot.KindRoot:
		return fmt.Sprintf("root %s (%s)", n.Name, n.ID)
	case snapshot.KindOU:
		return fmt.Sprintf("OU %s (%s)", n.Name, n.ID)
	}
	return fmt.Sprintf("account %s (%s)", n.Name, n.ID)
}

func nodeName(path []snapshot.Node, id string) string {
	for _, n := range path {
		if n.ID == id {
			return n.Name
		}
	}
	return id
}

func nodeLabel(path []snapshot.Node, id string) string {
	for _, n := range path {
		if n.ID == id {
			return levelLabel(n)
		}
	}
	return id
}

// idInParens extracts the ID from a level label such as "OU Payments (ou-1)".
func idInParens(level string) string {
	i, j := strings.LastIndex(level, "("), strings.LastIndex(level, ")")
	if i >= 0 && j > i {
		return level[i+1 : j]
	}
	return "<target ID>"
}

func firstEvidence(f evaluator.Finding, kind string) *evaluator.Evidence {
	for i := range f.Evidence {
		if f.Evidence[i].Kind == kind {
			return &f.Evidence[i]
		}
	}
	return nil
}

func evidenceSide(f evaluator.Finding, kind, side string) *evaluator.Evidence {
	for i := range f.Evidence {
		if f.Evidence[i].Kind == kind && f.Evidence[i].Side == side {
			return &f.Evidence[i]
		}
	}
	return nil
}

func hasEvidence(f evaluator.Finding, kind string) bool { return firstEvidence(f, kind) != nil }

func appendUnique(list []string, s string) []string {
	for _, e := range list {
		if e == s {
			return list
		}
	}
	return append(list, s)
}

func orNone(s string) string {
	if s == "" {
		return "none"
	}
	return s
}

func orUnknown(s string) string {
	if s == "" {
		return "unknown"
	}
	return s
}

func plural(n int, singular, pluralForm string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, singular)
	}
	return fmt.Sprintf("%d %s", n, pluralForm)
}

func sortedCopy(list []string) []string {
	out := append([]string(nil), list...)
	sort.Strings(out)
	return out
}
