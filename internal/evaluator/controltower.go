package evaluator

import (
	"fmt"
	"sort"
	"strings"

	"github.com/MrShaaba/orgshift/internal/snapshot"
)

// Documentation the Control Tower findings were verified against.
const (
	refCTEnroll         = "https://docs.aws.amazon.com/controltower/latest/userguide/enroll-account.html"
	refCTAutoEnrollment = "https://docs.aws.amazon.com/controltower/latest/userguide/account-auto-enrollment.html"
	refCTUnmanage       = "https://docs.aws.amazon.com/controltower/latest/userguide/unmanage-account.html"
	refCTBaselines      = "https://docs.aws.amazon.com/controltower/latest/userguide/types-of-baselines.html"
)

// ctSide is what Control Tower knows about one end of a move.
type ctSide struct {
	ct *snapshot.ControlTower
	// parent is the OU (or root) the account sits in on this side.
	parent snapshot.Node
	// registered is the registration of that parent, nil when it is the
	// root, not registered, or there is no landing zone.
	registered *snapshot.RegisteredOU
	// enrolled is the explicit enrolment record, if the snapshot has one.
	enrolled *snapshot.EnrolledAccount
	// governed is true when the account counts as enrolled here: listed as
	// enrolled, or (when enrolment was never collected) sitting in a
	// registered OU.
	governed bool
	// assumed is true when governed was derived from the OU, not listed.
	assumed bool
	// enrolmentKnown is true when the snapshot's enrolled list can be
	// trusted: it was collected (coverage complete) or written by hand.
	enrolmentKnown bool
	controls       []snapshot.EnabledControl
}

func (e *evaluation) ctSideFor(s *side) ctSide {
	out := ctSide{ct: s.snap.ControlTower}
	if len(s.path) >= 2 {
		out.parent = s.path[len(s.path)-2]
	}
	if out.ct == nil {
		return out
	}
	if !s.fresh[out.parent.ID] {
		out.registered = out.ct.RegisteredOU(out.parent.ID)
	}
	out.enrolled = out.ct.Enrolled(e.accountID)
	out.enrolmentKnown = len(out.ct.EnrolledAccounts) > 0 || s.snap.DomainStatus(snapshot.DomainEnrolledAccounts, "").Complete()
	switch {
	case out.enrolled != nil:
		out.governed = true
	case !out.enrolmentKnown && out.registered != nil:
		// The list was never collected: fall back to the OU and say so.
		out.governed, out.assumed = true, true
	}
	// Controls enabled on OUs along the path; recreated OUs carry none.
	for _, n := range s.path {
		if n.Kind == snapshot.KindOU && !s.fresh[n.ID] {
			out.controls = append(out.controls, out.ct.ControlsOn(n.ID)...)
		}
	}
	return out
}

func landingZoneEvidence(side string, ct *snapshot.ControlTower) Evidence {
	auto := "unknown"
	if ct.AutoEnrollment != "" {
		auto = ct.AutoEnrollment
	}
	return Evidence{Kind: "landing-zone", Side: side, Reference: ct.LandingZoneARN,
		Note: fmt.Sprintf("version %s, status %s, drift %s; home region %s; governed regions %s; auto-enrollment %s",
			orUnknown(ct.Version), orUnknown(ct.Status), orUnknown(ct.DriftStatus), orUnknown(ct.HomeRegion), orUnknown(strings.Join(ct.GovernedRegions, ", ")), auto)}
}

func registrationEvidence(side string, ou snapshot.Node, r *snapshot.RegisteredOU) Evidence {
	return Evidence{Kind: "registered-ou", Side: side, Reference: ou.ID,
		Note: fmt.Sprintf("OU %s registered: baseline %s, status %s, drift %s", ou.Name, orUnknown(r.BaselineVersion), orUnknown(r.Status), orUnknown(r.DriftStatus))}
}

func enrolmentEvidence(side string, e *snapshot.EnrolledAccount) Evidence {
	src := e.Source
	if src == "" {
		src = snapshot.EnrolledManual
	}
	return Evidence{Kind: "enrolled-account", Side: side, Reference: e.AccountID,
		Note: fmt.Sprintf("enrolled (source %s): status %s, drift %s, parent OU %s", src, orUnknown(e.Status), orUnknown(e.DriftStatus), orUnknown(e.ParentOUID))}
}

func controlEvidence(side string, c snapshot.EnabledControl) Evidence {
	name := c.Name
	if name == "" {
		name = snapshot.ControlShortID(c.ControlIdentifier)
	}
	return Evidence{Kind: "enabled-control", Side: side, Reference: c.ControlIdentifier,
		Note: fmt.Sprintf("%s\n%s control on OU %s; status %s, drift %s; implemented as %s",
			name, strings.ToLower(orUnknown(c.Behavior)), c.TargetOUID, orUnknown(c.Status), orUnknown(c.DriftStatus), orUnknown(c.Implementation))}
}

func orUnknown(s string) string {
	if s == "" {
		return "unknown"
	}
	return s
}

// autoEnrolmentText explains how the landing zone reacts to an account
// move, depending on whether the auto-enrollment setting is known.
func autoEnrolmentText(ct *snapshot.ControlTower) string {
	switch ct.AutoEnrollment {
	case snapshot.AutoEnrollmentEnabled:
		return "The landing zone has auto-enrollment on (it remediates inheritance drift), so Control Tower reacts to the move itself with an eventual-consistency model (minutes to hours)."
	case snapshot.AutoEnrollmentDisabled:
		return "The landing zone has auto-enrollment off, so a move made with Organizations leaves the account in inheritance drift until it is fixed from Account Factory."
	}
	return "The snapshot does not record whether the landing zone has auto-enrollment on (landing zone 3.1 and later, RemediationTypes INHERITANCE_DRIFT); with it on, Control Tower reacts to the move itself, with it off the move leaves inheritance drift to fix from Account Factory."
}

// evaluateControlTower covers enrolment, registered OUs, shared accounts,
// Account Factory and the controls that start or stop applying.
func (e *evaluation) evaluateControlTower(c *Check) {
	src, dst := e.ctSideFor(&e.src), e.ctSideFor(&e.dst)
	if src.ct == nil && dst.ct == nil {
		c.Summary = "Neither organization has a Control Tower landing zone."
		return
	}
	sameParent := !e.crossOrg && samePath(e.src.path, e.dst.path)
	// sameOU: the account keeps its parent OU (a whole-OU move inside the
	// organization). Enrolment then does not change, only what is inherited
	// from above, and the OU-level findings cover the registration.
	sameOU := !e.crossOrg && src.parent.ID == dst.parent.ID

	// Shared accounts never move.
	if src.ct != nil {
		for role, id := range map[string]string{"audit": src.ct.AuditAccountID, "log archive": src.ct.LogArchiveAccountID} {
			if id == e.accountID {
				c.add(Finding{Status: StatusNoGo, Title: fmt.Sprintf("Account is the Control Tower %s account", role),
					Detail:     fmt.Sprintf("The landing zone created this account and manages it from its Security OU. Control Tower does not support moving or unenrolling the %s account; it stays until the landing zone is decommissioned.", role),
					Evidence:   []Evidence{landingZoneEvidence("source", src.ct)},
					References: []string{refCTEnroll}})
			}
		}
	}

	enrolledNote := ""
	if src.assumed {
		enrolledNote = " (assumed enrolled because its OU is registered: the snapshot has no enrolled_accounts list and the control_tower.enrolled_accounts domain was not collected; the collector reads enrolment from ListEnabledBaselines, so collect again to be exact)"
	}
	srcEvidence := func() []Evidence {
		ev := []Evidence{landingZoneEvidence("source", src.ct)}
		if src.registered != nil {
			ev = append(ev, registrationEvidence("source", src.parent, src.registered))
		}
		if src.enrolled != nil {
			ev = append(ev, enrolmentEvidence("source", src.enrolled))
		}
		return ev
	}

	switch {
	case src.governed && e.crossOrg:
		c.add(Finding{Status: StatusReview, Title: "Account leaves the Control Tower landing zone and becomes unenrolled",
			Detail: fmt.Sprintf("The account is enrolled in the landing zone of %s%s. Unenroll it (Unmanage in Account Factory) before it leaves: unenrolling removes every resource Control Tower provisioned, including the AWSControlTowerExecution role, and moves the account to the root. Left enrolled, the landing zone reports drift and the baseline (Config recorders, the execution role, the StackSet-AWSControlTowerBP-* stacks) stays in the account unmanaged. "+
				"The %d preventive guardrail SCP(s) of its OU chain stop applying the moment it leaves and %d detective control(s) stop reporting.",
				e.from.Organization.ID, enrolledNote, countBehavior(src.controls, snapshot.ControlPreventive), countBehavior(src.controls, snapshot.ControlDetective)),
			Evidence: srcEvidence(), References: []string{refCTUnmanage}})
	case src.governed && !sameOU && dst.registered == nil:
		where := "is not registered with Control Tower"
		if dst.parent.Kind == snapshot.KindRoot {
			where = "is the root, which Control Tower never governs"
		}
		detail := fmt.Sprintf("Control Tower governs accounts through their OU, and %s (%s) %s. After the move the account is no longer enrolled%s: the %d preventive guardrail SCP(s) of the old OU chain stop applying (see the SCP diff) and %d detective control(s) stop reporting. ",
			dst.parent.Name, dst.parent.ID, where, enrolledNote, countBehavior(src.controls, snapshot.ControlPreventive), countBehavior(src.controls, snapshot.ControlDetective))
		switch src.ct.AutoEnrollment {
		case snapshot.AutoEnrollmentEnabled:
			detail += "The landing zone has auto-enrollment on, so moving the account out of the registered OU unenrolls it: Control Tower removes the deployed baselines and controls on its own (eventual consistency, minutes to hours). Any Service Catalog provisioned product from Account Factory is left behind and has to be cleaned up by hand. Decide whether leaving governance is the intent; otherwise register the target OU first."
		case snapshot.AutoEnrollmentDisabled:
			detail += "The landing zone has auto-enrollment off: moved with Organizations, the account keeps the baseline resources, shows inheritance drift and stays that way until it is unenrolled properly. Unenroll it from Account Factory first if leaving governance is the intent; otherwise register the target OU and move the account with Control Tower's update-account flow."
		default:
			detail += autoEnrolmentText(src.ct) + " Either way, unenroll from Account Factory first if leaving governance is the intent; otherwise register the target OU and move the account through Control Tower."
		}
		c.add(Finding{Status: StatusReview, Title: fmt.Sprintf("Moving out of the registered OU %s unenrolls the account from Control Tower", src.parent.Name),
			Detail: detail, Evidence: srcEvidence(), References: []string{refCTAutoEnrollment, refCTUnmanage}})
	case src.governed && !sameOU && dst.registered != nil:
		ev := []Evidence{registrationEvidence("source", src.parent, src.registered), registrationEvidence("target", dst.parent, dst.registered)}
		if src.enrolled != nil {
			ev = append(ev, enrolmentEvidence("source", src.enrolled))
		}
		if src.ct.AutoEnrollment == snapshot.AutoEnrollmentEnabled {
			same := sameControls(src.controls, dst.controls)
			status, drift := StatusInfo, "The two OUs enable the same controls, so no drift is expected."
			if !same {
				status, drift = StatusReview, "The two OUs enable different controls, so the account may show 'Moved member account' drift until Control Tower has re-applied the configuration; check the drift status afterwards."
			}
			c.add(Finding{Status: status, Title: fmt.Sprintf("Move between registered OUs %s and %s is handled by auto-enrollment", src.parent.Name, dst.parent.Name),
				Detail:   fmt.Sprintf("Both OUs are registered and the landing zone has auto-enrollment on, so a move made with Organizations re-applies the baseline and controls of %s with an eventual-consistency model (minutes to hours). %s Account Factory provisioned products are not updated by auto-enrollment; a vended account's product should still be updated to the new OU.", dst.parent.Name, drift),
				Evidence: ev, References: []string{refCTAutoEnrollment}})
		} else {
			c.add(Finding{Status: StatusReview, Title: fmt.Sprintf("Move between registered OUs %s and %s has to go through Control Tower", src.parent.Name, dst.parent.Name),
				Detail:   fmt.Sprintf("Both OUs are registered. %s Moving the account with Organizations directly leaves its baseline pointing at %s and the landing zone reports it as drifted. Use Account Factory's update-account flow (new OU %s) so the baseline is re-applied and the controls of the new OU deploy; the SCP and other checks on this board already reflect the new position.", autoEnrolmentText(src.ct), src.parent.Name, dst.parent.Name),
				Evidence: ev, References: []string{refCTAutoEnrollment}})
		}
	}

	if !src.governed && dst.ct != nil && dst.registered != nil && !sameOU {
		join := ""
		if e.crossOrg {
			join = fmt.Sprintf(" The account has to have joined %s before it can be enrolled.", e.to.Organization.ID)
		}
		how := "Enrolment is done from Account Factory (enroll account) and needs an AWSControlTowerExecution role in the account that trusts management account %s, no Config recorder or delivery channel of the account's own in the governed regions (%s), and an email address and name that Account Factory can register."
		if dst.ct.AutoEnrollment == snapshot.AutoEnrollmentEnabled {
			how = "The target landing zone has auto-enrollment on, so moving the account into the registered OU enrolls it without an Account Factory step (eventual consistency, minutes to hours). The enrolment prerequisites still apply: an AWSControlTowerExecution role trusting management account %s, no Config recorder or delivery channel of the account's own in the governed regions (%s)."
		}
		c.add(Finding{Status: StatusReview, Title: fmt.Sprintf("Target OU %s is registered with Control Tower; the account has to be enrolled", dst.parent.Name),
			Detail: fmt.Sprintf("Moving into a registered OU applies the OU's SCPs at once (the %d preventive guardrail SCP(s) on the chain are attached to the OUs), but the %d detective control(s) do not report and the baseline is not deployed until the account is enrolled. ",
				countBehavior(dst.controls, snapshot.ControlPreventive), countBehavior(dst.controls, snapshot.ControlDetective)) +
				fmt.Sprintf(how, e.to.Organization.ManagementAccountID, orUnknown(strings.Join(dst.ct.GovernedRegions, ", "))) + join,
			Evidence:   []Evidence{landingZoneEvidence("target", dst.ct), registrationEvidence("target", dst.parent, dst.registered)},
			References: []string{refCTEnroll, refCTAutoEnrollment}})
	}
	if dst.ct != nil && dst.registered == nil && !sameOU {
		c.add(Finding{Status: StatusInfo, Title: fmt.Sprintf("%s is not a registered OU; the account stays outside Control Tower governance there", dst.parent.Name),
			Detail:   fmt.Sprintf("The landing zone of %s governs only its registered OUs. No Control Tower controls apply to the account at %s, and Account Factory cannot enroll it until that OU is registered.", e.to.Organization.ID, snapshot.PathString(e.dst.path[:len(e.dst.path)-1])),
			Evidence: []Evidence{landingZoneEvidence("target", dst.ct)}})
	}

	// Account Factory provenance.
	if src.enrolled != nil && !sameOU {
		switch {
		case src.enrolled.VendedByAccountFactory:
			product := src.enrolled.ProvisionedProduct
			if product == "" {
				product = "its provisioned product"
			} else {
				product = "provisioned product " + product
			}
			if e.crossOrg {
				c.add(Finding{Status: StatusReview, Title: "Account was vended by Account Factory; " + product + " stays behind in the source",
					Detail:   "Account Factory tracks the account as a Service Catalog provisioned product in the source management account. After the account leaves, the product is orphaned and any update to it fails. Unenroll the account (which terminates the product without closing the account) before the move, and expect the target landing zone to treat it as an existing account to enroll, not one it vended.",
					Evidence: []Evidence{{Kind: "account-factory", Side: "source", Reference: src.enrolled.ProvisionedProduct, Note: "status " + orUnknown(src.enrolled.Status)}}})
			} else {
				c.add(Finding{Status: StatusInfo, Title: "Account was vended by Account Factory; move it by updating " + product,
					Detail:   "Account Factory records the OU as a parameter of the provisioned product. Changing the OU through the product (Service Catalog, update provisioned product, or the Control Tower console) performs the move and re-applies the baseline; moving it in Organizations directly leaves the product behind, and the landing zone in drift unless auto-enrollment is on.",
					Evidence: []Evidence{{Kind: "account-factory", Side: "source", Reference: src.enrolled.ProvisionedProduct, Note: "status " + orUnknown(src.enrolled.Status)}}})
			}
		case !src.enrolled.ProvenanceKnown():
			c.add(Finding{Status: StatusInfo, Title: "Whether Account Factory vended the account is not recorded",
				Detail:     "The enrolment was read from ListEnabledBaselines, which says the account is enrolled but not how it was created. Service Catalog (SearchProvisionedProducts) is not read by the collector. If Account Factory vended the account, a provisioned product tracks it and should be updated (same organization) or terminated by unenrolling (different organization) rather than left orphaned; check the Account Factory console.",
				Evidence:   []Evidence{enrolmentEvidence("source", src.enrolled)},
				References: []string{refCTBaselines}})
		}
	}

	// Controls that start or stop applying, grouped by behavior.
	if !sameParent {
		e.controlChanges(c, src, dst)
	}

	sortFindings(c.Findings)
	switch {
	case len(c.Findings) == 0 && sameParent:
		c.Summary = "The account stays in its OU; nothing changes for Control Tower."
	case len(c.Findings) == 0:
		c.Summary = "Control Tower is present but neither position is governed by it."
	default:
		c.Summary = fmt.Sprintf("%d item(s) to settle with Control Tower, %d informational.", countStatus(c.Findings, StatusReview)+countStatus(c.Findings, StatusNoGo), countStatus(c.Findings, StatusInfo))
	}
}

// sameControls reports whether two control lists enable the same controls
// (by short identifier).
func sameControls(a, b []snapshot.EnabledControl) bool {
	set := func(list []snapshot.EnabledControl) map[string]bool {
		m := map[string]bool{}
		for _, c := range list {
			m[snapshot.ControlShortID(c.ControlIdentifier)] = true
		}
		return m
	}
	sa, sb := set(a), set(b)
	if len(sa) != len(sb) {
		return false
	}
	for k := range sa {
		if !sb[k] {
			return false
		}
	}
	return true
}

func countBehavior(controls []snapshot.EnabledControl, behavior string) int {
	n := 0
	for _, c := range controls {
		if c.Behavior == behavior {
			n++
		}
	}
	return n
}

// controlChanges adds one INFO finding per behavior for the controls that
// start applying at the target and one per behavior for those that stop.
func (e *evaluation) controlChanges(c *Check, src, dst ctSide) {
	key := func(ctl snapshot.EnabledControl) string { return snapshot.ControlShortID(ctl.ControlIdentifier) }
	index := func(list []snapshot.EnabledControl) map[string]snapshot.EnabledControl {
		m := map[string]snapshot.EnabledControl{}
		for _, ctl := range list {
			if _, dup := m[key(ctl)]; !dup {
				m[key(ctl)] = ctl
			}
		}
		return m
	}
	srcIx, dstIx := index(src.controls), index(dst.controls)
	byBehavior := func(list []snapshot.EnabledControl, other map[string]snapshot.EnabledControl) map[string][]snapshot.EnabledControl {
		out := map[string][]snapshot.EnabledControl{}
		seen := map[string]bool{}
		for _, ctl := range list {
			k := key(ctl)
			if seen[k] {
				continue
			}
			seen[k] = true
			if _, same := other[k]; !same {
				b := ctl.Behavior
				if b == "" {
					b = "UNKNOWN"
				}
				out[b] = append(out[b], ctl)
			}
		}
		return out
	}
	starting, stopping := byBehavior(dst.controls, srcIx), byBehavior(src.controls, dstIx)
	order := []string{snapshot.ControlPreventive, snapshot.ControlDetective, snapshot.ControlProactive, "UNKNOWN"}
	label := map[string]string{snapshot.ControlPreventive: "preventive", snapshot.ControlDetective: "detective", snapshot.ControlProactive: "proactive", "UNKNOWN": "unclassified"}
	needsEnrolment := !src.governed || e.crossOrg
	for _, b := range order {
		if list := starting[b]; len(list) > 0 {
			detail := ""
			switch b {
			case snapshot.ControlPreventive:
				detail = "Preventive controls are the aws-guardrails-* SCPs attached to the OU chain; they apply as soon as the account is in the OU and the SCP check on this board evaluates them against the actions in use."
			case snapshot.ControlDetective:
				detail = "Detective controls are AWS Config rules that Control Tower deploys when the account is enrolled. Findings appear in the audit account's Security Hub and Config aggregator; nothing is blocked."
				if needsEnrolment {
					detail += " They start reporting only once the account is enrolled."
				}
			case snapshot.ControlProactive:
				detail = "Proactive controls are CloudFormation hooks that fail non-compliant stack deployments in the account; existing resources are not touched."
			default:
				detail = "The snapshot does not say whether these controls are preventive, detective or proactive."
			}
			c.add(Finding{Status: StatusInfo, Title: fmt.Sprintf("%d %s control(s) start applying at %s: %s", len(list), label[b], dst.parent.Name, controlNames(list)),
				Detail: detail, Evidence: controlEvidenceList("target", list)})
		}
		if list := stopping[b]; len(list) > 0 {
			detail := fmt.Sprintf("Enabled on the source OU chain and not on the target's. %s controls stop applying to the account after the move.", strings.ToUpper(label[b][:1])+label[b][1:])
			if b == snapshot.ControlDetective {
				detail += " The Config rules they deployed are removed when the account is unenrolled or moved through Control Tower (or by auto-enrollment); moved by hand without it, they linger unmanaged."
			}
			c.add(Finding{Status: StatusInfo, Title: fmt.Sprintf("%d %s control(s) stop applying: %s", len(list), label[b], controlNames(list)),
				Detail: detail, Evidence: controlEvidenceList("source", list)})
		}
	}
}

func controlNames(list []snapshot.EnabledControl) string {
	names := make([]string, 0, len(list))
	for _, ctl := range list {
		names = append(names, ctl.Label())
	}
	sort.Strings(names)
	return strings.Join(names, ", ")
}

func controlEvidenceList(side string, list []snapshot.EnabledControl) []Evidence {
	out := make([]Evidence, 0, len(list))
	for _, ctl := range list {
		out = append(out, controlEvidence(side, ctl))
	}
	return out
}
