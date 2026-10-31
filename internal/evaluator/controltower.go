package evaluator

import (
	"fmt"
	"sort"
	"strings"

	"github.com/MrShaaba/orgshift/internal/snapshot"
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
	// enrolled, or (without an enrolled_accounts list) sitting in a
	// registered OU.
	governed bool
	// assumed is true when governed was derived from the OU, not listed.
	assumed  bool
	controls []snapshot.EnabledControl
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
	switch {
	case out.enrolled != nil:
		out.governed = true
	case len(out.ct.EnrolledAccounts) == 0 && out.registered != nil:
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
	return Evidence{Kind: "landing-zone", Side: side, Reference: ct.LandingZoneARN,
		Note: fmt.Sprintf("version %s, status %s, drift %s; home region %s; governed regions %s",
			orUnknown(ct.Version), orUnknown(ct.Status), orUnknown(ct.DriftStatus), orUnknown(ct.HomeRegion), orUnknown(strings.Join(ct.GovernedRegions, ", ")))}
}

func registrationEvidence(side string, ou snapshot.Node, r *snapshot.RegisteredOU) Evidence {
	return Evidence{Kind: "registered-ou", Side: side, Reference: ou.ID,
		Note: fmt.Sprintf("OU %s registered: baseline %s, status %s, drift %s", ou.Name, orUnknown(r.BaselineVersion), orUnknown(r.Status), orUnknown(r.DriftStatus))}
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
					Detail:   fmt.Sprintf("The landing zone created this account and manages it from its Security OU. Control Tower does not support moving or unenrolling the %s account; it stays until the landing zone is decommissioned.", role),
					Evidence: []Evidence{landingZoneEvidence("source", src.ct)}})
			}
		}
	}

	enrolledNote := ""
	if src.assumed {
		enrolledNote = " (assumed enrolled because its OU is registered; list control_tower.enrolled_accounts in the snapshot to be exact)"
	}

	switch {
	case src.governed && e.crossOrg:
		f := Finding{Status: StatusReview, Title: "Account leaves the Control Tower landing zone and becomes unenrolled",
			Detail: fmt.Sprintf("The account is enrolled in the landing zone of %s%s. Unenroll it through Account Factory before it leaves; otherwise the landing zone reports drift and the baseline (Config recorders, the AWSControlTowerExecution role, the StackSet-AWSControlTowerBP-* stacks) is left in the account unmanaged. "+
				"The %d preventive guardrail SCP(s) of its OU chain stop applying the moment it leaves and %d detective control(s) stop reporting.",
				e.from.Organization.ID, enrolledNote, countBehavior(src.controls, snapshot.ControlPreventive), countBehavior(src.controls, snapshot.ControlDetective)),
			Evidence: []Evidence{landingZoneEvidence("source", src.ct)}}
		if src.registered != nil {
			f.Evidence = append(f.Evidence, registrationEvidence("source", src.parent, src.registered))
		}
		c.add(f)
	case src.governed && !sameOU && dst.registered == nil:
		where := "is not registered with Control Tower"
		if dst.parent.Kind == snapshot.KindRoot {
			where = "is the root, which Control Tower never governs"
		}
		f := Finding{Status: StatusReview, Title: fmt.Sprintf("Moving out of the registered OU %s unenrolls the account from Control Tower", src.parent.Name),
			Detail: fmt.Sprintf("Control Tower governs accounts through their OU, and %s (%s) %s. After the move the account is no longer enrolled%s: the %d preventive guardrail SCP(s) of the old OU chain stop applying (see the SCP diff), %d detective control(s) stop reporting, baseline updates stop and the landing zone shows the account as drifted until it is unenrolled properly. "+
				"Unenroll it from Account Factory first if leaving governance is the intent; otherwise register %s and move the account with Control Tower's update-account flow.",
				dst.parent.Name, dst.parent.ID, where, enrolledNote, countBehavior(src.controls, snapshot.ControlPreventive), countBehavior(src.controls, snapshot.ControlDetective), dst.parent.Name),
			Evidence: []Evidence{landingZoneEvidence("source", src.ct)}}
		if src.registered != nil {
			f.Evidence = append(f.Evidence, registrationEvidence("source", src.parent, src.registered))
		}
		c.add(f)
	case src.governed && !sameOU && dst.registered != nil:
		c.add(Finding{Status: StatusReview, Title: fmt.Sprintf("Move between registered OUs %s and %s has to go through Control Tower", src.parent.Name, dst.parent.Name),
			Detail:   fmt.Sprintf("Both OUs are registered. Moving the account with Organizations directly leaves its baseline pointing at %s and the landing zone reports it as drifted. Use Account Factory's update-account flow (new OU %s) so the baseline is re-applied and the controls of the new OU deploy; the SCP and other checks on this board already reflect the new position.", src.parent.Name, dst.parent.Name),
			Evidence: []Evidence{registrationEvidence("source", src.parent, src.registered), registrationEvidence("target", dst.parent, dst.registered)}})
	}

	if !src.governed && dst.ct != nil && dst.registered != nil && !sameOU {
		join := ""
		if e.crossOrg {
			join = fmt.Sprintf(" The account has to have joined %s before it can be enrolled.", e.to.Organization.ID)
		}
		c.add(Finding{Status: StatusReview, Title: fmt.Sprintf("Target OU %s is registered with Control Tower; the account has to be enrolled", dst.parent.Name),
			Detail: fmt.Sprintf("Moving into a registered OU does not enroll the account by itself. The %d preventive guardrail SCP(s) on the OU chain apply immediately because they are attached to the OUs, but the %d detective control(s) do not report and the baseline is not deployed until the account is enrolled from Account Factory. "+
				"Enrolment needs an AWSControlTowerExecution role in the account that trusts management account %s, no conflicting Config recorder or delivery channel in the governed regions (%s), and an email address and name that Account Factory can register.%s",
				countBehavior(dst.controls, snapshot.ControlPreventive), countBehavior(dst.controls, snapshot.ControlDetective), e.to.Organization.ManagementAccountID, orUnknown(strings.Join(dst.ct.GovernedRegions, ", ")), join),
			Evidence: []Evidence{landingZoneEvidence("target", dst.ct), registrationEvidence("target", dst.parent, dst.registered)}})
	}
	if dst.ct != nil && dst.registered == nil && !sameOU {
		c.add(Finding{Status: StatusInfo, Title: fmt.Sprintf("%s is not a registered OU; the account stays outside Control Tower governance there", dst.parent.Name),
			Detail:   fmt.Sprintf("The landing zone of %s governs only its registered OUs. No Control Tower controls apply to the account at %s, and Account Factory cannot enroll it until that OU is registered.", e.to.Organization.ID, snapshot.PathString(e.dst.path[:len(e.dst.path)-1])),
			Evidence: []Evidence{landingZoneEvidence("target", dst.ct)}})
	}

	// Account Factory provenance.
	if src.enrolled != nil && src.enrolled.VendedByAccountFactory && !sameOU {
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
				Detail:   "Account Factory records the OU as a parameter of the provisioned product. Changing the OU through the product (Service Catalog, update provisioned product, or the Control Tower console) performs the move and re-applies the baseline; moving it in Organizations directly leaves the product and the landing zone in drift.",
				Evidence: []Evidence{{Kind: "account-factory", Side: "source", Reference: src.enrolled.ProvisionedProduct, Note: "status " + orUnknown(src.enrolled.Status)}}})
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
				detail += " The Config rules they deployed are removed when the account is unenrolled or moved through Control Tower; moved by hand, they linger unmanaged."
			}
			c.add(Finding{Status: StatusInfo, Title: fmt.Sprintf("%d %s control(s) stop applying: %s", len(list), label[b], controlNames(list)),
				Detail: detail, Evidence: controlEvidenceList("source", list)})
		}
	}
}

func controlNames(list []snapshot.EnabledControl) string {
	names := make([]string, 0, len(list))
	for _, ctl := range list {
		names = append(names, controlLabel(ctl))
	}
	sort.Strings(names)
	return strings.Join(names, ", ")
}

// controlLabel is the short name of a control: the readable identifier
// (AWS-GR_ENCRYPTED_VOLUMES) when there is one, otherwise the alias at the
// start of the catalog name (CT.S3.PR.1) or the whole name.
func controlLabel(c snapshot.EnabledControl) string {
	id := snapshot.ControlShortID(c.ControlIdentifier)
	if !opaqueID(id) || c.Name == "" {
		return id
	}
	if i := strings.Index(c.Name, ": "); i > 0 && i <= 24 {
		return c.Name[:i]
	}
	return c.Name
}

// opaqueID reports whether a control identifier is a Control Catalog opaque
// ID (a long run of lower-case letters and digits) rather than a name.
func opaqueID(id string) bool {
	if len(id) < 16 {
		return false
	}
	for _, r := range id {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9') {
			return false
		}
	}
	return true
}

func controlEvidenceList(side string, list []snapshot.EnabledControl) []Evidence {
	out := make([]Evidence, 0, len(list))
	for _, ctl := range list {
		out = append(out, controlEvidence(side, ctl))
	}
	return out
}
