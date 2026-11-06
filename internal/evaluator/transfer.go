package evaluator

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/MrShaaba/orgshift/internal/policy"
	"github.com/MrShaaba/orgshift/internal/snapshot"
)

// Transfer evidence: every finding about the transfer procedure carries one
// evidence entry of kind "transfer" whose Reference says which part of the
// procedure it is about. The runbook keys its steps on it.
const (
	EvidenceTransfer = "transfer"

	TransferProcedure       = "procedure"
	TransferLeavePermission = "leave-organization"
	TransferRootLanding     = "root-landing"
	TransferOrgAge          = "organization-age"
	TransferSellerOfRecord  = "seller-of-record"
	TransferRootMFA         = "root-mfa"
	TransferAccountStatus   = "account-status"
	TransferAccountAge      = "account-age"
	TransferAccessRole      = "access-role"
	TransferUnconfirmed     = "unconfirmed-eligibility"
)

const minimumOrganizationAge = 7 * 24 * time.Hour

func transferEvidence(ref, note string) Evidence {
	return Evidence{Kind: EvidenceTransfer, Reference: ref, Note: note}
}

// transferMethod is the procedure that applies to this move: the one the
// operator chose, or the management-account sequence when the account is
// the source's management account, which has no other way out.
func (e *evaluation) transferMethod() string {
	if e.managementOf(&e.src) {
		return TransferManagementAccount
	}
	if e.method == TransferLeaveAndRejoin {
		return TransferLeaveAndRejoin
	}
	return TransferDirect
}

// snapshotTime is the moment the source snapshot describes.
func snapshotTime(s *snapshot.Snapshot) time.Time {
	if s.GeneratedAt != "" {
		if g, err := time.Parse(time.RFC3339, s.GeneratedAt); err == nil {
			return g
		}
	}
	return time.Now().UTC()
}

// transferFindings evaluates the transfer itself: the procedure that
// applies, the permission the account needs for it, where it lands, and the
// eligibility requirements of the migration page.
func (e *evaluation) transferFindings(c *Check) {
	method := e.transferMethod()
	src, dst := e.from.Organization, e.to.Organization
	switch method {
	case TransferDirect:
		c.add(Finding{Status: StatusInfo, Category: CategoryInformational, Confidence: ConfidenceHigh,
			Title: fmt.Sprintf("Direct transfer: %s invites the account and the account accepts; it is never standalone", dst.ManagementAccountID),
			Detail: fmt.Sprintf("With a direct account transfer the destination management account %s sends an invitation and the account accepts it: the account does not leave %s first and does not operate as a standalone account in between, so the standalone-account information (payment method, verified contact details, support plan) is not a prerequisite. Accepting needs the organizations:LeaveOrganization permission, because accepting moves the account out of its current organization. The invitation has to be answered within 15 days. On acceptance the account is added to the root of %s, the policies attached there apply at once and those of %s stop applying; the tags on the account are not carried over, organization-level reports and billing history stay with %s, and Reserved Instances and Savings Plans move with the account. The older sequence (leave or be removed, run standalone, then accept) is a separate procedure with its own prerequisites: evaluate it with the leave-and-rejoin method. Transfer procedure model %s.",
				dst.ManagementAccountID, src.ID, dst.ID, src.ID, src.ID, TransferModelVersion),
			Evidence: []Evidence{transferEvidence(TransferProcedure, TransferDirect)}, References: []string{refAccountMigration, refInvitations}})
	case TransferLeaveAndRejoin:
		c.add(Finding{Status: StatusReview, Category: CategoryPotentialImpact, Confidence: ConfidenceHigh,
			Title: "Leave or remove, then rejoin: the account is standalone between the two organizations",
			Detail: fmt.Sprintf("In this procedure the account first leaves %s (organizations:LeaveOrganization from inside the account) or is removed by its management account, and only then accepts the invitation from %s. Before it can leave it needs the standalone-account information: verified contact details, a payment method and a support plan choice; without them Organizations fails the removal with ConstraintViolationException. While it is standalone no SCP, RCP, tag or backup policy applies, the account pays its own bill, organization-scoped shares and Identity Center access are gone, and the role the former management account can assume is still there. Keep that interval short, or use the direct transfer, which has none. The invitation has to be answered within 15 days; on acceptance the account is added to the destination root. Transfer procedure model %s.",
				src.ID, dst.ManagementAccountID, TransferModelVersion),
			Evidence: []Evidence{transferEvidence(TransferProcedure, TransferLeaveAndRejoin)}, References: []string{refRemoveAccount, refInvitations, refAccountMigration}})
	case TransferManagementAccount:
		c.add(Finding{Status: StatusNoGo, Category: CategoryDeclaredImpact, Confidence: ConfidenceHigh,
			Title: "Account is the management account of the source organization",
			Detail: fmt.Sprintf("A management account is not transferred like a member: to migrate it, every member account has to be removed from %s and the organization deleted first; the account then operates as a standalone account, can accept the invitation from %s, and is a member account of the new organization from then on. Removing the members is a migration of its own for each of them (a direct transfer into another organization, or removal with the standalone-account information; created accounts wait four days; closed accounts block the deletion for up to 90 days). Deleting the organization deletes every SCP, RCP, tag, backup and other organization policy irrecoverably and ends its integrations (IAM Identity Center, for one). This sequence is neither a direct transfer nor leave-and-rejoin, and the direct-transfer findings do not apply to it. Transfer procedure model %s.",
				src.ID, dst.ManagementAccountID, TransferModelVersion),
			Evidence: []Evidence{transferEvidence(TransferProcedure, TransferManagementAccount)}, References: []string{refAccountMigration, refDeleteOrganization, refRemoveAccount}})
		if e.from.ControlTower != nil {
			c.add(Finding{Status: StatusNoGo, Category: CategoryDeclaredImpact, Title: "The source organization runs Control Tower from this management account",
				Detail:     fmt.Sprintf("The landing zone %s is operated from the management account. Before the organization can be deleted the landing zone has to be decommissioned, which removes the resources Control Tower created in the management, audit and log archive accounts and cannot be undone; S3 buckets and CloudWatch log groups remain to be deleted by hand. Deleting Control Tower resources by hand is not decommissioning and leaves a state from which no new landing zone can be set up.", e.from.ControlTower.LandingZoneARN),
				Evidence:   []Evidence{landingZoneEvidence("source", e.from.ControlTower)},
				References: []string{refDecommission}})
		}
	}
	if method != TransferManagementAccount {
		e.leavePermission(c, method)
	}
	e.rootLanding(c)
	e.eligibility(c, method)
}

// leavePermission evaluates organizations:LeaveOrganization against the
// source SCP chain. A direct transfer needs it because accepting moves the
// account out of its organization, and "an SCP in the source organization
// that denies organizations:LeaveOrganization blocks the transfer, even
// when the account's IAM policy allows it".
func (e *evaluation) leavePermission(c *Check, method string) {
	t := snapshot.PolicyTypeSCP
	if !e.from.PolicyTypeEnabled(t) {
		return
	}
	a := snapshot.ActionInUse{Action: "organizations:LeaveOrganization"}
	d := e.evalChain(e.chain(&e.src, t), e.ownRequest(&e.src, a, "us-east-1"))
	ev := append([]Evidence{transferEvidence(TransferLeavePermission, method)}, d.evidence("source", t)...)
	way := "Accepting the invitation needs organizations:LeaveOrganization, because accepting moves the account out of its organization"
	alternative := " Lift the deny for the principal that accepts the invitation, for the duration of the transfer. Removal by the source management account is not part of a direct transfer: it is the leave-and-rejoin procedure, with a standalone interval and the standalone-account prerequisites."
	if method == TransferLeaveAndRejoin {
		way = "Leaving from inside the account needs organizations:LeaveOrganization"
		alternative = " Lift the deny, or have the source management account remove the account (RemoveAccountFromOrganization), which SCPs do not restrict."
	}
	switch d.kind {
	case denied, implicitDenied:
		cause := d.reason
		if d.kind == denied {
			cause = "denied by " + d.cause()
		}
		if method == TransferLeaveAndRejoin {
			// Not a blocker of this procedure: the management account can
			// remove the account, and SCPs do not restrict it.
			c.add(Finding{Status: StatusReview, Category: CategoryDeclaredImpact, Confidence: ConfidenceHigh, Action: a.Action,
				Title:    "A source SCP denies organizations:LeaveOrganization: the account cannot leave by itself",
				Detail:   fmt.Sprintf("%s, and in %s it is %s.%s", way, e.src.orgID, cause, alternative),
				Evidence: ev, References: []string{refRemoveAccount, refAccountMigration}})
			return
		}
		c.add(Finding{Status: StatusNoGo, Category: CategoryDeclaredImpact, Confidence: ConfidenceHigh, Action: a.Action,
			Title:    "A source SCP denies organizations:LeaveOrganization, which blocks the transfer",
			Detail:   fmt.Sprintf("%s, and in %s it is %s. An SCP in the source organization that denies it blocks the transfer even when the account's own IAM policy allows it.%s", way, e.src.orgID, cause, alternative),
			Evidence: ev, References: []string{refAccountMigration}})
	case unknown:
		c.add(Finding{Status: StatusReview, Category: CategoryPotentialImpact, Confidence: ConfidenceMedium, Action: a.Action,
			Title:    "Whether a source SCP denies organizations:LeaveOrganization cannot be decided offline",
			Detail:   fmt.Sprintf("%s. The source chain has a statement about it that depends on context the snapshot does not carry (%s). Check it for the principal that accepts the invitation: a deny blocks the transfer.%s", way, d.cause(), alternative),
			Evidence: ev, References: []string{refAccountMigration}})
	}
}

// rootSide is the destination with the account at the root, where a
// migrated account always lands before it can be moved into an OU.
func (e *evaluation) rootSide() *side {
	if len(e.dst.path) < 2 {
		return nil
	}
	return &side{name: "target", snap: e.dst.snap, ix: e.dst.ix, orgID: e.dst.orgID,
		path: []snapshot.Node{e.dst.path[0], e.dst.path[len(e.dst.path)-1]}, fresh: e.dst.fresh}
}

// rootLanding evaluates the interval between acceptance and the move into
// the target OU. "Accounts that are migrated from one organization to
// another will be automatically added to the root of the new organization":
// until the destination management account moves it, only the policies at
// the root apply, so everything the target path adds below the root is not
// in force yet.
func (e *evaluation) rootLanding(c *Check) {
	if len(e.dst.path) <= 2 {
		c.add(Finding{Status: StatusInfo, Category: CategoryInformational, Confidence: ConfidenceHigh,
			Title:    "The account lands at the destination root, which is also its target",
			Detail:   "A migrated account is added to the root of the new organization. The target of this move is the root, so the position evaluated on the verdict board is the one the account is in from the moment it accepts.",
			Evidence: []Evidence{transferEvidence(TransferRootLanding, e.dst.path[0].ID)}, References: []string{refAccountMigration}})
		return
	}
	root := e.rootSide()
	target := e.dst.path[len(e.dst.path)-2]
	var pending []string
	for _, n := range e.dst.path[1 : len(e.dst.path)-1] {
		if e.dst.fresh[n.ID] {
			continue // an OU recreated for this move carries only the defaults
		}
		for _, t := range snapshot.AllPolicyTypes {
			for _, p := range e.dst.ix.Attached(n.ID, t) {
				if p.AWSManaged {
					continue // the defaults are attached to the account itself too
				}
				pending = append(pending, fmt.Sprintf("%s %s at %s", t.Short(), p.Name, levelLabel(n)))
			}
		}
	}
	governed := ""
	if ct := e.to.ControlTower; ct != nil {
		for _, n := range e.dst.path[1 : len(e.dst.path)-1] {
			if ct.RegisteredOU(n.ID) != nil {
				governed = fmt.Sprintf(" %s is registered with Control Tower; at the root the account is not governed and cannot be enrolled.", levelLabel(n))
			}
		}
	}
	// What the account can do at the root that the target position denies.
	var exposedActions, exposedInbound []string
	seen, seenInbound := map[string]bool{}, map[string]bool{}
	for _, t := range []snapshot.PolicyType{snapshot.PolicyTypeSCP, snapshot.PolicyTypeRCP} {
		if !e.to.PolicyTypeEnabled(t) {
			continue
		}
		rootChain, finalChain := e.chain(root, t), e.chain(&e.dst, t)
		for _, a := range e.usage.Actions {
			if isServiceLinkedRole(a.PrincipalArn) || seen[a.Action] {
				continue
			}
			if t == snapshot.PolicyTypeRCP {
				if applies, _ := rcpApplies(a.Action); !applies || policy.AccountFromPrincipal(a.Resource) != "" && policy.AccountFromPrincipal(a.Resource) != e.accountID {
					continue
				}
			}
			for _, r := range regionsFor(a.Action, a.Regions, e.account.EnabledRegions).regions {
				atRoot := e.evalChain(rootChain, e.ownRequest(root, a, r))
				final := e.evalChain(finalChain, e.ownRequest(&e.dst, a, r))
				if atRoot.kind == allowed && (final.kind == denied || final.kind == implicitDenied) {
					seen[a.Action] = true
					exposedActions = append(exposedActions, a.Action)
					break
				}
			}
		}
		if t != snapshot.PolicyTypeRCP {
			continue
		}
		for _, in := range e.usage.InboundAccess {
			for _, action := range in.Actions {
				if applies, _ := rcpApplies(action); !applies {
					continue
				}
				explicit := in.Regions
				if len(explicit) == 0 {
					if r := regionFromARN(in.Resource); r != "" {
						explicit = []string{r}
					}
				}
				for _, r := range regionsFor(action, explicit, e.account.EnabledRegions).regions {
					atRoot := e.evalChain(rootChain, e.inboundRequest(root, in, action, r))
					final := e.evalChain(finalChain, e.inboundRequest(&e.dst, in, action, r))
					if key := action + " by " + in.Principal; atRoot.kind == allowed && (final.kind == denied || final.kind == implicitDenied) && !seenInbound[key] {
						seenInbound[key] = true
						exposedInbound = append(exposedInbound, key)
						break
					}
				}
			}
		}
	}
	sort.Strings(exposedActions)
	sort.Strings(exposedInbound)
	ev := transferEvidence(TransferRootLanding, target.ID)
	if len(pending) == 0 && governed == "" {
		c.add(Finding{Status: StatusInfo, Category: CategoryInformational, Confidence: ConfidenceHigh,
			Title:    fmt.Sprintf("The account lands at the destination root first; nothing is attached below it on the way to %s", levelLabel(target)),
			Detail:   fmt.Sprintf("A migrated account is added to the root of the new organization and is moved into %s by the destination management account afterwards. No customer policy is attached between the root and that OU, so the same policies apply at the root as at the target position.", levelLabel(target)),
			Evidence: []Evidence{ev}, References: []string{refAccountMigration}})
		return
	}
	ev.Note = strings.Join(pending, "\n")
	detail := fmt.Sprintf("A migrated account is added to the root of the new organization; it reaches %s only when the destination management account moves it there. Until then only the policies attached to the root apply. Not in force during that interval: %s.", levelLabel(target), orNoneStr(strings.Join(pending, "; ")))
	detail += governed
	if len(exposedActions) > 0 {
		detail += fmt.Sprintf(" Of the actions in use, %d are allowed at the root and denied at the target position, so the account can still perform them in the interval: %s.", len(exposedActions), strings.Join(exposedActions, ", "))
	}
	if len(exposedInbound) > 0 {
		detail += fmt.Sprintf(" %d inbound request(s) that the target position denies are still admitted at the root: %s.", len(exposedInbound), strings.Join(exposedInbound, "; "))
	}
	if len(exposedActions)+len(exposedInbound) == 0 {
		detail += " None of the actions in use or inbound requests in the usage list is decided differently at the root; the difference is in what the account could do, not in what the list says it does."
	}
	detail += " Move the account in the same change as the acceptance, and treat anything done in between as done without the target OU's guardrails. The verdict board evaluates the target position; this finding is the root position."
	c.add(Finding{Status: StatusReview, Category: CategoryPotentialImpact, Confidence: ConfidenceHigh,
		Title:    fmt.Sprintf("The account lands at the destination root first: %d policy(ies) of the target path do not apply until it is moved into %s", len(pending), levelLabel(target)),
		Detail:   detail,
		Evidence: []Evidence{ev}, References: []string{refAccountMigration}})
}

// eligibility checks the requirements of the migration page that decide
// whether the account can be migrated at all. Each is confirmed, failed or
// not known from the snapshots; what is not known is one REVIEW that says
// how to supply it, never an assumption that the requirement is met.
func (e *evaluation) eligibility(c *Check, method string) {
	var confirmed, unconfirmed []string
	acct := e.account
	at := snapshotTime(e.from)

	// The destination organization is at least seven days old.
	// The Organizations API does not return a creation date, so it is in the
	// snapshot only when someone entered it. The date the management account
	// joined is offered as a hint and never used to decide: that the two are
	// the same moment is not documented.
	created := e.to.Organization.CreatedAt
	switch ts, err := time.Parse(time.RFC3339, created); {
	case created == "" || err != nil:
		hint := ""
		if m := e.dst.ix.AccountByID[e.to.Organization.ManagementAccountID]; m != nil && m.JoinedAt != "" {
			hint = fmt.Sprintf("; its management account is listed as joined at %s, which is a hint and not the documented creation date", m.JoinedAt)
		}
		unconfirmed = append(unconfirmed, fmt.Sprintf("the destination organization %s is at least seven days old (set organization.created_at in the destination snapshot%s)", e.dst.orgID, hint))
	case snapshotTime(e.to).Sub(ts) < minimumOrganizationAge:
		c.add(Finding{Status: StatusNoGo, Category: CategoryDeclaredImpact, Confidence: ConfidenceHigh,
			Title:    fmt.Sprintf("The destination organization %s is less than seven days old", e.dst.orgID),
			Detail:   fmt.Sprintf("To migrate an account to a new organization, the organization has to be at least seven days old. %s was created at %s (organization.created_at), so no account can be migrated into it before %s.", e.dst.orgID, created, ts.Add(minimumOrganizationAge).Format(time.RFC3339)),
			Evidence: []Evidence{transferEvidence(TransferOrgAge, created)}, References: []string{refAccountMigration}})
	default:
		confirmed = append(confirmed, fmt.Sprintf("the destination organization is older than seven days (created %s, from organization.created_at)", created))
	}

	// The Seller of Record matches.
	srcSOR, dstSOR := strings.TrimSpace(e.from.Organization.SellerOfRecord), strings.TrimSpace(e.to.Organization.SellerOfRecord)
	switch {
	case srcSOR == "" || dstSOR == "":
		unconfirmed = append(unconfirmed, "the Seller of Record of the account matches the destination organization's, or the move fails (set organization.seller_of_record in both snapshots, from the invoices)")
	case !strings.EqualFold(srcSOR, dstSOR):
		c.add(Finding{Status: StatusNoGo, Category: CategoryDeclaredImpact, Confidence: ConfidenceHigh,
			Title:    fmt.Sprintf("The Seller of Record differs: %s for the account, %s for the destination", srcSOR, dstSOR),
			Detail:   "The Seller of Record of the account being moved must match the Seller of Record of the destination organization; if they differ, the move fails. The values are the ones entered in the two snapshots.",
			Evidence: []Evidence{transferEvidence(TransferSellerOfRecord, srcSOR+" / "+dstSOR)}, References: []string{refAccountMigration}})
	default:
		confirmed = append(confirmed, "the Seller of Record matches ("+srcSOR+")")
	}

	// Closed or suspended accounts cannot be migrated.
	switch strings.ToUpper(acct.Status) {
	case "":
		unconfirmed = append(unconfirmed, "the account is active, not closed or suspended (the snapshot has no status for it)")
	case "ACTIVE":
		confirmed = append(confirmed, "the account is active")
	default:
		c.add(Finding{Status: StatusNoGo, Category: CategoryDeclaredImpact, Confidence: ConfidenceHigh,
			Title:    fmt.Sprintf("The account is %s: closed or suspended accounts cannot be migrated", strings.ToLower(acct.Status)),
			Detail:   "Closed or suspended accounts cannot be migrated to another organization. Reactivating an account goes through AWS Support.",
			Evidence: []Evidence{transferEvidence(TransferAccountStatus, acct.Status)}, References: []string{refAccountMigration}})
	}

	// An account created in the organization waits four days.
	switch {
	case acct.JoinedMethod == "":
		unconfirmed = append(unconfirmed, "the account was invited, or was created at least four days ago (the snapshot has no joined_method for it)")
	case acct.JoinedMethod != "CREATED":
		confirmed = append(confirmed, "the account was invited, so the four-day wait does not apply")
	case acct.JoinedAt == "":
		unconfirmed = append(unconfirmed, "the account, which was created in the organization, is at least four days old (the snapshot has no joined_at for it)")
	default:
		if joined, err := time.Parse(time.RFC3339, acct.JoinedAt); err == nil {
			if age := at.Sub(joined); age < minimumAccountAge {
				c.add(Finding{Status: StatusNoGo, Category: CategoryDeclaredImpact, Confidence: ConfidenceHigh,
					Title:    fmt.Sprintf("The account was created %s before the snapshot; it cannot be migrated until it is four days old", age.Round(time.Hour)),
					Detail:   fmt.Sprintf("To migrate an account that was created in an organization, at least four days have to pass after its creation. The account was created at %s, so the transfer fails until %s. Invited accounts are not subject to this wait.", acct.JoinedAt, joined.Add(minimumAccountAge).Format(time.RFC3339)),
					Evidence: []Evidence{transferEvidence(TransferAccountAge, acct.JoinedAt)}, References: []string{refAccountMigration, refRemoveAccount}})
			} else {
				confirmed = append(confirmed, "the account was created more than four days ago")
			}
		}
	}

	// Not a delegated administrator: its own NO-GO findings above.
	delegated := 0
	for _, d := range e.from.DelegatedAdministrators {
		if d.AccountID == e.accountID {
			delegated++
		}
	}
	if delegated == 0 {
		confirmed = append(confirmed, "the account is not a delegated administrator")
	}

	// Root MFA.
	switch {
	case acct.RootMFAEnabled == nil:
		unconfirmed = append(unconfirmed, "the root user has no MFA device registered (AWS asks for one to be removed before a migration to a new owner; set root_mfa_enabled on the account, from the IAM account summary)")
	case *acct.RootMFAEnabled:
		c.add(Finding{Status: StatusReview, Category: CategoryPotentialImpact, Confidence: ConfidenceHigh,
			Title:    "The root user has MFA registered: remove it before the migration if the account changes owner",
			Detail:   "If the account has MFA registered for the root user, AWS asks for it to be removed before the migration; otherwise the new owner might not be able to sign in as the root user. When the same people keep the root credentials after the move, the device can stay: decide which case this is. If the root email address is to change to the new owner's after the migration, the destination organization has to use all features; otherwise change it before migrating.",
			Evidence: []Evidence{transferEvidence(TransferRootMFA, "root_mfa_enabled: true")}, References: []string{refAccountMigration}})
	default:
		confirmed = append(confirmed, "the root user has no MFA device registered")
	}

	// The role that gives the former management account access stays.
	roleDetail := "When an account leaves an organization, any IAM role that was created to give the organization's management account access is not deleted. To end that access from the former organization's management account, delete the role by hand; the destination management account needs a role of its own, since Organizations does not create one for an invited account."
	if acct.JoinedMethod == "CREATED" {
		c.add(Finding{Status: StatusReview, Category: CategoryPotentialImpact, Confidence: ConfidenceHigh,
			Title:    fmt.Sprintf("OrganizationAccountAccessRole stays in the account: %s keeps administrator access until it is deleted", e.from.Organization.ManagementAccountID),
			Detail:   "The account was created in the source organization, which created an IAM role (OrganizationAccountAccessRole unless another name was given) that the source management account can assume. " + roleDetail,
			Evidence: []Evidence{transferEvidence(TransferAccessRole, "joined_method: CREATED")}, References: []string{refAccountMigration, refRemoveAccount}})
	} else {
		c.add(Finding{Status: StatusInfo, Category: CategoryInformational, Confidence: ConfidenceMedium,
			Title:    "A role that gives the source management account access, if one was created by hand, is not deleted by the transfer",
			Detail:   "The account was invited into the source organization, so Organizations did not create OrganizationAccountAccessRole for it; one may still have been created by hand. " + roleDetail,
			Evidence: []Evidence{transferEvidence(TransferAccessRole, "joined_method: "+orUnknown(acct.JoinedMethod))}, References: []string{refAccountMigration, refRemoveAccount}})
	}

	if method == TransferLeaveAndRejoin {
		unconfirmed = append(unconfirmed, "the account has the standalone-account information (verified contact details, a payment method, a support plan), without which leaving fails with ConstraintViolationException")
	}
	if len(unconfirmed) > 0 {
		detail := fmt.Sprintf("The snapshots do not say whether %d requirement(s) of the migration are met, and none of them is assumed: %s.", len(unconfirmed), strings.Join(unconfirmed, "; "))
		if len(confirmed) > 0 {
			detail += " Confirmed from the snapshots: " + strings.Join(confirmed, "; ") + "."
		}
		c.add(Finding{Status: StatusReview, Category: CategoryMissingEvidence, Confidence: ConfidenceLow,
			Title:    fmt.Sprintf("Transfer eligibility: %d requirement(s) cannot be confirmed from the snapshots", len(unconfirmed)),
			Detail:   detail,
			Evidence: []Evidence{transferEvidence(TransferUnconfirmed, strings.Join(unconfirmed, "\n"))}, References: []string{refAccountMigration}})
	} else if len(confirmed) > 0 {
		c.add(Finding{Status: StatusInfo, Category: CategoryInformational, Confidence: ConfidenceHigh,
			Title:    "Transfer eligibility: every requirement that can be read from the snapshots is met",
			Detail:   "Confirmed: " + strings.Join(confirmed, "; ") + ".",
			Evidence: []Evidence{transferEvidence(TransferUnconfirmed, "")}, References: []string{refAccountMigration}})
	}
}
