package evaluator

import (
	"fmt"
	"sort"
	"strings"

	"github.com/MrShaaba/orgshift/internal/snapshot"
)

// refSCPs is the page the SCP exemptions were checked against (2026-11-05):
// "SCPs don't affect users or roles in the management account. They affect
// only the member accounts in your organization." and "SCPs do not affect
// any service-linked role."
const refSCPs = "https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps.html"

// isServiceLinkedRole reports whether a principal is a service-linked role.
// IAM creates every service-linked role under the path /aws-service-role/.
func isServiceLinkedRole(principalARN string) bool {
	return strings.Contains(principalARN, ":role/aws-service-role/")
}

// managementOf reports whether the moving account is the management
// account of the organization on one side. The two sides are asked
// separately: a management account that becomes a member of another
// organization is exempt before the move and not after it.
func (e *evaluation) managementOf(s *side) bool {
	return s.snap.Organization.ManagementAccountID == e.accountID
}

// exemptOn reports whether a policy type does not restrict a request of
// the account on one side. SCPs never restrict the management account;
// RCPs never restrict resources that belong to it, so the exemption holds
// for an RCP only when the resource is the account's own (ownResource).
func (e *evaluation) exemptOn(s *side, t snapshot.PolicyType, ownResource bool) bool {
	if !e.managementOf(s) {
		return false
	}
	return t == snapshot.PolicyTypeSCP || ownResource
}

// exemptionNote says why one side was not evaluated against the chain, for
// findings where the other side was.
func (e *evaluation) exemptionNote(t snapshot.PolicyType, src, dst bool) string {
	what := "SCPs do not apply to the management account of an organization"
	if t == snapshot.PolicyTypeRCP {
		what = "RCPs do not restrict resources in the management account of an organization"
	}
	switch {
	case src && !dst:
		return fmt.Sprintf(" %s: the account is the management account of %s today, so nothing of this type restricts it before the move; as a member of %s it is subject to every %s on its path.", what, e.src.orgID, e.dst.orgID, t.Short())
	case dst && !src:
		return fmt.Sprintf(" %s: the account is the management account of %s after the move.", what, e.dst.orgID)
	}
	return ""
}

// exemptionFindings adds the informational findings that make the
// exemptions visible: the calls made by service-linked roles, which were
// not evaluated, and the sides on which the account is a management
// account.
func (e *evaluation) exemptionFindings(c *Check, t snapshot.PolicyType, serviceLinked []string) {
	ref := refSCPs
	if t == snapshot.PolicyTypeRCP {
		ref = RCPModelReference
	}
	if len(serviceLinked) > 0 {
		sort.Strings(serviceLinked)
		c.add(Finding{Status: StatusInfo, Category: CategoryInformational, Confidence: ConfidenceHigh,
			Title:      fmt.Sprintf("%d call(s) by a service-linked role are not restricted by %ss and were not evaluated", len(serviceLinked), t.Short()),
			Detail:     fmt.Sprintf("%ss do not affect service-linked roles, at either position: %s. Nothing of this type changes for these calls. What the role may do is decided by the service that owns it.", t.Short(), strings.Join(serviceLinked, "; ")),
			References: []string{ref}})
	}
	src, dst := e.managementOf(&e.src), e.managementOf(&e.dst)
	if !src && !dst {
		return
	}
	f := Finding{Status: StatusInfo, Category: CategoryInformational, Confidence: ConfidenceHigh, References: []string{ref}}
	subject := "SCPs do not apply to it"
	if t == snapshot.PolicyTypeRCP {
		subject = "RCPs do not restrict its resources"
	}
	switch {
	case src && dst:
		f.Title = fmt.Sprintf("The account is the management account of %s: %s at either position", e.src.orgID, subject)
		f.Detail = fmt.Sprintf("%s. The policies on its path are shown in the chain for reference and were not evaluated against its actions: nothing of this type restricts the account before or after the move.", exemptionSentence(t))
	case src:
		f.Title = fmt.Sprintf("The account is the management account of %s today: %s until it becomes a member of %s", e.src.orgID, subject, e.dst.orgID)
		f.Detail = fmt.Sprintf("%s. The source side was therefore evaluated as unrestricted, whatever is attached to its root, and the destination side with the full chain: every restriction the destination applies is new for this account, including ones its own organization has in a policy of the same content.", exemptionSentence(t))
	default:
		f.Title = fmt.Sprintf("The account is the management account of %s after the move: %s there", e.dst.orgID, subject)
		f.Detail = exemptionSentence(t) + "."
	}
	c.add(f)
}

func exemptionSentence(t snapshot.PolicyType) string {
	if t == snapshot.PolicyTypeRCP {
		return "RCPs do not restrict resources in the management account of an organization"
	}
	return "SCPs do not apply to the management account of an organization, only to its member accounts"
}
