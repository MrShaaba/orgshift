package evaluator

import (
	"bytes"
	"fmt"
	"sort"
	"strings"

	"github.com/MrShaaba/orgshift/internal/snapshot"
)

// evaluateIdentityCenter covers what IAM Identity Center loses when an
// account leaves its organization: the account assignments (users and
// groups per permission set) and the AWSReservedSSO_* roles provisioned in
// the account. Inside one organization nothing changes, because
// assignments are per account, not per OU.
func (e *evaluation) evaluateIdentityCenter(c *Check) {
	src, dst := e.from.IdentityCenter, e.to.IdentityCenter
	if src == nil && dst == nil {
		c.Summary = "Neither organization has an IAM Identity Center instance in its snapshot."
		return
	}
	assignments := src.AssignmentsFor(e.accountID)
	provisioned := src.ProvisionedIn(e.accountID)
	if !e.crossOrg {
		if src == nil {
			c.Summary = "No IAM Identity Center instance in the snapshot."
			return
		}
		c.Summary = fmt.Sprintf("Same organization: the %d assignment(s) and %d provisioned role(s) on the account are unchanged by a move between OUs.", len(assignments), len(provisioned))
		return
	}
	if src == nil {
		c.add(Finding{Status: StatusInfo, Title: "Target organization grants access through IAM Identity Center",
			Detail:   fmt.Sprintf("The source organization has no Identity Center instance in its snapshot, so no assignments are lost. The target instance has %d permission set(s); access to the account is granted by assigning them to users and groups after the account has joined. Any IAM users or federation the account uses today keep working until they are replaced.", len(dst.PermissionSets)),
			Evidence: []Evidence{instanceEvidence("target", dst)}})
		c.Summary = "The source has no Identity Center; access in the target is granted by assignment after the account joins."
		return
	}

	// One finding per permission set with assignments on the account.
	var matched, unmatched []string
	for _, ps := range src.PermissionSets {
		var list []snapshot.AccountAssignment
		for _, a := range assignments {
			if a.PermissionSetARN == ps.ARN {
				list = append(list, a)
			}
		}
		if len(list) == 0 {
			continue
		}
		labels := make([]string, 0, len(list))
		evidence := make([]Evidence, 0, len(list)+2)
		for _, a := range list {
			labels = append(labels, a.Label())
			evidence = append(evidence, Evidence{Kind: "account-assignment", Side: "source", Reference: a.PrincipalID,
				Note: fmt.Sprintf("%s %s has permission set %s in account %s", strings.ToLower(a.PrincipalType), orUnknown(a.PrincipalName), ps.Name, e.accountID)})
		}
		evidence = append(evidence, permissionSetEvidence("source", ps))
		detail := fmt.Sprintf("Account assignments exist only for accounts inside the organization that owns the instance. When the account leaves %s, Identity Center deletes these %d assignment(s) and the principals lose this access at once. ", e.from.Organization.ID, len(list))
		switch {
		case dst == nil:
			detail += "The target organization has no Identity Center instance in its snapshot, so the access has to be rebuilt with IAM roles or federation, or with an instance collected into the target snapshot."
		default:
			match := dst.PermissionSetByName(ps.Name)
			if match == nil {
				unmatched = append(unmatched, ps.Name)
				detail += fmt.Sprintf("The target instance has no permission set named %s. Create one there (or choose an equivalent) before re-assigning the %d principal(s), who have to exist in identity store %s under the target instance.", ps.Name, len(list), orUnknown(dst.IdentityStoreID))
			} else {
				matched = append(matched, ps.Name)
				detail += fmt.Sprintf("The target instance has a permission set with the same name; re-assign the principals to it once the account has joined. They are matched by name only: identity store %s is a different directory, so the users and groups are different objects there.", orUnknown(dst.IdentityStoreID))
				if diffs := permissionSetDifferences(ps, *match); len(diffs) > 0 {
					detail += " Same name, different settings: " + strings.Join(diffs, "; ") + "."
				} else {
					detail += " The two permission sets have the same policies, session duration and boundary."
				}
				evidence = append(evidence, permissionSetEvidence("target", *match))
			}
		}
		c.add(Finding{Status: StatusReview,
			Title:    fmt.Sprintf("Permission set %s: %d assignment(s) removed when the account leaves (%s)", ps.Name, len(list), strings.Join(labels, ", ")),
			Detail:   detail,
			Evidence: evidence})
	}

	// The provisioned roles.
	if len(provisioned) > 0 {
		patterns := make([]string, 0, len(provisioned))
		evidence := make([]Evidence, 0, len(provisioned))
		var stale []string
		for _, ps := range provisioned {
			n := 0
			for _, a := range assignments {
				if a.PermissionSetARN == ps.ARN {
					n++
				}
			}
			patterns = append(patterns, ps.ReservedRolePattern())
			note := fmt.Sprintf("role for permission set %s (%s) under %s; %d assignment(s) on the account", ps.Name, ps.ARN, src.ReservedRolePath(), n)
			if n == 0 {
				stale = append(stale, ps.ReservedRolePattern())
				note += "; provisioned without an assignment (stale)"
			}
			evidence = append(evidence, Evidence{Kind: "reserved-role", Side: "source", Reference: ps.ReservedRolePattern(), Note: note})
		}
		detail := fmt.Sprintf("Identity Center deletes the IAM roles it provisioned in the account (path %s) when the account leaves the organization. Anything that names these roles breaks: resource and trust policies, KMS key policies, S3 bucket policies, EKS access entries, pipelines and tools that assume them, and CloudTrail history keeps the old ARNs. The target instance provisions new roles with a different random suffix, so references have to be updated, not restored. The exact suffix is only visible in IAM; offline the roles are known by their pattern.", src.ReservedRolePath())
		if len(stale) > 0 {
			detail += fmt.Sprintf(" %d of them (%s) are provisioned without any assignment and are already unused; deprovisioning the permission set from the account before the move removes them cleanly.", len(stale), strings.Join(stale, ", "))
		}
		c.add(Finding{Status: StatusReview,
			Title:    fmt.Sprintf("%d AWSReservedSSO_* role(s) are deleted from the account: %s", len(provisioned), strings.Join(patterns, ", ")),
			Detail:   detail,
			Evidence: evidence})
	}

	switch {
	case len(assignments) == 0 && len(provisioned) == 0:
		c.Summary = "The source Identity Center has no assignments or provisioned roles on this account."
		if dst != nil {
			c.add(Finding{Status: StatusInfo, Title: "Target organization grants access through IAM Identity Center",
				Detail:   fmt.Sprintf("The target instance has %d permission set(s). Access to the account is granted by assignment after it has joined.", len(dst.PermissionSets)),
				Evidence: []Evidence{instanceEvidence("target", dst)}})
		}
	case dst != nil:
		sort.Strings(matched)
		sort.Strings(unmatched)
		detail := fmt.Sprintf("Assignments are not copied between instances. The target instance uses identity store %s (the source uses %s); users and groups there are separate objects even when their names match, so each assignment is re-created by name after the account has accepted the invitation.", orUnknown(dst.IdentityStoreID), orUnknown(src.IdentityStoreID))
		if len(matched) > 0 {
			detail += fmt.Sprintf(" Permission set names that exist in both instances: %s.", strings.Join(matched, ", "))
		}
		if len(unmatched) > 0 {
			detail += fmt.Sprintf(" Missing in the target: %s.", strings.Join(unmatched, ", "))
		}
		c.add(Finding{Status: StatusInfo, Title: "Access is re-created in the target Identity Center instance, not moved",
			Detail:   detail,
			Evidence: []Evidence{instanceEvidence("source", src), instanceEvidence("target", dst)}})
		c.Summary = fmt.Sprintf("%d assignment(s) across %d permission set(s) and %d provisioned role(s) go away with the move; %d permission set name(s) exist in the target, %d do not.",
			len(assignments), len(matched)+len(unmatched), len(provisioned), len(matched), len(unmatched))
	default:
		c.add(Finding{Status: StatusInfo, Title: "Target organization has no IAM Identity Center instance in its snapshot",
			Detail:   "If the target runs Identity Center, collect its instance (run the collector with --region set to the instance's region) so permission sets can be matched by name. Otherwise access to the account has to be re-established with IAM roles or federation once it has left.",
			Evidence: []Evidence{instanceEvidence("source", src)}})
		c.Summary = fmt.Sprintf("%d assignment(s) and %d provisioned role(s) go away with the move and nothing in the target snapshot replaces them.", len(assignments), len(provisioned))
	}
	sortFindings(c.Findings)
}

func instanceEvidence(side string, ic *snapshot.IdentityCenter) Evidence {
	return Evidence{Kind: "identity-center-instance", Side: side, Reference: ic.InstanceARN,
		Note: fmt.Sprintf("%s; identity store %s; region %s; owner account %s; %d permission set(s), %d account assignment(s)",
			orUnknown(ic.Name), orUnknown(ic.IdentityStoreID), orUnknown(ic.Region), orUnknown(ic.OwnerAccountID), len(ic.PermissionSets), len(ic.Assignments))}
}

func permissionSetEvidence(side string, ps snapshot.PermissionSet) Evidence {
	var lines []string
	if ps.Description != "" {
		lines = append(lines, ps.Description)
	}
	lines = append(lines, "session duration "+orUnknown(ps.SessionDuration))
	if len(ps.ManagedPolicies) > 0 {
		lines = append(lines, "managed policies: "+strings.Join(ps.ManagedPolicies, ", "))
	}
	if len(ps.CustomerManagedPolicies) > 0 {
		lines = append(lines, "customer managed policies (must exist in the account): "+strings.Join(ps.CustomerManagedPolicies, ", "))
	}
	if len(ps.InlinePolicy) > 0 {
		lines = append(lines, "has an inline policy")
	}
	if ps.PermissionsBoundary != "" {
		lines = append(lines, "permissions boundary "+ps.PermissionsBoundary)
	}
	if len(ps.ProvisionedAccounts) > 0 {
		lines = append(lines, fmt.Sprintf("provisioned in %d account(s)", len(ps.ProvisionedAccounts)))
	}
	return Evidence{Kind: "permission-set", Side: side, Reference: ps.ARN, Note: ps.Name + "\n" + strings.Join(lines, "\n"), StatementJSON: ps.InlinePolicy}
}

// permissionSetDifferences lists what differs between two permission sets
// of the same name in the two instances.
func permissionSetDifferences(a, b snapshot.PermissionSet) []string {
	var out []string
	if d := setDifference(a.ManagedPolicies, b.ManagedPolicies); d != "" {
		out = append(out, "managed policies "+d)
	}
	if d := setDifference(a.CustomerManagedPolicies, b.CustomerManagedPolicies); d != "" {
		out = append(out, "customer managed policies "+d)
	}
	switch {
	case len(a.InlinePolicy) > 0 && len(b.InlinePolicy) == 0:
		out = append(out, "only the source has an inline policy")
	case len(a.InlinePolicy) == 0 && len(b.InlinePolicy) > 0:
		out = append(out, "only the target has an inline policy")
	case len(a.InlinePolicy) > 0 && !bytes.Equal(bytes.Join(bytes.Fields(a.InlinePolicy), nil), bytes.Join(bytes.Fields(b.InlinePolicy), nil)):
		out = append(out, "the inline policies differ")
	}
	if a.SessionDuration != b.SessionDuration {
		out = append(out, fmt.Sprintf("session duration %s vs %s", orUnknown(a.SessionDuration), orUnknown(b.SessionDuration)))
	}
	if a.PermissionsBoundary != b.PermissionsBoundary {
		out = append(out, fmt.Sprintf("permissions boundary %s vs %s", orNoneStr(a.PermissionsBoundary), orNoneStr(b.PermissionsBoundary)))
	}
	return out
}

// setDifference describes two string sets as "only in the source: …; only
// in the target: …", or returns "" when they are equal.
func setDifference(a, b []string) string {
	only := func(x, y []string) []string {
		var out []string
		for _, s := range x {
			if !contains(y, s) {
				out = append(out, s)
			}
		}
		sort.Strings(out)
		return out
	}
	var parts []string
	if d := only(a, b); len(d) > 0 {
		parts = append(parts, "only in the source: "+strings.Join(d, ", "))
	}
	if d := only(b, a); len(d) > 0 {
		parts = append(parts, "only in the target: "+strings.Join(d, ", "))
	}
	return strings.Join(parts, "; ")
}

func orNoneStr(s string) string {
	if s == "" {
		return "none"
	}
	return s
}
