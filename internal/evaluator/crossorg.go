package evaluator

import (
	"fmt"
	"sort"
	"strings"

	"github.com/MrShaaba/orgshift/internal/snapshot"
)

// networkingShareTypes are RAM resource types whose loss is a NO-GO.
var networkingShareTypes = map[string]bool{
	"ec2:TransitGateway": true, "ec2:Subnet": true, "route53resolver:ResolverRule": true, "ec2:IpamPool": true,
	"ec2:PrefixList": true, "ec2:TransitGatewayMulticastDomain": true, "route53resolver:FirewallRuleGroup": true,
	"ec2:LocalGatewayRouteTable": true, "networkmanager:CoreNetwork": true, "ec2:VerifiedAccessGroup": true,
	"ec2:TrafficMirrorTarget": true, "route53resolver:ResolverQueryLogConfig": true,
}

type shareScope struct {
	kind string // "organization", "ou", "account", "other"
	id   string
}

func classifyPrincipal(p string) shareScope {
	switch {
	case strings.Contains(p, ":organization/"):
		return shareScope{"organization", p[strings.LastIndex(p, "/")+1:]}
	case strings.Contains(p, ":ou/"):
		return shareScope{"ou", p[strings.LastIndex(p, "/")+1:]}
	case len(p) == 12 && strings.Trim(p, "0123456789") == "":
		return shareScope{"account", p}
	}
	return shareScope{"other", p}
}

// reaches reports whether a share principal covers an account positioned at
// the given path inside the given organization.
func reaches(sc shareScope, orgID, accountID string, path []snapshot.Node) bool {
	switch sc.kind {
	case "organization":
		return sc.id == orgID
	case "ou":
		for _, n := range path {
			if n.ID == sc.id {
				return true
			}
		}
		return false
	case "account":
		return sc.id == accountID
	}
	return false
}

func describeScopes(principals []string) string {
	var parts []string
	for _, p := range principals {
		sc := classifyPrincipal(p)
		switch sc.kind {
		case "organization":
			parts = append(parts, "organization "+sc.id)
		case "ou":
			parts = append(parts, "OU "+sc.id)
		case "account":
			parts = append(parts, "account "+sc.id)
		default:
			parts = append(parts, p)
		}
	}
	return strings.Join(parts, ", ")
}

func shareTypes(sh snapshot.ResourceShare) (types []string, networking bool) {
	seen := map[string]bool{}
	for _, r := range sh.Resources {
		if !seen[r.Type] {
			seen[r.Type] = true
			types = append(types, r.Type)
		}
		if networkingShareTypes[r.Type] {
			networking = true
		}
	}
	sort.Strings(types)
	return types, networking
}

func shareEvidence(side string, sh snapshot.ResourceShare) Evidence {
	var lines []string
	for _, r := range sh.Resources {
		lines = append(lines, r.Type+"  "+r.ARN)
	}
	return Evidence{Kind: "resource-share", Side: side, Reference: sh.ARN,
		Note: fmt.Sprintf("owner %s; principals: %s\n%s", sh.OwnerAccountID, describeScopes(sh.Principals), strings.Join(lines, "\n"))}
}

// evaluateShares compares which RAM shares reach the account before and after.
func (e *evaluation) evaluateShares(c *Check) {
	lost, gained, kept := 0, 0, 0
	for _, sh := range e.from.ResourceShares {
		if sh.OwnerAccountID == e.accountID {
			if e.crossOrg {
				for _, p := range sh.Principals {
					sc := classifyPrincipal(p)
					if sc.kind == "organization" || sc.kind == "ou" {
						types, _ := shareTypes(sh)
						c.add(Finding{Status: StatusReview, Title: fmt.Sprintf("Share %s owned by this account stops reaching %s", sh.Name, describeScopes([]string{p})),
							Detail:   "The account owns this share and offers it to its current organization. Once it leaves, the organization-scoped principals no longer resolve, so the consumers lose access to: " + strings.Join(types, ", ") + ".",
							Evidence: []Evidence{shareEvidence("source", sh)}})
						break
					}
				}
			}
			continue
		}
		before, after, uncertain := false, false, false
		for _, p := range sh.Principals {
			sc := classifyPrincipal(p)
			if reaches(sc, e.src.orgID, e.accountID, e.src.path) {
				before = true
			}
			if e.crossOrg {
				if sc.kind == "account" && sc.id == e.accountID {
					uncertain = true
				}
				continue
			}
			if reaches(sc, e.dst.orgID, e.accountID, e.dst.path) {
				after = true
			}
		}
		if !before {
			continue
		}
		types, networking := shareTypes(sh)
		switch {
		case after:
			kept++
		case uncertain:
			status := StatusReview
			c.add(Finding{Status: status, Title: fmt.Sprintf("Share %s is shared with this account directly; confirm it survives leaving the organization", sh.Name),
				Detail: fmt.Sprintf("Shared by account %s with the account ID as principal. Outside the organization the share must allow external principals (currently %t) and the association may need to be re-accepted. Resource types: %s.",
					sh.OwnerAccountID, sh.AllowExternalPrincipals, strings.Join(types, ", ")),
				Evidence: []Evidence{shareEvidence("source", sh)}})
			lost++
		default:
			status := StatusReview
			why := "no longer reaches the account at its new position"
			if e.crossOrg {
				why = "is scoped to the source organization or one of its OUs and stops applying when the account leaves"
			}
			if networking {
				status = StatusNoGo
			}
			title := fmt.Sprintf("Share %s is lost: %s", sh.Name, strings.Join(types, ", "))
			if networking {
				title = fmt.Sprintf("Networking share %s is lost: %s", sh.Name, strings.Join(types, ", "))
			}
			c.add(Finding{Status: status, Title: title,
				Detail: fmt.Sprintf("Shared by account %s with %s. It %s. Anything attached to or routed through these resources from this account breaks unless the owner re-shares them with the account directly (and, for a different organization, enables external principals).",
					sh.OwnerAccountID, describeScopes(sh.Principals), why),
				Evidence: []Evidence{shareEvidence("source", sh)}})
			lost++
		}
	}
	if e.crossOrg {
		for _, sh := range e.to.ResourceShares {
			for _, p := range sh.Principals {
				if reaches(classifyPrincipal(p), e.dst.orgID, e.accountID, e.dst.path) {
					types, _ := shareTypes(sh)
					gained++
					c.add(Finding{Status: StatusInfo, Title: fmt.Sprintf("Share %s becomes available after the move: %s", sh.Name, strings.Join(types, ", ")),
						Detail:   fmt.Sprintf("Shared by account %s with %s in the target organization. New attachments must be created by hand; nothing is attached automatically.", sh.OwnerAccountID, describeScopes(sh.Principals)),
						Evidence: []Evidence{shareEvidence("target", sh)}})
					break
				}
			}
		}
	} else {
		for _, sh := range e.to.ResourceShares {
			if sh.OwnerAccountID == e.accountID {
				continue
			}
			before, after := false, false
			for _, p := range sh.Principals {
				sc := classifyPrincipal(p)
				before = before || reaches(sc, e.src.orgID, e.accountID, e.src.path)
				after = after || reaches(sc, e.dst.orgID, e.accountID, e.dst.path)
			}
			if after && !before {
				types, _ := shareTypes(sh)
				gained++
				c.add(Finding{Status: StatusInfo, Title: fmt.Sprintf("Share %s becomes available after the move: %s", sh.Name, strings.Join(types, ", ")),
					Detail:   fmt.Sprintf("Shared by account %s with %s.", sh.OwnerAccountID, describeScopes(sh.Principals)),
					Evidence: []Evidence{shareEvidence("target", sh)}})
			}
		}
	}
	sortFindings(c.Findings)
	c.Summary = fmt.Sprintf("%d share(s) kept, %d lost or uncertain, %d newly available.", kept, lost, gained)
}

// evaluateOrgServices covers delegated administration, the org trail, Config
// aggregation, StackSets and membership prerequisites.
func (e *evaluation) evaluateOrgServices(c *Check) {
	srcOUs := snapshot.OUPath(e.src.path)
	dstOUs := snapshot.OUPath(e.dst.path)
	inList := func(list []string, ids ...string) bool {
		for _, l := range list {
			for _, id := range ids {
				if l == id {
					return true
				}
			}
		}
		return false
	}

	// StackSets follow OU membership in both kinds of move.
	for _, ss := range e.from.StackSets {
		if ss.PermissionModel != "SERVICE_MANAGED" {
			continue
		}
		before := inList(ss.TargetOUs, srcOUs...) || inList(ss.TargetAccounts, e.accountID)
		after := !e.crossOrg && (inList(ss.TargetOUs, dstOUs...) || inList(ss.TargetAccounts, e.accountID))
		ev := Evidence{Kind: "stackset", Side: "source", Reference: ss.Name,
			Note: fmt.Sprintf("admin %s; targets OUs %s accounts %s; regions %s; auto-deployment %t; retain on removal %t",
				ss.AdministrationAccountID, strings.Join(ss.TargetOUs, ","), strings.Join(ss.TargetAccounts, ","), strings.Join(ss.Regions, ","), ss.AutoDeployment, ss.RetainStacksOnAccountRemoval)}
		switch {
		case before && !after:
			what := "deleted from the account"
			if ss.RetainStacksOnAccountRemoval {
				what = "detached but the stacks are retained in the account (retain_stacks_on_account_removal)"
			}
			c.add(Finding{Status: StatusReview, Title: fmt.Sprintf("StackSet %s stops targeting the account; stack instances are %s", ss.Name, what),
				Detail:   "Service-managed StackSets deploy by OU. " + firstSentence(ss.Description) + " Check what those stacks provide (roles, Config recorders, GuardDuty membership) before moving.",
				Evidence: []Evidence{ev}})
		case !before && after:
			c.add(Finding{Status: StatusInfo, Title: fmt.Sprintf("StackSet %s starts targeting the account", ss.Name),
				Detail: firstSentence(ss.Description) + " Stack instances are created automatically when auto-deployment is on.", Evidence: []Evidence{ev}})
		}
	}
	if e.crossOrg {
		for _, ss := range e.to.StackSets {
			if ss.PermissionModel == "SERVICE_MANAGED" && (inList(ss.TargetOUs, dstOUs...) || inList(ss.TargetAccounts, e.accountID)) {
				c.add(Finding{Status: StatusInfo, Title: fmt.Sprintf("StackSet %s in the target organization starts targeting the account", ss.Name),
					Detail:   firstSentence(ss.Description) + " Stack instances are created automatically when auto-deployment is on.",
					Evidence: []Evidence{{Kind: "stackset", Side: "target", Reference: ss.Name, Note: fmt.Sprintf("admin %s; targets OUs %s; regions %s", ss.AdministrationAccountID, strings.Join(ss.TargetOUs, ","), strings.Join(ss.Regions, ","))}}})
			}
		}
	}

	if !e.crossOrg {
		if len(c.Findings) == 0 {
			c.Summary = "Same organization: delegated administration, the org trail and Config aggregation are unchanged."
		} else {
			c.Summary = "Same organization: only StackSet targeting changes."
		}
		sortFindings(c.Findings)
		return
	}

	for _, d := range e.from.DelegatedAdministrators {
		if d.AccountID == e.accountID {
			c.add(Finding{Status: StatusReview, Title: "Account is the delegated administrator for " + d.ServicePrincipal,
				Detail:   "Delegated administration is tied to organization membership. Leaving the organization removes the delegation, and the service's organization-wide view (and often its member enrolment) with it. Re-delegate to another account before the move.",
				Evidence: []Evidence{{Kind: "delegated-admin", Side: "source", Reference: d.ServicePrincipal, Note: "delegated " + d.DelegationDate}}})
		}
	}
	for _, tr := range e.from.OrganizationTrails {
		c.add(Finding{Status: StatusReview, Title: "Organization trail " + tr.Name + " stops logging this account",
			Detail:   fmt.Sprintf("The trail is owned by account %s and covers members of the source organization only. After the move the account has no CloudTrail coverage from it; the target organization's trail (if any) takes over once the account joins.", tr.OwnerAccountID),
			Evidence: []Evidence{{Kind: "org-trail", Side: "source", Reference: tr.ARN, Note: "bucket " + tr.S3BucketName + ", home region " + tr.HomeRegion}}})
		if tr.OwnerAccountID == e.accountID {
			c.add(Finding{Status: StatusNoGo, Title: "Account owns the organization trail " + tr.Name,
				Detail:   "The organization trail lives in this account. Leaving breaks logging for every other account in the source organization. Move the trail first.",
				Evidence: []Evidence{{Kind: "org-trail", Side: "source", Reference: tr.ARN}}})
		}
	}
	for _, tr := range e.to.OrganizationTrails {
		c.add(Finding{Status: StatusInfo, Title: "Organization trail " + tr.Name + " in the target starts covering the account",
			Detail:   fmt.Sprintf("Owned by account %s, delivering to %s.", tr.OwnerAccountID, tr.S3BucketName),
			Evidence: []Evidence{{Kind: "org-trail", Side: "target", Reference: tr.ARN}}})
	}
	for _, ag := range e.from.ConfigAggregators {
		if !ag.OrganizationSource {
			continue
		}
		c.add(Finding{Status: StatusReview, Title: "Config aggregator " + ag.Name + " loses this account",
			Detail:   fmt.Sprintf("The organization-sourced aggregator in account %s (%s) stops receiving this account's configuration and compliance data when it leaves.", ag.AccountID, ag.Region),
			Evidence: []Evidence{{Kind: "config-aggregator", Side: "source", Reference: ag.Name}}})
		if ag.AccountID == e.accountID {
			c.add(Finding{Status: StatusNoGo, Title: "Account hosts the organization Config aggregator " + ag.Name,
				Detail:   "The aggregator lives in this account; leaving breaks aggregation for the whole source organization.",
				Evidence: []Evidence{{Kind: "config-aggregator", Side: "source", Reference: ag.Name}}})
		}
	}
	for _, ag := range e.to.ConfigAggregators {
		if ag.OrganizationSource {
			c.add(Finding{Status: StatusInfo, Title: "Config aggregator " + ag.Name + " in the target starts receiving the account",
				Detail: fmt.Sprintf("Hosted in account %s (%s).", ag.AccountID, ag.Region), Evidence: []Evidence{{Kind: "config-aggregator", Side: "target", Reference: ag.Name}}})
		}
	}
	srcSvc := map[string]bool{}
	for _, s := range e.from.TrustedAccessServices {
		srcSvc[s] = true
	}
	var missing []string
	for _, s := range e.from.TrustedAccessServices {
		if !contains(e.to.TrustedAccessServices, s) {
			missing = append(missing, s)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		c.add(Finding{Status: StatusReview, Title: "Trusted access is not enabled in the target for: " + strings.Join(missing, ", "),
			Detail: "Organization-integrated features of these services (for example organization-wide GuardDuty, RAM sharing with the organization, service-managed StackSets) are not available in the target organization until trusted access is enabled there."})
	}
	for _, d := range e.to.DelegatedAdministrators {
		c.add(Finding{Status: StatusInfo, Title: fmt.Sprintf("In the target, %s administers %s", d.AccountID, d.ServicePrincipal),
			Detail: "The account will be enrolled by that administrator's configuration once it joins."})
	}
	if e.account.ID == e.from.Organization.ManagementAccountID {
		c.add(Finding{Status: StatusNoGo, Title: "Account is the management account of the source organization",
			Detail: "A management account cannot leave its organization. The organization would have to be deleted first."})
	}
	c.add(Finding{Status: StatusReview, Title: "Standalone account prerequisites and invitation",
		Detail: "Before it can leave, the account needs its own contact information, a payment method, a support plan choice and completed identity verification. It then has to be invited by the target management account and accept the invitation. SCPs in the source that deny organizations:LeaveOrganization must be lifted for the move."})
	sortFindings(c.Findings)
	c.Summary = fmt.Sprintf("Cross-organization move: %d item(s) to settle before the account leaves.", countStatus(c.Findings, StatusReview)+countStatus(c.Findings, StatusNoGo))
}

func countStatus(fs []Finding, s Status) int {
	n := 0
	for _, f := range fs {
		if f.Status == s {
			n++
		}
	}
	return n
}

func firstSentence(s string) string {
	if s == "" {
		return ""
	}
	if !strings.HasSuffix(s, ".") {
		s += "."
	}
	return s
}
