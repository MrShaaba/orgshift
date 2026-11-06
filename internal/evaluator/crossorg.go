package evaluator

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/MrShaaba/orgshift/internal/snapshot"
)

// Documentation the cross-organization findings were verified against.
const (
	refRemoveAccount      = "https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_accounts_remove.html"
	refInvitations        = "https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_accounts_invites.html"
	refDeleteOrganization = "https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_org_delete.html"
	refDecommission       = "https://docs.aws.amazon.com/controltower/latest/userguide/decommission-landing-zone.html"
	refRAMSharing         = "https://docs.aws.amazon.com/ram/latest/userguide/getting-started-sharing.html"
	refTGWUnshare         = "https://docs.aws.amazon.com/vpc/latest/tgw/transit-gateway-share.html#transit-gateway-unshare"
	refSubnetUnshare      = "https://docs.aws.amazon.com/vpc/latest/userguide/vpc-sharing-share-subnet-working-with.html#vpc-sharing-stop-share-subnet"
	refResolverSharing    = "https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/resolver-rules-managing.html#resolver-rules-managing-sharing"
	refShareable          = "https://docs.aws.amazon.com/ram/latest/userguide/shareable.html"
)

// The RAM behaviour model: what happens to a consumer when a share stops
// reaching it, per resource type. RAM removes the consumer's access to the
// shared resource (its control plane: describing, creating, modifying);
// whether traffic that already flows through the resource stops is a
// property of the service, not of RAM, and is only claimed where the
// service documentation says so. Everything else is "unverified" and
// reported for review, never as a confirmed outage and never as fine.
const (
	RAMModelVersion   = "2026-11-01"
	RAMModelReference = refRAMSharing
)

const (
	dataPlaneContinues  = "continues"
	dataPlaneStops      = "stops"
	dataPlaneUnverified = "unverified"
)

type shareBehaviour struct {
	networking bool
	dataPlane  string
	// detail is the documented behaviour after unsharing.
	detail string
	// orgOnly resources can only be shared inside one organization, so a
	// cross-organization move cannot be fixed by re-sharing.
	orgOnly   bool
	reference string
	// dependentActions are actions in use that need the share's control
	// plane; one of them in use turns the loss into a blocker.
	dependentActions []string
	// possibleActions are actions in use that may or may not go through the
	// shared resource; they are listed as potentially affected.
	possibleActions []string
}

var shareBehaviours = map[string]shareBehaviour{
	"ec2:TransitGateway": {networking: true, dataPlane: dataPlaneContinues, reference: refTGWUnshare,
		detail:           "existing transit gateway attachments remain functional; the account can no longer describe the transit gateway or create new attachments, and either side can delete the attachments",
		dependentActions: []string{"ec2:CreateTransitGatewayVpcAttachment", "ec2:CreateTransitGatewayPeeringAttachment", "ec2:CreateTransitGatewayConnect", "ec2:CreateTransitGatewayConnectPeer", "ec2:CreateTransitGatewayMulticastDomain", "ec2:ModifyTransitGatewayVpcAttachment"},
		possibleActions:  []string{"ec2:DescribeTransitGateways", "ec2:DescribeTransitGatewayAttachments", "ec2:DescribeTransitGatewayVpcAttachments"}},
	"ec2:Subnet": {networking: true, dataPlane: dataPlaneContinues, orgOnly: true, reference: refSubnetUnshare,
		detail:          "existing participant resources continue to run in the subnet; no new resources can be created in it, while existing ones can still be modified, described and deleted (subnets can only be shared inside one organization)",
		possibleActions: []string{"ec2:RunInstances", "ec2:CreateNetworkInterface", "rds:CreateDBInstance", "rds:CreateDBCluster", "lambda:CreateFunction", "elasticloadbalancing:CreateLoadBalancer", "ecs:RunTask", "eks:CreateCluster", "autoscaling:CreateAutoScalingGroup", "redshift:CreateCluster"}},
	"route53resolver:ResolverRule": {networking: true, dataPlane: dataPlaneStops, reference: refResolverSharing,
		detail: "the rule's associations with the account's VPCs are removed and Resolver answers those queries from the remaining rules at once (an OU-scoped rule keeps its associations only when it is also shared with the destination OU)"},
	"ec2:PrefixList":                         {networking: true, dataPlane: dataPlaneUnverified, reference: refShareable},
	"ec2:IpamPool":                           {networking: true, dataPlane: dataPlaneUnverified, reference: refShareable, possibleActions: []string{"ec2:AllocateIpamPoolCidr", "ec2:CreateVpc"}},
	"ec2:TransitGatewayMulticastDomain":      {networking: true, dataPlane: dataPlaneUnverified, reference: refShareable},
	"route53resolver:FirewallRuleGroup":      {networking: true, dataPlane: dataPlaneUnverified, reference: refShareable},
	"route53resolver:ResolverQueryLogConfig": {networking: true, dataPlane: dataPlaneUnverified, reference: refShareable},
	"ec2:LocalGatewayRouteTable":             {networking: true, dataPlane: dataPlaneUnverified, reference: refShareable},
	"networkmanager:CoreNetwork":             {networking: true, dataPlane: dataPlaneUnverified, reference: refShareable},
	"ec2:VerifiedAccessGroup":                {networking: true, dataPlane: dataPlaneUnverified, reference: refShareable},
	"ec2:TrafficMirrorTarget":                {networking: true, dataPlane: dataPlaneUnverified, reference: refShareable},
	"ec2:SecurityGroup":                      {networking: true, dataPlane: dataPlaneUnverified, orgOnly: true, reference: refShareable},
}

// RAMModel describes the model for the result's model list.
func RAMModel() ModelRef {
	return ModelRef{ID: "ram-behaviour", Version: RAMModelVersion, Reference: RAMModelReference,
		Note: "access through a share ends when the account leaves the organization or the OU the share is addressed to, unless the share was created with RetainSharingOnAccountLeaveOrganization for the account itself; what happens to traffic already flowing is modelled per resource type (transit gateways and subnets keep existing attachments and resources working, Resolver rules stop answering, others unverified)"}
}

func behaviourOf(resourceType string) shareBehaviour {
	if b, ok := shareBehaviours[resourceType]; ok {
		return b
	}
	return shareBehaviour{dataPlane: dataPlaneUnverified, reference: refShareable}
}

// networkingShareTypes answers the older question "is this a networking
// share"; it is derived from the behaviour model.
func isNetworkingType(t string) bool { return behaviourOf(t).networking }

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
		if isNetworkingType(r.Type) {
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
	flags := fmt.Sprintf("allow external principals %t", sh.AllowExternalPrincipals)
	if sh.RetainSharingOnAccountLeave {
		flags += ", retains sharing when the account leaves the organization"
	}
	return Evidence{Kind: "resource-share", Side: side, Reference: sh.ARN,
		Note: fmt.Sprintf("owner %s; principals: %s; %s\n%s", sh.OwnerAccountID, describeScopes(sh.Principals), flags, strings.Join(lines, "\n"))}
}

// lostShareImpact decides how bad losing a share is for this account from
// the behaviour model and the actions in use, and explains it per resource
// type. The status is NO-GO when a resource type's data plane is documented
// to stop, or when an action in use needs the share's control plane;
// otherwise REVIEW.
func (e *evaluation) lostShareImpact(sh snapshot.ResourceShare) (status Status, lines []string, refs []string) {
	status = StatusReview
	usage := e.usage
	inUse := func(action string) (exact bool, wild bool) {
		for _, a := range usage.Actions {
			if strings.EqualFold(a.Action, action) {
				return true, false
			}
			if strings.HasSuffix(a.Action, ":*") && strings.EqualFold(serviceOf(a.Action), serviceOf(action)) {
				wild = true
			}
		}
		return false, wild
	}
	types, _ := shareTypes(sh)
	seenRef := map[string]bool{}
	for _, t := range types {
		b := behaviourOf(t)
		if b.reference != "" && !seenRef[b.reference] {
			seenRef[b.reference] = true
			refs = append(refs, b.reference)
		}
		var needed, possible, wildcards []string
		for _, a := range b.dependentActions {
			if exact, wild := inUse(a); exact {
				needed = append(needed, a)
			} else if wild {
				wildcards = append(wildcards, a)
			}
		}
		for _, a := range b.possibleActions {
			if exact, _ := inUse(a); exact {
				possible = append(possible, a)
			}
		}
		switch b.dataPlane {
		case dataPlaneStops:
			status = StatusNoGo
			lines = append(lines, fmt.Sprintf("%s: traffic is affected at once, %s.", t, b.detail))
		case dataPlaneContinues:
			line := fmt.Sprintf("%s: %s.", t, b.detail)
			if len(needed) > 0 {
				status = StatusNoGo
				line += fmt.Sprintf(" The account uses %s, which needs the share: that stops working.", strings.Join(needed, ", "))
			}
			if len(wildcards) > 0 {
				line += fmt.Sprintf(" The usage list has a service-wide entry, so it is not known whether %s are used.", strings.Join(wildcards, ", "))
			}
			if len(possible) > 0 {
				line += fmt.Sprintf(" Potentially affected: %s in use may target the shared resources; confirm.", strings.Join(possible, ", "))
			}
			lines = append(lines, line)
		default:
			line := fmt.Sprintf("%s: what happens to resources already using it is not verified against the service documentation; treat it as potentially affected.", t)
			if len(possible) > 0 {
				line += fmt.Sprintf(" In use and potentially affected: %s.", strings.Join(possible, ", "))
			}
			lines = append(lines, line)
		}
		if b.orgOnly && e.crossOrg {
			lines = append(lines, fmt.Sprintf("%s can only be shared inside one organization, so it cannot be re-shared with the account once it has left.", t))
		}
	}
	return status, lines, refs
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
							Detail:     "The account owns this share and offers it to its current organization. Once it leaves, the organization-scoped principals no longer resolve, so the consumers lose access to: " + strings.Join(types, ", ") + ".",
							Evidence:   []Evidence{shareEvidence("source", sh)},
							References: []string{refRAMSharing}})
						break
					}
				}
			}
			continue
		}
		before, after, retained := false, false, false
		for _, p := range sh.Principals {
			sc := classifyPrincipal(p)
			if reaches(sc, e.src.orgID, e.accountID, e.src.path) {
				before = true
			}
			if e.crossOrg {
				// Leaving the organization ends access through every principal
				// scope, except a share addressed to the account itself that
				// was created to retain sharing when the account leaves.
				if sc.kind == "account" && sc.id == e.accountID && sh.RetainSharingOnAccountLeave && sh.AllowExternalPrincipals {
					retained = true
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
		types, _ := shareTypes(sh)
		switch {
		case after:
			kept++
		case retained:
			kept++
			c.add(Finding{Status: StatusInfo, Title: fmt.Sprintf("Share %s keeps reaching the account after it leaves: %s", sh.Name, strings.Join(types, ", ")),
				Detail:     fmt.Sprintf("Account %s shared it with the account ID as principal and created the share with RetainSharingOnAccountLeaveOrganization, so RAM keeps the account as a principal when it leaves; the share then arrives as an invitation that has to be accepted (seven days for networking resource types, twelve hours otherwise).", sh.OwnerAccountID),
				Evidence:   []Evidence{shareEvidence("source", sh)},
				References: []string{refRAMSharing}})
		default:
			lost++
			status, lines, refs := e.lostShareImpact(sh)
			why := "no longer reaches the account at its new position"
			switch {
			case e.crossOrg && containsScope(sh.Principals, "account", e.accountID):
				why = "is addressed to the account ID, but RAM ends access to shares inside the organization when the account leaves (the share was not created with RetainSharingOnAccountLeaveOrganization)"
			case e.crossOrg:
				why = "is scoped to the source organization or one of its OUs and stops applying when the account leaves"
			}
			_, networking := shareTypes(sh)
			title := fmt.Sprintf("Share %s is lost: %s", sh.Name, strings.Join(types, ", "))
			if networking {
				title = fmt.Sprintf("Networking share %s is lost: %s", sh.Name, strings.Join(types, ", "))
			}
			fix := " Ask the owner to re-share the resources with the account directly before the move"
			if e.crossOrg {
				fix += ", with external principals allowed, and accept the invitation after the move"
			}
			fix += "."
			detail := fmt.Sprintf("Shared by account %s with %s. It %s. What the documentation says happens: %s%s",
				sh.OwnerAccountID, describeScopes(sh.Principals), why, strings.Join(lines, " "), fix)
			c.add(Finding{Status: status, Title: title, Detail: detail,
				Evidence: []Evidence{shareEvidence("source", sh)}, References: append([]string{refRAMSharing}, refs...)})
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
	c.Summary = fmt.Sprintf("%d share(s) kept, %d lost, %d newly available (RAM behaviour model %s).", kept, lost, gained, RAMModelVersion)
}

func containsScope(principals []string, kind, id string) bool {
	for _, p := range principals {
		if sc := classifyPrincipal(p); sc.kind == kind && sc.id == id {
			return true
		}
	}
	return false
}

// minimumAccountAge is how old an account created by Organizations must be
// before it can be removed.
const minimumAccountAge = 4 * 24 * time.Hour

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
			what := "stack instances are deleted from the account"
			switch {
			case !ss.AutoDeployment:
				what = "with automatic deployment off, what happens to its stack instances is not documented"
			case ss.RetainStacksOnAccountRemoval:
				what = "stack instances are detached but the stacks are retained in the account (retain_stacks_on_account_removal)"
			}
			detail := "Service-managed StackSets deploy by OU. " + firstSentence(ss.Description) + " Check what those stacks provide (roles, Config recorders, GuardDuty membership) before moving."
			if e.from.WorkloadsFor(e.accountID) != nil {
				detail += " The workloads check lists the instances found in this account and what each contains."
			}
			c.add(Finding{Status: StatusReview, Title: fmt.Sprintf("StackSet %s stops targeting the account; %s", ss.Name, what),
				Detail: detail, Evidence: []Evidence{ev}, References: []string{refAutoDeployment}})
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
			c.add(Finding{Status: StatusNoGo, Title: "Account is the delegated administrator for " + d.ServicePrincipal,
				Detail:     "If the account is a delegated administrator, the delegated administrator permissions have to be deregistered before it is migrated, whatever the procedure: a direct transfer, RemoveAccountFromOrganization and LeaveOrganization all fail until then (or until another account that stays is made the administrator). Deregister through the service's console or API, or with the Organizations deregister-delegated-administrator call where the service supports it. The service's organization-wide view, and often its member enrolment, moves with the role.",
				Evidence:   []Evidence{{Kind: "delegated-admin", Side: "source", Reference: d.ServicePrincipal, Note: "delegated " + d.DelegationDate}},
				References: []string{refAccountMigration, refRemoveAccount}})
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
	e.transferFindings(c)
	if len(e.account.Tags) > 0 {
		keys := make([]string, 0, len(e.account.Tags))
		for k := range e.account.Tags {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		c.add(Finding{Status: StatusInfo, Title: fmt.Sprintf("The %d tag(s) on the account are deleted when it leaves: %s", len(keys), strings.Join(keys, ", ")),
			Detail:     "Organizations deletes every tag attached to the account itself when it leaves. Anything that selects accounts by these tags (cost allocation, automation, SCP conditions on aws:PrincipalTag do not use them, but Organizations tag policies and reporting do) no longer sees the account. Re-tag it in the target organization.",
			References: []string{refRemoveAccount}})
	}
	sortFindings(c.Findings)
	how := map[string]string{TransferDirect: "by direct transfer", TransferLeaveAndRejoin: "by leaving and rejoining", TransferManagementAccount: "of a management account"}[e.transferMethod()]
	c.Summary = fmt.Sprintf("Cross-organization move %s: %d item(s) to settle before the account changes organization.", how, countStatus(c.Findings, StatusReview)+countStatus(c.Findings, StatusNoGo))
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
