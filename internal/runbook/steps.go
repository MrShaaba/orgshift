package runbook

import (
	"fmt"
	"strings"

	"github.com/MrShaaba/orgshift/internal/evaluator"
	"github.com/MrShaaba/orgshift/internal/policy"
	"github.com/MrShaaba/orgshift/internal/snapshot"
)

func actionMatches(patterns []string, action string) bool {
	return policy.MatchAction(patterns, action) == policy.Yes
}

// describeRequest renders a finding's request: "ec2:RunInstances by
// 999999999999 in us-east-1, ap-southeast-1".
func describeRequest(f evaluator.Finding) string {
	s := f.Action
	if f.Principal != "" {
		s += " by " + f.Principal
	}
	if len(f.Regions) > 0 {
		s += " in " + strings.Join(f.Regions, ", ")
	}
	return s
}

// targetEvidence returns the evidence from the target side that explains a
// policy finding.
func targetEvidence(f evaluator.Finding) *evaluator.Evidence {
	for i := range f.Evidence {
		if f.Evidence[i].Side == "target" && (f.Evidence[i].Kind == "policy-statement" || f.Evidence[i].Kind == "implicit-deny") {
			return &f.Evidence[i]
		}
	}
	return nil
}

// policySteps turns the SCP or RCP findings into one step per policy
// statement (or per level without an allow), listing every request it
// affects.
func (b *builder) policySteps(c evaluator.Check) {
	typ := "SCP"
	if c.ID == "rcp" {
		typ = "RCP"
	}
	type group struct {
		ev       *evaluator.Evidence
		status   evaluator.Status
		findings []evaluator.Finding
	}
	groups := map[string]*group{}
	var order []string
	for _, f := range c.Findings {
		if f.Status != evaluator.StatusNoGo && f.Status != evaluator.StatusReview {
			continue
		}
		if hasEvidence(f, "coverage") {
			continue // handled by coverageSteps
		}
		if ev := firstEvidence(f, "policy-unparseable"); ev != nil && f.Action == "" {
			// A malformed policy on a chain: nothing behind it is decided
			// until the document is corrected and collected again.
			where, side := b.targetMgmt(), "destination"
			if ev.Side == "source" {
				where, side = b.sourceMgmt(), "source"
			}
			b.add(PhaseBefore, Step{Kind: KindPolicy, Status: f.Status, Title: fmt.Sprintf("Correct or replace the malformed %s %s, then collect again", typ, ev.PolicyName), Check: c.ID, Finding: f.Title, Where: where,
				Detail: f.Detail + " The actions that meet this policy are listed as REVIEW below for the same reason; they are decided once the document is well formed.",
				Commands: []string{
					fmt.Sprintf("aws organizations describe-policy --policy-id %s --query Policy.Content --output text > %s.json", ev.PolicyID, ev.PolicyID),
					fmt.Sprintf("# correct the statement named above, then: aws organizations update-policy --policy-id %s --content file://%s.json", ev.PolicyID, ev.PolicyID),
					fmt.Sprintf("orgshift collect --config orgshift.yaml --side %s --out <%s snapshot>", side, map[string]string{"source": "source", "destination": "target"}[side]),
				}, Evidence: f.Evidence})
			continue
		}
		if f.Action == "" {
			b.add(PhaseBefore, Step{Kind: KindInput, Status: f.Status, Title: f.Title, Detail: f.Detail, Check: c.ID, Finding: f.Title,
				Commands: []string{fmt.Sprintf("orgshift simulate --from <source snapshot> --to <target snapshot> --account %s --target-ou %s --last-accessed <get-service-last-accessed-details output>", b.acct, b.res.Subject.TargetOUID)}})
			continue
		}
		b.flagged = appendUnique(b.flagged, describeRequest(f))
		ev := targetEvidence(f)
		key := string(f.Status)
		if ev != nil {
			key += "|" + ev.Kind + "|" + ev.PolicyID + "|" + ev.Statement + "|" + ev.Level
		}
		g, ok := groups[key]
		if !ok {
			g = &group{ev: ev, status: f.Status}
			groups[key] = g
			order = append(order, key)
		}
		g.findings = append(g.findings, f)
	}
	for _, key := range order {
		g := groups[key]
		b.add(PhaseBefore, b.policyStep(typ, c.ID, g.status, g.ev, g.findings))
	}
}

func (b *builder) policyStep(typ, checkID string, status evaluator.Status, ev *evaluator.Evidence, fs []evaluator.Finding) Step {
	var what, actions, principals []string
	for _, f := range fs {
		what = append(what, describeRequest(f))
		actions = appendUnique(actions, f.Action)
		if f.Principal != "" {
			principals = appendUnique(principals, f.Principal)
		}
	}
	s := Step{Kind: KindPolicy, Status: status, Check: checkID, Actions: actions, Where: b.targetMgmt()}
	if len(fs) == 1 {
		s.Finding, s.Principal, s.Resource, s.Regions = fs[0].Title, fs[0].Principal, fs[0].Resource, fs[0].Regions
	} else {
		s.Finding = fmt.Sprintf("%d findings with the same cause", len(fs))
	}
	count := plural(len(fs), "request", "requests")
	if len(principals) == 0 {
		count = plural(len(fs), "action", "actions")
	}
	if ev == nil {
		s.Kind = KindDecision
		s.Title = fmt.Sprintf("Review %s the %s check flagged without policy evidence", count, typ)
		s.Detail = strings.Join(what, "; ") + "."
		return s
	}
	s.Evidence = []evaluator.Evidence{*ev}
	if ev.Kind == "implicit-deny" {
		s.Title = fmt.Sprintf("No %s at %s allows %s the account uses", typ, ev.Level, count)
		s.Detail = fmt.Sprintf("%s. Affected: %s. The change to review: add the actions to an Allow statement of a policy attached at that level, or attach a policy there that allows them (FullAWSAccess if the level is meant to be unrestricted). Otherwise the callers have to stop using them before the move.",
			ev.Note, strings.Join(what, "; "))
		s.Commands = []string{fmt.Sprintf("aws organizations list-policies-for-target --target-id %s --filter %s", idInParens(ev.Level), policyTypeName(typ))}
		return s
	}
	guardrail := strings.HasPrefix(ev.Note, "Control Tower guardrail")
	var change string
	switch {
	case guardrail:
		change = fmt.Sprintf("%s is a Control Tower guardrail: do not edit the SCP. Disable the control on %s in the Control Tower console, pick a target OU without it, or stop using the actions.", ev.PolicyName, ev.Level)
	case typ == "RCP":
		change = fmt.Sprintf("edit statement %s so these principals are exempt (for example list their organization in the aws:PrincipalOrgID condition, or exempt the resource), detach %s from %s, or move the callers inside the target organization.", ev.Statement, ev.PolicyName, ev.Level)
	default:
		change = fmt.Sprintf("edit statement %s so it no longer covers account %s (for example a Condition on aws:PrincipalAccount, or a narrower Action or Resource list), detach %s from %s, or stop using the actions before the move.", ev.Statement, b.acct, ev.PolicyName, ev.Level)
	}
	if status == evaluator.StatusNoGo {
		s.Title = fmt.Sprintf("%s %s / %s denies %s after the move", typ, ev.PolicyName, ev.Statement, count)
		s.Detail = fmt.Sprintf("Attached at %s in the target organization. Allowed today; after the move it denies: %s. The change to review: %s", ev.Level, strings.Join(what, "; "), change)
	} else {
		s.Kind = KindDecision
		s.Title = fmt.Sprintf("Decide whether %s %s / %s applies to %s", typ, ev.PolicyName, ev.Statement, count)
		s.Detail = fmt.Sprintf("Attached at %s. Cannot be decided offline: %s. Affected: %s. Check the condition against the real callers; if it matches, treat this as a blocker and %s If it does not, record the decision here.", ev.Level, ev.Note, strings.Join(what, "; "), change)
	}
	s.Commands = []string{
		fmt.Sprintf("aws organizations describe-policy --policy-id %s --query Content --output text", ev.PolicyID),
	}
	if !guardrail {
		s.Commands = append(s.Commands, fmt.Sprintf("# after editing the document by hand:\naws organizations update-policy --policy-id %s --content file://%s.json", ev.PolicyID, ev.PolicyName))
	}
	return s
}

func policyTypeName(short string) string {
	switch short {
	case "RCP":
		return string(snapshot.PolicyTypeRCP)
	case "TAG":
		return string(snapshot.PolicyTypeTag)
	case "BACKUP":
		return string(snapshot.PolicyTypeBackup)
	}
	return string(snapshot.PolicyTypeSCP)
}

// tagSteps: enforced non-compliance is fixed before the move, the rest after.
func (b *builder) tagSteps(c evaluator.Check) {
	for _, f := range c.Findings {
		if hasEvidence(f, "coverage") {
			continue // handled by coverageSteps
		}
		ev := firstEvidence(f, "tag-compliance")
		switch {
		case f.Status == evaluator.StatusReview && ev == nil:
			b.add(PhaseBefore, Step{Kind: KindInput, Status: f.Status, Title: f.Title, Detail: f.Detail, Check: c.ID, Finding: f.Title, Where: b.accountWhere(),
				Commands: []string{"aws resourcegroupstaggingapi get-resources --resources-per-page 100   # sample to add as usage.tagged_resources"}})
		case f.Status == evaluator.StatusReview:
			arns := strings.Split(ev.Note, "\n")
			b.add(PhaseBefore, Step{Kind: KindTags, Status: f.Status, Title: "Re-tag before the move: " + f.Title, Check: c.ID, Finding: f.Title, Where: b.accountWhere(),
				Detail:   f.Detail + " Do it before the move: afterwards the target tag policy rejects non-compliant tag operations on these resource types, so the fix itself is blocked.",
				Resource: strings.Join(arns, ", "),
				Commands: []string{fmt.Sprintf("aws resourcegroupstaggingapi tag-resources --resource-arn-list %s --tags <Key>=<allowed value>", strings.Join(arns, " "))},
				Evidence: f.Evidence})
		case f.Status == evaluator.StatusInfo && ev != nil:
			b.add(PhaseAfter, Step{Kind: KindTags, Status: f.Status, Title: "Tag to the target standard: " + f.Title, Check: c.ID, Finding: f.Title, Where: b.accountWhere(),
				Detail: f.Detail + " Not enforced, so this can wait until after the move.", Evidence: f.Evidence})
		}
	}
}

// shareInfo looks a share up in the snapshots, falling back to the evidence.
func (b *builder) shareInfo(ev *evaluator.Evidence) (owner string, scopes string, types []string) {
	for _, snap := range []*snapshot.Snapshot{b.from, b.to} {
		if snap == nil {
			continue
		}
		for _, sh := range snap.ResourceShares {
			if sh.ARN == ev.Reference {
				seen := map[string]bool{}
				for _, r := range sh.Resources {
					if !seen[r.Type] {
						seen[r.Type] = true
						types = append(types, r.Type)
					}
				}
				return sh.OwnerAccountID, strings.Join(sh.Principals, ", "), sortedCopy(types)
			}
		}
	}
	// Note format: "owner X; principals: ...\n<type> <arn>" lines.
	lines := strings.Split(ev.Note, "\n")
	if len(lines) > 0 {
		head := lines[0]
		if i := strings.Index(head, "; principals: "); i >= 0 {
			owner = strings.TrimPrefix(head[:i], "owner ")
			scopes = head[i+len("; principals: "):]
		}
		for _, l := range lines[1:] {
			if f := strings.Fields(l); len(f) > 0 {
				types = appendUnique(types, f[0])
			}
		}
	}
	return owner, scopes, sortedCopy(types)
}

func shareName(f evaluator.Finding) string {
	t := strings.TrimPrefix(strings.TrimPrefix(f.Title, "Networking share "), "Share ")
	if i := strings.Index(t, " "); i > 0 {
		return t[:i]
	}
	return t
}

// shareSteps: lost shares are re-shared directly before the move and
// confirmed afterwards.
func (b *builder) shareSteps(c evaluator.Check) {
	for _, f := range c.Findings {
		ev := firstEvidence(f, "resource-share")
		if ev == nil {
			continue
		}
		name := shareName(f)
		owner, scopes, types := b.shareInfo(ev)
		typeList := strings.Join(types, ", ")
		ownerWhere := "owner account " + orUnknown(owner)
		switch {
		case f.Status == evaluator.StatusInfo:
			b.add(PhaseAfter, Step{Kind: KindShare, Status: f.Status, Title: fmt.Sprintf("Share %s becomes available: %s", name, typeList), Check: c.ID, Finding: f.Title, Where: b.accountWhere(),
				Detail:   f.Detail,
				Commands: []string{fmt.Sprintf("aws ram list-resources --resource-owner OTHER-ACCOUNTS --resource-share-arns %s", ev.Reference)}, Evidence: f.Evidence})
		case owner == b.acct:
			b.add(PhaseRecreate, Step{Kind: KindShare, Status: f.Status, Title: fmt.Sprintf("Re-share the account's own share %s with its consumers directly", name), Check: c.ID, Finding: f.Title, Where: b.accountWhere(),
				Detail: fmt.Sprintf("The account owns %s (%s) and offers it to %s. Once it leaves, those principals no longer resolve. List the consuming accounts, add them as principals and allow external principals so consumers in another organization can accept.", name, typeList, scopes),
				Commands: []string{
					fmt.Sprintf("aws ram list-principals --resource-owner SELF --resource-share-arns %s", ev.Reference),
					fmt.Sprintf("aws ram update-resource-share --resource-share-arn %s --allow-external-principals", ev.Reference),
					fmt.Sprintf("aws ram associate-resource-share --resource-share-arn %s --principals <consumer account IDs>", ev.Reference),
				}, Evidence: f.Evidence})
		default:
			detail := fmt.Sprintf("Owner %s shares %s (%s) with %s today. After the move those principals no longer cover the account. Ask the owner to add account %s as a principal before the move so nothing attached to these resources is interrupted.", orUnknown(owner), name, typeList, scopes, b.acct)
			cmds := []string{fmt.Sprintf("aws ram associate-resource-share --resource-share-arn %s --principals %s", ev.Reference, b.acct)}
			if b.cross {
				detail += " The account will be outside the organization, so the share has to allow external principals and the account has to accept an invitation."
				cmds = append([]string{fmt.Sprintf("aws ram update-resource-share --resource-share-arn %s --allow-external-principals", ev.Reference)}, cmds...)
			}
			if f.Status == evaluator.StatusNoGo {
				detail += " The documentation says traffic or a declared operation stops with this share, so the move stays NO-GO until it is done: " + f.Detail
			}
			b.add(PhaseRecreate, Step{Kind: KindShare, Status: f.Status, Title: fmt.Sprintf("Re-share %s with the account directly: %s", name, typeList), Check: c.ID, Finding: f.Title, Where: ownerWhere,
				Detail: detail, Resource: ev.Reference, Commands: cmds, Evidence: f.Evidence})
			if b.cross {
				b.add(PhaseAfter, b.acceptShareStep(name, ev.Reference, typeList, c.ID, f.Title))
			} else {
				b.add(PhaseAfter, Step{Kind: KindCheck, Title: fmt.Sprintf("Confirm share %s still reaches the account", name), Check: c.ID, Finding: f.Title, Where: b.accountWhere(),
					Detail:   fmt.Sprintf("Inside one organization no invitation is needed. The %s should still be listed and the attachments that use them should still work.", typeList),
					Commands: []string{fmt.Sprintf("aws ram list-resources --resource-owner OTHER-ACCOUNTS --resource-share-arns %s", ev.Reference)}})
			}
		}
	}
}

func (b *builder) acceptShareStep(name, arn, types, checkID, finding string) Step {
	return Step{Kind: KindCheck, Title: fmt.Sprintf("Accept the invitation for share %s and confirm the resources", name), Check: checkID, Finding: finding, Where: b.accountWhere(),
		Detail: fmt.Sprintf("Outside the owner's organization the share arrives as an invitation. Accept it, then check that the %s are listed and that what is attached to them still works.", types),
		Commands: []string{
			fmt.Sprintf("aws ram get-resource-share-invitations --query \"resourceShareInvitations[?resourceShareName=='%s']\"", name),
			"aws ram accept-resource-share-invitation --resource-share-invitation-arn <invitation ARN from the previous command>",
			fmt.Sprintf("aws ram list-resources --resource-owner OTHER-ACCOUNTS --resource-share-arns %s", arn),
		}}
}

func (b *builder) trailName(ev *evaluator.Evidence) string {
	for _, snap := range []*snapshot.Snapshot{b.from, b.to} {
		if snap == nil {
			continue
		}
		for _, tr := range snap.OrganizationTrails {
			if tr.ARN == ev.Reference {
				return tr.Name
			}
		}
	}
	return ev.Reference
}

func (b *builder) trailBucket(ev *evaluator.Evidence) string {
	if b.to != nil {
		for _, tr := range b.to.OrganizationTrails {
			if tr.ARN == ev.Reference {
				return tr.S3BucketName
			}
		}
	}
	return ""
}

func (b *builder) stackSetAdmin(name string) string {
	for _, snap := range []*snapshot.Snapshot{b.from, b.to} {
		if snap == nil {
			continue
		}
		for _, ss := range snap.StackSets {
			if ss.Name == name {
				return ss.AdministrationAccountID
			}
		}
	}
	return "<administration account>"
}

// orgServiceSteps covers delegated administration, logging, Config,
// StackSets, trusted access and the standalone prerequisites.
func (b *builder) orgServiceSteps(c evaluator.Check) {
	var srcTrails, dstTrails, srcAggs, dstAggs []evaluator.Finding
	var targetAdmins []string
	for _, f := range c.Findings {
		switch {
		case hasEvidence(f, "delegated-admin"):
			ev := firstEvidence(f, "delegated-admin")
			svc := ev.Reference
			b.delegated = append(b.delegated, svc)
			b.add(PhaseBefore, Step{Kind: KindDelegatedAdmin, Status: f.Status, Title: fmt.Sprintf("Hand over delegated administration for %s before the account leaves", svc), Check: c.ID, Finding: f.Title, Where: b.sourceMgmt(),
				Detail: f.Detail + " Some services need the administrator disabled in the service itself first (GuardDuty, Security Hub, Macie, Inspector and Detective have a disable-organization-admin-account call); the organization-wide view of the service moves to the stand-in.",
				Commands: []string{
					fmt.Sprintf("aws organizations deregister-delegated-administrator --account-id %s --service-principal %s", b.acct, svc),
					fmt.Sprintf("aws organizations register-delegated-administrator --account-id <stand-in account> --service-principal %s", svc),
				}, Evidence: f.Evidence})
			b.add(PhaseAfter, Step{Kind: KindDelegatedAdmin, Status: evaluator.StatusReview, Title: fmt.Sprintf("Re-create the delegation for %s in %s if the account keeps that role", svc, orgLabel(b.res.Subject.TargetOrg)), Check: c.ID, Finding: f.Title, Where: b.targetMgmt(),
				Detail: "Delegated administration does not travel. Decide whether the account administers the service in the target organization too; if so, enable trusted access there (when it is not enabled yet) and register the account once it has joined.",
				Commands: []string{
					fmt.Sprintf("aws organizations enable-aws-service-access --service-principal %s", svc),
					fmt.Sprintf("aws organizations register-delegated-administrator --account-id %s --service-principal %s", b.acct, svc),
				}})
		case hasEvidence(f, "org-trail"):
			ev := firstEvidence(f, "org-trail")
			switch {
			case f.Status == evaluator.StatusNoGo:
				b.add(PhaseBefore, Step{Kind: KindLogging, Status: f.Status, Title: fmt.Sprintf("Move the organization trail %s out of the account first", b.trailName(ev)), Check: c.ID, Finding: f.Title, Where: b.accountWhere(),
					Detail:   f.Detail + " Create the organization trail in the account that stays (usually the log archive or management account), confirm delivery, then delete this one.",
					Commands: []string{fmt.Sprintf("aws cloudtrail get-trail --name %s", ev.Reference)}, Evidence: f.Evidence})
			case ev.Side == "target":
				dstTrails = append(dstTrails, f)
			default:
				srcTrails = append(srcTrails, f)
			}
		case hasEvidence(f, "config-aggregator"):
			ev := firstEvidence(f, "config-aggregator")
			switch {
			case f.Status == evaluator.StatusNoGo:
				b.add(PhaseBefore, Step{Kind: KindLogging, Status: f.Status, Title: fmt.Sprintf("Move the organization Config aggregator %s out of the account first", ev.Reference), Check: c.ID, Finding: f.Title, Where: b.accountWhere(),
					Detail:   f.Detail + " Create the aggregator in the account that stays, confirm it receives data, then delete this one.",
					Commands: []string{fmt.Sprintf("aws configservice describe-configuration-aggregators --configuration-aggregator-names %s", ev.Reference)}, Evidence: f.Evidence})
			case ev.Side == "target":
				dstAggs = append(dstAggs, f)
			default:
				srcAggs = append(srcAggs, f)
			}
		case hasEvidence(f, "stackset"):
			ev := firstEvidence(f, "stackset")
			admin := b.stackSetAdmin(ev.Reference)
			if f.Status == evaluator.StatusReview {
				b.add(PhaseRecreate, Step{Kind: KindStackSet, Status: f.Status, Title: fmt.Sprintf("Replace what StackSet %s deploys into the account", ev.Reference), Check: c.ID, Finding: f.Title, Where: "administration account " + admin,
					Detail: f.Detail + " Decide: redeploy the template by hand in the account, add the account to a self-managed StackSet, or accept the loss.",
					Commands: []string{
						fmt.Sprintf("aws cloudformation list-stack-instances --stack-set-name %s --stack-instance-account %s", ev.Reference, b.acct),
						fmt.Sprintf("aws cloudformation describe-stack-set --stack-set-name %s --query StackSet.TemplateBody --output text", ev.Reference),
					}, Evidence: f.Evidence})
			} else {
				b.add(PhaseAfter, Step{Kind: KindStackSet, Status: f.Status, Title: fmt.Sprintf("Confirm StackSet %s deployed its stack instances to the account", ev.Reference), Check: c.ID, Finding: f.Title, Where: "administration account " + admin,
					Detail:   f.Detail,
					Commands: []string{fmt.Sprintf("aws cloudformation list-stack-instances --stack-set-name %s --stack-instance-account %s", ev.Reference, b.acct)}, Evidence: f.Evidence})
			}
		case strings.HasPrefix(f.Title, "Trusted access is not enabled in the target for: "):
			services := strings.Split(strings.TrimPrefix(f.Title, "Trusted access is not enabled in the target for: "), ", ")
			var cmds []string
			for _, svc := range services {
				cmds = append(cmds, "aws organizations enable-aws-service-access --service-principal "+svc)
			}
			b.add(PhaseRecreate, Step{Kind: KindTrustedAccess, Status: f.Status, Title: fmt.Sprintf("Enable trusted access in %s for: %s", orgLabel(b.res.Subject.TargetOrg), strings.Join(services, ", ")), Check: c.ID, Finding: f.Title, Where: b.targetMgmt(),
				Detail: f.Detail + " Only for the integrations the account relies on; enabling trusted access is an organization-wide setting.", Commands: cmds})
		case strings.HasPrefix(f.Title, "In the target, "):
			targetAdmins = append(targetAdmins, strings.TrimPrefix(f.Title, "In the target, "))
		case hasEvidence(f, evaluator.EvidenceTransfer):
			b.transferStep(c, f)
		}
	}
	if len(srcTrails)+len(dstTrails) > 0 {
		var names, ev []string
		var evidence []evaluator.Evidence
		for _, f := range srcTrails {
			names = append(names, b.trailName(firstEvidence(f, "org-trail")))
			evidence = append(evidence, f.Evidence...)
		}
		detail := fmt.Sprintf("Organization trail(s) %s stop logging the account the moment it leaves. ", orNone(strings.Join(names, ", ")))
		for _, f := range dstTrails {
			e := firstEvidence(f, "org-trail")
			ev = append(ev, fmt.Sprintf("%s (bucket %s)", b.trailName(e), orUnknown(b.trailBucket(e))))
			evidence = append(evidence, f.Evidence...)
		}
		if len(ev) > 0 {
			detail += "Trail(s) " + strings.Join(ev, ", ") + " of the target cover it once it has joined; confirm events arrive there. Between leaving and joining nothing logs management events unless the account has a trail of its own."
		} else {
			detail += "The target snapshot has no organization trail, so create a trail in the account (or add it to one) before the move to avoid a gap."
		}
		b.add(PhaseAfter, Step{Kind: KindLogging, Title: "Confirm CloudTrail coverage", Check: c.ID, Where: b.accountWhere(), Detail: detail,
			Commands: []string{"aws cloudtrail describe-trails --include-shadow-trails", "aws cloudtrail lookup-events --max-results 5   # the most recent management events should be minutes old"}, Evidence: evidence})
	}
	if len(srcAggs)+len(dstAggs) > 0 {
		var names, targets []string
		var evidence []evaluator.Evidence
		for _, f := range srcAggs {
			names = append(names, firstEvidence(f, "config-aggregator").Reference)
			evidence = append(evidence, f.Evidence...)
		}
		for _, f := range dstAggs {
			targets = append(targets, firstEvidence(f, "config-aggregator").Reference)
			evidence = append(evidence, f.Evidence...)
		}
		detail := fmt.Sprintf("Aggregator(s) %s of the source stop receiving the account's configuration and compliance data. ", orNone(strings.Join(names, ", ")))
		if len(targets) > 0 {
			detail += "Aggregator(s) " + strings.Join(targets, ", ") + " in the target pick it up once it has joined and the recorder in the account is running; confirm the account appears as a source."
		} else {
			detail += "The target snapshot has no organization aggregator; keep the account's own recorder and delivery channel so its history is not lost."
		}
		b.add(PhaseAfter, Step{Kind: KindLogging, Title: "Confirm AWS Config aggregation", Check: c.ID, Where: b.accountWhere(), Detail: detail,
			Commands: []string{"aws configservice describe-configuration-recorder-status", "aws configservice describe-configuration-aggregator-sources-status --configuration-aggregator-name <target aggregator>   # in the aggregator account"}, Evidence: evidence})
	}
	if len(targetAdmins) > 0 {
		b.add(PhaseAfter, Step{Kind: KindDelegatedAdmin, Status: evaluator.StatusInfo, Title: "Confirm the target's delegated administrators enrol the account", Check: c.ID, Where: b.targetMgmt(),
			Detail:   "In the target organization: " + strings.Join(targetAdmins, "; ") + ". Each administrator's auto-enable settings decide whether the account is enrolled on joining; check the service consoles for the new member.",
			Commands: []string{"aws organizations list-delegated-administrators"}})
	}
}

// controlTowerSteps covers unenrolment, enrolment and Account Factory.
func (b *builder) controlTowerSteps(c evaluator.Check) {
	var leaves, vended, enroll *evaluator.Finding
	var starting []evaluator.Finding
	for i := range c.Findings {
		f := &c.Findings[i]
		switch {
		case f.Status == evaluator.StatusNoGo:
			b.add(PhaseBefore, Step{Kind: KindBlocker, Status: f.Status, Title: "Stop: " + f.Title, Check: c.ID, Finding: f.Title, Where: b.sourceMgmt(),
				Detail: f.Detail + " There is no supported way to carry this account out; the landing zone has to be decommissioned first.", Evidence: f.Evidence})
		case strings.HasPrefix(f.Title, "Account leaves the Control Tower landing zone"):
			leaves = f
		case strings.HasPrefix(f.Title, "Moving out of the registered OU"):
			b.add(PhaseBefore, Step{Kind: KindDecision, Status: f.Status, Title: f.Title, Check: c.ID, Finding: f.Title, Where: b.sourceMgmt() + " (Account Factory)",
				Detail: f.Detail + " Decide which of the two it is and record it here; the rest of this runbook assumes the account is moved with Organizations and ends up unenrolled.",
				Commands: []string{
					fmt.Sprintf("# unenroll: Control Tower console → Account Factory → %s → Unmanage account", b.res.Subject.AccountName),
					"# or register the target OU: Control Tower console → Organization → the OU → Register OU, then move the account with the Update account flow",
				}, Evidence: f.Evidence})
		case strings.HasPrefix(f.Title, "Move between registered OUs"):
			b.viaAccountFactory = true
			b.accountFactory = *f
		case strings.HasPrefix(f.Title, "Target OU ") && strings.Contains(f.Title, "has to be enrolled"):
			enroll = f
		case strings.HasPrefix(f.Title, "Account was vended by Account Factory"):
			vended = f
		case strings.Contains(f.Title, "start applying"):
			starting = append(starting, *f)
		case strings.Contains(f.Title, "stop applying") && strings.Contains(f.Title, "detective"):
			b.add(PhaseAfter, Step{Kind: KindControlTower, Status: f.Status, Title: "Check for Config rules left behind by the detective controls that stopped applying", Check: c.ID, Finding: f.Title, Where: b.accountWhere(),
				Detail:   f.Detail,
				Commands: []string{"aws configservice describe-config-rules --query \"ConfigRules[?starts_with(ConfigRuleName, 'AWSControlTower')].ConfigRuleName\""}, Evidence: f.Evidence})
		}
	}
	if len(starting) > 0 {
		var titles []string
		var evidence []evaluator.Evidence
		for _, f := range starting {
			titles = append(titles, f.Title)
			evidence = append(evidence, f.Evidence...)
		}
		b.add(PhaseAfter, Step{Kind: KindControlTower, Status: evaluator.StatusInfo, Title: fmt.Sprintf("Confirm the Control Tower controls that start applying at %s", nodeName(b.res.Subject.TargetPath, b.res.Subject.TargetOUID)), Check: c.ID, Where: b.targetMgmt(),
			Detail:   strings.Join(titles, ". ") + ". Preventive controls apply through the OU's SCPs at once; detective and proactive ones report once the account is enrolled.",
			Commands: []string{fmt.Sprintf("aws controltower list-enabled-controls --target-identifier <ARN of OU %s>", b.res.Subject.TargetOUID)}, Evidence: evidence})
	}
	if leaves != nil {
		b.governed = true
		s := Step{Kind: KindControlTower, Status: leaves.Status, Title: "Unenroll the account from Control Tower before it leaves", Check: c.ID, Finding: leaves.Title, Where: b.sourceMgmt() + " (Account Factory)",
			Detail: leaves.Detail, Evidence: leaves.Evidence,
			Commands: []string{fmt.Sprintf("# Control Tower console → Account Factory → %s → Unmanage account", b.res.Subject.AccountName)}}
		if vended != nil {
			s.Detail += " " + vended.Detail
			s.Evidence = append(s.Evidence, vended.Evidence...)
			if ev := firstEvidence(*vended, "account-factory"); ev != nil && ev.Reference != "" {
				s.Commands = append(s.Commands, fmt.Sprintf("aws servicecatalog describe-provisioned-product --name %s   # unmanaging terminates this product without closing the account", ev.Reference))
			}
		}
		b.add(PhaseBefore, s)
	} else if vended != nil {
		if ev := firstEvidence(*vended, "account-factory"); ev != nil {
			b.product = ev.Reference
		}
		if b.cross {
			b.add(PhaseBefore, Step{Kind: KindControlTower, Status: vended.Status, Title: "Unenroll the account from Account Factory before it leaves", Check: c.ID, Finding: vended.Title, Where: b.sourceMgmt() + " (Account Factory)",
				Detail: vended.Detail, Evidence: vended.Evidence, Commands: []string{fmt.Sprintf("# Control Tower console → Account Factory → %s → Unmanage account", b.res.Subject.AccountName)}})
		} else {
			b.viaAccountFactory = true
			b.accountFactory = *vended
		}
	}
	if enroll != nil {
		dst := b.targetMgmtID()
		if b.cross {
			b.add(PhaseRecreate, Step{Kind: KindControlTower, Status: evaluator.StatusReview, Title: fmt.Sprintf("Create the AWSControlTowerExecution role in the account, trusting management account %s", dst), Check: c.ID, Finding: enroll.Title, Where: b.accountWhere(),
				Detail: "Account Factory assumes this role to enroll an existing account. It needs AdministratorAccess and a trust policy for the target management account. Also make sure no Config recorder or delivery channel of the account's own conflicts in the governed regions.",
				Commands: []string{
					fmt.Sprintf("aws iam create-role --role-name AWSControlTowerExecution --assume-role-policy-document '{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":{\"AWS\":\"arn:aws:iam::%s:root\"},\"Action\":\"sts:AssumeRole\"}]}'", dst),
					"aws iam attach-role-policy --role-name AWSControlTowerExecution --policy-arn arn:aws:iam::aws:policy/AdministratorAccess",
					"aws configservice describe-configuration-recorders   # per governed region",
				}})
		}
		b.add(PhaseAfter, Step{Kind: KindControlTower, Status: enroll.Status, Title: fmt.Sprintf("Enroll the account in Control Tower from Account Factory (OU %s)", nodeName(b.res.Subject.TargetPath, b.res.Subject.TargetOUID)), Check: c.ID, Finding: enroll.Title, Where: b.targetMgmt() + " (Account Factory)",
			Detail:   enroll.Detail,
			Commands: []string{fmt.Sprintf("# Control Tower console → Account Factory → Enroll account → %s, OU %s", b.res.Subject.AccountName, nodeLabel(b.res.Subject.TargetPath, b.res.Subject.TargetOUID))}, Evidence: enroll.Evidence})
	}
}

// principalOf parses an account-assignment evidence note.
func principalOf(ev evaluator.Evidence) (ptype, name string) {
	head := ev.Note
	if i := strings.Index(head, " has permission set "); i >= 0 {
		head = head[:i]
	}
	if i := strings.Index(head, " "); i > 0 {
		return strings.ToUpper(head[:i]), head[i+1:]
	}
	return "GROUP", head
}

func (b *builder) sourceIdC() *snapshot.IdentityCenter {
	if b.from == nil {
		return nil
	}
	return b.from.IdentityCenter
}

func (b *builder) targetIdC() *snapshot.IdentityCenter {
	if b.to == nil {
		return nil
	}
	return b.to.IdentityCenter
}

func idcWhere(org evaluator.OrgRef, ic *snapshot.IdentityCenter) string {
	if ic == nil {
		return "Identity Center of " + orgLabel(org)
	}
	return fmt.Sprintf("Identity Center of %s (account %s, %s)", orgLabel(org), orUnknown(ic.OwnerAccountID), orUnknown(ic.Region))
}

// identityCenterSteps prepares permission sets before the move and
// re-creates the assignments after it.
func (b *builder) identityCenterSteps(c evaluator.Check) {
	src, dst := b.sourceIdC(), b.targetIdC()
	dstARN, dstStore := "<target instance ARN>", "<target identity store ID>"
	if dst != nil {
		dstARN, dstStore = dst.InstanceARN, orUnknown(dst.IdentityStoreID)
	}
	srcWhere, dstWhere := idcWhere(b.res.Subject.SourceOrg, src), idcWhere(b.res.Subject.TargetOrg, dst)
	for _, f := range c.Findings {
		switch {
		case strings.HasPrefix(f.Title, "Permission set "):
			name := strings.TrimPrefix(f.Title, "Permission set ")
			if i := strings.Index(name, ":"); i > 0 {
				name = name[:i]
			}
			srcEv, tgtEv := evidenceSide(f, "permission-set", "source"), evidenceSide(f, "permission-set", "target")
			var labels, assignCmds []string
			for _, ev := range f.Evidence {
				if ev.Kind != "account-assignment" {
					continue
				}
				ptype, pname := principalOf(ev)
				labels = append(labels, strings.ToLower(ptype)+" "+pname)
				lookup := fmt.Sprintf("aws identitystore list-groups --identity-store-id %s --filters AttributePath=DisplayName,AttributeValue=\"%s\" --query \"Groups[].GroupId\" --output text", dstStore, pname)
				if ptype == snapshot.PrincipalUser {
					lookup = fmt.Sprintf("aws identitystore list-users --identity-store-id %s --filters AttributePath=UserName,AttributeValue=\"%s\" --query \"Users[].UserId\" --output text", dstStore, pname)
				}
				psARN := "<ARN of permission set " + name + " in the target>"
				if tgtEv != nil {
					psARN = tgtEv.Reference
				}
				assignCmds = append(assignCmds, lookup,
					fmt.Sprintf("aws sso-admin create-account-assignment --instance-arn %s --target-id %s --target-type AWS_ACCOUNT --permission-set-arn %s --principal-type %s --principal-id <ID from the previous command>", dstARN, b.acct, psARN, ptype))
			}
			prep := Step{Kind: KindIdentityCenter, Status: f.Status, Check: c.ID, Finding: f.Title, Where: dstWhere, Evidence: f.Evidence, Detail: f.Detail}
			switch {
			case dst == nil && tgtEv == nil:
				prep.Title = fmt.Sprintf("Plan replacement access for permission set %s (%s)", name, strings.Join(labels, ", "))
				prep.Detail += " Decide between an IAM role with the same policies and a trust to the new identity provider, or collecting the target's Identity Center instance into the snapshot and re-running the simulation."
				if srcEv != nil {
					prep.Commands = []string{fmt.Sprintf("aws sso-admin describe-permission-set --instance-arn %s --permission-set-arn %s", srcInstance(src), srcEv.Reference)}
				}
				b.add(PhaseRecreate, prep)
				continue
			case tgtEv != nil:
				prep.Title = fmt.Sprintf("Review permission set %s in the target instance before re-assigning it", name)
				prep.Commands = []string{
					fmt.Sprintf("aws sso-admin describe-permission-set --instance-arn %s --permission-set-arn %s", dstARN, tgtEv.Reference),
					fmt.Sprintf("aws sso-admin list-managed-policies-in-permission-set --instance-arn %s --permission-set-arn %s", dstARN, tgtEv.Reference),
					fmt.Sprintf("aws sso-admin get-inline-policy-for-permission-set --instance-arn %s --permission-set-arn %s", dstARN, tgtEv.Reference),
				}
			default:
				prep.Title = fmt.Sprintf("Create permission set %s in the target instance", name)
				prep.Commands = b.createPermissionSetCommands(src, srcEv, dstARN, name)
			}
			b.add(PhaseRecreate, prep)
			b.add(PhaseAfter, Step{Kind: KindIdentityCenter, Status: evaluator.StatusReview, Title: fmt.Sprintf("Assign %s to %s for the account in the target instance", name, strings.Join(labels, ", ")), Check: c.ID, Finding: f.Title, Where: dstWhere,
				Detail:   fmt.Sprintf("Users and groups in identity store %s are different objects from the source ones, so look each one up by name first; create it there if it is missing. Identity Center then provisions a new AWSReservedSSO_%s_* role in the account.", dstStore, name),
				Commands: assignCmds})
		case strings.Contains(f.Title, "AWSReservedSSO_* role(s) are deleted"):
			region := "<region>"
			if src != nil && src.Region != "" {
				region = src.Region
			}
			b.add(PhaseBefore, Step{Kind: KindIdentityCenter, Status: f.Status, Title: fmt.Sprintf("Find what references the %s of the account", strings.TrimSuffix(strings.SplitN(f.Title, " are deleted", 2)[0], " ")), Check: c.ID, Finding: f.Title, Where: b.accountWhere(),
				Detail: f.Detail + " List the exact role ARNs now, while they exist, and search for them so the references can be updated after the move.",
				Commands: []string{
					fmt.Sprintf("aws iam list-roles --path-prefix /aws-reserved/sso.amazonaws.com/%s/ --query \"Roles[].Arn\"", region),
					"# search bucket, key, topic, queue and secret policies, EKS access entries, role trust policies and CI configuration for AWSReservedSSO_",
				}, Evidence: f.Evidence})
			var stale []string
			for _, ev := range f.Evidence {
				if ev.Kind == "reserved-role" && strings.Contains(ev.Note, "(stale)") {
					stale = append(stale, strings.TrimSuffix(strings.TrimPrefix(ev.Reference, snapshot.ReservedSSORolePrefix), "_*"))
				}
			}
			if len(stale) > 0 {
				var cmds []string
				for _, n := range stale {
					arn := "<permission set ARN>"
					if ps := src.PermissionSetByName(n); ps != nil {
						arn = ps.ARN
					}
					cmds = append(cmds, fmt.Sprintf("aws sso-admin list-accounts-for-provisioned-permission-set --instance-arn %s --permission-set-arn %s", srcInstance(src), arn),
						fmt.Sprintf("# Identity Center console → Permission sets → %s → AWS accounts → remove %s", n, b.acct))
				}
				b.add(PhaseBefore, Step{Kind: KindIdentityCenter, Status: evaluator.StatusReview, Title: "Deprovision the stale permission set(s) from the account: " + strings.Join(stale, ", "), Check: c.ID, Finding: f.Title, Where: srcWhere,
					Detail:   "These permission sets are provisioned in the account without any assignment, so their roles are unused. Removing them now deletes the roles cleanly and keeps them out of the reference search above.",
					Commands: cmds})
			}
			b.add(PhaseAfter, Step{Kind: KindIdentityCenter, Title: "Update references to the deleted AWSReservedSSO_* roles with the ARNs the target instance provisions", Check: c.ID, Finding: f.Title, Where: b.accountWhere(),
				Detail:   "The new roles have a different random suffix. Replace the old ARNs found before the move in resource policies, key policies, EKS access entries and tooling.",
				Commands: []string{"aws iam list-roles --path-prefix /aws-reserved/sso.amazonaws.com/ --query \"Roles[].Arn\""}})
		case strings.HasPrefix(f.Title, "Target organization grants access through IAM Identity Center"):
			b.add(PhaseAfter, Step{Kind: KindIdentityCenter, Status: f.Status, Title: "Grant access to the account by assignment in the target instance", Check: c.ID, Finding: f.Title, Where: dstWhere,
				Detail:   f.Detail,
				Commands: []string{fmt.Sprintf("aws sso-admin list-permission-sets --instance-arn %s", dstARN), fmt.Sprintf("aws sso-admin create-account-assignment --instance-arn %s --target-id %s --target-type AWS_ACCOUNT --permission-set-arn <permission set ARN> --principal-type GROUP --principal-id <group ID>", dstARN, b.acct)}, Evidence: f.Evidence})
		case strings.HasPrefix(f.Title, "Target organization has no IAM Identity Center instance"):
			b.add(PhaseAfter, Step{Kind: KindIdentityCenter, Status: f.Status, Title: "Re-establish access to the account without a target Identity Center instance in the snapshot", Check: c.ID, Finding: f.Title, Where: b.accountWhere(),
				Detail: f.Detail, Evidence: f.Evidence})
		}
	}
}

func srcInstance(ic *snapshot.IdentityCenter) string {
	if ic == nil {
		return "<source instance ARN>"
	}
	return ic.InstanceARN
}

// createPermissionSetCommands builds the calls that re-create a source
// permission set in the target instance.
func (b *builder) createPermissionSetCommands(src *snapshot.IdentityCenter, srcEv *evaluator.Evidence, dstARN, name string) []string {
	var ps *snapshot.PermissionSet
	if srcEv != nil {
		ps = src.PermissionSet(srcEv.Reference)
	}
	if ps == nil {
		ps = src.PermissionSetByName(name)
	}
	if ps == nil {
		return []string{fmt.Sprintf("aws sso-admin create-permission-set --instance-arn %s --name %s", dstARN, name)}
	}
	create := fmt.Sprintf("aws sso-admin create-permission-set --instance-arn %s --name %s", dstARN, ps.Name)
	if ps.Description != "" {
		create += fmt.Sprintf(" --description \"%s\"", ps.Description)
	}
	if ps.SessionDuration != "" {
		create += " --session-duration " + ps.SessionDuration
	}
	cmds := []string{create}
	const psARN = "<ARN returned by create-permission-set>"
	for _, p := range ps.ManagedPolicies {
		cmds = append(cmds, fmt.Sprintf("aws sso-admin attach-managed-policy-to-permission-set --instance-arn %s --permission-set-arn %s --managed-policy-arn %s", dstARN, psARN, p))
	}
	for _, p := range ps.CustomerManagedPolicies {
		path, n := "/", p
		if i := strings.LastIndex(p, "/"); i >= 0 {
			path, n = p[:i+1], p[i+1:]
		}
		cmds = append(cmds, fmt.Sprintf("aws sso-admin attach-customer-managed-policy-reference-to-permission-set --instance-arn %s --permission-set-arn %s --customer-managed-policy-reference Name=%s,Path=%s   # the policy must exist in the account", dstARN, psARN, n, path))
	}
	if len(ps.InlinePolicy) > 0 {
		cmds = append(cmds, fmt.Sprintf("aws sso-admin put-inline-policy-to-permission-set --instance-arn %s --permission-set-arn %s --inline-policy file://%s-inline.json   # the inline policy is in the evidence below", dstARN, psARN, ps.Name))
	}
	if ps.PermissionsBoundary != "" {
		cmds = append(cmds, fmt.Sprintf("aws sso-admin put-permissions-boundary-to-permission-set --instance-arn %s --permission-set-arn %s --permissions-boundary <%s>", dstARN, psARN, ps.PermissionsBoundary))
	}
	return cmds
}

// transferStep turns one finding about the transfer procedure into its
// step. The findings carry an evidence entry that says which part of the
// procedure they are about (evaluator.Transfer* constants).
func (b *builder) transferStep(c evaluator.Check, f evaluator.Finding) {
	ev := firstEvidence(f, evaluator.EvidenceTransfer)
	s := b.res.Subject
	switch ev.Reference {
	case evaluator.TransferProcedure:
		switch ev.Note {
		case evaluator.TransferManagementAccount:
			b.add(PhaseBefore, Step{Kind: KindBlocker, Status: f.Status, Title: "Stop: a management account moves only after its organization is emptied and deleted", Check: c.ID, Finding: f.Title,
				Detail: f.Detail + " There is no runbook for this move as a single account move: migrate or remove every member account first (each one has a runbook of its own), delete the organization, and then run the invitation and acceptance steps below for the standalone account.",
				Commands: []string{
					"aws organizations list-accounts --query \"Accounts[?Status=='ACTIVE'].[Id,Name]\" --output table   # every member has to be gone first",
					"# after the last member has left: aws organizations delete-organization   (run by the management account; irreversible)",
				}, Evidence: f.Evidence})
		case evaluator.TransferLeaveAndRejoin:
			b.add(PhaseBefore, Step{Kind: KindPrerequisite, Status: f.Status, Title: "Make the account able to stand alone", Check: c.ID, Finding: f.Title, Where: b.accountWhere() + ", signed in as root or an administrator",
				Detail: f.Detail + " Contact information, alternate contacts and the payment method can be checked with the Account API; identity verification and the support plan are done in the console. A direct transfer needs none of this.",
				Commands: []string{
					"aws account get-contact-information",
					"aws account get-alternate-contact --alternate-contact-type BILLING",
					"# console: Billing and Cost Management → Payment preferences; Account → Identity verification; Support → Support plan",
				}, Evidence: f.Evidence})
		}
	case evaluator.TransferLeavePermission:
		policyEv := firstEvidence(f, "policy-statement")
		title := "Settle organizations:LeaveOrganization for the principal that accepts the invitation"
		cmds := []string{}
		if policyEv != nil {
			title = fmt.Sprintf("Lift the deny on organizations:LeaveOrganization in SCP %s / %s for the transfer", policyEv.PolicyName, policyEv.Statement)
			cmds = append(cmds, fmt.Sprintf("aws organizations describe-policy --policy-id %s --query Policy.Content --output text > %s.json", policyEv.PolicyID, policyEv.PolicyID),
				fmt.Sprintf("# except the principal that accepts the invitation in the statement (or detach the policy for the transfer), then: aws organizations update-policy --policy-id %s --content file://%s.json", policyEv.PolicyID, policyEv.PolicyID),
				"# put the statement back in the source organization once the account has left; it no longer applies to this account")
		}
		if b.method() == evaluator.TransferLeaveAndRejoin {
			if policyEv != nil {
				title = fmt.Sprintf("Lift the deny on organizations:LeaveOrganization in SCP %s / %s, or have the management account remove the account", policyEv.PolicyName, policyEv.Statement)
			}
			cmds = append(cmds, fmt.Sprintf("aws organizations remove-account-from-organization --account-id %s   # the alternative for leave-and-rejoin: removal by the management account, which SCPs do not restrict", b.acct))
		}
		b.add(PhaseBefore, Step{Kind: KindPolicy, Status: f.Status, Title: title, Check: c.ID, Finding: f.Title, Where: b.sourceMgmt(),
			Detail: f.Detail, Actions: []string{"organizations:LeaveOrganization"}, Commands: cmds, Evidence: f.Evidence})
	case evaluator.TransferRootLanding:
		if f.Status != evaluator.StatusReview {
			return
		}
		b.add(PhaseBefore, Step{Kind: KindDecision, Status: f.Status, Title: "Plan the interval at the destination root: accept and move in one change", Check: c.ID, Finding: f.Title, Where: b.targetMgmt(),
			Detail:   f.Detail + " The move step that follows the acceptance in this runbook closes the interval; have the destination management account ready to run it as soon as the account has joined.",
			Evidence: f.Evidence})
	case evaluator.TransferOrgAge:
		b.add(PhaseBefore, Step{Kind: KindBlocker, Status: f.Status, Title: "Wait until the destination organization is seven days old", Check: c.ID, Finding: f.Title, Where: b.targetMgmt(),
			Detail: f.Detail, Evidence: f.Evidence})
	case evaluator.TransferSellerOfRecord:
		b.add(PhaseBefore, Step{Kind: KindBlocker, Status: f.Status, Title: "Stop: the Seller of Record of the account and of the destination differ", Check: c.ID, Finding: f.Title,
			Detail:   f.Detail + " Compare the legal entity on a recent invoice of the account with one of the destination management account; AWS Support can say whether and how an account changes Seller of Record.",
			Commands: []string{"# console: Billing and Cost Management → Bills → the invoice header names the selling entity, in both the account and the destination management account"}, Evidence: f.Evidence})
	case evaluator.TransferAccountStatus:
		b.add(PhaseBefore, Step{Kind: KindBlocker, Status: f.Status, Title: "Stop: a closed or suspended account cannot be migrated", Check: c.ID, Finding: f.Title, Where: b.sourceMgmt(),
			Detail:   f.Detail,
			Commands: []string{fmt.Sprintf("aws organizations describe-account --account-id %s --query Account.Status", b.acct)}, Evidence: f.Evidence})
	case evaluator.TransferAccountAge:
		b.add(PhaseBefore, Step{Kind: KindBlocker, Status: f.Status, Title: "Wait until the account is four days old", Check: c.ID, Finding: f.Title, Where: b.sourceMgmt(),
			Detail:   f.Detail,
			Commands: []string{fmt.Sprintf("aws organizations describe-account --account-id %s --query \"Account.[JoinedMethod,JoinedTimestamp]\"", b.acct)}, Evidence: f.Evidence})
	case evaluator.TransferRootMFA:
		b.add(PhaseBefore, Step{Kind: KindDecision, Status: f.Status, Title: "Decide whether the root user changes hands, and remove its MFA device if it does", Check: c.ID, Finding: f.Title, Where: b.accountWhere() + ", signed in as the root user",
			Detail: f.Detail,
			Commands: []string{
				"aws iam get-account-summary --query SummaryMap.AccountMFAEnabled   # 1 means the root user has an MFA device",
				"# console, as the root user: Security credentials → Multi-factor authentication → remove the device; the new owner registers its own after the migration",
			}, Evidence: f.Evidence})
	case evaluator.TransferUnconfirmed:
		if f.Status != evaluator.StatusReview {
			return
		}
		b.add(PhaseBefore, Step{Kind: KindInput, Status: f.Status, Title: "Confirm the transfer eligibility requirements the snapshots do not show", Check: c.ID, Finding: f.Title,
			Detail: f.Detail + " Record what you find in the snapshots (organization.created_at and organization.seller_of_record on both sides, root_mfa_enabled on the account) and simulate again, so the next result says confirmed instead of unknown.",
			Commands: []string{
				fmt.Sprintf("aws organizations describe-account --account-id %s --query \"Account.[Status,JoinedMethod,JoinedTimestamp]\"", b.acct),
				"aws iam get-account-summary --query SummaryMap.AccountMFAEnabled   # inside the account",
				"# console: Billing and Cost Management → Bills → the invoice header names the Seller of Record, in the account and in the destination management account",
			}, Evidence: f.Evidence})
	case evaluator.TransferAccessRole:
		if f.Status != evaluator.StatusReview {
			return
		}
		b.add(PhaseAfter, Step{Kind: KindPrerequisite, Status: f.Status, Title: fmt.Sprintf("Delete the role that lets %s into the account, and give %s its own", mgmtID(b.from), orgLabel(s.TargetOrg)), Check: c.ID, Finding: f.Title, Where: b.accountWhere(),
			Detail: f.Detail + " Look at the role's trust policy first: delete it only when it trusts the former management account and nothing else depends on it.",
			Commands: []string{
				"aws iam get-role --role-name OrganizationAccountAccessRole --query Role.AssumeRolePolicyDocument",
				"aws iam list-attached-role-policies --role-name OrganizationAccountAccessRole",
				"# detach its policies, then: aws iam delete-role --role-name OrganizationAccountAccessRole",
			}, Evidence: f.Evidence})
	}
}

// method is the transfer method the result was evaluated with.
func (b *builder) method() string {
	if m := b.res.Subject.TransferMethod; m != "" {
		return m
	}
	return evaluator.TransferDirect
}
