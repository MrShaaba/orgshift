package runbook

import (
	"fmt"
	"strings"

	"github.com/MrShaaba/orgshift/internal/evaluator"
	"github.com/MrShaaba/orgshift/internal/snapshot"
	"github.com/MrShaaba/orgshift/internal/workload"
)

// Step kinds of the workload layer.
const (
	KindWorkload       = "workload"
	KindResourcePolicy = "resource-policy"
)

// stackOf finds the stack a finding is about in the account's inventory.
func (b *builder) stackOf(inv *workload.Inventory, name string, regions []string) *workload.StackView {
	if inv == nil {
		return nil
	}
	for i := range inv.Stacks {
		st := &inv.Stacks[i]
		if st.Name == name && (len(regions) == 0 || st.Region == regions[0]) {
			return st
		}
	}
	return nil
}

func regionFlag(regions []string) string {
	if len(regions) == 0 || regions[0] == "" {
		return " --region <region>"
	}
	return " --region " + regions[0]
}

func lastSegment(arn string) string {
	if i := strings.LastIndexAny(arn, ":/"); i >= 0 {
		return arn[i+1:]
	}
	return arn
}

// workloadSteps turns the findings of the workloads check into steps: what
// to keep or replace before a StackSet deletes it, which stacks have to
// leave shared networking, which references and resource policies to
// change, and what to adopt afterwards.
func (b *builder) workloadSteps(c evaluator.Check) {
	var inv *workload.Inventory
	if b.from != nil {
		inv = workload.Build(b.from, b.acct)
	}
	for _, f := range c.Findings {
		if hasEvidence(f, "coverage") || len(f.Evidence) == 0 {
			continue // handled by coverageSteps, or nothing to act on
		}
		ev := f.Evidence[0]
		region := regionFlag(f.Regions)
		st := b.stackOf(inv, ev.Reference, f.Regions)
		describe := fmt.Sprintf("aws cloudformation describe-stack-resources --stack-name %s%s --query 'StackResources[].[ResourceType,LogicalResourceId,PhysicalResourceId]' --output table", ev.Reference, region)
		switch ev.Kind {
		case evaluator.EvidenceStackInstance:
			name, admin, ous := "<StackSet>", "<administration account>", "<target OU>"
			if st != nil && st.StackSetSettings != nil {
				name, admin = st.StackSetSettings.Name, orUnknown(st.StackSetSettings.AdministrationAccountID)
				if len(st.StackSetSettings.TargetOUs) > 0 {
					ous = strings.Join(st.StackSetSettings.TargetOUs, ",")
				}
			}
			where := "administration account " + admin
			switch {
			case f.Status == evaluator.StatusInfo:
				b.add(PhaseAfter, Step{Kind: KindStackSet, Status: f.Status, Title: fmt.Sprintf("Adopt or replace stack %s, which StackSet %s left behind", ev.Reference, name), Check: c.ID, Finding: f.Title, Where: b.accountWhere(), Regions: f.Regions,
					Detail:   f.Detail + " The stack is an ordinary stack of the account from now on: keep it under the account's own deployment, or delete it once the destination's baseline provides the same.",
					Commands: []string{fmt.Sprintf("aws cloudformation describe-stacks --stack-name %s%s --query 'Stacks[0].[StackStatus,LastUpdatedTime]'", ev.Reference, region), describe}, Evidence: f.Evidence})
			case f.Category == evaluator.CategoryDeclaredImpact:
				b.add(PhaseBefore, Step{Kind: KindStackSet, Status: f.Status, Title: fmt.Sprintf("Keep or replace stack %s before StackSet %s deletes it", ev.Reference, name), Check: c.ID, Finding: f.Title, Where: where, Regions: f.Regions,
					Detail: f.Detail + " Turning retention on is a setting of the whole StackSet and applies to every account that leaves its targets from then on.",
					Commands: []string{
						describe + "   # in the account: what the instance contains",
						fmt.Sprintf("aws cloudformation describe-stack-set --stack-set-name %s --query StackSet.AutoDeployment", name),
						"# to keep the stack in the account when it leaves (add --capabilities and --parameters as the StackSet needs them):",
						fmt.Sprintf("aws cloudformation update-stack-set --stack-set-name %s --use-previous-template --auto-deployment Enabled=true,RetainStacksOnAccountRemoval=true", name),
					}, Evidence: f.Evidence})
				b.add(PhaseAfter, Step{Kind: KindStackSet, Status: evaluator.StatusReview, Title: fmt.Sprintf("Confirm what became of stack %s", ev.Reference), Check: c.ID, Finding: f.Title, Where: b.accountWhere(), Regions: f.Regions,
					Detail:   "With retention on, the stack is still there and no longer belongs to the StackSet; with retention off, it and its resources are gone and whatever replaced them has to be in place.",
					Commands: []string{fmt.Sprintf("aws cloudformation describe-stacks --stack-name %s%s --query 'Stacks[0].StackStatus'", ev.Reference, region)}})
			default:
				b.add(PhaseBefore, Step{Kind: KindStackSet, Status: f.Status, Title: fmt.Sprintf("Remove stack %s from StackSet %s explicitly", ev.Reference, name), Check: c.ID, Finding: f.Title, Where: where, Regions: f.Regions,
					Detail: f.Detail + " Removing the instance with the stack retained keeps the resources in the account; without --retain-stacks they are deleted.",
					Commands: []string{
						fmt.Sprintf("aws cloudformation list-stack-instances --stack-set-name %s --stack-instance-account %s", name, b.acct),
						fmt.Sprintf("aws cloudformation delete-stack-instances --stack-set-name %s --deployment-targets OrganizationalUnitIds=%s,Accounts=%s,AccountFilterType=INTERSECTION --regions %s --retain-stacks", name, ous, b.acct, strings.TrimSpace(strings.TrimPrefix(region, " --region"))),
					}, Evidence: f.Evidence})
			}
		case evaluator.EvidenceExternalStackSet:
			b.add(PhaseBefore, Step{Kind: KindStackSet, Status: f.Status, Title: fmt.Sprintf("Find who administers stack %s and decide whether that access stays", ev.Reference), Check: c.ID, Finding: f.Title, Where: b.accountWhere(), Regions: f.Regions,
				Detail: f.Detail + " The execution role's trust policy names the administrator account; AWSCloudFormationStackSetExecutionRole is the default name for self-managed StackSets.",
				Commands: []string{
					fmt.Sprintf("aws cloudformation describe-stacks --stack-name %s%s --query 'Stacks[0].[RoleARN,Tags]'", ev.Reference, region),
					"aws iam get-role --role-name AWSCloudFormationStackSetExecutionRole --query Role.AssumeRolePolicyDocument",
				}, Evidence: f.Evidence})
		case evaluator.EvidenceStackReference:
			phase, title := PhaseRecreate, fmt.Sprintf("Plan stack %s off the shared networking it references", ev.Reference)
			if f.Status == evaluator.StatusNoGo {
				phase, title = PhaseBefore, fmt.Sprintf("Move stack %s off the shared networking before the account leaves", ev.Reference)
			}
			var ids []string
			if st != nil {
				for _, ref := range st.References {
					if ref.Kind == snapshot.RefSubnet {
						ids = append(ids, ref.ID)
					}
				}
			}
			cmds := []string{describe}
			if len(ids) > 0 {
				cmds = append(cmds, fmt.Sprintf("aws ec2 describe-subnets --subnet-ids %s%s --query 'Subnets[].[SubnetId,OwnerId,VpcId,AvailabilityZone]' --output table", strings.Join(ids, " "), region))
			}
			b.add(phase, Step{Kind: KindWorkload, Status: f.Status, Title: title, Check: c.ID, Finding: f.Title, Where: b.accountWhere(), Regions: f.Regions,
				Detail:   f.Detail + " Redeploying the stack with subnets and attachments the account owns, or that the destination shares with it, is the fix; the parameters named above are where the stack takes them from.",
				Commands: cmds, Evidence: f.Evidence})
		case evaluator.EvidenceStackOutputReference:
			if f.Status == evaluator.StatusInfo {
				continue
			}
			role := lastSegment(f.Resource)
			owner := snapshot.AccountFromARN(f.Resource)
			b.add(PhaseBefore, Step{Kind: KindDecision, Status: f.Status, Title: fmt.Sprintf("Decide where stack %s reads its cross-account output from after the move", ev.Reference), Check: c.ID, Finding: f.Title, Where: "account " + orUnknown(owner), Regions: f.Regions,
				Actions: []string{"sts:AssumeRole"}, Resource: f.Resource,
				Detail:   f.Detail + " Either keep the reference (the role's trust policy has to admit this account by ID rather than by organization) or replace it with a parameter that carries the value.",
				Commands: []string{fmt.Sprintf("aws iam get-role --role-name %s --query Role.AssumeRolePolicyDocument   # in account %s: does the trust name account %s, or the organization?", role, orUnknown(owner), b.acct)}, Evidence: f.Evidence})
			b.add(PhaseAfter, Step{Kind: KindCheck, Status: evaluator.StatusReview, Title: fmt.Sprintf("Confirm stack %s still resolves its cross-account output", ev.Reference), Check: c.ID, Finding: f.Title, Where: b.accountWhere(), Regions: f.Regions,
				Detail:   "The reference is resolved only when the stack is created or updated, so nothing fails until the next deployment. Create a change set for the stack with its template unchanged, check that it is created without an access error, and delete it without executing it.",
				Commands: []string{fmt.Sprintf("aws cloudformation describe-stacks --stack-name %s%s --query 'Stacks[0].[StackStatus,LastUpdatedTime]'", ev.Reference, region)}})
		case evaluator.EvidenceResourcePolicy:
			var cmds []string
			where := b.accountWhere()
			name := lastSegment(f.Resource)
			transition := fmt.Sprintf("# edit the condition on organization identity so it admits the destination as well for the transition: today it names %s, the account will be in %s (path %s)",
				b.res.Subject.SourceOrg.ID, b.res.Subject.TargetOrg.ID, b.res.Subject.TargetOrgPath)
			if !b.cross {
				transition = fmt.Sprintf("# edit the condition on the organization path so it also covers the account's new path %s", b.res.Subject.TargetOrgPath)
			}
			switch ev.PolicyType {
			case snapshot.PolicyKindBucket:
				cmds = []string{
					fmt.Sprintf("aws s3api get-bucket-policy --bucket %s --query Policy --output text > %s-policy.json", name, name),
					transition,
					fmt.Sprintf("aws s3api put-bucket-policy --bucket %s --policy file://%s-policy.json", name, name),
				}
			case snapshot.PolicyKindRoleTrust:
				cmds = []string{
					fmt.Sprintf("aws iam get-role --role-name %s --query Role.AssumeRolePolicyDocument > %s-trust.json", name, name),
					transition,
					fmt.Sprintf("aws iam update-assume-role-policy --role-name %s --policy-document file://%s-trust.json", name, name),
				}
			default:
				stack := "<stack>"
				if i := strings.Index(ev.Reference, " of stack "); i >= 0 {
					stack = ev.Reference[i+len(" of stack "):]
				}
				if owner := b.stackOf(inv, stack, nil); owner != nil {
					region = regionFlag([]string{owner.Region})
				}
				cmds = []string{
					fmt.Sprintf("aws cloudformation get-template --stack-name %s%s --query TemplateBody", stack, region),
					"# change the value in the template's source and deploy it through the stack's usual pipeline",
				}
			}
			title := fmt.Sprintf("Change the policy of %s to name the destination organization", ev.Reference)
			if !b.cross {
				title = fmt.Sprintf("Change the policy of %s to cover the account's new OU path", ev.Reference)
			}
			b.add(PhaseBefore, Step{Kind: KindResourcePolicy, Status: f.Status, Title: title, Check: c.ID, Finding: f.Title, Where: where, Resource: f.Resource,
				Detail: f.Detail, Commands: cmds, Evidence: f.Evidence})
			if b.cross && ev.PolicyType != snapshot.PolicyKindTemplate {
				b.add(PhaseAfter, Step{Kind: KindResourcePolicy, Status: evaluator.StatusReview, Title: fmt.Sprintf("Take %s out of the policy of %s once nothing there needs it", b.res.Subject.SourceOrg.ID, ev.Reference), Check: c.ID, Finding: f.Title, Where: where, Resource: f.Resource,
					Detail: "A condition that names both organizations is a transition state: it keeps admitting every principal of the organization the account left. Remove the former organization when the consumers that stayed behind no longer need the resource, or replace it with the specific accounts that do."})
			}
		}
	}
}
