package runbook

import (
	"strings"
	"testing"

	"github.com/MrShaaba/orgshift/internal/evaluator"
	"github.com/MrShaaba/orgshift/internal/fixtures"
)

// The workload findings become steps in the phase where they are acted on,
// with read commands for the operator and the stack's Region filled in.
func TestWorkloadSteps(t *testing.T) {
	rb := buildScenario(t, scenarios()[0])
	cmds := func(s Step) string { return strings.Join(s.Commands, "\n") }

	s := stepWith(t, rb, PhaseBefore, "Change the policy of "+fixtures.LarkspurSettlementBucket+" to name the destination organization")
	if s.Status != evaluator.StatusNoGo || s.Kind != KindResourcePolicy || s.Check != "workloads" || s.Resource != fixtures.LarkspurSettlementBucket ||
		!strings.Contains(cmds(s), "aws s3api get-bucket-policy --bucket larkspur-payments-settlement-files") || !strings.Contains(cmds(s), "today it names o-larkspur0001, the account will be in o-fernhill0001") {
		t.Errorf("bucket policy step: %+v", s)
	}
	after := stepWith(t, rb, PhaseAfter, "Take o-larkspur0001 out of the policy of "+fixtures.LarkspurSettlementBucket)
	if after.Status != evaluator.StatusReview || !strings.Contains(after.Detail, "transition state") {
		t.Errorf("the transition state of the policy is closed afterwards: %+v", after)
	}
	s = stepWith(t, rb, PhaseBefore, "Change the policy of arn:aws:iam::111111111115:role/DataExportReader")
	if !strings.Contains(cmds(s), "aws iam update-assume-role-policy --role-name DataExportReader") {
		t.Errorf("trust policy step: %v", s.Commands)
	}
	s = stepWith(t, rb, PhaseBefore, "Change the policy of resource AppLogSubscriptionRole of stack payments-api")
	if !strings.Contains(cmds(s), "aws cloudformation get-template --stack-name payments-api --region us-east-1") {
		t.Errorf("template policy step should name the stack and its Region: %v", s.Commands)
	}

	s = stepWith(t, rb, PhaseBefore, "Move stack payments-api off the shared networking before the account leaves")
	if s.Status != evaluator.StatusNoGo || s.Kind != KindWorkload || len(s.Regions) != 1 || s.Regions[0] != "us-east-1" ||
		!strings.Contains(cmds(s), "aws ec2 describe-subnets --subnet-ids subnet-") || !strings.Contains(cmds(s), "describe-stack-resources --stack-name payments-api --region us-east-1") {
		t.Errorf("blocking shared-subnet step: %+v", s)
	}
	s = stepWith(t, rb, PhaseRecreate, "Plan stack payments-ledger-db off the shared networking")
	if s.Status != evaluator.StatusReview || s.Kind != KindWorkload {
		t.Errorf("a stack that only needs a plan is prepared with the things to re-create: %+v", s)
	}
	stepWith(t, rb, PhaseRecreate, "Plan stack payments-network off the shared networking")

	s = stepWith(t, rb, PhaseBefore, "before StackSet "+fixtures.LarkspurBaselineStackSet+" deletes it")
	if s.Status != evaluator.StatusReview || s.Kind != KindStackSet || !strings.Contains(s.Where, "administration account 111111111111") ||
		!strings.Contains(cmds(s), "describe-stack-set --stack-set-name larkspur-baseline-roles --query StackSet.AutoDeployment") ||
		!strings.Contains(cmds(s), "--auto-deployment Enabled=true,RetainStacksOnAccountRemoval=true") {
		t.Errorf("StackSet deletion step: %+v", s)
	}
	stepWith(t, rb, PhaseAfter, "Confirm what became of stack StackSet-"+fixtures.LarkspurBaselineStackSet)
	s = stepWith(t, rb, PhaseAfter, "which StackSet "+fixtures.LarkspurRecorderStackSet+" left behind")
	if s.Status != evaluator.StatusInfo || !strings.Contains(s.Title, "Adopt or replace stack StackSet-"+fixtures.LarkspurRecorderStackSet) {
		t.Errorf("retained stack step: %+v", s)
	}

	s = stepWith(t, rb, PhaseBefore, "Decide where stack payments-api reads its cross-account output from")
	if s.Kind != KindDecision || s.Resource != fixtures.LarkspurObservabilityRole || !strings.Contains(s.Where, "111111111113") ||
		!strings.Contains(cmds(s), "aws iam get-role --role-name CfnOutputReader") {
		t.Errorf("stack output reference step: %+v", s)
	}
	stepWith(t, rb, PhaseAfter, "Confirm stack payments-api still resolves its cross-account output")

	// Imports that stay inside the account need no step.
	for _, st := range rb.Steps() {
		if strings.Contains(st.Finding, "import(s) between stacks") {
			t.Errorf("an informational import finding should not become a step: %s", st.Title)
		}
		if st.Check == "workloads" && st.Kind == "" {
			t.Errorf("workload step without a kind: %+v", st)
		}
	}
}

// A missing workload inventory is one collection step per domain, pointing
// at the member inspection configuration rather than the management profile.
func TestMissingWorkloadInventoryIsACollectionStep(t *testing.T) {
	rb := buildScenario(t, scenarios()[3]) // the security account has no inventory
	s := stepWith(t, rb, PhaseBefore, "Collect the missing evidence: workloads.stacks (source snapshot)")
	joined := strings.Join(s.Commands, "\n")
	if s.Kind != KindInput || s.Check != "workloads" || !strings.Contains(joined, "add 111111111113 to member_inspection.accounts") ||
		!strings.Contains(joined, "orgshift collect --config orgshift.yaml --side source") || !strings.Contains(joined, "orgshift workloads --snapshot <source snapshot> --account 111111111113") {
		t.Errorf("workload collection step: %+v", s)
	}
	stepWith(t, rb, PhaseBefore, "Collect the missing evidence: workloads.resources (source snapshot)")
	stepWith(t, rb, PhaseBefore, "Collect the missing evidence: workloads.policies (source snapshot)")
}

// Inside one organization the instance of an OU-targeted StackSet is the
// workload step.
func TestSameOrgWorkloadStep(t *testing.T) {
	rb := buildScenario(t, scenarios()[4])
	s := stepWith(t, rb, PhaseBefore, "before StackSet "+fixtures.FernhillBaselineStackSet+" deletes it")
	if s.Status != evaluator.StatusReview || !strings.Contains(s.Finding, "target OUs (ou-fern-bu)") {
		t.Errorf("same-organization StackSet step: %+v", s)
	}
}
