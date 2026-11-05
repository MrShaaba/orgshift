package evaluator

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/MrShaaba/orgshift/internal/fixtures"
	"github.com/MrShaaba/orgshift/internal/snapshot"
	"github.com/MrShaaba/orgshift/internal/workload"
)

func paymentsToFernhill(t *testing.T, mutate func(l, f *snapshot.Snapshot)) *Result {
	t.Helper()
	l, f := fixtures.Larkspur(), fixtures.Fernhill()
	if mutate != nil {
		mutate(l, f)
	}
	res, err := Evaluate(Input{From: l, To: f, AccountID: fixtures.LarkspurPaymentsProd, TargetOUID: fixtures.FernhillPaymentsOU})
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func titled(sub ...string) func(Finding) bool {
	return func(f Finding) bool {
		for _, s := range sub {
			if !strings.Contains(f.Title, s) {
				return false
			}
		}
		return true
	}
}

func hasKind(f Finding, kind string) bool {
	for _, ev := range f.Evidence {
		if ev.Kind == kind {
			return true
		}
	}
	return false
}

func stackOfAccount(t *testing.T, s *snapshot.Snapshot, account, prefix string) *snapshot.Stack {
	t.Helper()
	w := s.Workloads[account]
	for i := range w.Stacks {
		if strings.HasPrefix(w.Stacks[i].Name, prefix) {
			return &w.Stacks[i]
		}
	}
	t.Fatalf("no stack %s in account %s", prefix, account)
	return nil
}

// Every planted workload problem of the payments account is reported by the
// workloads check, with the category, confidence and evidence it rests on.
func TestWorkloadCheckReportsThePlantedProblems(t *testing.T) {
	res := paymentsToFernhill(t, nil)
	c := check(res, "workloads")
	if c.Status != StatusNoGo || c.Title != "Workloads" || !strings.Contains(c.Summary, "Workload layer evaluated: 8 stack(s) with 37 resource(s), 14 sampled resource(s) from tagging-api") {
		t.Fatalf("workloads check: %s %s", c.Status, c.Summary)
	}
	wl := res.WorkloadLayer
	if wl == nil || wl.Evaluation != workload.Evaluated || wl.Stacks != 8 || wl.StackResources != 37 || wl.SampledResources != 14 || wl.PoliciesOnOrgIdentity != 3 || wl.PoliciesInspected != 17 ||
		wl.ResourceSource != snapshot.ResourceSourceTaggingAPI || len(wl.Groups) != 3 || len(wl.Coverage) != 3 {
		t.Fatalf("workload layer: %+v", wl)
	}
	for _, f := range c.Findings {
		if f.Category == "" || f.Confidence == "" || len(f.Evidence) == 0 {
			t.Errorf("finding %q needs a category, a confidence and evidence", f.Title)
		}
	}

	// A service-managed StackSet instance that is deleted on leaving.
	deleted := find(t, res, "workloads", titled("StackSet instance StackSet-"+fixtures.LarkspurBaselineStackSet, "is deleted when the account leaves the organization: 4 resource(s)"))
	if deleted.Status != StatusReview || deleted.Category != CategoryDeclaredImpact || deleted.Confidence != ConfidenceHigh || !hasKind(deleted, EvidenceStackInstance) ||
		!strings.Contains(deleted.Detail, "automatic deployment on and RetainStacksOnAccountRemoval off") || !strings.Contains(deleted.Detail, "AWS::IAM::Role x3") ||
		!strings.Contains(deleted.Evidence[0].Note, "the stack ID is one of the StackSet's instances") || len(deleted.Regions) != 1 || len(deleted.References) == 0 {
		t.Errorf("deleted instance: %+v", deleted)
	}
	// The recorder StackSet retains its stacks: informational, in both Regions.
	retained := 0
	for _, f := range c.Findings {
		if strings.Contains(f.Title, "stays in the account, detached from StackSet "+fixtures.LarkspurRecorderStackSet) {
			retained++
			if f.Status != StatusInfo || f.Category != CategoryInformational {
				t.Errorf("retained instance: %+v", f)
			}
		}
	}
	if retained != 2 {
		t.Errorf("the recorder StackSet has an instance in two Regions, got %d findings", retained)
	}

	// A cross-stack export: imports stay inside the account and fix the order.
	imports := find(t, res, "workloads", titled("2 import(s) between stacks of the account move with it"))
	if imports.Status != StatusInfo || !hasKind(imports, EvidenceStackImport) || !strings.Contains(imports.Detail, "payments-api imports payments-app-sg from payments-network") ||
		!strings.Contains(imports.Detail, "inside one account and Region only") {
		t.Errorf("imports: %+v", imports)
	}
	// A cross-account reference: Fn::GetStackOutput through a role in the
	// security account, with the sts:AssumeRole call derived for the chains.
	output := find(t, res, "workloads", titled("Stack payments-api reads output LogDestinationArn of stack shared-observability in account 111111111113"))
	if output.Status != StatusReview || output.Category != CategoryPotentialImpact || output.Source != SourceWorkload || output.Action != "sts:AssumeRole" ||
		output.Resource != fixtures.LarkspurObservabilityRole || !hasKind(output, EvidenceStackOutputReference) ||
		!strings.Contains(output.Detail, "which stays in organization o-larkspur0001") || !strings.Contains(output.Detail, "resolved when the consuming stack is created or updated") {
		t.Errorf("stack output reference: %+v", output)
	}
	if res.Subject.DerivedOperations != 1 {
		t.Errorf("one operation is derived from the inventory, got %d", res.Subject.DerivedOperations)
	}

	// A bucket policy on aws:PrincipalOrgID that locks the account itself out.
	bucket := find(t, res, "workloads", titled("Bucket policy of "+fixtures.LarkspurSettlementBucket, "denies the account's own principals after the move"))
	if bucket.Status != StatusNoGo || bucket.Category != CategoryDeclaredImpact || bucket.Confidence != ConfidenceHigh || bucket.Source != SourceWorkload || bucket.Resource != fixtures.LarkspurSettlementBucket ||
		!strings.Contains(bucket.Detail, "Statement DataPerimeter (Deny): it denies s3:* to the account's own principals after the move") ||
		!strings.Contains(bucket.Detail, "StringNotEqualsIfExists aws:PrincipalOrgID o-larkspur0001, o-acquirer0001") {
		t.Errorf("bucket policy: %+v", bucket)
	}
	var statements []string
	for _, ev := range bucket.Evidence {
		if ev.Kind != EvidenceResourcePolicy || ev.PolicyType != snapshot.PolicyKindBucket || len(ev.StatementJSON) == 0 {
			t.Errorf("bucket policy evidence: %+v", ev)
		}
		statements = append(statements, ev.Statement)
	}
	if strings.Join(statements, ",") != "ReadFromTheOrganization,DataPerimeter" {
		t.Errorf("the evidence should carry the two statements that change, got %v", statements)
	}
	// A trust policy that stays tied to the organization the account leaves.
	trust := find(t, res, "workloads", titled("Trust policy of arn:aws:iam::111111111115:role/DataExportReader stays tied to the organization the account leaves"))
	if trust.Status != StatusReview || trust.Category != CategoryPotentialImpact || !strings.Contains(trust.Detail, "keeps admitting principals of o-larkspur0001") || !strings.Contains(trust.Detail, "does not admit principals of o-fernhill0001") {
		t.Errorf("trust policy: %+v", trust)
	}
	// A condition found in a template: reported, not evaluated.
	tmpl := find(t, res, "workloads", titled("Template policy for resource AppLogSubscriptionRole of stack payments-api"))
	if tmpl.Status != StatusReview || tmpl.Category != CategoryPotentialImpact || !strings.Contains(tmpl.Detail, "aws:PrincipalOrgPaths o-larkspur0001/r-lark/ou-lark-sec/*") ||
		!strings.Contains(tmpl.Detail, "cannot be evaluated here") {
		t.Errorf("template policy: %+v", tmpl)
	}

	// An app on shared subnets: the stack with an Auto Scaling group blocks,
	// the database stack and the transit gateway attachment need a plan.
	api := find(t, res, "workloads", titled("Stack payments-api sits on 2 subnets shared through larkspur-core-network"))
	if api.Status != StatusNoGo || api.Category != CategoryDeclaredImpact || api.Confidence != ConfidenceHigh || !hasKind(api, EvidenceStackReference) || !hasKind(api, "resource-share") ||
		!strings.Contains(api.Detail, "(parameter AppSubnetIds)") || !strings.Contains(api.Detail, "AWS::AutoScaling::AutoScalingGroup, which launches instances into its subnets") ||
		!strings.Contains(api.Detail, "can only be shared inside one organization") {
		t.Errorf("app on shared subnets: %+v", api)
	}
	db := find(t, res, "workloads", titled("Stack payments-ledger-db sits on 2 subnets"))
	if db.Status != StatusReview || strings.Contains(db.Detail, "AutoScaling") {
		t.Errorf("database on shared subnets: %+v", db)
	}
	tgw := find(t, res, "workloads", titled("Stack payments-network sits on a transit gateway shared through larkspur-core-network"))
	if tgw.Status != StatusReview || !strings.Contains(tgw.Detail, "The stack owns the attachment") || !strings.Contains(tgw.Detail, "existing transit gateway attachments remain functional") {
		t.Errorf("transit gateway: %+v", tgw)
	}

	// Tag-policy compliance of the collected sample at the destination,
	// including the resources that miss the cost-center tag.
	if res.Subject.TaggedResources != 14 {
		t.Errorf("the tag check should use the collected sample of 14, got %d", res.Subject.TaggedResources)
	}
	tags := check(res, "tags")
	if !strings.Contains(tags.Summary, "across 14 sampled resources") {
		t.Errorf("tags summary: %s", tags.Summary)
	}
	missing := find(t, res, "tags", titled("cost-center: lambda:function resources carry no cost-center tag"))
	if !strings.Contains(missing.Detail, "function:settlement-notifier") {
		t.Errorf("missing cost-center: %+v", missing)
	}
	find(t, res, "tags", titled("cost-center: ec2:instance resources carry no cost-center tag"))
	find(t, res, "tags", titled("cost-center: sqs:queue resources carry no cost-center tag"))

	// The older organization-level StackSet finding points at the detail.
	old := find(t, res, "org-services", titled("StackSet "+fixtures.LarkspurBaselineStackSet+" stops targeting the account; stack instances are deleted"))
	if !strings.Contains(old.Detail, "The workloads check lists the instances found in this account") {
		t.Errorf("org-services StackSet finding: %+v", old)
	}
	// The model is listed with its date.
	if m := res.Models[len(res.Models)-1]; m.ID != "workload-behaviour" || m.Version != WorkloadModelVersion || !strings.Contains(m.Note, "not a documented rule") {
		t.Errorf("workload model: %+v", m)
	}
}

// The role CloudFormation assumes for a cross-account stack output is
// evaluated against the destination's SCPs like any other operation.
func TestDerivedOperationIsEvaluatedAgainstThePolicyChains(t *testing.T) {
	res := paymentsToFernhill(t, func(l, f *snapshot.Snapshot) {
		f.Policies = append(f.Policies, snapshot.Policy{ID: "p-noassume", Name: "No-Cross-Account-Roles", Type: snapshot.PolicyTypeSCP,
			Document: json.RawMessage(`{"Version":"2012-10-17","Statement":[{"Sid":"NoRolesElsewhere","Effect":"Deny","Action":"sts:AssumeRole","Resource":"arn:aws:iam::111111111113:role/*"}]}`),
			Targets:  []string{fixtures.FernhillPaymentsOU}})
	})
	f := find(t, res, "scp", func(f Finding) bool { return f.Action == "sts:AssumeRole" && f.Source == SourceWorkload })
	if f.Status != StatusNoGo || f.Resource != fixtures.LarkspurObservabilityRole || !strings.Contains(f.Detail, "derived from the workload inventory") ||
		!strings.Contains(f.Detail, "to resolve Fn::GetStackOutput in stack payments-api") {
		t.Errorf("derived operation against the SCP chain: %+v", f)
	}
	// Without that policy the derived call is allowed and nothing is flagged.
	clean := paymentsToFernhill(t, nil)
	for _, c := range clean.Checks {
		if c.ID != "scp" && c.ID != "rcp" {
			continue
		}
		for _, f := range c.Findings {
			if f.Source == SourceWorkload {
				t.Errorf("no policy stops the derived call in the plain fixtures: %+v", f)
			}
		}
	}
}

func TestStackSetInstanceVariants(t *testing.T) {
	baseline := "StackSet-" + fixtures.LarkspurBaselineStackSet
	stackSet := func(l *snapshot.Snapshot) *snapshot.StackSet {
		for i := range l.StackSets {
			if l.StackSets[i].Name == fixtures.LarkspurBaselineStackSet {
				return &l.StackSets[i]
			}
		}
		t.Fatal("no baseline StackSet")
		return nil
	}
	// Automatic deployment off: the documentation does not say what happens.
	res := paymentsToFernhill(t, func(l, f *snapshot.Snapshot) { stackSet(l).AutoDeployment = false })
	f := find(t, res, "workloads", titled("What happens to StackSet instance "+baseline, "is not documented"))
	if f.Status != StatusReview || f.Category != CategoryPotentialImpact || f.Confidence != ConfidenceMedium || !strings.Contains(f.Detail, "automatic deployment off") {
		t.Errorf("auto-deployment off: %+v", f)
	}
	org := find(t, res, "org-services", titled("StackSet "+fixtures.LarkspurBaselineStackSet+" stops targeting the account"))
	if !strings.Contains(org.Title, "what happens to its stack instances is not documented") {
		t.Errorf("the organization-level finding should not claim a deletion either: %s", org.Title)
	}
	// Retention on: the stack stays, detached.
	res = paymentsToFernhill(t, func(l, f *snapshot.Snapshot) { stackSet(l).RetainStacksOnAccountRemoval = true })
	if f := find(t, res, "workloads", titled("StackSet instance "+baseline, "stays in the account")); f.Status != StatusInfo {
		t.Errorf("retained: %+v", f)
	}
	// Matched by name only: the same claim at medium confidence.
	res = paymentsToFernhill(t, func(l, f *snapshot.Snapshot) {
		stackSet(l).Instances = nil
		stackOfAccount(t, l, fixtures.LarkspurPaymentsProd, baseline).StackSet = nil
	})
	f = find(t, res, "workloads", titled("StackSet instance "+baseline, "is deleted"))
	if f.Confidence != ConfidenceMedium || !strings.Contains(f.Evidence[0].Note, "which is a convention; no instance record confirms it") {
		t.Errorf("name-only match: %+v", f)
	}
	// An import of the instance's export blocks the deletion.
	res = paymentsToFernhill(t, func(l, f *snapshot.Snapshot) {
		stackOfAccount(t, l, fixtures.LarkspurPaymentsProd, baseline).Outputs = []snapshot.StackOutput{{Key: "AuditRoleArn", ExportName: "baseline-audit-role"}}
		api := stackOfAccount(t, l, fixtures.LarkspurPaymentsProd, fixtures.LarkspurAPIStack)
		api.Imports = append(api.Imports, snapshot.StackImport{ExportName: "baseline-audit-role"})
	})
	f = find(t, res, "workloads", titled("StackSet instance "+baseline, "is deleted"))
	if !strings.Contains(f.Detail, "payments-api (imports baseline-audit-role) still import") || !strings.Contains(f.Detail, "refuses to delete a stack whose export is imported") {
		t.Errorf("an imported export blocks the deletion: %s", f.Detail)
	}
	// A self-managed StackSet does not depend on the organization.
	res = paymentsToFernhill(t, func(l, f *snapshot.Snapshot) {
		ss := stackSet(l)
		ss.PermissionModel, ss.AutoDeployment = "SELF_MANAGED", false
	})
	f = find(t, res, "workloads", titled("Self-managed StackSet "+fixtures.LarkspurBaselineStackSet+" keeps operating stack"))
	if f.Status != StatusReview || f.Category != CategoryPotentialImpact || !hasKind(f, EvidenceExternalStackSet) || !strings.Contains(f.Detail, "neither depends on the organization") {
		t.Errorf("self-managed: %+v", f)
	}
}

// Fernhill's accounts leaving for Larkspur: the Control Tower baseline and a
// StackSet instance nobody in the organization administers.
func TestControlTowerBaselineAndUnknownStackSetOnLeaving(t *testing.T) {
	l, f := fixtures.Larkspur(), fixtures.Fernhill()
	res, err := Evaluate(Input{From: f, To: l, AccountID: fixtures.FernhillRetailProd, TargetOUID: "ou-lark-prod"})
	if err != nil {
		t.Fatal(err)
	}
	ct := find(t, res, "workloads", titled("Control Tower baseline stack(s)", "belong to the source landing zone"))
	if ct.Status != StatusInfo || ct.Category != CategoryInformational || !strings.Contains(ct.Detail, "StackSet-AWSControlTowerBP-BASELINE-CONFIG") || !strings.Contains(ct.Detail, "The Control Tower check has the sequence") {
		t.Errorf("control tower baseline: %+v", ct)
	}
	if res.WorkloadLayer.ResourceSource != snapshot.ResourceSourceResourceExplorer {
		t.Errorf("the retail account was sampled with Resource Explorer: %+v", res.WorkloadLayer)
	}
	find(t, res, "workloads", titled("StackSet instance StackSet-"+fixtures.FernhillBaselineStackSet, "is deleted when the account leaves the organization"))

	res, err = Evaluate(Input{From: f, To: l, AccountID: "222222222227", TargetOUID: "ou-lark-sand"})
	if err != nil {
		t.Fatal(err)
	}
	unknown := find(t, res, "workloads", titled("Stack StackSet-team-tooling", "looks like a StackSet instance, but no StackSet in the snapshot owns it"))
	if unknown.Status != StatusReview || unknown.Category != CategoryPotentialImpact || unknown.Confidence != ConfidenceMedium || !hasKind(unknown, EvidenceExternalStackSet) ||
		!strings.Contains(unknown.Detail, "not a documented rule") {
		t.Errorf("unknown StackSet: %+v", unknown)
	}
}

// Inside one organization only what follows the OU path changes.
func TestWorkloadsInsideOneOrganization(t *testing.T) {
	f := fixtures.Fernhill()
	res, err := Evaluate(Input{From: f, AccountID: fixtures.FernhillRetailProd, TargetOUID: fixtures.FernhillSandboxOU})
	if err != nil {
		t.Fatal(err)
	}
	left := find(t, res, "workloads", titled("StackSet instance StackSet-"+fixtures.FernhillBaselineStackSet, "is deleted when the account leaves the StackSet's target OUs (ou-fern-bu)"))
	if left.Status != StatusReview || left.Category != CategoryDeclaredImpact {
		t.Errorf("leaving a target OU: %+v", left)
	}
	for _, fd := range check(res, "workloads").Findings {
		if strings.Contains(fd.Title, "Control Tower baseline") || strings.Contains(fd.Title, "import(s) between stacks") {
			t.Errorf("a move inside the organization should not report %q", fd.Title)
		}
	}
	// A move that stays under the StackSet's target OU keeps the instance.
	res, err = Evaluate(Input{From: f, AccountID: fixtures.FernhillRetailProd, TargetOUID: fixtures.FernhillPaymentsOU})
	if err != nil {
		t.Fatal(err)
	}
	for _, fd := range check(res, "workloads").Findings {
		if strings.Contains(fd.Title, "StackSet instance") {
			t.Errorf("still under ou-fern-bu, the instance stays: %q", fd.Title)
		}
	}
	// A template condition on the OU path that covers the old path only.
	l := fixtures.Larkspur()
	w := l.Workloads["111111111116"]
	w.ResourcePolicies = append(w.ResourcePolicies, snapshot.ResourcePolicy{Kind: snapshot.PolicyKindTemplate, Resource: "QueuePolicy", Stack: "dev-queues", Source: "cloudformation:GetTemplate",
		Conditions: []snapshot.OrgCondition{{Effect: "Allow", Operator: "ForAnyValue:StringLike", Key: "aws:PrincipalOrgPaths", Values: []string{"o-larkspur0001/r-lark/ou-lark-work/ou-lark-dev/*"}},
			{Effect: "Allow", Operator: "StringEquals", Key: "aws:PrincipalOrgID", Values: []string{"${OrgId}"}, Dynamic: true}}})
	res, err = Evaluate(Input{From: l, AccountID: "111111111116", TargetOUID: "ou-lark-prod"})
	if err != nil {
		t.Fatal(err)
	}
	path := find(t, res, "workloads", titled("Template policy for resource QueuePolicy of stack dev-queues"))
	if path.Status != StatusReview || path.Category != CategoryUnsupported || !strings.Contains(path.Detail, "covers the account's path o-larkspur0001/r-lark/ou-lark-work/ou-lark-dev/") ||
		!strings.Contains(path.Detail, "a value is computed in the template and not known offline") {
		t.Errorf("path condition inside one organization: %+v", path)
	}
}

func TestWorkloadLayerFollowsCoverage(t *testing.T) {
	f := fixtures.Fernhill()
	// Denied inventory on a cross-organization move: not evaluated, and the
	// three domains are gaps of the workloads check.
	p := fixtures.LarkspurPartial()
	res, err := Evaluate(Input{From: p, To: f, AccountID: fixtures.LarkspurPaymentsProd, TargetOUID: fixtures.FernhillPaymentsOU})
	if err != nil {
		t.Fatal(err)
	}
	c := check(res, "workloads")
	if res.WorkloadLayer.Evaluation != workload.NotEvaluated || c.Status != StatusReview || len(c.CoverageGaps) != 3 || len(gapFindings(c)) != 3 || !strings.Contains(c.Summary, "was not evaluated") {
		t.Fatalf("denied inventory: %s %+v gaps %v", res.WorkloadLayer.Evaluation, c.Summary, c.CoverageGaps)
	}
	for _, g := range gapFindings(c) {
		if g.Category != CategoryMissingEvidence || !strings.Contains(g.Title, "denied access to workloads.") {
			t.Errorf("gap finding: %+v", g)
		}
	}
	// One domain denied: partially evaluated; what was read is still assessed.
	l := fixtures.Larkspur()
	for i := range l.Coverage.Domains {
		d := &l.Coverage.Domains[i]
		if d.Domain == snapshot.DomainWorkloadPolicies && d.AccountID == fixtures.LarkspurPaymentsProd {
			d.Status, d.Error = snapshot.CoverageAccessDenied, "AccessDenied: s3:GetBucketPolicy"
		}
	}
	l.Workloads[fixtures.LarkspurPaymentsProd].ResourcePolicies = nil
	res, err = Evaluate(Input{From: l, To: f, AccountID: fixtures.LarkspurPaymentsProd, TargetOUID: fixtures.FernhillPaymentsOU})
	if err != nil {
		t.Fatal(err)
	}
	c = check(res, "workloads")
	if res.WorkloadLayer.Evaluation != workload.PartiallyEvaluated || !strings.Contains(c.Summary, "partially evaluated") || len(c.CoverageGaps) != 1 || c.CoverageGaps[0] != "workloads.policies on source" {
		t.Fatalf("partial inventory: %s %s %v", res.WorkloadLayer.Evaluation, c.Summary, c.CoverageGaps)
	}
	find(t, res, "workloads", titled("StackSet instance", "is deleted"))
	// An account that was not inspected, inside one organization: said, not
	// required, and the verdict does not move.
	l = fixtures.Larkspur()
	res, err = Evaluate(Input{From: l, AccountID: "111111111117", TargetOUID: "ou-lark-prod"})
	if err != nil {
		t.Fatal(err)
	}
	c = check(res, "workloads")
	info := find(t, res, "workloads", titled("No workload inventory for this account"))
	if c.Status != StatusGo || info.Status != StatusInfo || info.Category != CategoryMissingEvidence || len(c.CoverageGaps) != 0 || res.WorkloadLayer.Evaluation != workload.NotEvaluated {
		t.Errorf("uninspected account inside one organization: %s %+v", c.Status, info)
	}
	// The same account across organizations: the inventory is required.
	res, err = Evaluate(Input{From: l, To: f, AccountID: "111111111117", TargetOUID: fixtures.FernhillSandboxOU})
	if err != nil {
		t.Fatal(err)
	}
	if c = check(res, "workloads"); len(c.CoverageGaps) != 3 || res.Verdict == StatusGo {
		t.Errorf("uninspected account across organizations: %v, verdict %s", c.CoverageGaps, res.Verdict)
	}
	// A hand-written snapshot that asserts completeness and lists no
	// workloads: an empty inventory, evaluated.
	s := shareOrg(t, shareCase{types: []string{"ec2:Subnet"}})
	res, err = Evaluate(Input{From: s, AccountID: "111111111113", TargetOUID: "r-shr1"})
	if err != nil {
		t.Fatal(err)
	}
	if c = check(res, "workloads"); res.WorkloadLayer.Evaluation != workload.Evaluated || res.WorkloadLayer.Stacks != 0 || len(c.Findings) != 0 || c.Status != StatusGo {
		t.Errorf("asserted empty inventory: %s %+v", res.WorkloadLayer.Evaluation, c.Findings)
	}
	// A snapshot upgraded from schema version 2 asserted completeness
	// before the workload domains existed: the assertion does not cover them.
	l, f = fixtures.Larkspur(), fixtures.Fernhill()
	l.Workloads = nil
	var kept []snapshot.DomainCoverage
	for _, d := range l.Coverage.Domains {
		if !snapshot.IsWorkloadDomain(d.Domain) {
			kept = append(kept, d)
		}
	}
	l.Coverage.Domains, l.Coverage.AssertedComplete, l.UpgradedFrom = kept, true, 2
	res, err = Evaluate(Input{From: l, To: f, AccountID: fixtures.LarkspurPaymentsProd, TargetOUID: fixtures.FernhillPaymentsOU})
	if err != nil {
		t.Fatal(err)
	}
	if c = check(res, "workloads"); res.WorkloadLayer.Evaluation != workload.NotEvaluated || len(c.CoverageGaps) != 3 {
		t.Errorf("an assertion made at schema version 2 must not cover the workload domains: %s %v", res.WorkloadLayer.Evaluation, c.CoverageGaps)
	}
}

func TestResourcePolicyVariants(t *testing.T) {
	policies := func(l *snapshot.Snapshot, ps ...snapshot.ResourcePolicy) {
		w := l.Workloads[fixtures.LarkspurPaymentsProd]
		w.ResourcePolicies = ps
	}
	bucket := func(doc string) snapshot.ResourcePolicy {
		return snapshot.ResourcePolicy{Kind: snapshot.PolicyKindBucket, ResourceARN: "arn:aws:s3:::probe", Source: "s3:GetBucketPolicy", Document: json.RawMessage(doc)}
	}
	// A policy that already names both organizations changes nothing.
	res := paymentsToFernhill(t, func(l, f *snapshot.Snapshot) {
		policies(l, bucket(`{"Version":"2012-10-17","Statement":[{"Sid":"Perimeter","Effect":"Deny","Principal":"*","Action":"s3:*","Resource":"arn:aws:s3:::probe/*","Condition":{"StringNotEqualsIfExists":{"aws:PrincipalOrgID":["o-larkspur0001","o-fernhill0001"]}}}]}`))
	})
	for _, f := range check(res, "workloads").Findings {
		if strings.Contains(f.Title, "arn:aws:s3:::probe") {
			t.Errorf("a perimeter that names both organizations should not be reported: %+v", f)
		}
	}
	// An Allow that stops applying is a potential impact, not a blocker.
	res = paymentsToFernhill(t, func(l, f *snapshot.Snapshot) {
		policies(l, bucket(`{"Version":"2012-10-17","Statement":[{"Sid":"OrgRead","Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::probe/*","Condition":{"StringEquals":{"aws:PrincipalOrgID":"o-larkspur0001"}}}]}`))
	})
	f := find(t, res, "workloads", titled("Bucket policy of arn:aws:s3:::probe ties access to organization identity that changes with the move"))
	if f.Status != StatusReview || f.Category != CategoryPotentialImpact || f.Confidence != ConfidenceMedium || !strings.Contains(f.Detail, "an identity policy can still grant the access") {
		t.Errorf("allow that stops applying: %+v", f)
	}
	// aws:ResourceOrgID follows the resource's own account into the new organization.
	res = paymentsToFernhill(t, func(l, f *snapshot.Snapshot) {
		policies(l, bucket(`{"Version":"2012-10-17","Statement":[{"Sid":"OnlyOurResources","Effect":"Deny","Principal":"*","Action":"s3:*","Resource":"arn:aws:s3:::probe/*","Condition":{"StringNotEquals":{"aws:ResourceOrgID":"o-larkspur0001"}}}]}`))
	})
	f = find(t, res, "workloads", titled("Bucket policy of arn:aws:s3:::probe denies the account's own principals after the move"))
	if f.Status != StatusNoGo || !strings.Contains(f.Detail, "aws:ResourceOrgID") {
		t.Errorf("resource organization condition: %+v", f)
	}
	// A document that cannot be parsed is unsupported, never ignored.
	res = paymentsToFernhill(t, func(l, f *snapshot.Snapshot) { policies(l, bucket(`{"Statement": 7}`)) })
	f = find(t, res, "workloads", titled("Bucket policy of arn:aws:s3:::probe could not be parsed"))
	if f.Status != StatusReview || f.Category != CategoryUnsupported {
		t.Errorf("unparsable policy: %+v", f)
	}
}

// A share the account keeps (retained for it by the owner) does not strand
// the stacks that reference its resources.
func TestStacksOnRetainedSharesAreNotReported(t *testing.T) {
	res := paymentsToFernhill(t, func(l, f *snapshot.Snapshot) {
		for i := range l.ResourceShares {
			sh := &l.ResourceShares[i]
			if sh.Name == "larkspur-core-network" {
				sh.Principals = append(sh.Principals, fixtures.LarkspurPaymentsProd)
				sh.AllowExternalPrincipals, sh.RetainSharingOnAccountLeave = true, true
			}
		}
	})
	for _, f := range check(res, "workloads").Findings {
		if strings.Contains(f.Title, "shared through larkspur-core-network") {
			t.Errorf("the share is retained for the account, so the stack keeps its networking: %q", f.Title)
		}
	}
}
