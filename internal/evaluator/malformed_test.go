package evaluator

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/MrShaaba/orgshift/internal/snapshot"
)

func runWithTargetPolicy(t *testing.T, srcDoc, dstDoc string, edit func(src, dst *snapshot.Snapshot)) *Result {
	t.Helper()
	src, dst := twoOrgs(t, srcDoc, dstDoc, false)
	src.Usage["111111111112"].Actions[0].Resource = "arn:aws:ec2:us-east-1:111111111112:instance/platform-1"
	if edit != nil {
		edit(src, dst)
	}
	res, err := Evaluate(Input{From: src, To: dst, AccountID: "111111111112", TargetOUID: "r-dst1"})
	if err != nil {
		t.Fatal(err)
	}
	return res
}

// M5 defect 3. A malformed policy is unknown in both directions: the check
// whose chain holds it is a REVIEW, never the definite answer the evaluator
// used to give by reading the statement as if it were well formed.
func TestMalformedPolicyMakesTheCheckReview(t *testing.T) {
	cases := map[string]struct{ doc, reason string }{
		// Read as Resource "*" on HEAD: a definite NO-GO.
		"deny without resource": {`{"Version":"2012-10-17","Statement":[{"Sid":"NoResource","Effect":"Deny","Action":"ec2:RunInstances"}]}`, "must include a Resource or NotResource element"},
		// Read as NotAction only on HEAD: a definite NO-GO.
		"action and notaction": {`{"Version":"2012-10-17","Statement":[{"Sid":"Both","Effect":"Deny","Action":"ec2:RunInstances","NotAction":"s3:*","Resource":"*"}]}`, "both Action and NotAction"},
		// Read as NotResource only on HEAD: a GO.
		"resource and notresource": {`{"Version":"2012-10-17","Statement":[{"Sid":"Both","Effect":"Deny","Action":"ec2:RunInstances","Resource":"*","NotResource":"arn:aws:ec2:*:*:instance/*"}]}`, "both Resource and NotResource"},
		// An Allow with a specific resource is not a valid SCP either.
		"allow with a resource arn": {`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"ec2:*","Resource":"arn:aws:ec2:*:*:instance/*"}]}`, `can only have "*" as its Resource`},
	}
	for name, c := range cases {
		res := runWithTargetPolicy(t, denyNothingUsed, c.doc, nil)
		scp := check(res, "scp")
		if scp.Status != StatusReview {
			t.Errorf("%s: the SCP check should be REVIEW, got %s (%s)", name, scp.Status, scp.Summary)
			continue
		}
		bad := find(t, res, "scp", func(f Finding) bool { return strings.Contains(f.Title, "is malformed") })
		if bad.Status != StatusReview || bad.Category != CategoryUnsupported || !strings.Contains(bad.Title, "SCP Guardrails on the target chain") ||
			!strings.Contains(bad.Detail, c.reason) || len(bad.Evidence) != 1 || bad.Evidence[0].Kind != "policy-unparseable" || bad.Evidence[0].Side != "target" {
			t.Errorf("%s: the malformed policy is named with the reason: %+v", name, bad)
		}
		// The action that meets the policy is undecided, not denied or allowed.
		act := find(t, res, "scp", func(f Finding) bool { return f.Action == "ec2:RunInstances" })
		if act.Status != StatusReview || !strings.Contains(act.Detail, c.reason) {
			t.Errorf("%s: the action is a REVIEW with the reason: %s %s", name, act.Status, act.Detail)
		}
		if res.Verdict != StatusReview {
			t.Errorf("%s: verdict %s", name, res.Verdict)
		}
		// The diff shows the policy as malformed instead of summarizing it.
		var marked bool
		for _, d := range res.Diff {
			for _, ref := range append(append([]PolicyRef{}, d.Added...), d.Changed...) {
				if ref.Name == "Guardrails" && strings.Contains(ref.Malformed, c.reason) && len(ref.Statements) == 0 {
					marked = true
				}
			}
		}
		if !marked {
			t.Errorf("%s: the diff should mark the policy as malformed", name)
		}
	}

	// On the source chain only: the destination is decided, and the check is
	// still a REVIEW because "what applies today" rests on the document.
	res := runWithTargetPolicy(t, cases["action and notaction"].doc, denyNothingUsed, nil)
	if scp := check(res, "scp"); scp.Status != StatusReview {
		t.Errorf("a malformed policy on the source chain makes the check REVIEW, got %s", scp.Status)
	}
	bad := find(t, res, "scp", func(f Finding) bool { return strings.Contains(f.Title, "is malformed") })
	if !strings.Contains(bad.Title, "on the source chain") || bad.Evidence[0].Side != "source" {
		t.Errorf("source-side malformed policy: %+v", bad)
	}
	// Without any action in use the malformed policy is still reported.
	res = runWithTargetPolicy(t, denyNothingUsed, cases["deny without resource"].doc, func(src, dst *snapshot.Snapshot) {
		src.Usage["111111111112"].Actions = nil
	})
	find(t, res, "scp", func(f Finding) bool { return strings.Contains(f.Title, "is malformed") })
	// A malformed policy attached elsewhere in the organization does not
	// touch this account's checks.
	res = runWithTargetPolicy(t, denyNothingUsed, denyNothingUsed, func(src, dst *snapshot.Snapshot) {
		dst.OUs = append(dst.OUs, snapshot.OU{ID: "ou-dst1-other", Name: "Other", ParentID: "r-dst1"})
		dst.Policies[0].Targets = append(dst.Policies[0].Targets, "ou-dst1-other")
		dst.Policies = append(dst.Policies, snapshot.Policy{ID: "p-elsewhere01", Name: "Elsewhere", Type: snapshot.PolicyTypeSCP,
			Document: json.RawMessage(cases["deny without resource"].doc), Malformed: "recorded", Targets: []string{"ou-dst1-other"}})
	})
	if scp := check(res, "scp"); scp.Status != StatusGo {
		t.Errorf("a malformed policy off the account's path changes nothing: %s (%s)", scp.Status, scp.Summary)
	}
	// A recorded reason on a document that is well formed is not trusted
	// over the document.
	res = runWithTargetPolicy(t, denyNothingUsed, denyRunInstances, func(src, dst *snapshot.Snapshot) {
		dst.Policies[1].Malformed = "stale record"
	})
	if f := find(t, res, "scp", func(f Finding) bool { return f.Action == "ec2:RunInstances" }); f.Status != StatusNoGo {
		t.Errorf("the document decides, not the record: %s", f.Status)
	}
	// RCPs: a statement without a Resource element is malformed there too.
	src, dst := rcpOrgs(t, "arn:aws:kms:us-east-1:111111111112:key/abc")
	dst.Policies = append(dst.Policies, snapshot.Policy{ID: "p-dst-rcp9", Name: "NoResource", Type: snapshot.PolicyTypeRCP,
		Document: json.RawMessage(`{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Principal":"*","Action":"kms:*"}]}`), Malformed: "recorded by the collector", Targets: []string{"r-dst1"}})
	if err := dst.Validate(); err != nil {
		t.Fatal(err)
	}
	rres, err := Evaluate(Input{From: src, To: dst, AccountID: "111111111112", TargetOUID: "r-dst1"})
	if err != nil {
		t.Fatal(err)
	}
	if rcp := check(rres, "rcp"); rcp.Status != StatusReview {
		t.Errorf("a malformed RCP makes the RCP check REVIEW: %s (%s)", rcp.Status, rcp.Summary)
	}
	find(t, rres, "rcp", func(f Finding) bool {
		return strings.Contains(f.Title, "RCP NoResource on the target chain is malformed") && strings.Contains(f.Detail, "must include a Resource or NotResource element")
	})
}

// An unresolved policy variable in Resource or NotResource is unknown,
// never a definite non-match, through the whole evaluation.
func TestPolicyVariableInAnSCPResource(t *testing.T) {
	variable := `{"Version":"2012-10-17","Statement":[{"Sid":"Var","Effect":"Deny","Action":"ec2:RunInstances","Resource":"arn:aws:ec2:*:*:instance/${aws:PrincipalTag/team}-*"}]}`
	// HEAD read ${...} as literal text: no match, a GO behind a Deny that
	// may well apply.
	res := runWithTargetPolicy(t, denyNothingUsed, variable, nil)
	f := find(t, res, "scp", func(f Finding) bool { return f.Action == "ec2:RunInstances" })
	if f.Status != StatusReview || f.Category != CategoryPotentialImpact || !strings.Contains(f.Detail, "policy variable") || !strings.Contains(f.Detail, "${aws:PrincipalTag/team}") {
		t.Errorf("a Deny behind an unresolved variable is a REVIEW that names it: %s [%s] %s", f.Status, f.Category, f.Detail)
	}
	// The usage entry says which team the caller is tagged with: decided.
	res = runWithTargetPolicy(t, denyNothingUsed, variable, func(src, dst *snapshot.Snapshot) {
		src.Usage["111111111112"].Actions[0].PrincipalTags = map[string]string{"team": "platform"}
	})
	if f = find(t, res, "scp", func(f Finding) bool { return f.Action == "ec2:RunInstances" }); f.Status != StatusNoGo {
		t.Errorf("team=platform resolves the variable and the Deny applies: %s %s", f.Status, f.Title)
	}
	res = runWithTargetPolicy(t, denyNothingUsed, variable, func(src, dst *snapshot.Snapshot) {
		src.Usage["111111111112"].Actions[0].PrincipalTags = map[string]string{"team": "data"}
	})
	if got := scpFindingsFor(res, "ec2:RunInstances"); len(got) != 0 {
		t.Errorf("team=data resolves the variable and the Deny does not apply: %+v", got)
	}
	// The caller is known to carry no team tag: the pattern matches nothing.
	res = runWithTargetPolicy(t, denyNothingUsed, variable, func(src, dst *snapshot.Snapshot) {
		src.Usage["111111111112"].Actions[0].PrincipalTags = map[string]string{"cost-center": "x"}
	})
	if got := scpFindingsFor(res, "ec2:RunInstances"); len(got) != 0 {
		t.Errorf("a variable with no value matches no resource: %+v", got)
	}
	// NotResource: the Deny applies to everything except the team's own
	// instances; whether this instance is excepted depends on the tag.
	except := `{"Version":"2012-10-17","Statement":[{"Sid":"Var","Effect":"Deny","Action":"ec2:RunInstances","NotResource":"arn:aws:ec2:*:*:instance/${aws:PrincipalTag/team}-*"}]}`
	res = runWithTargetPolicy(t, denyNothingUsed, except, nil)
	if f = find(t, res, "scp", func(f Finding) bool { return f.Action == "ec2:RunInstances" }); f.Status != StatusReview || !strings.Contains(f.Detail, "NotResource names a policy variable") {
		t.Errorf("HEAD read this as a definite deny; it is a REVIEW: %s %s", f.Status, f.Detail)
	}
	res = runWithTargetPolicy(t, denyNothingUsed, except, func(src, dst *snapshot.Snapshot) {
		src.Usage["111111111112"].Actions[0].PrincipalTags = map[string]string{"team": "platform"}
	})
	if got := scpFindingsFor(res, "ec2:RunInstances"); len(got) != 0 {
		t.Errorf("the team's own instance is excepted: %+v", got)
	}
	res = runWithTargetPolicy(t, denyNothingUsed, except, func(src, dst *snapshot.Snapshot) {
		src.Usage["111111111112"].Actions[0].PrincipalTags = map[string]string{"team": "data"}
	})
	if f = find(t, res, "scp", func(f Finding) bool { return f.Action == "ec2:RunInstances" }); f.Status != StatusNoGo {
		t.Errorf("another team's instance is not excepted: %s", f.Status)
	}
}
