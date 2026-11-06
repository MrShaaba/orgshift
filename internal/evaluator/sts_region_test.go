package evaluator

import (
	"strings"
	"testing"

	"github.com/MrShaaba/orgshift/internal/snapshot"
)

// A region guardrail without the usual exemption for global services: every
// request outside eu-west-1 is denied, whatever the service.
const euWestOnly = `{"Version":"2012-10-17","Statement":[{"Sid":"EuWestOnly","Effect":"Deny","Action":"*","Resource":"*","Condition":{"StringNotEquals":{"aws:RequestedRegion":"eu-west-1"}}}]}`

func stsMove(t *testing.T, srcDoc, dstDoc string, actions ...snapshot.ActionInUse) *Result {
	t.Helper()
	src, dst := twoOrgs(t, srcDoc, dstDoc, false)
	for _, s := range []*snapshot.Snapshot{src, dst} {
		for i := range s.Accounts {
			s.Accounts[i].EnabledRegions = []string{"eu-west-1", "us-east-1"}
		}
	}
	src.Usage["111111111112"] = &snapshot.AccountUsage{Actions: actions}
	for _, s := range []*snapshot.Snapshot{src, dst} {
		if err := s.Validate(); err != nil {
			t.Fatal(err)
		}
	}
	res, err := Evaluate(Input{From: src, To: dst, AccountID: "111111111112", TargetOUID: "r-dst1"})
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func scpStatuses(res *Result, action string) []string {
	var out []string
	for _, f := range scpFindingsFor(res, action) {
		out = append(out, string(f.Status)+": "+f.Title+" "+strings.Join(f.Regions, ","))
	}
	return out
}

// M5 defect 2. AWS STS has Regional endpoints; only a request to the global
// endpoint carries us-east-1 as aws:RequestedRegion. The evaluator treated
// every sts call as us-east-1.
func TestSTSIsEvaluatedInTheRegionOfItsEndpoint(t *testing.T) {
	assume := func(regions ...string) snapshot.ActionInUse {
		return snapshot.ActionInUse{Action: "sts:AssumeRole", Regions: regions}
	}

	// Allowed before, denied after: the destination only admits eu-west-1.
	// Through the eu-west-1 endpoint the call is allowed on both sides.
	res := stsMove(t, denyNothingUsed, euWestOnly, assume("eu-west-1"))
	if got := scpStatuses(res, "sts:AssumeRole"); len(got) != 0 {
		t.Errorf("sts through the eu-west-1 endpoint is allowed by a guardrail that admits eu-west-1: %v", got)
	}
	// Through the us-east-1 endpoint it becomes denied.
	res = stsMove(t, denyNothingUsed, euWestOnly, assume("us-east-1"))
	f := find(t, res, "scp", func(f Finding) bool { return f.Action == "sts:AssumeRole" })
	if f.Status != StatusNoGo || !strings.Contains(f.Title, "becomes denied after the move") || strings.Join(f.Regions, ",") != "us-east-1" {
		t.Errorf("sts through us-east-1: %s %s %v", f.Status, f.Title, f.Regions)
	}
	// The global endpoint counts as us-east-1 for aws:RequestedRegion.
	res = stsMove(t, denyNothingUsed, euWestOnly, assume("global"))
	f = find(t, res, "scp", func(f Finding) bool { return f.Action == "sts:AssumeRole" })
	if f.Status != StatusNoGo || !strings.Contains(f.Detail, "global endpoint") || !strings.Contains(f.Detail, "us-east-1") {
		t.Errorf("sts through the global endpoint: %s %s", f.Status, f.Detail)
	}
	// Both endpoints in use: one finding for the one that is denied.
	res = stsMove(t, denyNothingUsed, euWestOnly, assume("eu-west-1", "us-east-1"))
	if got := scpStatuses(res, "sts:AssumeRole"); len(got) != 1 || !strings.HasPrefix(got[0], "NO-GO") || !strings.HasSuffix(got[0], " us-east-1") {
		t.Errorf("only the us-east-1 endpoint is denied: %v", got)
	}
	// An endpoint that is not known is uncertain, not a guess at us-east-1.
	res = stsMove(t, denyNothingUsed, euWestOnly, assume())
	f = find(t, res, "scp", func(f Finding) bool { return f.Action == "sts:AssumeRole" })
	if f.Status != StatusReview || f.Category != CategoryMissingEvidence || !strings.Contains(f.Detail, "endpoint") || !strings.Contains(f.Detail, `"global"`) {
		t.Errorf("an unknown STS endpoint is a REVIEW that says what to add: %s [%s] %s", f.Status, f.Category, f.Detail)
	}

	// The reverse: denied before, allowed after. The source only admits
	// eu-west-1 and the destination has no region guardrail.
	res = stsMove(t, euWestOnly, denyNothingUsed, assume("eu-west-1"))
	if got := scpStatuses(res, "sts:AssumeRole"); len(got) != 0 {
		t.Errorf("sts through eu-west-1 was never denied by the source guardrail: %v", got)
	}
	res = stsMove(t, euWestOnly, denyNothingUsed, assume("us-east-1"))
	f = find(t, res, "scp", func(f Finding) bool { return f.Action == "sts:AssumeRole" })
	if f.Status != StatusInfo || !strings.Contains(f.Title, "becomes allowed after the move") {
		t.Errorf("sts through us-east-1 is denied today and allowed after: %s %s", f.Status, f.Title)
	}
	// Unknown endpoint, denied-before direction: the source side cannot be
	// decided, the destination allows; nothing blocks and nothing is guessed.
	res = stsMove(t, euWestOnly, denyNothingUsed, assume())
	for _, f := range scpFindingsFor(res, "sts:AssumeRole") {
		if f.Status == StatusNoGo || strings.Contains(f.Title, "becomes allowed") {
			t.Errorf("an unknown endpoint must not be read as us-east-1 on the source side: %s %s", f.Status, f.Title)
		}
	}

	// A guardrail that denies us-east-1 only does not touch a Regional call.
	noVirginia := `{"Version":"2012-10-17","Statement":[{"Sid":"NoVirginia","Effect":"Deny","Action":"*","Resource":"*","Condition":{"StringEquals":{"aws:RequestedRegion":"us-east-1"}}}]}`
	res = stsMove(t, denyNothingUsed, noVirginia, assume("eu-west-1"))
	if got := scpStatuses(res, "sts:AssumeRole"); len(got) != 0 {
		t.Errorf("a deny on us-east-1 does not reach sts in eu-west-1: %v", got)
	}

	// A policy that does not look at the Region decides an sts call whatever
	// its endpoint: no uncertainty is invented.
	denySTS := `{"Version":"2012-10-17","Statement":[{"Sid":"NoAssume","Effect":"Deny","Action":"sts:AssumeRole","Resource":"*"}]}`
	res = stsMove(t, denyNothingUsed, denySTS, assume())
	if f = find(t, res, "scp", func(f Finding) bool { return f.Action == "sts:AssumeRole" }); f.Status != StatusNoGo {
		t.Errorf("a deny without a region condition applies to any endpoint: %s %s", f.Status, f.Title)
	}
	res = stsMove(t, denyNothingUsed, denyNothingUsed, assume())
	if got := scpStatuses(res, "sts:AssumeRole"); len(got) != 0 {
		t.Errorf("nothing restricts sts here, so nothing is reported: %v", got)
	}

	// IAM stays a global service evaluated in us-east-1.
	res = stsMove(t, denyNothingUsed, euWestOnly, snapshot.ActionInUse{Action: "iam:CreateRole"})
	if f = find(t, res, "scp", func(f Finding) bool { return f.Action == "iam:CreateRole" }); f.Status != StatusNoGo {
		t.Errorf("iam is called in us-east-1: %s %s", f.Status, f.Title)
	}
}

// Inbound sts:AssumeRole requests go through the same rule on the RCP side.
func TestInboundSTSRegion(t *testing.T) {
	src, dst := rcpOrgs(t, "")
	rcp := `{"Version":"2012-10-17","Statement":[{"Sid":"EuWestOnly","Effect":"Deny","Principal":"*","Action":"sts:AssumeRole","Resource":"*","Condition":{"StringNotEquals":{"aws:RequestedRegion":"eu-west-1"}}}]}`
	dst.Policies = append(dst.Policies, snapshot.Policy{ID: "p-dst-rcp3", Name: "Assume-EuWestOnly", Type: snapshot.PolicyTypeRCP, Document: []byte(rcp), Targets: []string{"r-dst1"}})
	in := func(regions ...string) []snapshot.InboundAccess {
		return []snapshot.InboundAccess{{Principal: "arn:aws:iam::111111111113:role/Ingest", Actions: []string{"sts:AssumeRole"}, Resource: "arn:aws:iam::111111111112:role/Reader", Regions: regions}}
	}
	run := func(regions ...string) *Result {
		src.Usage["111111111112"].InboundAccess = in(regions...)
		res, err := Evaluate(Input{From: src, To: dst, AccountID: "111111111112", TargetOUID: "r-dst1"})
		if err != nil {
			t.Fatal(err)
		}
		return res
	}
	inbound := func(res *Result) []Finding {
		var out []Finding
		for _, f := range check(res, "rcp").Findings {
			if f.Action == "sts:AssumeRole" && f.Principal != "" {
				out = append(out, f)
			}
		}
		return out
	}
	if got := inbound(run("eu-west-1")); len(got) != 0 {
		t.Errorf("an inbound AssumeRole through eu-west-1 is admitted: %+v", got)
	}
	if got := inbound(run("us-east-1")); len(got) != 1 || got[0].Status != StatusNoGo {
		t.Errorf("an inbound AssumeRole through us-east-1 becomes denied: %+v", got)
	}
	if got := inbound(run()); len(got) != 1 || got[0].Status != StatusReview || !strings.Contains(got[0].Detail, "endpoint") {
		t.Errorf("an inbound AssumeRole through an unknown endpoint is a REVIEW: %+v", got)
	}
}
