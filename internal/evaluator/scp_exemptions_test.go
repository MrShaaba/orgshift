package evaluator

import (
	"strings"
	"testing"

	"github.com/MrShaaba/orgshift/internal/snapshot"
)

const denyRunInstances = `{"Version":"2012-10-17","Statement":[{"Sid":"NoInstances","Effect":"Deny","Action":"ec2:RunInstances","Resource":"*"}]}`
const denyNothingUsed = `{"Version":"2012-10-17","Statement":[{"Sid":"Nothing","Effect":"Deny","Action":"glacier:DeleteVault","Resource":"*"}]}`

const autoScalingServiceLinkedRole = "arn:aws:iam::111111111112:role/aws-service-role/autoscaling.amazonaws.com/AWSServiceRoleForAutoScaling"

func scpFindingsFor(res *Result, action string) []Finding {
	var out []Finding
	for _, c := range res.Checks {
		if c.ID != "scp" {
			continue
		}
		for _, f := range c.Findings {
			if f.Action == action {
				out = append(out, f)
			}
		}
	}
	return out
}

// M5 defect 1, case A. SCPs do not affect service-linked roles
// (orgs_manage_policies_scps.html: "SCPs do not affect any service-linked
// role"), so a Deny at the target root must not turn a call made by one
// into a blocker.
func TestSCPsDoNotRestrictServiceLinkedRoles(t *testing.T) {
	src, dst := twoOrgs(t, denyNothingUsed, denyRunInstances, false)
	src.Usage["111111111112"] = &snapshot.AccountUsage{Actions: []snapshot.ActionInUse{
		{Action: "ec2:RunInstances", PrincipalArn: autoScalingServiceLinkedRole},
	}}
	res, err := Evaluate(Input{From: src, To: dst, AccountID: "111111111112", TargetOUID: "r-dst1"})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range scpFindingsFor(res, "ec2:RunInstances") {
		if f.Status == StatusNoGo || f.Status == StatusReview {
			t.Errorf("a call by a service-linked role is not restricted by SCPs, got %s: %s", f.Status, f.Title)
		}
	}
	if c := check(res, "scp"); c.Status == StatusNoGo {
		t.Errorf("the SCP check must not block on a service-linked role: %s", c.Summary)
	}
	exempt := find(t, res, "scp", func(f Finding) bool { return strings.Contains(f.Title, "service-linked role") })
	if exempt.Status != StatusInfo || exempt.Category != CategoryInformational || !strings.Contains(exempt.Detail, "ec2:RunInstances") || !strings.Contains(exempt.Detail, "AWSServiceRoleForAutoScaling") || len(exempt.References) == 0 {
		t.Errorf("the exemption is reported, with the action, the role and the documentation: %+v", exempt)
	}

	// The same action by an ordinary role of the account is still a blocker,
	// and the two are told apart when both are in the usage list.
	src.Usage["111111111112"].Actions = append(src.Usage["111111111112"].Actions, snapshot.ActionInUse{Action: "ec2:RunInstances", PrincipalArn: "arn:aws:iam::111111111112:role/App"})
	res, err = Evaluate(Input{From: src, To: dst, AccountID: "111111111112", TargetOUID: "r-dst1"})
	if err != nil {
		t.Fatal(err)
	}
	blocked := find(t, res, "scp", func(f Finding) bool { return f.Action == "ec2:RunInstances" && f.Status == StatusNoGo })
	if !strings.Contains(blocked.Title, "becomes denied after the move") {
		t.Errorf("an ordinary role is denied: %+v", blocked)
	}
	find(t, res, "scp", func(f Finding) bool { return strings.Contains(f.Title, "service-linked role") })

	// The exemption holds on the source side too: a Deny in the source does
	// not make the service-linked role's call "denied today".
	src, dst = twoOrgs(t, denyRunInstances, denyNothingUsed, false)
	src.Usage["111111111112"] = &snapshot.AccountUsage{Actions: []snapshot.ActionInUse{{Action: "ec2:RunInstances", PrincipalArn: autoScalingServiceLinkedRole}}}
	res, err = Evaluate(Input{From: src, To: dst, AccountID: "111111111112", TargetOUID: "r-dst1"})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range scpFindingsFor(res, "ec2:RunInstances") {
		if strings.Contains(f.Title, "becomes allowed") || strings.Contains(f.Title, "already denied") {
			t.Errorf("the source SCPs never applied to the service-linked role: %s", f.Title)
		}
	}
}

// M5 defect 1, case B. SCPs do not affect the management account ("SCPs
// don't affect users or roles in the management account. They affect only
// the member accounts"). A management account that becomes a member of
// another organization is unrestricted today, whatever its own root says,
// and restricted after the move: a new restriction, not one that already
// applies.
func TestManagementAccountIsExemptOnItsOwnSideOnly(t *testing.T) {
	src, dst := twoOrgs(t, denyRunInstances, denyRunInstances, false)
	src.Usage["111111111111"] = &snapshot.AccountUsage{Actions: []snapshot.ActionInUse{{Action: "ec2:RunInstances"}}}
	res, err := Evaluate(Input{From: src, To: dst, AccountID: "111111111111", TargetOUID: "r-dst1"})
	if err != nil {
		t.Fatal(err)
	}
	fs := scpFindingsFor(res, "ec2:RunInstances")
	if len(fs) != 1 {
		t.Fatalf("one finding for the action, got %d: %+v", len(fs), fs)
	}
	f := fs[0]
	if f.Status != StatusNoGo || f.Category != CategoryDeclaredImpact || !strings.Contains(f.Title, "becomes denied after the move") || strings.Contains(f.Title, "already denied") {
		t.Errorf("a new destination restriction, not one that already applies: %s %s", f.Status, f.Title)
	}
	if !strings.Contains(f.Detail, "management account") || !strings.Contains(f.Detail, "SCPs do not apply") {
		t.Errorf("the finding says why the source SCPs did not apply: %s", f.Detail)
	}
	if len(f.Evidence) == 0 || f.Evidence[0].Side != "target" || f.Evidence[0].Statement != "NoInstances" {
		t.Errorf("evidence is the destination statement: %+v", f.Evidence)
	}
	// The prerequisite blocker is a separate finding of its own check.
	blocker := find(t, res, "org-services", func(f Finding) bool { return strings.Contains(f.Title, "management account") })
	if blocker.Status != StatusNoGo {
		t.Errorf("the management-account prerequisite still blocks: %+v", blocker)
	}

	// A member account at the same position is restricted on both sides:
	// the deny already applies.
	res, err = Evaluate(Input{From: src, To: dst, AccountID: "111111111112", TargetOUID: "r-dst1"})
	if err != nil {
		t.Fatal(err)
	}
	if m := find(t, res, "scp", func(f Finding) bool { return f.Action == "ec2:RunInstances" }); m.Status != StatusInfo || !strings.Contains(m.Title, "already denied today") {
		t.Errorf("a member is denied on both sides: %+v", m)
	}

	// Inside one organization the management account stays exempt wherever
	// it sits, so a deny on the OU it moves under changes nothing.
	one, _ := twoOrgs(t, denyNothingUsed, denyNothingUsed, false)
	one.OUs = []snapshot.OU{{ID: "ou-src1-locked", Name: "Locked", ParentID: "r-src1"}}
	one.Policies = append(one.Policies, snapshot.Policy{ID: "p-locked0001", Name: "Locked", Type: snapshot.PolicyTypeSCP, Document: []byte(denyRunInstances), Targets: []string{"ou-src1-locked"}})
	one.Policies[0].Targets = append(one.Policies[0].Targets, "ou-src1-locked")
	one.Usage["111111111111"] = &snapshot.AccountUsage{Actions: []snapshot.ActionInUse{{Action: "ec2:RunInstances"}}}
	if err := one.Validate(); err != nil {
		t.Fatal(err)
	}
	res, err = Evaluate(Input{From: one, AccountID: "111111111111", TargetOUID: "ou-src1-locked"})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range scpFindingsFor(res, "ec2:RunInstances") {
		if f.Status == StatusNoGo || f.Status == StatusReview {
			t.Errorf("SCPs never restrict the management account of the organization it manages: %s %s", f.Status, f.Title)
		}
	}
	exempt := find(t, res, "scp", func(f Finding) bool { return strings.Contains(f.Title, "management account") })
	if exempt.Status != StatusInfo || !strings.Contains(exempt.Detail, "SCPs do not apply") {
		t.Errorf("the exemption is said: %+v", exempt)
	}
}

// The same per-side rule for RCPs: they do not restrict resources in a
// management account, so an inbound request to the source management
// account that the destination's RCP denies is a new restriction even
// when the source root carries the same deny.
func TestManagementAccountResourcesAreExemptFromRCPsOnItsOwnSideOnly(t *testing.T) {
	src, dst := rcpOrgs(t, "")
	outsiders := `{"Version":"2012-10-17","Statement":[{"Sid":"OrgOnly","Effect":"Deny","Principal":"*","Action":"s3:*","Resource":"*","Condition":{"StringNotEqualsIfExists":{"aws:PrincipalOrgID":["o-source000001","o-target000001"]}}}]}`
	src.Policies = append(src.Policies, snapshot.Policy{ID: "p-src-rcp2", Name: "Root-OrgOnly", Type: snapshot.PolicyTypeRCP, Document: []byte(outsiders), Targets: []string{"r-src1"}})
	dst.Policies = append(dst.Policies, snapshot.Policy{ID: "p-dst-rcp2", Name: "Root-OrgOnly", Type: snapshot.PolicyTypeRCP, Document: []byte(outsiders), Targets: []string{"r-dst1"}})
	in := snapshot.InboundAccess{Principal: "999999999999", PrincipalOrgID: "o-partner000001", Actions: []string{"s3:GetObject"}, Resource: "arn:aws:s3:::mgmt-exports/*"}
	src.Usage["111111111111"] = &snapshot.AccountUsage{Actions: []snapshot.ActionInUse{{Action: "s3:GetObject", Resource: "arn:aws:s3:::mgmt-exports/*"}}, InboundAccess: []snapshot.InboundAccess{in}}
	src.Usage["111111111112"].InboundAccess = []snapshot.InboundAccess{in}
	for _, s := range []*snapshot.Snapshot{src, dst} {
		if err := s.Validate(); err != nil {
			t.Fatal(err)
		}
	}
	res, err := Evaluate(Input{From: src, To: dst, AccountID: "111111111111", TargetOUID: "r-dst1"})
	if err != nil {
		t.Fatal(err)
	}
	f := find(t, res, "rcp", func(f Finding) bool { return f.Principal == "999999999999" })
	if f.Status != StatusNoGo || !strings.Contains(f.Title, "becomes denied after the move") || !strings.Contains(f.Detail, "RCPs do not restrict resources in the management account") {
		t.Errorf("the partner's access to the management account's bucket is unrestricted today and denied after: %s %s: %s", f.Status, f.Title, f.Detail)
	}
	note := find(t, res, "rcp", func(f Finding) bool {
		return strings.Contains(f.Title, "is the management account of o-source000001 today")
	})
	if note.Status != StatusInfo || len(note.References) == 0 {
		t.Errorf("the exemption is said once: %+v", note)
	}
	// A member with the same inbound entry is denied on both sides.
	res, err = Evaluate(Input{From: src, To: dst, AccountID: "111111111112", TargetOUID: "r-dst1"})
	if err != nil {
		t.Fatal(err)
	}
	if m := find(t, res, "rcp", func(f Finding) bool { return f.Principal == "999999999999" }); m.Status != StatusInfo || !strings.Contains(m.Title, "already denied today") {
		t.Errorf("a member's bucket is restricted on both sides: %+v", m)
	}
	// A service-linked role's call is not restricted by RCPs either.
	src.Usage["111111111112"].Actions = []snapshot.ActionInUse{{Action: "s3:GetObject", Resource: "arn:aws:s3:::member-data/*", PrincipalArn: autoScalingServiceLinkedRole}}
	res, err = Evaluate(Input{From: src, To: dst, AccountID: "111111111112", TargetOUID: "r-dst1"})
	if err != nil {
		t.Fatal(err)
	}
	slr := find(t, res, "rcp", func(f Finding) bool { return strings.Contains(f.Title, "service-linked role") })
	if slr.Status != StatusInfo || !strings.Contains(slr.Title, "not restricted by RCPs") {
		t.Errorf("service-linked role under RCPs: %+v", slr)
	}
}
