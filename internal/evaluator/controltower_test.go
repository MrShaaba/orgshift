package evaluator

import (
	"strings"
	"testing"

	"github.com/MrShaaba/orgshift/internal/fixtures"
	"github.com/MrShaaba/orgshift/internal/snapshot"
)

func TestControlTowerLeavingRegisteredOU(t *testing.T) {
	f := fixtures.Fernhill()
	res, err := Evaluate(Input{From: f, AccountID: fixtures.FernhillRetailProd, TargetOUID: fixtures.FernhillSandboxOU})
	if err != nil {
		t.Fatal(err)
	}
	if res.Verdict != StatusReview {
		t.Fatalf("leaving a registered OU should be REVIEW, got %s: %s", res.Verdict, res.Summary)
	}
	ct := check(res, "control-tower")
	if ct.Status != StatusReview {
		t.Fatalf("control tower check should be REVIEW, got %s", ct.Status)
	}
	f1 := find(t, res, "control-tower", func(f Finding) bool { return strings.Contains(f.Title, "unenrolls the account") })
	if f1.Status != StatusReview || !strings.Contains(f1.Detail, "3 preventive guardrail SCP(s)") || !strings.Contains(f1.Detail, "4 detective control(s)") {
		t.Errorf("unenrolment finding wrong: %+v", f1)
	}
	if strings.Contains(f1.Detail, "assumed enrolled") {
		t.Error("the account is listed explicitly; no assumption note expected")
	}
	find(t, res, "control-tower", func(f Finding) bool {
		return f.Status == StatusInfo && strings.Contains(f.Title, "vended by Account Factory") && strings.Contains(f.Title, "fernhill-retail-prod")
	})
	find(t, res, "control-tower", func(f Finding) bool {
		return f.Status == StatusInfo && strings.HasPrefix(f.Title, "4 detective control(s) stop applying") && strings.Contains(f.Title, "AWS-GR_RESTRICTED_COMMON_PORTS")
	})
	find(t, res, "control-tower", func(f Finding) bool {
		return f.Status == StatusInfo && strings.HasPrefix(f.Title, "3 preventive control(s) stop applying")
	})
	// The guardrail SCP leaves the chain and is labelled as Control Tower managed.
	var removed []PolicyRef
	for _, d := range res.Diff {
		if d.TypeShort == "SCP" {
			removed = d.Removed
		}
	}
	found := false
	for _, r := range removed {
		if r.Name == "aws-guardrails-kjwqpf" {
			found = r.ControlTowerManaged
		}
	}
	if !found {
		t.Errorf("the guardrail SCP should be removed from the chain and marked Control Tower managed: %+v", removed)
	}
	for _, c := range res.Checks {
		for _, f := range c.Findings {
			if f.Status == StatusNoGo {
				t.Errorf("nothing should block this move, got %s: %s", c.ID, f.Title)
			}
		}
	}
}

func TestControlTowerEnrolmentNeeded(t *testing.T) {
	f := fixtures.Fernhill()
	// An unenrolled sandbox account moving into a registered OU.
	res, err := Evaluate(Input{From: f, AccountID: "222222222227", TargetOUID: fixtures.FernhillRetailOU})
	if err != nil {
		t.Fatal(err)
	}
	e := find(t, res, "control-tower", func(f Finding) bool { return strings.Contains(f.Title, "has to be enrolled") })
	if e.Status != StatusReview || !strings.Contains(e.Detail, "AWSControlTowerExecution") || !strings.Contains(e.Detail, "222222222221") || strings.Contains(e.Detail, "joined") {
		t.Errorf("enrolment finding wrong: %+v", e)
	}
	find(t, res, "control-tower", func(f Finding) bool {
		return f.Status == StatusInfo && strings.HasPrefix(f.Title, "4 detective control(s) start applying at Retail") && strings.Contains(f.Detail, "only once the account is enrolled")
	})
	for _, f := range check(res, "control-tower").Findings {
		if strings.Contains(f.Title, "stop applying") || strings.Contains(f.Title, "unenroll") {
			t.Errorf("an unenrolled account has nothing to lose: %s", f.Title)
		}
	}

	// Cross-org: the Larkspur payments account lands in a registered OU and gets the proactive control under its alias.
	res, err = Evaluate(Input{From: fixtures.Larkspur(), To: f, AccountID: fixtures.LarkspurPaymentsProd, TargetOUID: fixtures.FernhillPaymentsOU})
	if err != nil {
		t.Fatal(err)
	}
	e = find(t, res, "control-tower", func(f Finding) bool { return strings.Contains(f.Title, "has to be enrolled") })
	if !strings.Contains(e.Detail, "joined o-fernhill0001") {
		t.Errorf("cross-org enrolment should mention joining first: %s", e.Detail)
	}
	find(t, res, "control-tower", func(f Finding) bool {
		return strings.HasPrefix(f.Title, "1 proactive control(s) start applying at Payments: CT.S3.PR.1")
	})
	// The guardrail that now applies is in the target chain, labelled.
	for _, d := range res.Diff {
		if d.TypeShort != "SCP" {
			continue
		}
		labelled := false
		for _, l := range d.TargetChain {
			for _, p := range l.Policies {
				if p.Name == "aws-guardrails-kjwqpf" && p.ControlTowerManaged {
					labelled = true
				}
			}
		}
		if !labelled {
			t.Errorf("target SCP chain should carry the labelled guardrail: %+v", d.TargetChain)
		}
	}
}

func TestControlTowerSharedAccountAndRegisteredToRegistered(t *testing.T) {
	f := fixtures.Fernhill()
	res, err := Evaluate(Input{From: f, AccountID: fixtures.FernhillAuditAccount, TargetOUID: fixtures.FernhillBusinessUnitsOU})
	if err != nil {
		t.Fatal(err)
	}
	if res.Verdict != StatusNoGo {
		t.Fatalf("moving the audit account should be NO-GO, got %s", res.Verdict)
	}
	find(t, res, "control-tower", func(f Finding) bool { return f.Status == StatusNoGo && strings.Contains(f.Title, "audit account") })

	res, err = Evaluate(Input{From: f, AccountID: "222222222226", TargetOUID: fixtures.FernhillRetailOU})
	if err != nil {
		t.Fatal(err)
	}
	r := find(t, res, "control-tower", func(f Finding) bool { return strings.Contains(f.Title, "between registered OUs Payments and Retail") })
	if r.Status != StatusReview || len(r.Evidence) != 2 || r.Evidence[1].Side != "target" {
		t.Errorf("registered-to-registered finding wrong: %+v", r)
	}
	find(t, res, "control-tower", func(f Finding) bool {
		return strings.HasPrefix(f.Title, "1 proactive control(s) stop applying: CT.S3.PR.1")
	})

	// Staying put: nothing to say.
	res, err = Evaluate(Input{From: f, AccountID: "222222222226", TargetOUID: fixtures.FernhillPaymentsOU})
	if err != nil {
		t.Fatal(err)
	}
	if c := check(res, "control-tower"); c.Status != StatusGo || len(c.Findings) != 0 {
		t.Errorf("same OU should produce no Control Tower findings: %+v", c)
	}
}

func TestControlTowerAssumedEnrolmentAndAbsence(t *testing.T) {
	f := fixtures.Fernhill()
	f.ControlTower.EnrolledAccounts = nil
	res, err := Evaluate(Input{From: f, AccountID: fixtures.FernhillRetailProd, TargetOUID: fixtures.FernhillSandboxOU})
	if err != nil {
		t.Fatal(err)
	}
	u := find(t, res, "control-tower", func(f Finding) bool { return strings.Contains(f.Title, "unenrolls the account") })
	if !strings.Contains(u.Detail, "assumed enrolled because its OU is registered") {
		t.Errorf("without an enrolled list the finding should say the enrolment is assumed: %s", u.Detail)
	}
	for _, fd := range check(res, "control-tower").Findings {
		if strings.Contains(fd.Title, "Account Factory") {
			t.Error("Account Factory provenance needs the explicit list")
		}
	}

	// Leaving for an organization without Control Tower: unenrolled, nothing to enroll into.
	res, err = Evaluate(Input{From: fixtures.Fernhill(), To: fixtures.Larkspur(), AccountID: fixtures.FernhillRetailProd, TargetOUID: fixtures.LarkspurWorkloadsOU})
	if err != nil {
		t.Fatal(err)
	}
	find(t, res, "control-tower", func(f Finding) bool {
		return f.Status == StatusReview && strings.Contains(f.Title, "leaves the Control Tower landing zone")
	})
	find(t, res, "control-tower", func(f Finding) bool {
		return f.Status == StatusReview && strings.Contains(f.Title, "stays behind in the source")
	})
	for _, fd := range check(res, "control-tower").Findings {
		if strings.Contains(fd.Title, "start applying") || strings.Contains(fd.Title, "enrolled") && fd.Status != StatusReview {
			t.Errorf("Larkspur has no landing zone: %s", fd.Title)
		}
	}

	// Neither side has Control Tower.
	res, err = Evaluate(Input{From: fixtures.Larkspur(), AccountID: "111111111116", TargetOUID: "ou-lark-prod"})
	if err != nil {
		t.Fatal(err)
	}
	if c := check(res, "control-tower"); c.Status != StatusGo || len(c.Findings) != 0 || !strings.Contains(c.Summary, "Neither") {
		t.Errorf("no landing zone anywhere should be a quiet GO: %+v", c)
	}
}

func TestControlLabel(t *testing.T) {
	cases := map[string]snapshot.EnabledControl{
		"AWS-GR_ENCRYPTED_VOLUMES": {ControlIdentifier: "arn:aws:controltower:eu-west-1::control/AWS-GR_ENCRYPTED_VOLUMES", Name: "Detect whether encryption is enabled"},
		"CT.S3.PR.1":               {ControlIdentifier: "arn:aws:controlcatalog:::control/7f3kq9x2m1pz8r4v6t0nb5cy", Name: "CT.S3.PR.1: Require block public access"},
		"Some long catalog name":   {ControlIdentifier: "arn:aws:controlcatalog:::control/7f3kq9x2m1pz8r4v6t0nb5cy", Name: "Some long catalog name"},
		"7f3kq9x2m1pz8r4v6t0nb5cy": {ControlIdentifier: "arn:aws:controlcatalog:::control/7f3kq9x2m1pz8r4v6t0nb5cy"},
	}
	for want, c := range cases {
		if got := controlLabel(c); got != want {
			t.Errorf("controlLabel(%+v) = %q, want %q", c, got, want)
		}
	}
}
