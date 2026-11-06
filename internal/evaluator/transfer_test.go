package evaluator

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/MrShaaba/orgshift/internal/snapshot"
)

// M5 defect 4. The tests in this file hold the transfer procedure to
// orgs_account_migration.html as read on 2026-11-05: a direct transfer is
// invite then accept with no standalone interval, needs
// organizations:LeaveOrganization, lands at the destination root, and has
// eligibility requirements of its own. Leave or remove then rejoin and the
// management-account migration are other procedures.

const (
	denyLeave            = `{"Version":"2012-10-17","Statement":[{"Sid":"NoLeaving","Effect":"Deny","Action":"organizations:LeaveOrganization","Resource":"*"}]}`
	denyLeaveForSomeRole = `{"Version":"2012-10-17","Statement":[{"Sid":"NoLeavingUnlessBreakGlass","Effect":"Deny","Action":"organizations:LeaveOrganization","Resource":"*","Condition":{"ArnNotLike":{"aws:PrincipalARN":"arn:aws:iam::*:role/BreakGlass"}}}]}`
)

// transferOrgs is twoOrgs with every eligibility fact the migration page
// asks for present and met, so a test changes one thing at a time.
func transferOrgs(t *testing.T, srcDoc, dstDoc string) (*snapshot.Snapshot, *snapshot.Snapshot) {
	t.Helper()
	src, dst := twoOrgs(t, srcDoc, dstDoc, false)
	no := false
	for _, s := range []*snapshot.Snapshot{src, dst} {
		s.GeneratedAt = "2026-11-05T10:00:00Z"
		s.Organization.CreatedAt = "2024-02-01T09:00:00Z"
		s.Organization.SellerOfRecord = "Amazon Web Services EMEA SARL"
		for i := range s.Accounts {
			s.Accounts[i].Status, s.Accounts[i].JoinedMethod, s.Accounts[i].JoinedAt = "ACTIVE", "INVITED", "2024-03-01T09:00:00Z"
			s.Accounts[i].RootMFAEnabled = &no
		}
	}
	return src, dst
}

func member(s *snapshot.Snapshot) *snapshot.Account {
	for i := range s.Accounts {
		if s.Accounts[i].ID == "111111111112" {
			return &s.Accounts[i]
		}
	}
	return nil
}

func transfer(t *testing.T, src, dst *snapshot.Snapshot, in Input) *Result {
	t.Helper()
	for _, s := range []*snapshot.Snapshot{src, dst} {
		if err := s.Validate(); err != nil {
			t.Fatal(err)
		}
	}
	in.From, in.To = src, dst
	if in.AccountID == "" {
		in.AccountID = "111111111112"
	}
	if in.TargetOUID == "" {
		in.TargetOUID = "r-dst1"
	}
	res, err := Evaluate(in)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

// transferFinding returns the org-services finding about one part of the
// transfer procedure, or nil.
func transferFinding(res *Result, ref string) *Finding {
	c := check(res, "org-services")
	for i, f := range c.Findings {
		for _, ev := range f.Evidence {
			if ev.Kind == EvidenceTransfer && ev.Reference == ref {
				return &c.Findings[i]
			}
		}
	}
	return nil
}

func anyTitle(res *Result, sub string) bool {
	for _, c := range res.Checks {
		for _, f := range c.Findings {
			if strings.Contains(f.Title, sub) || strings.Contains(f.Detail, sub) {
				return true
			}
		}
	}
	return false
}

func TestDirectTransferHasNoStandaloneInterval(t *testing.T) {
	src, dst := transferOrgs(t, denyNothingUsed, denyNothingUsed)
	res := transfer(t, src, dst, Input{})
	if res.Subject.TransferMethod != TransferDirect {
		t.Errorf("direct transfer is the default method, got %q", res.Subject.TransferMethod)
	}
	p := transferFinding(res, TransferProcedure)
	if p == nil || p.Status != StatusInfo || !strings.HasPrefix(p.Title, "Direct transfer: 222222222221 invites the account and the account accepts; it is never standalone") {
		t.Fatalf("procedure: %+v", p)
	}
	for _, want := range []string{"does not leave o-source000001 first", "does not operate as a standalone account", "is not a prerequisite", "organizations:LeaveOrganization", "15 days", "added to the root of o-target000001", "Transfer procedure model " + TransferModelVersion} {
		if !strings.Contains(p.Detail, want) {
			t.Errorf("direct transfer detail misses %q:\n%s", want, p.Detail)
		}
	}
	if len(p.References) == 0 || p.References[0] != refAccountMigration {
		t.Errorf("the migration page is the source: %v", p.References)
	}
	// The old leave-then-join sequence is not presented as what happens.
	for _, gone := range []string{"Standalone account prerequisites", "Between leaving the source", "ConstraintViolationException"} {
		if anyTitle(res, gone) {
			t.Errorf("a direct transfer has no standalone step, but the result says %q", gone)
		}
	}
	// With everything supplied and nothing in the way, the transfer adds no
	// REVIEW or NO-GO of its own.
	for _, f := range check(res, "org-services").Findings {
		if hasKind(f, EvidenceTransfer) && f.Status != StatusInfo {
			t.Errorf("clean direct transfer: %s %s", f.Status, f.Title)
		}
	}
	if e := transferFinding(res, TransferUnconfirmed); e == nil || e.Status != StatusInfo || !strings.Contains(e.Title, "every requirement that can be read from the snapshots is met") {
		t.Errorf("eligibility: %+v", e)
	}

	// The model version moved with the change of procedure and is in the result.
	if TransferModelVersion != "2026-11-05" || TransferModel().Reference != refAccountMigration {
		t.Errorf("transfer model %s (%s)", TransferModelVersion, TransferModel().Reference)
	}
	found := false
	for _, m := range res.Models {
		if m.ID == "transfer-procedure" {
			found = m.Version == TransferModelVersion && strings.Contains(m.Note, "Three procedures, kept apart")
		}
	}
	if !found {
		t.Errorf("the result names the transfer model: %+v", res.Models)
	}

	// A move inside one organization is not a transfer.
	same, err := Evaluate(Input{From: src, AccountID: "111111111112", TargetOUID: "r-src1"})
	if err != nil {
		t.Fatal(err)
	}
	if same.Subject.TransferMethod != "" || transferFinding(same, TransferProcedure) != nil {
		t.Errorf("same-organization move: method %q", same.Subject.TransferMethod)
	}
}

func TestLeaveAndRejoinIsASeparateProcedure(t *testing.T) {
	src, dst := transferOrgs(t, denyNothingUsed, denyNothingUsed)
	res := transfer(t, src, dst, Input{TransferMethod: TransferLeaveAndRejoin})
	if res.Subject.TransferMethod != TransferLeaveAndRejoin {
		t.Errorf("method %q", res.Subject.TransferMethod)
	}
	p := transferFinding(res, TransferProcedure)
	if p == nil || p.Status != StatusReview || p.Category != CategoryPotentialImpact || p.Title != "Leave or remove, then rejoin: the account is standalone between the two organizations" {
		t.Fatalf("procedure: %+v", p)
	}
	for _, want := range []string{"verified contact details, a payment method and a support plan", "ConstraintViolationException", "While it is standalone no SCP", "or use the direct transfer, which has none"} {
		if !strings.Contains(p.Detail, want) {
			t.Errorf("leave-and-rejoin detail misses %q", want)
		}
	}
	// The standalone-account information is not in any snapshot: it is asked
	// for, not assumed.
	e := transferFinding(res, TransferUnconfirmed)
	if e == nil || e.Status != StatusReview || e.Category != CategoryMissingEvidence || !strings.Contains(e.Detail, "standalone-account information") {
		t.Errorf("standalone prerequisites are unconfirmed: %+v", e)
	}
	if anyTitle(res, "Direct transfer: 222222222221 invites") {
		t.Error("the two procedures are not mixed")
	}
	// An unknown method is refused rather than read as one of the two.
	if _, err := Evaluate(Input{From: src, To: dst, AccountID: "111111111112", TargetOUID: "r-dst1", TransferMethod: "teleport"}); err == nil || !strings.Contains(err.Error(), "transfer method") {
		t.Errorf("unknown method: %v", err)
	}
}

func TestSourceDenyOfLeaveOrganizationBlocksADirectTransfer(t *testing.T) {
	// Denied in the source: the transfer is blocked, whatever IAM says.
	src, dst := transferOrgs(t, denyLeave, denyNothingUsed)
	res := transfer(t, src, dst, Input{})
	f := transferFinding(res, TransferLeavePermission)
	if f == nil || f.Status != StatusNoGo || f.Title != "A source SCP denies organizations:LeaveOrganization, which blocks the transfer" || f.Action != "organizations:LeaveOrganization" {
		t.Fatalf("leave deny: %+v", f)
	}
	if !strings.Contains(f.Detail, "denied by Guardrails, NoLeaving, attached at root Root (r-src1)") || !strings.Contains(f.Detail, "even when the account's own IAM policy allows it") || !strings.Contains(f.Detail, "not part of a direct transfer") {
		t.Errorf("leave deny detail: %s", f.Detail)
	}
	var stmt *Evidence
	for i, ev := range f.Evidence {
		if ev.Kind == "policy-statement" {
			stmt = &f.Evidence[i]
		}
	}
	if stmt == nil || stmt.Side != "source" || stmt.PolicyID != "p-shared001" || stmt.Statement != "NoLeaving" {
		t.Errorf("the denying statement is the evidence: %+v", f.Evidence)
	}
	if c := check(res, "org-services"); c.Status != StatusNoGo {
		t.Errorf("the check blocks: %s %s", c.Status, c.Summary)
	}
	if res.Verdict != StatusNoGo {
		t.Errorf("verdict %s", res.Verdict)
	}

	// The same deny under leave-and-rejoin is not a blocker of that
	// procedure: the management account can remove the account.
	res = transfer(t, src, dst, Input{TransferMethod: TransferLeaveAndRejoin})
	f = transferFinding(res, TransferLeavePermission)
	if f == nil || f.Status != StatusReview || !strings.Contains(f.Title, "the account cannot leave by itself") || !strings.Contains(f.Detail, "RemoveAccountFromOrganization") {
		t.Errorf("leave-and-rejoin with a deny: %+v", f)
	}

	// A deny that depends on the caller is not decided offline: REVIEW, and
	// it does not turn into "allowed".
	src, dst = transferOrgs(t, denyLeaveForSomeRole, denyNothingUsed)
	res = transfer(t, src, dst, Input{})
	f = transferFinding(res, TransferLeavePermission)
	if f == nil || f.Status != StatusReview || !strings.Contains(f.Title, "cannot be decided offline") || !strings.Contains(f.Detail, "a deny blocks the transfer") {
		t.Errorf("conditional leave deny: %+v", f)
	}

	// An allow list that does not include it denies it implicitly.
	src, dst = transferOrgs(t, denyNothingUsed, denyNothingUsed)
	for i := range src.Policies {
		if src.Policies[i].AWSManaged {
			src.Policies[i].Targets = []string{"r-src1", "111111111111"}
		}
	}
	src.Policies = append(src.Policies, snapshot.Policy{ID: "p-allowlist1", Name: "OnlyCompute", Type: snapshot.PolicyTypeSCP,
		Document: json.RawMessage(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"ec2:*","Resource":"*"}]}`), Targets: []string{"111111111112"}})
	res = transfer(t, src, dst, Input{})
	if f = transferFinding(res, TransferLeavePermission); f == nil || f.Status != StatusNoGo {
		t.Errorf("an allow list without organizations:LeaveOrganization blocks the transfer: %+v", f)
	}

	// No deny in the source: nothing to report. A deny in the destination is
	// not about leaving the source.
	src, dst = transferOrgs(t, denyNothingUsed, denyLeave)
	res = transfer(t, src, dst, Input{})
	if f = transferFinding(res, TransferLeavePermission); f != nil {
		t.Errorf("the destination's deny does not block the way in: %+v", f)
	}
}

func TestAccountLandsAtTheDestinationRoot(t *testing.T) {
	build := func(attach bool) (*snapshot.Snapshot, *snapshot.Snapshot) {
		src, dst := transferOrgs(t, denyNothingUsed, denyNothingUsed)
		dst.OUs = []snapshot.OU{{ID: "ou-dst1-apps0001", Name: "Apps", ParentID: "r-dst1"}}
		if attach {
			dst.Policies = append(dst.Policies, snapshot.Policy{ID: "p-ouguard01", Name: "AppsGuard", Type: snapshot.PolicyTypeSCP,
				Document: json.RawMessage(denyRunInstances), Targets: []string{"ou-dst1-apps0001"}})
		}
		return src, dst
	}

	// A guardrail of the target OU is not in force while the account sits
	// at the root, and the action it denies can still be performed there.
	src, dst := build(true)
	res := transfer(t, src, dst, Input{TargetOUID: "ou-dst1-apps0001"})
	f := transferFinding(res, TransferRootLanding)
	if f == nil || f.Status != StatusReview || f.Category != CategoryPotentialImpact ||
		f.Title != "The account lands at the destination root first: 1 policy(ies) of the target path do not apply until it is moved into OU Apps (ou-dst1-apps0001)" {
		t.Fatalf("root landing: %+v", f)
	}
	for _, want := range []string{"added to the root of the new organization", "Not in force during that interval: SCP AppsGuard at OU Apps (ou-dst1-apps0001).",
		"1 are allowed at the root and denied at the target position, so the account can still perform them in the interval: ec2:RunInstances.", "Move the account in the same change as the acceptance"} {
		if !strings.Contains(f.Detail, want) {
			t.Errorf("root landing detail misses %q:\n%s", want, f.Detail)
		}
	}
	// The verdict board still judges the target position.
	if scp := find(t, res, "scp", func(f Finding) bool { return f.Action == "ec2:RunInstances" }); scp.Status != StatusNoGo {
		t.Errorf("target position: %+v", scp)
	}

	// Nothing attached on the way down: said, not a REVIEW.
	src, dst = build(false)
	res = transfer(t, src, dst, Input{TargetOUID: "ou-dst1-apps0001"})
	if f = transferFinding(res, TransferRootLanding); f == nil || f.Status != StatusInfo || !strings.Contains(f.Title, "nothing is attached below it on the way to OU Apps") {
		t.Errorf("root landing without OU policies: %+v", f)
	}

	// Target is the root: there is no interval.
	res = transfer(t, src, dst, Input{})
	if f = transferFinding(res, TransferRootLanding); f == nil || f.Status != StatusInfo || !strings.Contains(f.Title, "which is also its target") {
		t.Errorf("root target: %+v", f)
	}

	// The landing applies to leave-and-rejoin too: an invited account
	// always joins at the root.
	src, dst = build(true)
	res = transfer(t, src, dst, Input{TargetOUID: "ou-dst1-apps0001", TransferMethod: TransferLeaveAndRejoin})
	if f = transferFinding(res, TransferRootLanding); f == nil || f.Status != StatusReview {
		t.Errorf("root landing under leave-and-rejoin: %+v", f)
	}
}

func TestTransferEligibility(t *testing.T) {
	yes := true
	cases := []struct {
		name   string
		edit   func(src, dst *snapshot.Snapshot)
		ref    string // the finding expected, by transfer reference
		status Status
		title  string
		// unconfirmed is text the "cannot be confirmed" finding must carry.
		unconfirmed string
	}{
		{name: "destination organization three days old",
			edit: func(src, dst *snapshot.Snapshot) { dst.Organization.CreatedAt = "2026-11-02T10:00:00Z" },
			ref:  TransferOrgAge, status: StatusNoGo, title: "The destination organization o-target000001 is less than seven days old"},
		{name: "destination organization age unknown",
			edit:        func(src, dst *snapshot.Snapshot) { dst.Organization.CreatedAt = "" },
			unconfirmed: "the destination organization o-target000001 is at least seven days old (set organization.created_at in the destination snapshot"},
		{name: "the management account's join date is a hint, not the creation date",
			edit: func(src, dst *snapshot.Snapshot) {
				dst.Organization.CreatedAt = ""
				dst.Accounts[0].JoinedAt = "2026-11-04T10:00:00Z"
			},
			unconfirmed: "its management account is listed as joined at 2026-11-04T10:00:00Z, which is a hint and not the documented creation date"},
		{name: "seller of record differs",
			edit: func(src, dst *snapshot.Snapshot) { dst.Organization.SellerOfRecord = "Amazon Web Services, Inc." },
			ref:  TransferSellerOfRecord, status: StatusNoGo, title: "The Seller of Record differs: Amazon Web Services EMEA SARL for the account, Amazon Web Services, Inc. for the destination"},
		{name: "seller of record unknown on one side",
			edit:        func(src, dst *snapshot.Snapshot) { src.Organization.SellerOfRecord = "" },
			unconfirmed: "the Seller of Record of the account matches the destination organization's, or the move fails"},
		{name: "suspended account",
			edit: func(src, dst *snapshot.Snapshot) { member(src).Status = "SUSPENDED" },
			ref:  TransferAccountStatus, status: StatusNoGo, title: "The account is suspended: closed or suspended accounts cannot be migrated"},
		{name: "account pending closure",
			edit: func(src, dst *snapshot.Snapshot) { member(src).Status = "PENDING_CLOSURE" },
			ref:  TransferAccountStatus, status: StatusNoGo, title: "The account is pending_closure: closed or suspended accounts cannot be migrated"},
		{name: "account status unknown",
			edit:        func(src, dst *snapshot.Snapshot) { member(src).Status = "" },
			unconfirmed: "the account is active, not closed or suspended"},
		{name: "account created two days ago",
			edit: func(src, dst *snapshot.Snapshot) {
				member(src).JoinedMethod, member(src).JoinedAt = "CREATED", "2026-11-03T10:00:00Z"
			},
			ref: TransferAccountAge, status: StatusNoGo, title: "The account was created 48h0m0s before the snapshot; it cannot be migrated until it is four days old"},
		{name: "created account without a date",
			edit: func(src, dst *snapshot.Snapshot) {
				member(src).JoinedMethod, member(src).JoinedAt = "CREATED", ""
			},
			unconfirmed: "the account, which was created in the organization, is at least four days old"},
		{name: "root MFA registered",
			edit: func(src, dst *snapshot.Snapshot) { member(src).RootMFAEnabled = &yes },
			ref:  TransferRootMFA, status: StatusReview, title: "The root user has MFA registered: remove it before the migration if the account changes owner"},
		{name: "root MFA unknown",
			edit:        func(src, dst *snapshot.Snapshot) { member(src).RootMFAEnabled = nil },
			unconfirmed: "the root user has no MFA device registered"},
		{name: "created account keeps the role of the old management account",
			edit: func(src, dst *snapshot.Snapshot) {
				member(src).JoinedMethod, member(src).JoinedAt = "CREATED", "2025-01-01T00:00:00Z"
			},
			ref: TransferAccessRole, status: StatusReview, title: "OrganizationAccountAccessRole stays in the account: 111111111111 keeps administrator access until it is deleted"},
		{name: "invited account has no role created by Organizations",
			ref: TransferAccessRole, status: StatusInfo, title: "A role that gives the source management account access, if one was created by hand, is not deleted by the transfer"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			src, dst := transferOrgs(t, denyNothingUsed, denyNothingUsed)
			if tc.edit != nil {
				tc.edit(src, dst)
			}
			res := transfer(t, src, dst, Input{})
			if tc.ref != "" {
				f := transferFinding(res, tc.ref)
				if f == nil || f.Status != tc.status || f.Title != tc.title {
					t.Fatalf("want %s %q, got %+v", tc.status, tc.title, f)
				}
				if len(f.References) == 0 || f.References[0] != refAccountMigration {
					t.Errorf("the migration page is the source: %v", f.References)
				}
				if tc.status == StatusNoGo && (res.Verdict != StatusNoGo || check(res, "org-services").Status != StatusNoGo) {
					t.Errorf("a failed requirement blocks: verdict %s", res.Verdict)
				}
			}
			e := transferFinding(res, TransferUnconfirmed)
			if tc.unconfirmed == "" {
				if e != nil && e.Status != StatusInfo {
					t.Errorf("nothing is unconfirmed here: %s", e.Detail)
				}
				return
			}
			if e == nil || e.Status != StatusReview || e.Category != CategoryMissingEvidence || e.Title != "Transfer eligibility: 1 requirement(s) cannot be confirmed from the snapshots" ||
				!strings.Contains(e.Detail, tc.unconfirmed) || !strings.Contains(e.Detail, "none of them is assumed") {
				t.Fatalf("want an unconfirmed requirement with %q, got %+v", tc.unconfirmed, e)
			}
			if res.Verdict == StatusGo {
				t.Error("an unconfirmed requirement is never GO")
			}
		})
	}

	// A delegated administrator is blocked by its own finding and is not
	// listed as confirmed.
	src, dst := transferOrgs(t, denyNothingUsed, denyNothingUsed)
	src.DelegatedAdministrators = []snapshot.DelegatedAdministrator{{AccountID: "111111111112", ServicePrincipal: "guardduty.amazonaws.com"}}
	res := transfer(t, src, dst, Input{})
	da := find(t, res, "org-services", func(f Finding) bool {
		return strings.Contains(f.Title, "delegated administrator") && f.Status == StatusNoGo
	})
	if !strings.Contains(da.Title, "guardduty.amazonaws.com") || !strings.Contains(da.Detail, "have to be deregistered before it is migrated") {
		t.Errorf("delegated administrator: %+v", da)
	}
	if e := transferFinding(res, TransferUnconfirmed); e == nil || strings.Contains(e.Detail, "the account is not a delegated administrator") {
		t.Errorf("a delegated administrator is not confirmed as eligible: %+v", e)
	}
}

func TestManagementAccountMigrationIsItsOwnProcedure(t *testing.T) {
	// Even with a deny of LeaveOrganization in the source, which does not
	// apply to a management account, and whatever method was asked for.
	for _, method := range []string{"", TransferDirect, TransferLeaveAndRejoin} {
		src, dst := transferOrgs(t, denyLeave, denyNothingUsed)
		res := transfer(t, src, dst, Input{AccountID: "111111111111", TransferMethod: method})
		if res.Subject.TransferMethod != TransferManagementAccount {
			t.Errorf("method %q: a management account has one procedure, got %q", method, res.Subject.TransferMethod)
		}
		p := transferFinding(res, TransferProcedure)
		if p == nil || p.Status != StatusNoGo || p.Title != "Account is the management account of the source organization" {
			t.Fatalf("procedure: %+v", p)
		}
		for _, want := range []string{"every member account has to be removed from o-source000001 and the organization deleted first", "then operates as a standalone account", "accept the invitation from 222222222221",
			"neither a direct transfer nor leave-and-rejoin"} {
			if !strings.Contains(p.Detail, want) {
				t.Errorf("management account detail misses %q", want)
			}
		}
		if f := transferFinding(res, TransferLeavePermission); f != nil {
			t.Errorf("SCPs do not apply to the management account, and it does not leave: %+v", f)
		}
		if anyTitle(res, "Direct transfer: 222222222221 invites") || anyTitle(res, "Leave or remove, then rejoin") {
			t.Error("the member procedures are not reported for a management account")
		}
	}
}
