package runbook

import (
	"strings"
	"testing"

	"github.com/MrShaaba/orgshift/internal/evaluator"
	"github.com/MrShaaba/orgshift/internal/fixtures"
	"github.com/MrShaaba/orgshift/internal/snapshot"
)

func paymentsRunbook(t *testing.T, method string, edit func(l, f *snapshot.Snapshot)) *Runbook {
	t.Helper()
	l, f := fixtures.Larkspur(), fixtures.Fernhill()
	if edit != nil {
		edit(l, f)
	}
	res, err := evaluator.Evaluate(evaluator.Input{From: l, To: f, AccountID: fixtures.LarkspurPaymentsProd, TargetOUID: fixtures.FernhillPaymentsOU, TransferMethod: method})
	if err != nil {
		t.Fatal(err)
	}
	return Build(res, l, f)
}

func payments(s *snapshot.Snapshot) *snapshot.Account {
	for i := range s.Accounts {
		if s.Accounts[i].ID == fixtures.LarkspurPaymentsProd {
			return &s.Accounts[i]
		}
	}
	return nil
}

// M5 defect 4: each eligibility requirement of the migration page that is
// not met stops the runbook before the move, with its own step.
func TestTransferEligibilitySteps(t *testing.T) {
	cases := []struct {
		name  string
		edit  func(l, f *snapshot.Snapshot)
		title string
		kind  string
		cmd   string
	}{
		{"young destination organization", func(l, f *snapshot.Snapshot) { f.Organization.CreatedAt = "2025-12-29T00:00:00Z" },
			"Wait until the destination organization is seven days old", KindBlocker, ""},
		{"seller of record", func(l, f *snapshot.Snapshot) { f.Organization.SellerOfRecord = "Amazon Web Services EMEA SARL" },
			"Stop: the Seller of Record of the account and of the destination differ", KindBlocker, "invoice header names the selling entity"},
		{"suspended", func(l, f *snapshot.Snapshot) { payments(l).Status = "SUSPENDED" },
			"Stop: a closed or suspended account cannot be migrated", KindBlocker, "describe-account --account-id 111111111115 --query Account.Status"},
		{"created three days ago", func(l, f *snapshot.Snapshot) {
			payments(l).JoinedMethod, payments(l).JoinedAt = "CREATED", "2025-12-29T00:00:00Z"
		},
			"Wait until the account is four days old", KindBlocker, "JoinedMethod,JoinedTimestamp"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rb := paymentsRunbook(t, "", tc.edit)
			s := stepWith(t, rb, PhaseBefore, tc.title)
			if s.Status != evaluator.StatusNoGo || s.Kind != tc.kind || !strings.Contains(strings.Join(s.Commands, "\n"), tc.cmd) || len(s.Evidence) == 0 || s.Evidence[0].Kind != evaluator.EvidenceTransfer {
				t.Errorf("step: %+v", s)
			}
		})
	}

	// With the Seller of Record entered on both sides and matching, the
	// fixture's only unconfirmed requirement is gone and so is the step.
	rb := paymentsRunbook(t, "", func(l, f *snapshot.Snapshot) { f.Organization.SellerOfRecord = l.Organization.SellerOfRecord })
	for _, s := range rb.Steps() {
		if strings.Contains(s.Title, "Confirm the transfer eligibility requirements") {
			t.Errorf("nothing is left to confirm: %s", s.Detail)
		}
	}
}

// A management account has no single-account runbook: the step says so and
// keeps the sequence apart from the member procedures.
func TestManagementAccountRunbookStops(t *testing.T) {
	l, f := fixtures.Larkspur(), fixtures.Fernhill()
	res, err := evaluator.Evaluate(evaluator.Input{From: l, To: f, AccountID: l.Organization.ManagementAccountID, TargetOUID: f.Root.ID})
	if err != nil {
		t.Fatal(err)
	}
	rb := Build(res, l, f)
	s := stepWith(t, rb, PhaseBefore, "Stop: a management account moves only after its organization is emptied and deleted")
	if s.Status != evaluator.StatusNoGo || s.Kind != KindBlocker || !strings.Contains(s.Detail, "neither a direct transfer nor leave-and-rejoin") || !strings.Contains(strings.Join(s.Commands, "\n"), "delete-organization") {
		t.Errorf("management account step: %+v", s)
	}
	for _, st := range rb.Steps() {
		if strings.Contains(st.Title, "Lift the deny on organizations:LeaveOrganization") {
			t.Errorf("SCPs do not apply to a management account: %q", st.Title)
		}
	}
}

// An OU move between organizations transfers each account with the chosen
// method; the OU runbook and the account runbooks agree on it.
func TestOURunbookFollowsTheTransferMethod(t *testing.T) {
	l, f := fixtures.Larkspur(), fixtures.Fernhill()
	for _, tc := range []struct{ method, want, title, intro string }{
		{"", evaluator.TransferDirect, "Transfer the 3 account(s) one by one: invite, accept", "in one step"},
		{evaluator.TransferLeaveAndRejoin, evaluator.TransferLeaveAndRejoin, "Move the 3 account(s) one by one: invite, leave, accept", "is standalone until it accepts"},
	} {
		res, err := evaluator.EvaluateOU(evaluator.OUInput{From: l, To: f, OUID: fixtures.LarkspurWorkloadsOU, TargetParentID: fixtures.FernhillBusinessUnitsOU, TransferMethod: tc.method})
		if err != nil {
			t.Fatal(err)
		}
		if res.Subject.TransferMethod != tc.want {
			t.Errorf("OU subject method %q, want %q", res.Subject.TransferMethod, tc.want)
		}
		rb := BuildOU(res, l, f)
		s := ouStepWith(t, rb, PhaseMove, tc.title)
		leaves := strings.Contains(strings.Join(s.Commands, "\n"), "leave-organization")
		if leaves != (tc.want == evaluator.TransferLeaveAndRejoin) || !strings.Contains(rb.Phase(PhaseMove).Intro, tc.intro) {
			t.Errorf("%s: OU move step %+v, intro %q", tc.want, s, rb.Phase(PhaseMove).Intro)
		}
		for _, a := range rb.Accounts {
			if a.Subject.TransferMethod != tc.want {
				t.Errorf("account %s runbook method %q", a.Subject.AccountID, a.Subject.TransferMethod)
			}
			// The account's own prerequisites follow the method too.
			alone := false
			for _, st := range a.Phase(PhaseBefore).Steps {
				alone = alone || st.Title == "Make the account able to stand alone"
			}
			if alone != (tc.want == evaluator.TransferLeaveAndRejoin) {
				t.Errorf("%s: account %s standalone prerequisites step present: %v", tc.want, a.Subject.AccountID, alone)
			}
		}
	}
	// Inside one organization there is no transfer and no method.
	res, err := evaluator.EvaluateOU(evaluator.OUInput{From: l, OUID: "ou-lark-prod", TargetParentID: "r-lark"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Subject.TransferMethod != "" {
		t.Errorf("same-organization OU move has no transfer method: %q", res.Subject.TransferMethod)
	}
	if _, err := evaluator.EvaluateOU(evaluator.OUInput{From: l, To: f, OUID: fixtures.LarkspurWorkloadsOU, TargetParentID: fixtures.FernhillBusinessUnitsOU, TransferMethod: "teleport"}); err == nil {
		t.Error("an unknown method is refused")
	}
}
