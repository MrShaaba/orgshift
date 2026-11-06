package evaluator

import (
	"fmt"
	"strings"
)

// TransferModelVersion dates the transfer-procedure model: what AWS
// Organizations and Control Tower require to take an account out of one
// organization and into another, as read from the official documentation
// on that day. The findings that use it name the version so a reader can
// tell how current the sequence is instead of trusting a hardcoded one.
//
// 2026-11-05 replaced the single leave-then-join sequence of 2026-11-02
// with the three procedures the documentation describes and the
// eligibility requirements of the migration page.
const TransferModelVersion = "2026-11-05"

// Transfer methods: how an account gets from one organization to another.
const (
	// TransferDirect is the direct account transfer: the destination
	// invites, the account accepts, and that acceptance moves it out of its
	// current organization. It is never standalone in between.
	TransferDirect = "direct"
	// TransferLeaveAndRejoin is the older sequence: the account leaves (or
	// the source management account removes it), runs standalone, and then
	// accepts an invitation.
	TransferLeaveAndRejoin = "leave-and-rejoin"
	// TransferManagementAccount is the only way a management account
	// moves: remove every member, delete the organization, then accept the
	// invitation as the standalone account that is left.
	TransferManagementAccount = "management-account"
)

// TransferMethods lists the methods an operator can choose; the management
// account sequence is not a choice, it follows from the account.
var TransferMethods = []string{TransferDirect, TransferLeaveAndRejoin}

// ValidTransferMethod accepts the methods an operator can choose, and the
// empty string for the default (direct). Anything else is an error rather
// than a silent fall back to one of the two.
func ValidTransferMethod(method string) error {
	if method == "" {
		return nil
	}
	for _, m := range TransferMethods {
		if method == m {
			return nil
		}
	}
	return fmt.Errorf("transfer method %q is not one of %s", method, strings.Join(TransferMethods, ", "))
}

// TransferMethodLabel says in a few words what a transfer method is, for
// report headers.
func TransferMethodLabel(method string) string {
	switch method {
	case TransferDirect:
		return "direct transfer (invite, accept; no standalone interval)"
	case TransferLeaveAndRejoin:
		return "leave or remove, then rejoin (standalone in between)"
	case TransferManagementAccount:
		return "management account (remove every member, delete the organization, then accept)"
	}
	return method
}

// refAccountMigration is the page the direct transfer and the eligibility
// requirements were checked against.
const refAccountMigration = "https://docs.aws.amazon.com/organizations/latest/userguide/orgs_account_migration.html"

// TransferModel describes the model and the pages it was verified against.
func TransferModel() ModelRef {
	return ModelRef{ID: "transfer-procedure", Version: TransferModelVersion, Reference: refAccountMigration,
		Note: "Three procedures, kept apart. " +
			"Direct transfer: the destination invites and the account accepts; it does not leave first and is never standalone, but it needs organizations:LeaveOrganization and a source SCP that denies it blocks the transfer; the account lands at the destination root. " +
			"Leave or remove, then rejoin: the account needs the standalone-account information (verified contact details, payment method, support plan) or the removal fails with ConstraintViolationException, and is outside any organization until it accepts an invitation. " +
			"Management account: remove every member, delete the organization (which deletes every organization policy; a Control Tower landing zone has to be decommissioned first), then accept the invitation as a standalone account. " +
			"Eligibility: the destination organization is at least seven days old; the Seller of Record of the account matches the destination's or the move fails; the account is not a delegated administrator; root MFA is removed when the owner changes; closed or suspended accounts cannot be migrated; an account created in an organization waits four days; the IAM role that gives the former management account access is not deleted. " +
			"Invitations: 15 days to answer, root policies apply at once on acceptance, OrganizationAccountAccessRole is not created for invited accounts; account tags are not carried over; organization-level reports and history stay behind. " +
			"Control Tower enrollment: from an unregistered OU of the same organization, with an AWSControlTowerExecution role trusting the management account and no AWS Config recorder or delivery channel of the account's own. " +
			"Verified against " + refAccountMigration + ", " + refRemoveAccount + ", " + refInvitations + ", " + refDeleteOrganization + ", " + refDecommission + " and " + refCTEnroll + "."}
}
