package evaluator

// TransferModelVersion dates the transfer-procedure model: what AWS
// Organizations and Control Tower require to take an account out of one
// organization and into another, as read from the official documentation
// on that day. The findings that use it name the version so a reader can
// tell how current the sequence is instead of trusting a hardcoded one.
const TransferModelVersion = "2026-11-02"

// TransferModel describes the model and the pages it was verified against.
func TransferModel() ModelRef {
	return ModelRef{ID: "transfer-procedure", Version: TransferModelVersion, Reference: refRemoveAccount,
		Note: "Removing a member account: standalone-account information (verified contact details, payment method, support plan) or ConstraintViolationException; created accounts wait four days; no delegated administrator; tags deleted; the role Organizations created is kept; cost data stays with the management account. " +
			"Invitations: one organization at a time, 15 days to answer, root and OU policies apply at once on acceptance, the organization trail applies automatically, OrganizationAccountAccessRole is not created for invited accounts. " +
			"Management account: leaves only by deleting the organization after every member is removed, which deletes every organization policy; a Control Tower landing zone has to be decommissioned first, which cannot be undone. " +
			"Control Tower enrollment: from an unregistered OU of the same organization, with an AWSControlTowerExecution role trusting the management account and no AWS Config recorder or delivery channel of the account's own; enrolling deploys the baseline StackSets, enables Config and applies the OU's SCPs; existing VPCs are left alone; account-level CloudTrail trails duplicate the organization trail. " +
			"Verified against " + refRemoveAccount + ", " + refInvitations + ", " + refDeleteOrganization + ", " + refDecommission + " and " + refCTEnroll + "."}
}
