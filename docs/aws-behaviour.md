# AWS behaviour the evaluator relies on

Every claim orgshift makes about what AWS does when an account moves is
listed here with the documentation page it was checked against and the date
of the check. The evaluator records the versioned models it used in every
result (`models` in the JSON, "Models used" in the reports), so a reader can
tell how current the assumptions were. When AWS changes a behaviour, update
the model, bump its version date and add the page here.

Finding-level references are also attached to the findings themselves
(`references` in the JSON, "Documentation:" in the Markdown and the UI).

## Resource control policies (model `rcp-applicability`, version 2026-11-01)

Source: [Resource control policies (RCPs)](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_rcps.html#rcp-supported-services).

- RCPs apply to the actions of a fixed list of services; the model lists the
  62 service prefixes on the page on the model date. Actions of any other
  service are reported as "not evaluated against RCPs", never as allowed,
  and the RCP check names them.
- RCPs apply to the resources authorized as part of a request, so the RCPs
  of the **resource owner's** organization apply. For an action in use that
  names a resource in another account, orgshift evaluates the owner's chain
  and only changes the caller's organization (`aws:PrincipalOrgID`) before
  and after the move. A resource whose owner is in neither snapshot is a
  REVIEW.
- RCPs do not affect resources in the management account, calls by
  service-linked roles, AWS managed KMS keys, or `kms:RetireGrant`.
- An RCP never grants permission. The evaluator checks governance policies
  only; it is not a replacement for IAM authorization.

## Resource shares (model `ram-behaviour`, version 2026-11-01)

Sources: [Sharing your AWS resources](https://docs.aws.amazon.com/ram/latest/userguide/getting-started-sharing.html),
[Shareable AWS resources](https://docs.aws.amazon.com/ram/latest/userguide/shareable.html),
[Unshare a transit gateway](https://docs.aws.amazon.com/vpc/latest/tgw/transit-gateway-share.html#transit-gateway-unshare),
[Unshare a shared subnet](https://docs.aws.amazon.com/vpc/latest/userguide/vpc-sharing-share-subnet-working-with.html#vpc-sharing-stop-share-subnet),
[Sharing Resolver rules](https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/resolver-rules-managing.html#resolver-rules-managing-sharing).

What RAM does (control plane):

- Shares addressed to an organization or an OU follow membership: an
  account that leaves the organization or the OU loses access through the
  share at once.
- A share addressed to the account ID also stops when the account leaves
  the organization, unless the share was created with
  `RetainSharingOnAccountLeaveOrganization` (which requires
  `allowExternalPrincipals`, is set only at creation, and is not available
  for resource types that can only be shared inside an organization). Then
  the share arrives as an invitation to accept: seven days for the
  networking resource types, twelve hours otherwise.
- Subnets and security groups can only be shared inside one organization.

What the services do with resources already in use (data plane), which RAM
does not decide:

| Resource type | Documented behaviour after the share stops | orgshift severity when lost |
| --- | --- | --- |
| `ec2:TransitGateway` | Existing attachments remain functional; the account can no longer describe the transit gateway or create attachments; either side can delete the attachments. | REVIEW; NO-GO when an action in use creates or modifies attachments |
| `ec2:Subnet` | Existing participant resources keep running; no new resources can be created in the subnet; existing ones can be modified, described and deleted. | REVIEW, listing resource-creating actions in use as potentially affected |
| `route53resolver:ResolverRule` | Associations with the account's VPCs are removed and Resolver answers from the remaining rules at once. An OU-scoped rule keeps its associations only if it is also shared with the destination OU. | NO-GO |
| prefix lists, IPAM pools, multicast domains, Resolver firewall rule groups and query log configs, local gateway route tables, core networks, Verified Access groups, traffic mirror targets, security groups | Not verified against the service documentation. | REVIEW, saying so |
| everything else | Not modelled. | REVIEW |

The collector does not read `RetainSharingOnAccountLeaveOrganization`: the
RAM SDK module that exposes it on `ResourceShare` requires Go 1.24, which
this build does not use yet. The field is in the snapshot schema for hand
entry and defaults to false, which is the safe reading (the share is lost).

## AWS Control Tower

Sources: [About enrolling existing accounts](https://docs.aws.amazon.com/controltower/latest/userguide/enroll-account.html),
[Move and enroll accounts with auto-enrollment](https://docs.aws.amazon.com/controltower/latest/userguide/account-auto-enrollment.html),
[Optionally configure auto-enrollment](https://docs.aws.amazon.com/controltower/latest/userguide/configure-auto-enroll.html),
[Unenroll an account](https://docs.aws.amazon.com/controltower/latest/userguide/unmanage-account.html),
[Types of baselines](https://docs.aws.amazon.com/controltower/latest/userguide/types-of-baselines.html),
[Examples for baseline API usage](https://docs.aws.amazon.com/controltower/latest/userguide/baseline-api-examples.html).

- Enrolment is visible read-only: `ListEnabledBaselines` with
  `includeChildren` returns a child enabled baseline for every enrolled
  account (target: the account, `parentIdentifier`: the OU's enabled
  baseline). The collector fills `control_tower.enrolled_accounts` from it
  and records the `control_tower.enrolled_accounts` coverage domain. An
  account under a registered OU without such a record is **not** enrolled.
  Only when that domain was never collected does the evaluator fall back to
  "in a registered OU, so assumed enrolled", and the finding says so.
- Whether Account Factory vended an account is not visible this way
  (Service Catalog is not read); records from the API say so.
- Auto-enrollment (landing zone 3.1 and later) is the `INHERITANCE_DRIFT`
  remediation type on the landing zone, read from `GetLandingZone`. With it
  on, moving an account into a registered OU enrols it and moving it out
  (to an unregistered OU or the root) unenrols it, with eventual
  consistency (minutes to hours); Service Catalog provisioned products are
  not touched; moves between OUs with different controls may show "Moved
  member account" drift. With it off, a move made with Organizations
  leaves inheritance drift to fix from Account Factory. The setting is not
  retroactive.
- Unenrolling removes every resource Control Tower provisioned, including
  the `AWSControlTowerExecution` role, and moves the account to the root.
- Enrolling an existing account needs the `AWSControlTowerExecution` role
  trusting the management account, no Config recorder or delivery channel
  of the account's own in the governed regions, and an account in an
  unregistered OU of the same organization. The audit and log archive
  accounts cannot be moved or re-enrolled.

## Leaving an organization

Source: [Removing a member account](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_accounts_remove.html).

- The account must have the information a standalone account needs
  (verified contact information, a payment method, a support plan); the
  removal fails with `ConstraintViolationException` otherwise.
- An account created by Organizations cannot be removed until four days
  after creation (NO-GO when the snapshot shows it is younger; REVIEW when
  the creation date is missing). Invited accounts are not affected.
- A delegated administrator for any service cannot be removed until it is
  deregistered (NO-GO).
- The management account cannot leave; the organization has to be deleted.
- Tags attached to the account are deleted; the IAM role Organizations
  created for the management account is not deleted; the account loses
  access to its cost and usage data for the membership period and to the
  organization's agreements; principals are no longer affected by any
  organization policy.

## IAM Identity Center

Source: [AWS IAM Identity Center and AWS Organizations](https://docs.aws.amazon.com/organizations/latest/userguide/services-that-can-integrate-sso.html).

- When an account is removed from the organization, Identity Center cleans
  up its metadata and resources in the account (the page names the
  service-linked role) and a standalone account no longer works with
  Identity Center. orgshift reports every assignment on the account as
  removed and the `AWSReservedSSO_*` roles as expected to disappear, with
  the instruction to confirm in IAM after the move, since the page does not
  name those roles.

## Not yet verified

These are reported as REVIEW with the reason, never as fine:

- Data-plane behaviour of the RAM resource types listed as unverified above.
- Whether the policy inheritance of an account sitting at the target root
  between accepting the invitation and the move into its OU matters for the
  workloads (the stage model of Section 6 of the brief; milestone M3).
