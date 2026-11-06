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

The collector reads `RetainSharingOnAccountLeaveOrganization` from each
share's `resourceShareConfiguration` (RAM API `ResourceShare`,
[reference](https://docs.aws.amazon.com/ram/latest/APIReference/API_ResourceShare.html),
checked 2026-11-02) since the move to Go 1.24 and RAM SDK module v1.45.
When the API returns no configuration the field stays false, which is the
documented default and the safe reading (the share is lost). The preflight
shows the first share's value so an unexpected "not reported" is visible
before collection.

## Transfer procedure (Organizations)

Sources: [Migrating an account to another organization](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_account_migration.html),
checked 2026-11-05;
[Removing a member account](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_accounts_remove.html),
[Managing account invitations](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_accounts_invites.html),
[Deleting an organization](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_org_delete.html),
[Decommission a landing zone](https://docs.aws.amazon.com/controltower/latest/userguide/decommission-landing-zone.html),
[About enrolling existing accounts](https://docs.aws.amazon.com/controltower/latest/userguide/enroll-account.html),
checked 2026-11-02. Versioned as the `transfer-procedure` model
(`evaluator.TransferModelVersion`, `2026-11-05`), named in the findings that
use it. Version `2026-11-02` modelled a single sequence, leave and then
join, and presented its standalone interval as part of every move between
organizations; that was wrong for a direct transfer and is what M5 defect 4
corrected.

There are three procedures and orgshift keeps them apart. The result names
the one that applies in `subject.transfer_method`.

**Direct transfer** (`direct`, the default).

- "With direct account transfer, you migrate an account by having the new
  organization send an invitation and the migrating account accept it. The
  migrating account doesn't need to leave its current organization or
  operate as a standalone account first." There is no standalone interval,
  and the standalone-account information is not a prerequisite.
- "It does need the `organizations:LeaveOrganization` permission, because
  accepting the invitation moves it out of its current organization." and
  "An SCP in the source organization that denies
  `organizations:LeaveOrganization` blocks the transfer, even when the
  account's IAM policy allows it." orgshift evaluates the action against the
  source SCP chain: a deny (explicit, or implicit under an allow list) is a
  NO-GO with the statement as evidence; a deny that depends on the caller
  or another condition is a REVIEW; no finding when nothing denies it.
  Removal by the management account is not a way round it: that is the
  other procedure.
- "Accounts that are migrated ... will be automatically added to the root
  of the new organization." Until the destination management account moves
  the account into its OU, only the policies attached to the root apply.
  orgshift reports that interval on its own (REVIEW when anything is
  attached below the root on the target path): the policies not yet in
  force, the actions in use and inbound requests that the target position
  denies and the root still admits, and whether the target OU is governed
  by Control Tower. The verdict board keeps evaluating the target position.
- An invitation must be answered within 15 days (invitations page).

**Leave or remove, then rejoin** (`leave-and-rejoin`, chosen with
`--transfer-method` or `membership.method`).

- The account leaves (`LeaveOrganization` from inside it) or is removed by
  the source management account, runs standalone, and then accepts an
  invitation. It can only do so with the standalone-account information in
  place (verified contact details, a payment method, a support plan),
  otherwise `ConstraintViolationException`. Reported as a REVIEW of its
  own, and the standalone-account information as a requirement the
  snapshots cannot confirm.
- A source SCP that denies `organizations:LeaveOrganization` is a REVIEW
  here, not a blocker: the management account can remove the account, and
  SCPs do not restrict the management account.
- The account lands at the destination root in this procedure too.

**Management account** (`management-account`, follows from the account, not
a choice).

- "you must remove all member accounts from the organization and delete the
  organization before migrating" the management account; it then accepts
  the invitation as a standalone account and is a member account from then
  on. Deleting the organization deletes every organization policy
  irrecoverably; a Control Tower landing zone operated from it has to be
  decommissioned first, which cannot be undone and leaves S3 buckets and
  log groups to delete by hand. Both are NO-GO findings, separate from the
  policy comparison, and neither of the member procedures is reported for
  such an account.

**Eligibility**, for any of them. Each requirement is confirmed, failed or
reported as not confirmed; none is assumed to be met.

| Requirement (migration page) | In the snapshot | Finding |
| --- | --- | --- |
| The destination organization is at least seven days old | `organization.created_at` of the destination (entered by hand; no Organizations API returns it) | NO-GO when younger at `generated_at`; not confirmed when absent. The date the management account joined is shown as a hint only: nothing documents it as the creation date. |
| The Seller of Record of the account matches the destination's, or "the move fails" | `organization.seller_of_record` on both sides (entered by hand, from the invoices) | NO-GO when they differ; not confirmed when either is absent |
| The account is not a delegated administrator | `delegated_administrators` | NO-GO per service |
| Root MFA: "remove it before the migration. Otherwise, the new owner might not be able to sign in as the root user." | `accounts[].root_mfa_enabled` (entered by hand) | REVIEW when `true` (a decision: it matters when the owner changes); not confirmed when absent |
| "Closed or suspended accounts cannot be migrated." | `accounts[].status` | NO-GO unless `ACTIVE`; not confirmed when absent |
| An account created in an organization waits four days | `accounts[].joined_method`, `joined_at` | NO-GO when younger at `generated_at`; not confirmed when the date is absent; does not apply to invited accounts |
| The IAM role that gives the old management account access "isn't automatically deleted" | `accounts[].joined_method` | REVIEW for created accounts (`OrganizationAccountAccessRole` exists), with a step after the move to delete it; INFO for invited ones |

What is not confirmed is one REVIEW of category `missing-evidence` that
lists each requirement and the field that settles it.

Also from the migration page: the tags on the account are not carried over
and have to be recreated, organization-level reports and billing history
stay with the old organization, and Reserved Instances and Savings Plans
move with the account. From the invitations page: the destination's
organization trail covers the account automatically and Config, GuardDuty
or Security Hub may enable automatically for new members (duplicate charges
with account-level trails); Organizations does not create
`OrganizationAccountAccessRole` for an invited account.

Not modelled: what a direct transfer does to consolidated-billing
proration, tax settings and AWS Marketplace subscriptions. The page does
not describe a rollback; orgshift's rollback is another direct transfer in
the other direction, with the same requirements applied to the other
organization.

- Control Tower enrolls an existing account from an unregistered OU of the
  same organization into a registered OU; it needs an
  `AWSControlTowerExecution` role trusting the management account and no
  AWS Config recorder or delivery channel of the account's own; enrolling
  deploys the baseline StackSets, enables Config, adds the detective rules
  and applies the OU's SCPs; existing VPCs are left alone; an account-level
  CloudTrail trail duplicates the organization trail's charges. The
  collector cannot see the role or the Config resources, so the scenario
  overlay carries declarations (`execution_role_present`,
  `config_resources_removed`) that the stage findings report as satisfied,
  unknown or declared unsatisfied.
- Policy inheritance: a proposed OU, registered or not, inherits every policy
  attached above it, and a child cannot override an inherited explicit deny
  ([inheritance](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_inheritance_auth.html)).
  The staged evaluation derives the proposed OU into the chain, so the
  evaluator applies the same rule it applies to collected OUs.

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

This section is about `LeaveOrganization` and
`RemoveAccountFromOrganization`, the first half of the leave-and-rejoin
procedure. A direct transfer does not go through it; see
[Transfer procedure](#transfer-procedure-organizations).

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

## Who SCPs and RCPs do not restrict

Source: [Service control policies](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps.html),
checked on 2026-11-05; the RCP exemptions are part of the
`rcp-applicability` model above.

- "SCPs don't affect users or roles in the management account. They affect
  only the member accounts in your organization." The evaluator asks this
  of each side separately: an account is exempt in the organization it
  manages and nowhere else. A management account that becomes a member of
  another organization is evaluated as unrestricted before the move and
  against the full chain after it, so every restriction of the destination
  is reported as new, including one its own root carries in a policy of
  the same content. Inside one organization the management account is
  exempt at either position. The prerequisite that a management account
  cannot leave the organization it manages is a separate finding of the
  organization services check.
- "SCPs do not affect any service-linked role." A usage entry whose
  `principal_arn` is under `role/aws-service-role/` is not evaluated
  against SCPs or RCPs on either side; an informational finding lists the
  calls that were left out.
- The same page lists other tasks SCPs cannot restrict (registering for
  the Enterprise support plan as the root user, CloudFront trusted
  signers, reverse DNS for Lightsail and EC2 as the root user, and tasks
  on a few AWS-related services). They are not modelled: none of them is
  an action a usage list would carry.
- RCPs do not restrict resources that belong to a management account, on
  the side where the account is one. The rule is applied to the moving
  account's own resources and inbound access the same way.

Before 2026-11-05 the evaluator ran both sides through the chain whatever
the account was, so a management account read as "already denied" by its
own root, and a service-linked role's call as denied by any SCP.

## The Region of a request (`aws:RequestedRegion`)

Source: [Manage AWS STS in an AWS Region](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_temp_region-endpoints.html),
checked on 2026-11-05.

- Services with one global endpoint (IAM, Organizations, CloudFront,
  Route 53 and the others in the evaluator's list) are evaluated in
  `us-east-1`.
- AWS STS has Regional endpoints (`sts.eu-west-1.amazonaws.com`) and a
  global one (`sts.amazonaws.com`). "Requests made to the AWS STS global
  endpoint have a value of `us-east-1` for the `aws:RequestedRegion`
  condition key, regardless of which Region served the request." A request
  to a Regional endpoint is evaluated in that Region. So an `sts` usage
  entry is evaluated in the Regions it names, with `"global"` (or
  `"aws-global"`) standing for the global endpoint.
- When an `sts` entry names no Region, the endpoint is not known and
  neither is the Region: `aws:RequestedRegion` is left unknown. A policy
  that does not look at the Region still decides the call; one that does
  gives a REVIEW (missing evidence) that says what to add. The account's
  enabled Regions are not used as a stand-in, because the endpoint a
  client calls is a client setting, not an account one. This also holds
  for the `sts:AssumeRole` call derived from a `Fn::GetStackOutput`
  reference: which endpoint CloudFormation uses is not documented.

Before 2026-11-05 every `sts` call was evaluated in `us-east-1`, which made
a call through a Regional endpoint look denied by a guardrail that admits
its Region, or allowed by one that only denies `us-east-1`.

## Malformed policies and policy variables

Sources: [SCP syntax](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps_syntax.html),
[RCP syntax](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_rcps_syntax.html),
[IAM policy grammar](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_grammar.html),
[IAM policy variables](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_variables.html).
Checked on 2026-11-05.

- One action element and one resource element per statement. The grammar
  writes a statement as an `<action_block>` and a `<resource_block>`, each
  an alternative: `("Action" | "NotAction")` and `("Resource" |
  "NotResource")`. No page says "not both" in words; the rule is read from
  the grammar. A statement with both is treated as malformed, not as if
  one of the two were absent.
- What a missing `Resource` means depends on the policy type. "Each
  statement in an SCP must include a `Resource` or `NotResource` element",
  and for RCPs "Each statement must contain the `Resource` or
  `NotResource` element". So in an SCP or RCP a statement without one is
  malformed; it is never read as a statement about every resource. A role
  trust policy, by contrast, has no `Resource` at all, and its statements
  are about the role.
- Further rules of the two types: in an SCP, "in statements where the
  `Effect` element has a value of `Allow`, you can specify only "\*" in
  the `Resource` element" and `Principal` and `NotPrincipal` are not
  supported; in an RCP the `Principal` must be `"*"` and `NotPrincipal`
  and `NotAction` are not supported.
- A malformed policy is kept in the snapshot with the reason
  (`malformed`). The evaluator treats it as unknown in both directions: it
  may hold a Deny that applies or the Allow a level needs, so the check
  whose chain holds it is a REVIEW, with one finding that names the
  policy, where it is attached and why it is malformed.
- Policy variables. "You can use policy variables in the `Resource`
  element and in string comparisons in the `Condition` element." In
  `Resource` and `NotResource` the engine resolves a variable from the
  request context when it knows the value (a `principal_tags` entry gives
  `${aws:PrincipalTag/...}`), uses the default of `${key, 'default'}`
  when the key has no value, and follows the documented rule for a key
  that is known to be absent and has no default: "the resource that
  includes a policy variable with no value will not match any resource".
  When the value is not known, the pattern is tried with a wildcard in the
  variable's place: if that cannot match the resource the answer is a
  definite no, otherwise it is unknown (REVIEW), for `Allow` and `Deny`
  and for `Resource` and `NotResource` alike. In `Condition` values a
  variable is always unknown.

Before 2026-11-05 the parser accepted a statement with both elements and
used one of them, gave a statement without `Resource` the value `*`, and
compared `${...}` in a resource as literal text, which made a Deny behind
a variable a definite non-match. A malformed policy that the parser did
reject stopped the whole collection.

## Wildcards in ARNs

Sources: [IAM condition operators](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition_operators.html),
[IAM policy elements: Resource](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_resource.html).
Checked on 2026-11-05.

IAM matches a wildcard differently depending on where the pattern stands,
and the policy engine (`internal/policy`) follows each rule:

- ARN condition operators (`ArnLike`, `ArnEquals` and their negations):
  "Each of the six colon-delimited components of the ARN is checked
  separately". A wildcard never reaches into the next component.
- String condition operators (`StringLike`): wildcards can stand
  "anywhere in the string", and the comparison "does not enforce a
  predefined format". A `*` can stand for a colon.
- The `Resource` element: wildcards are used "within the individual
  segments of an ARN", and "if the `*` wildcard is the last character of a
  resource ARN segment, it can expand to match beyond the colon
  boundaries". So `arn:aws:logs:*:log-group:prod`, which leaves a component
  out, still matches a log group ARN. Whether a `*` in the middle of a
  component or a `?` can do the same is not stated; when a match depends
  on it the engine answers unknown (REVIEW), never "no match".

A value that is itself a pattern is the evaluator's way of writing a set of
real ARNs ("any role of the account" is `role/*`). Its wildcards stand for
a name, not for further colon-separated parts, so the root-user pattern
`arn:aws:iam::*:root` does not match `arn:aws:iam::111111111111:role/*`.
This is an assumption about names, and it is the reason the common
root-user deny is evaluated instead of turning every action into a REVIEW.

Before 2026-11-05 the engine matched ARN-shaped values component by
component everywhere, which is right for the ARN operators and too strict
for `Resource` and `StringLike`: a Deny whose pattern left a component out
was read as not matching. The fuzz test that compares the matching
algorithms with each other found the case.

## Workloads (model `workload-behaviour`, version 2026-11-05)

What the Workloads check and the workload inventory rely on. Checked on
2026-11-05.

StackSets. Sources:
[AutoDeployment](https://docs.aws.amazon.com/AWSCloudFormation/latest/APIReference/API_AutoDeployment.html),
[Enable or disable automatic deployments](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/stacksets-orgs-manage-auto-deployment.html),
[ListStackSets](https://docs.aws.amazon.com/AWSCloudFormation/latest/APIReference/API_ListStackSets.html),
[ListStackInstances](https://docs.aws.amazon.com/AWSCloudFormation/latest/APIReference/API_ListStackInstances.html).

- With automatic deployment enabled on a service-managed StackSet, "if an
  account is removed from a target organization or OU, StackSets deletes
  stack instances from the account". With `RetainStacksOnAccountRemoval`
  true the stack resources are retained and the stacks leave the StackSet;
  with false they are deleted. orgshift reports a deleted instance as
  REVIEW (declared impact) with the resource types it contains, and a
  retained one as informational.
- What happens to the instances when automatic deployment is **off** is not
  stated. orgshift reports it as REVIEW (potential impact, "not
  documented") and never assumes either outcome.
- The stack name form `StackSet-<name>-<id>` appears in AWS's examples and
  is not a documented rule. A stack is a StackSet instance for orgshift
  when its ID is in the StackSet's instance list (high confidence); a match
  by name alone is medium confidence and says so.
- From the management account with `CallAs` SELF (the default),
  `ListStackSets` "returns all StackSets in the management account".
  StackSets created by a CloudFormation delegated administrator are not in
  that list; orgshift does not read them yet.

Cross-stack references. Sources:
[Exporting stack output values](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/using-cfn-stack-exports.html),
[Fn::GetStackOutput](https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/intrinsic-function-reference-getstackoutput.html),
[ListImports](https://docs.aws.amazon.com/AWSCloudFormation/latest/APIReference/API_ListImports.html).

- `Export` and `Fn::ImportValue`: "cross-stack references are limited to
  the same account and Region", and the exporting stack cannot be deleted
  nor its exported output changed while another stack imports it. So an
  import never points at another account: orgshift reports imports as
  informational (they move with the account and fix the redeployment
  order), and notes when an import would block a StackSet from deleting its
  instance.
- `Fn::GetStackOutput` reads an output of a stack in another account or
  Region through an IAM role and is "resolved at stack create or update
  time"; it is a weak reference with no referential integrity. orgshift
  reports a cross-account one as REVIEW (potential impact) on a move
  between organizations and evaluates the `sts:AssumeRole` call it implies
  against the SCP and RCP chains. The page says nothing about
  organizations; the trust policy of the role, which lives in the other
  account, is not read.
- `ListImports` for an export that no stack imports is not documented. The
  service answers with a `ValidationError`; the collector reads that as
  "no importer" and treats any other error as a failure of the domain.

The inventory itself. Sources:
[DescribeStacks](https://docs.aws.amazon.com/AWSCloudFormation/latest/APIReference/API_DescribeStacks.html),
[GetTemplate](https://docs.aws.amazon.com/AWSCloudFormation/latest/APIReference/API_GetTemplate.html),
[GetResources](https://docs.aws.amazon.com/resourcegroupstagging/latest/APIReference/API_GetResources.html),
[Resource Explorer Search](https://docs.aws.amazon.com/resource-explorer/latest/apireference/API_Search.html),
[ListRoles](https://docs.aws.amazon.com/IAM/latest/APIReference/API_ListRoles.html),
[GetRole](https://docs.aws.amazon.com/IAM/latest/APIReference/API_GetRole.html),
[ListBuckets](https://docs.aws.amazon.com/AmazonS3/latest/API/API_ListBuckets.html).

- `DescribeStacks` without a stack name describes every stack and
  "requires `ListStacks` and `DescribeStacks` permissions"; the member role
  grants both.
- `GetTemplate` returns the processed template by default. The collector
  parses it in memory and stores only derived facts.
- The Resource Groups Tagging API "returns all the tagged or previously
  tagged resources" of a Region and does not return untagged resources. A
  resource created outside CloudFormation that never carried a tag is
  therefore missing from the sample, and the reports say so.
- Resource Explorer `Search` "can return only the first 1,000 results"; a
  sample of 1,000 is marked truncated. It needs an index (an aggregator
  index for all Regions) and a view; without a default view in the
  aggregator's Region the search fails and the collector falls back to the
  Tagging API, recording why.
- `ListRoles` returns each role with its trust policy and omits
  `PermissionsBoundary`, `RoleLastUsed` and `Tags`. IAM returns policies
  URL-encoded (RFC 3986), which the collector decodes.
- `ListBuckets` returns each bucket's Region, which is where its policy is
  read. The error code for a bucket without a policy
  (`NoSuchBucketPolicy`) could not be confirmed on the S3 error page, which
  did not render when it was checked; the collector treats that code as "no
  policy" and any other error as a failure.

Cost. Sources: [S3 pricing](https://aws.amazon.com/s3/pricing/),
[S3 usage report](https://docs.aws.amazon.com/AmazonS3/latest/userguide/aws-usage-report-understand.html),
[CloudFormation pricing](https://aws.amazon.com/cloudformation/pricing/),
[IAM FAQ](https://aws.amazon.com/iam/faqs/),
[Resource Explorer pricing](https://aws.amazon.com/resourceexplorer/pricing/).

- S3 charges per request by request type; "DELETE and CANCEL requests are
  free". LIST requests are in the PUT, COPY, POST, LIST class and
  everything else is "GET and all other non-Tier1 requests". Nothing says a
  bucket-policy read is exempt, so `ListBuckets` and `GetBucketPolicy` are
  classified as billable reads and are off by default.
- CloudFormation charges handler operations of third-party registry
  extensions and hooks; its read API calls are not on the price list.
- "IAM is offered at no additional charge." "AWS Resource Explorer is
  offered at no additional charge."
- No price and no statement of charge was found for the Resource Groups
  Tagging API on its documentation pages; it is treated as free.

## Not yet verified

These are reported as REVIEW with the reason, never as fine:

- What a service-managed StackSet does with an account's instances when
  the account leaves and automatic deployment is off (above).
- Data-plane behaviour of the RAM resource types listed as unverified above.
- Whether the policy inheritance of an account sitting at the target root
  between accepting the invitation and the move into its OU matters for the
  workloads (the stage model of Section 6 of the brief; milestone M3).
