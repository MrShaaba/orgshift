# Permissions and operations

orgshift is read-only by construction:

- every API operation it calls or plans to call is listed in the operation
  catalog, `internal/collector/operations.go`, with its semantics: `read`
  (free, returns existing state), `read-billable` (returns existing state
  but AWS bills the call; only behind an opt-in) or `session` (obtains or
  describes temporary credentials; changes nothing in any account);
- `TestEveryReferencedOperationIsInTheCatalog` scans the collector, the
  preflight, the credential builder and the CLI and fails on any call that
  is not a used catalog entry; `TestEveryUsedOperationIsReferenced` fails
  on a catalog entry nothing calls, so the IAM templates never grant a
  permission nothing needs;
- `TestCatalogSemantics` fails on any `write`, on any name that starts with
  a write verb (Create, Delete, Update, Put, Attach, Move, Enable, ...)
  whatever kind it declares, on a billable read without an opt-in, and on a
  name that does not start with a read verb (List, Describe, Get, Search,
  Lookup, Select, ...) unless it carries a note justifying its kind;
- `TestBillableReadsAreOffByDefault` fails on a billable read this build
  calls unless it is on a short list of gated reads, and each entry of that
  list has a test proving the call is not made without its opt-in
  (`TestBucketPoliciesAreReadOnlyWithTheOptIn`);
- the rest of the tool (`simulate`, `serve`, `config`, `iam-templates`)
  never touches AWS at all.

Credentials come from the onboarding configuration (profiles, Identity
Center sessions, assume-role chains; see [onboarding.md](onboarding.md)).
orgshift stores no credentials and writes none into snapshots. Every
credential is checked with `sts:GetCallerIdentity` against the account the
configuration names before anything is read.

A missing permission does not fail a collection (only the organization and
its tree are required): the domain is recorded as `access_denied` in the
snapshot's `coverage` block, with the error, and simulations against the
snapshot report it as REVIEW until it is collected. `orgshift preflight`
finds the gaps before collecting.

## IAM templates

[iam/README.md](iam/README.md) has one role per collector responsibility,
generated from the catalog by `orgshift iam-templates`: the trust policy,
the permissions policy, the account the role goes in, the
delegated-administrator alternative and a justification for every
`Resource: "*"`. Regenerate them for your configuration with
`orgshift iam-templates --config orgshift.yaml --out docs/iam`.

## Operations this build calls

| Action | Kind | Role | Fills | Purpose |
| --- | --- | --- | --- | --- |
| `organizations:DescribeOrganization` | read | org-management | `organization` | organization ID, management account and feature set |
| `organizations:ListRoots` | read | org-management | `tree` | the root and the policy types enabled on it |
| `organizations:ListOrganizationalUnitsForParent` | read | org-management | `tree` | the OU hierarchy |
| `organizations:ListAccountsForParent` | read | org-management | `tree` | the accounts under each root and OU, with join dates |
| `organizations:ListPolicies` | read | org-management | `policies.*` | SCPs, RCPs, tag and backup policies |
| `organizations:DescribePolicy` | read | org-management | `policies.*` | the document of each policy |
| `organizations:ListTargetsForPolicy` | read | org-management | `policies.*` | where each policy is attached |
| `organizations:ListTagsForResource` | read | org-management | `account_tags` | account tags |
| `organizations:ListDelegatedAdministrators` | read | org-management | `delegated_administrators` | accounts that administer a service |
| `organizations:ListDelegatedServicesForAccount` | read | org-management | `delegated_administrators` | which services each delegated administrator administers |
| `organizations:ListAWSServiceAccessForOrganization` | read | org-management | `trusted_access` | services with trusted access |
| `account:ListRegions` | read | org-management | `enabled_regions` | enabled regions of every member account (needs trusted access for `account.amazonaws.com`) |
| `ram:GetResourceShares` | read | org-management, network | `resource_shares` | shares owned by the caller, with `RetainSharingOnAccountLeaveOrganization` |
| `ram:ListPrincipals` | read | org-management, network | `resource_shares` | the principals of each share |
| `ram:ListResources` | read | org-management, network | `resource_shares` | the resources in each share |
| `controltower:ListLandingZones` | read | control-tower | `control_tower` | the landing zone ARN |
| `controltower:GetLandingZone` | read | control-tower | `control_tower` | version, drift, auto-enrollment and the manifest |
| `controltower:ListEnabledBaselines` | read | control-tower | `control_tower`, `control_tower.enrolled_accounts` | registered OUs and enrolled accounts |
| `controltower:ListEnabledControls` | read | control-tower | `control_tower` | controls enabled on each registered OU |
| `controlcatalog:GetControl` | read | control-tower | `control_tower` | name and behavior of each enabled control |
| `sso:ListInstances` | read | identity-center | `identity_center` | the instance and its identity store |
| `sso:ListPermissionSets` | read | identity-center | `identity_center` | every permission set |
| `sso:DescribePermissionSet` | read | identity-center | `identity_center` | name and session duration |
| `sso:ListManagedPoliciesInPermissionSet` | read | identity-center | `identity_center` | AWS managed policies attached |
| `sso:ListCustomerManagedPolicyReferencesInPermissionSet` | read | identity-center | `identity_center` | customer managed policies referenced |
| `sso:GetInlinePolicyForPermissionSet` | read | identity-center | `identity_center` | the inline policy |
| `sso:GetPermissionsBoundaryForPermissionSet` | read | identity-center | `identity_center` | the permissions boundary |
| `sso:ListAccountsForProvisionedPermissionSet` | read | identity-center | `identity_center` | accounts each permission set is provisioned in |
| `sso:ListAccountAssignments` | read | identity-center | `identity_center` | assignments per account and permission set |
| `identitystore:DescribeUser` | read | identity-center | `identity_center` | user names for assignment principals |
| `identitystore:DescribeGroup` | read | identity-center | `identity_center` | group names for assignment principals |
| `cloudformation:ListStackSets` | read | org-management | `stack_sets` | the StackSets administered from the management account |
| `cloudformation:DescribeStackSet` | read | org-management | `stack_sets` | permission model, target OUs, automatic deployment and `RetainStacksOnAccountRemoval` |
| `cloudformation:ListStackInstances` | read | org-management | `stack_sets` | the stack each StackSet has in each account and Region |
| `cloudformation:DescribeStacks` (with `cloudformation:ListStacks`) | read | member-inspection | `workloads.stacks` | every stack of a workload Region: status, tags, output keys and export names, termination protection; parameter values are read for infrastructure identifiers only and not stored |
| `cloudformation:ListStackResources` | read | member-inspection | `workloads.stacks` | the resource types of each stack and how many of each |
| `cloudformation:ListExports` | read | member-inspection | `workloads.stacks` | the exported output names of the account and Region |
| `cloudformation:ListImports` | read | member-inspection | `workloads.stacks` | the stacks that import each export |
| `cloudformation:GetTemplate` | read | member-inspection | `workloads.stacks` | the template of each stack, read in memory for cross-account stack outputs, infrastructure identifiers and conditions on organization identity; never stored |
| `tag:GetResources` | read | member-inspection | `workloads.resources` | a sample of the resources that are or were tagged |
| `resource-explorer-2:ListIndexes` | read | member-inspection | `workloads.resources` | whether the account has an aggregator index, and where |
| `resource-explorer-2:Search` | read | member-inspection | `workloads.resources` | the resource sample from the aggregator index, when there is one |
| `iam:ListRoles` | read | member-inspection | `workloads.policies` | the trust policy of every role, read for conditions on the organization ID or path |
| `s3:ListBuckets` (IAM action `s3:ListAllMyBuckets`) | read-billable, opt-in `billable.bucket_policies` / `--with-bucket-policies` | member-inspection | `workloads.policies` | the buckets of the account with their Regions |
| `s3:GetBucketPolicy` | read-billable, opt-in `billable.bucket_policies` / `--with-bucket-policies` | member-inspection | `workloads.policies` | the policy of each bucket, read for conditions on the organization ID or path |
| `sts:GetCallerIdentity` | session | every role | identity check | verify that the credentials belong to the configured account; needs no permission |
| `sts:AssumeRole` | session | org-management | identity check, member inspection | assume-role chains and the member and network roles; AWS labels it Write because it issues a session, it changes no resource |

## What the workload inventory costs

Checked against the AWS documentation on 2026-11-05.

| Calls | Charge | Source |
| --- | --- | --- |
| CloudFormation reads (`DescribeStacks`, `ListStackResources`, `ListExports`, `ListImports`, `GetTemplate`, `ListStackSets`, `DescribeStackSet`, `ListStackInstances`) | None listed. The CloudFormation price list charges handler operations of third-party registry extensions and hooks only; API reads are not on it. | <https://aws.amazon.com/cloudformation/pricing/> |
| `iam:ListRoles` | None. "IAM is offered at no additional charge." | <https://aws.amazon.com/iam/faqs/> |
| `resource-explorer-2:ListIndexes`, `Search` | None. "AWS Resource Explorer is offered at no additional charge." | <https://aws.amazon.com/resourceexplorer/pricing/> |
| `tag:GetResources` | No price is published for the Resource Groups Tagging API, and its documentation states no charge either way. It is treated as free. | <https://docs.aws.amazon.com/resourcegroupstagging/latest/APIReference/overview.html> |
| `s3:ListBuckets`, `s3:GetBucketPolicy` | **Billed per request.** S3 charges every request except DELETE and CANCEL: `ListBuckets` is a LIST request (the PUT, COPY, POST, LIST class) and a policy read falls under "GET and all other requests". | <https://aws.amazon.com/s3/pricing/> |

The S3 reads are therefore off by default. With `billable.bucket_policies:
true` (or `--with-bucket-policies`) the collector makes one `ListBuckets`
request per inspected account (per 10,000 buckets) and one `GetBucketPolicy`
request per bucket in the workload Regions, up to `workloads.max_buckets`
(200). At S3 request prices that is a fraction of a cent per account, but
it is not zero, so it is your decision. Without the opt-in:

- no S3 client is built for the member accounts and no S3 call is made;
- role trust policies and the policies declared in templates are still
  read;
- `workloads.policies` gets a second coverage record, `skipped`, with the
  reason, so the workload layer reads **partially evaluated** and a
  cross-organization verdict is REVIEW at best until the bucket policies
  are read or added by hand;
- the member role's default permissions policy does not grant the S3
  actions; `docs/iam/member-inspection-billable-opt-in.json` is the
  separate policy to attach when you opt in.

What is read but never stored: template bodies, stack output values and
stack parameter values. Templates and parameters are scanned for identifiers
of infrastructure (subnets, transit gateways, VPCs, Resolver rules, prefix
lists), for `Fn::GetStackOutput` references and for policy conditions on
`aws:PrincipalOrgID`, `aws:PrincipalOrgPaths`, `aws:ResourceOrgID` and
`aws:ResourceOrgPaths`; only those facts go into the snapshot. Bucket and
trust policies are stored only when they carry such a condition.

## Planned operations

Listed in the catalog so their semantics and opt-ins are decided before the
code that calls them exists; not called by this build and not granted by
the templates (the per-role README lists them as planned).

| Action | Kind | Opt-in | Milestone |
| --- | --- | --- | --- |
| `cloudtrail:DescribeTrails`, `cloudtrail:GetTrailStatus` | read | | organization trails |
| `config:DescribeConfigurationAggregators` | read | | Config aggregators |
| `servicecatalog:SearchProvisionedProducts` | read | | Account Factory provenance |
| `iam:GenerateServiceLastAccessedDetails`, `iam:GetServiceLastAccessedDetails` | read (AWS access level Read: starts a report, changes nothing) | | actions in use from member accounts |
| `cloudtrail:LookupEvents` | read (free, slow) | | actions in use |
| `cloudtrail:StartQuery`, `GetQueryResults`, `DescribeQuery` | read-billable | `billable.cloudtrail_lake` / `--with-cloudtrail-lake` | actions in use from CloudTrail Lake; billed per TB scanned |
| `config:SelectAggregateResourceConfig` | read-billable | `billable.config_queries` / `--with-config-queries` | resource inventories; billed per query |
| `ram:GetResourceShareAssociations` | read | | shares received by the account |
| `ec2:DescribeTransitGatewayAttachments`, `ec2:DescribeTransitGatewayVpcAttachments`, `ec2:DescribeVpcs`, `ec2:DescribeSubnets`, `ec2:DescribeRouteTables`, `ec2:DescribeVpcPeeringConnections`, `ec2:DescribeManagedPrefixLists`, `route53resolver:ListResolverRuleAssociations` | read | | network paths (Section 8) |

## What is not collected, and why

| Data | Status | Cost |
| --- | --- | --- |
| Organization trails, Config aggregators | Not collected in this version; recorded as `unsupported` in the coverage block so simulations that need them say so, and reported as `unknown` by the preflight. Add them to the snapshot by hand (see `docs/snapshot.md`) and record them under `coverage.domains`. | Free API calls when added. |
| StackSets of a CloudFormation delegated administrator | Only the StackSets administered from the management account are listed (`CallAs` SELF). StackSets created by a delegated administrator live in that account and are not read yet; a stack they deployed is classified by its name, at medium confidence, as a StackSet instance whose permission model is unknown. | Free. |
| Workloads of accounts not named for inspection | The inventory is read only in `member_inspection.accounts`. Other accounts have no workload records and their workload layer reads not evaluated. | Free, except the bucket policies. |
| Bucket policies | Off by default (above). | Billed per S3 request. |
| Resources that were never tagged and are outside CloudFormation | Not in the Tagging API sample (it returns resources that are or were tagged). Resource Explorer returns untagged resources but only the first 1,000 results of a search. | Free. |
| KMS key policies, SQS, SNS, Secrets Manager and other resource policies; IAM identity policies | Not read. A policy of those kinds declared in a template is still scanned for organization conditions. | Free when added. |
| Account Factory provenance (`vended_by_account_factory`, `provisioned_product`) | Not collected yet; `servicecatalog:SearchProvisionedProducts` is in the catalog as a planned read. Enrolment itself is collected; the provenance is reported as unknown. | Free. |
| Identity Center group memberships and the exact `AWSReservedSSO_*` role names | Not collected. Memberships would need `identitystore:ListGroupMemberships` per group and do not change the verdict; the role suffix is only visible to IAM inside each member account, so roles are reported as `AWSReservedSSO_<permission set>_*`. | Free. |
| IAM last-accessed data and networking state of member accounts | Not read yet; the catalog lists the planned calls. | Free. |
| Actions in use | Entered by hand or imported from an IAM last-accessed export with `orgshift simulate --last-accessed export.json`. | Free. |
| Actions in use from CloudTrail Lake | `--with-cloudtrail-lake` and `billable.cloudtrail_lake` exist but are refused in this version. | Billed per TB of event data scanned per query. Will stay opt-in and off by default. |
| Resource inventories from Config advanced queries | `--with-config-queries` and `billable.config_queries` exist but are refused in this version. | Billed per advanced query against an aggregator. Will stay opt-in and off by default. |
| Resource tags for tag policy checks | Taken from the workload inventory's resource sample for inspected accounts; entered by hand under `usage.tagged_resources` otherwise (both are merged by ARN). | Free. |

Nothing in orgshift calls `MoveAccount`, `AttachPolicy`, `DetachPolicy`,
`CreateOrganizationalUnit`, `InviteAccountToOrganization`,
`LeaveOrganization`, `EnableControl`, `DisableControl`, `EnableBaseline`,
`UpdateLandingZone`, `CreateAccountAssignment`, `DeleteAccountAssignment`,
`ProvisionPermissionSet`, `PutResourcePolicy`, `CreateResourceShare`,
`CreateStack`, `UpdateStack`, `DeleteStack`, `UpdateStackSet`,
`DeleteStackInstances`, `PutBucketPolicy`, `UpdateAssumeRolePolicy` or any
other write operation, and the tests keep it that way.
