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
| `sts:GetCallerIdentity` | session | every role | identity check | verify that the credentials belong to the configured account; needs no permission |
| `sts:AssumeRole` | session | org-management | identity check, member inspection | assume-role chains and the member and network roles; AWS labels it Write because it issues a session, it changes no resource |

## Planned operations

Listed in the catalog so their semantics and opt-ins are decided before the
code that calls them exists; not called by this build and not granted by
the templates (the per-role README lists them as planned).

| Action | Kind | Opt-in | Milestone |
| --- | --- | --- | --- |
| `cloudtrail:DescribeTrails`, `cloudtrail:GetTrailStatus` | read | | organization trails (M4) |
| `config:DescribeConfigurationAggregators` | read | | Config aggregators (M4) |
| `cloudformation:ListStackSets`, `DescribeStackSet`, `ListStackInstances` | read | | StackSets (M4) |
| `servicecatalog:SearchProvisionedProducts` | read | | Account Factory provenance (M4) |
| `iam:GenerateServiceLastAccessedDetails`, `iam:GetServiceLastAccessedDetails` | read (AWS access level Read: starts a report, changes nothing) | | actions in use from member accounts (M4) |
| `cloudtrail:LookupEvents` | read (free, slow) | | actions in use (M4) |
| `cloudtrail:StartQuery`, `GetQueryResults`, `DescribeQuery` | read-billable | `billable.cloudtrail_lake` / `--with-cloudtrail-lake` | actions in use from CloudTrail Lake; billed per TB scanned |
| `config:SelectAggregateResourceConfig` | read-billable | `billable.config_queries` / `--with-config-queries` | resource inventories; billed per query |
| `tag:GetResources` | read | | tagged resource sample (M4) |
| `ram:GetResourceShareAssociations` | read | | shares received by the account (M4) |
| `ec2:DescribeTransitGatewayAttachments`, `ec2:DescribeTransitGatewayVpcAttachments`, `ec2:DescribeVpcs`, `ec2:DescribeSubnets`, `ec2:DescribeRouteTables`, `ec2:DescribeVpcPeeringConnections`, `ec2:DescribeManagedPrefixLists`, `route53resolver:ListResolverRuleAssociations` | read | | network paths (Section 8) |

## What is not collected, and why

| Data | Status | Cost |
| --- | --- | --- |
| Organization trails, Config aggregators, StackSets | Not collected in this version; recorded as `unsupported` in the coverage block so simulations that need them say so, and reported as `unknown` by the preflight. Add them to the snapshot by hand (see `docs/snapshot.md`) and record them under `coverage.domains`. | Free API calls when added. |
| Account Factory provenance (`vended_by_account_factory`, `provisioned_product`) | Not collected yet; `servicecatalog:SearchProvisionedProducts` is in the catalog as a planned read. Enrolment itself is collected; the provenance is reported as unknown. | Free. |
| Identity Center group memberships and the exact `AWSReservedSSO_*` role names | Not collected. Memberships would need `identitystore:ListGroupMemberships` per group and do not change the verdict; the role suffix is only visible to IAM inside each member account, so roles are reported as `AWSReservedSSO_<permission set>_*`. | Free. |
| Anything from member accounts | Nothing in this build calls into member accounts; the member inspection role is created and its trust verified by the preflight so M4 can read IAM last-accessed data and networking state. | Free. |
| Actions in use | Entered by hand or imported from an IAM last-accessed export with `orgshift simulate --last-accessed export.json`. | Free. |
| Actions in use from CloudTrail Lake | `--with-cloudtrail-lake` and `billable.cloudtrail_lake` exist but are refused in this version. | Billed per TB of event data scanned per query. Will stay opt-in and off by default. |
| Resource inventories from Config advanced queries | `--with-config-queries` and `billable.config_queries` exist but are refused in this version. | Billed per advanced query against an aggregator. Will stay opt-in and off by default. |
| Resource tags for tag policy checks | Entered by hand under `usage.tagged_resources`. | Free. |

Nothing in orgshift calls `MoveAccount`, `AttachPolicy`, `DetachPolicy`,
`CreateOrganizationalUnit`, `InviteAccountToOrganization`,
`LeaveOrganization`, `EnableControl`, `DisableControl`, `EnableBaseline`,
`UpdateLandingZone`, `CreateAccountAssignment`, `DeleteAccountAssignment`,
`ProvisionPermissionSet`, `PutResourcePolicy`, `CreateResourceShare` or any
other write operation, and the tests keep it that way.
