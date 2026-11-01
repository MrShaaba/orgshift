# Snapshot schema (version 1)

A snapshot is a JSON file that describes one AWS organization well enough for
orgshift to simulate moves offline. It is produced by `orgshift collect`
(read-only API calls), by `orgshift fixtures` (fictional organizations) or by
hand. Snapshots are plain data and contain no credentials.

The loader rejects files with a `schema_version` newer than the build supports
and files with unknown fields, so typos are caught early. Referential
integrity is validated on load: every parent, policy target and usage key
must exist.

Go types live in `internal/snapshot/snapshot.go`; this document is the
human-readable contract.

## Top level

| Field | Type | Notes |
| --- | --- | --- |
| `schema_version` | int | Always `1` for this version. Required. |
| `generated_at` | string | RFC 3339 timestamp. Informational. |
| `source` | string | `collector`, `fixture` or `manual`. |
| `organization` | object | See [Organization](#organization). |
| `root` | object | See [Root](#root). |
| `organizational_units` | array | See [OU](#ou). |
| `accounts` | array | See [Account](#account). |
| `policies` | array | See [Policy](#policy). |
| `resource_shares` | array | See [Resource share](#resource-share). |
| `delegated_administrators` | array | `{account_id, service_principal, delegation_date}` |
| `trusted_access_services` | array of string | Service principals with trusted access enabled, for example `cloudtrail.amazonaws.com`. |
| `organization_trails` | array | `{name, arn, owner_account_id, home_region, s3_bucket_name}`; only trails with `IsOrganizationTrail=true`. |
| `config_aggregators` | array | `{name, account_id, region, organization_source}` |
| `stack_sets` | array | See [StackSet](#stackset). |
| `control_tower` | object | See [Control Tower](#control-tower). Optional; absent when there is no landing zone. |
| `identity_center` | object | See [Identity Center](#identity-center). Optional; absent when there is no instance. |
| `usage` | object | Map of account ID to [Account usage](#account-usage). Optional. |

## Organization

| Field | Notes |
| --- | --- |
| `id` | `o-…` identifier. Required. Two snapshots with different IDs describe a cross-organization move. |
| `arn` | Organization ARN. |
| `management_account_id` | 12 digit account ID. |
| `feature_set` | `ALL` or `CONSOLIDATED_BILLING`. |
| `name` | Friendly label. AWS has no such attribute; the collector takes it from `--name`. |

## Root

| Field | Notes |
| --- | --- |
| `id` | `r-…` identifier. Required. |
| `name` | Usually `Root`. |
| `enabled_policy_types` | Subset of `SERVICE_CONTROL_POLICY`, `RESOURCE_CONTROL_POLICY`, `TAG_POLICY`, `BACKUP_POLICY`. A type that is not enabled is not evaluated. |

## OU

| Field | Notes |
| --- | --- |
| `id` | `ou-…` identifier. |
| `name` | Display name. |
| `parent_id` | Root or OU ID. Must exist. |

## Account

| Field | Notes |
| --- | --- |
| `id` | 12 digit account ID. Fixtures use `111111111111`-style IDs. |
| `name`, `email`, `status`, `joined_method` | As returned by Organizations. Email is optional and may be redacted. |
| `parent_id` | Root or OU the account sits in. |
| `tags` | Account tags as a string map. |
| `enabled_regions` | Regions that are enabled or opted in for the account. Used as the default region set when evaluating `aws:RequestedRegion`. |

## Policy

| Field | Notes |
| --- | --- |
| `id`, `arn`, `name`, `description` | As returned by Organizations. |
| `type` | One of the four policy type names. |
| `aws_managed` | `true` for `FullAWSAccess` and `RCPFullAWSAccess`. |
| `document` | The policy document, verbatim. IAM JSON for SCP and RCP; the tag or backup policy syntax otherwise. |
| `targets` | Root, OU and account IDs the policy is attached to. Each must exist. |

## Resource share

AWS RAM shares as seen from the owning organization.

| Field | Notes |
| --- | --- |
| `arn`, `name`, `owner_account_id`, `status` | As returned by RAM. |
| `allow_external_principals` | Whether the share can reach accounts outside the organization. |
| `principals` | Account IDs, organization ARNs (`arn:aws:organizations::123456789012:organization/o-…`), OU ARNs (`arn:aws:organizations::123456789012:ou/o-…/ou-…`), IAM ARNs or service principals. The scope (organization, OU, account) is derived from the shape of each value. |
| `resources` | Array of `{arn, type}` where `type` uses RAM notation: `ec2:TransitGateway`, `ec2:Subnet`, `route53resolver:ResolverRule`, `ec2:IpamPool`, `ec2:PrefixList`, and others. The evaluator treats the five listed types, plus a few more networking types, as networking dependencies. |

## StackSet

| Field | Notes |
| --- | --- |
| `name`, `administration_account_id`, `description` | As returned by CloudFormation. |
| `permission_model` | `SERVICE_MANAGED` or `SELF_MANAGED`. Only service-managed StackSets follow OU membership. |
| `auto_deployment`, `retain_stacks_on_account_removal` | Auto-deployment settings. |
| `target_ous`, `target_accounts`, `regions` | Deployment targets. |

## Control Tower

Present when AWS Control Tower governs the organization. The collector fills
it from the Control Tower and Control Catalog APIs in the landing zone's home
region; it can also be written by hand.

| Field | Notes |
| --- | --- |
| `landing_zone_arn`, `version`, `status`, `drift_status` | As returned by `GetLandingZone`. |
| `home_region`, `governed_regions` | Where the landing zone lives and which regions its controls are deployed to. |
| `audit_account_id`, `log_archive_account_id` | The shared accounts the landing zone created. Moving either is a NO-GO. |
| `registered_ous` | Array of `{ou_id, baseline_version, status, drift_status}`: the OUs with the Control Tower baseline enabled. Accounts are governed by living in one of them. |
| `enrolled_accounts` | Optional array of `{account_id, vended_by_account_factory, provisioned_product, status}`. When the array is empty or missing, every account whose parent OU is registered is assumed to be enrolled; list the accounts explicitly to be exact and to record which ones Account Factory created. The collector cannot fill this list with read-only `List`/`Describe`/`Get` calls, so it is left for you. |
| `enabled_controls` | Array of `{control_identifier, name, behavior, target_ou_id, status, drift_status, implementation}`. `behavior` is `PREVENTIVE`, `DETECTIVE` or `PROACTIVE` (or empty when unknown). Controls enabled on an OU also apply to the OUs nested under it. |

Preventive controls are enforced by service control policies that Control
Tower attaches to each registered OU, named `aws-guardrails-<random>`. They
are ordinary entries in `policies` and are evaluated like any other SCP; the
name prefix is what marks them as Control Tower managed in the chain and diff
views.

## Identity Center

Present when IAM Identity Center is attached to the organization. The
collector fills it from the SSO Admin and Identity Store APIs in the
instance's region; it can also be written by hand.

| Field | Notes |
| --- | --- |
| `instance_arn` | `arn:aws:sso:::instance/ssoins-…`. Required. |
| `identity_store_id` | The `d-…` directory the users and groups live in. Two organizations always have different identity stores, so principals are never matched across them. |
| `region` | Where the instance lives. The provisioned roles sit under `/aws-reserved/sso.amazonaws.com/<region>/`. |
| `owner_account_id`, `name` | The management account (or delegated administrator) and the instance name. |
| `permission_sets` | Array of `{arn, name, description, session_duration, managed_policies, customer_managed_policies, inline_policy, permissions_boundary, provisioned_accounts}`. `managed_policies` are AWS managed policy ARNs; `customer_managed_policies` are path plus name of policies that have to exist in each account; `inline_policy` is the IAM JSON document; `provisioned_accounts` lists the accounts where the `AWSReservedSSO_<name>_*` role exists. When `provisioned_accounts` is empty the role is assumed to exist wherever the permission set has an assignment. |
| `account_assignments` | Array of `{account_id, permission_set_arn, principal_type, principal_id, principal_name}`. `principal_type` is `USER` or `GROUP`; `principal_name` is the user name or group display name when known. Each entry must point at an account and a permission set in the snapshot. |

A cross-organization move removes every assignment on the account and
deletes the provisioned roles; the evaluator reports both and matches
permission sets in the two instances by name. Inside one organization the
block is informational only.

## Account usage

Per-account data about how the account is used. Only needed for the accounts
you plan to move. Keyed by account ID under `usage`.

### `actions`

One entry per IAM action that principals in the account perform.

| Field | Notes |
| --- | --- |
| `action` | `service:Action`. Wildcards are accepted, for example `dynamodb:*` for an import that only knows the service was used. |
| `resource` | Optional ARN or ARN pattern. When empty the resource is unknown and statements that are scoped to specific resources produce a REVIEW instead of a verdict. |
| `regions` | Optional. Defaults to the account's `enabled_regions`. Global services (IAM, STS, Organizations, Route 53, CloudFront, Support, and similar) are evaluated in `us-east-1`. |
| `principal_arn`, `principal_tags` | Optional caller description. Needed for `aws:PrincipalArn` and `aws:PrincipalTag/*` conditions; without them those conditions produce a REVIEW. |
| `source` | `manual` or `iam-last-accessed`. |
| `last_used`, `note` | Free text. |

Entries can be typed by hand or imported from an IAM last-accessed export
(`aws iam get-service-last-accessed-details … > export.json`, then
`orgshift simulate --last-accessed export.json`). Services with tracked
actions become one entry per action; services without tracked actions become
`service:*`.

### `inbound_access`

Principals outside the account that call into it. Resource control policies
at the destination apply to these requests, so they are evaluated against
RCPs rather than SCPs.

| Field | Notes |
| --- | --- |
| `principal` | Account ID, IAM ARN or service principal. |
| `principal_org_id` | Optional. When omitted the evaluator looks the account up in both snapshots; a principal in neither snapshot and without this field produces a REVIEW for any `aws:PrincipalOrgID` condition. |
| `actions` | Actions performed. |
| `resource` | Optional ARN or pattern. |
| `regions` | Optional, defaults like `actions.regions`. |

### `tagged_resources`

A sample of the account's resources and their tags, as returned by the
Resource Groups Tagging API. Used to check tag policy compliance.

| Field | Notes |
| --- | --- |
| `arn` | Resource ARN. |
| `type` | Tag policy resource type notation, for example `ec2:instance`, `rds:db`, `s3:bucket`. |
| `region` | Optional. |
| `tags` | String map. |

## Which fields the collector fills

`orgshift collect` fills the organization, root, OUs, accounts (including
tags and enabled regions), policies with targets, resource shares, delegated
administrators, trusted-access services, the Control Tower block (landing
zone, registered OUs and enabled controls; not `enrolled_accounts`) and the
Identity Center block (instance, permission sets with their policies and
provisioned accounts, account assignments with principal names).
Organization trails, Config aggregators, StackSets and usage are left empty
by the current collector and can be added by hand; see `ROADMAP.md`.

## Example

A complete, fictional example is produced by `orgshift fixtures --out ./fixtures`.
