# Snapshot schema (version 3)

A snapshot is a JSON file that describes one AWS organization well enough for
orgshift to simulate moves offline. It is produced by `orgshift collect`
(read-only API calls), by `orgshift fixtures` (fictional organizations) or by
hand. Snapshots are plain data and contain no credentials. A snapshot is
never modified by `simulate` or `serve`; usage inputs passed at simulation
time are merged in memory only.

The loader rejects files with a `schema_version` newer than the build supports
and files with unknown fields, so typos are caught early. Older files are
accepted and upgraded in memory. Version 1 files have no `coverage` block, so
every domain reads as unknown and simulations against them report that.
Version 2 files have no `workloads` block and no records for the three
`workloads.*` coverage domains, so those read as unknown, also under an
`asserted_complete` assertion, which was made before they existed. Referential
integrity is validated on load: every parent, policy target and usage key
must exist, and every policy document must parse for its type.

Go types live in `internal/snapshot/snapshot.go`; this document is the
human-readable contract.

## Top level

| Field | Type | Notes |
| --- | --- | --- |
| `schema_version` | int | `3` for this version; `1` and `2` are accepted and upgraded. Required. |
| `generated_at` | string | RFC 3339 timestamp. Informational, and the reference time for the four-day rule on created accounts. |
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
| `coverage` | object | See [Coverage](#coverage). Optional, but without it every domain is of unknown completeness. |
| `control_tower` | object | See [Control Tower](#control-tower). Optional; absent when there is no landing zone (the coverage block says whether that was checked). |
| `identity_center` | object | See [Identity Center](#identity-center). Optional; absent when there is no instance. |
| `workloads` | object | Map of account ID to [Account workloads](#account-workloads): what was read inside the member accounts that were inspected. Optional. |
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
| `joined_at` | RFC 3339. When `joined_method` is `CREATED`, Organizations refuses to remove the account until four days after this time; a missing value makes that check a REVIEW. |
| `parent_id` | Root or OU the account sits in. |
| `tags` | Account tags as a string map. Deleted by AWS when the account leaves the organization. |
| `enabled_regions` | Regions that are enabled or opted in for the account. Used as the default region set when evaluating `aws:RequestedRegion`. |

## Policy

| Field | Notes |
| --- | --- |
| `id`, `arn`, `name`, `description` | As returned by Organizations. |
| `type` | One of the four policy type names. |
| `aws_managed` | `true` for `FullAWSAccess` and `RCPFullAWSAccess`. |
| `document` | The policy document, verbatim. IAM JSON for SCP and RCP; the tag or backup policy syntax otherwise. Validation parses it: an SCP or RCP must be a valid policy document (an RCP statement carries `Principal: "*"`, an SCP statement no Principal), a tag policy an object with a `tags` map, a backup policy an object with a `plans` map. The message names the policy and the statement at fault. |
| `targets` | Root, OU and account IDs the policy is attached to. Each must exist. |

Policies are identified inside the evaluator by organization, ID and a
fingerprint of the document, so two organizations that use the same policy
ID (the AWS managed defaults always do) never get mixed up.

## Resource share

AWS RAM shares as seen from the owning organization.

| Field | Notes |
| --- | --- |
| `arn`, `name`, `owner_account_id`, `status` | As returned by RAM. |
| `allow_external_principals` | Whether the share can reach accounts outside the organization. |
| `retain_sharing_on_account_leave_organization` | RAM's `RetainSharingOnAccountLeaveOrganization`: a share addressed to an account ID keeps reaching it after it leaves the organization (as an invitation). Read by the collector from the share's configuration; false when RAM reports none, the safe reading (see docs/aws-behaviour.md). |
| `principals` | Account IDs, organization ARNs (`arn:aws:organizations::123456789012:organization/o-…`), OU ARNs (`arn:aws:organizations::123456789012:ou/o-…/ou-…`), IAM ARNs or service principals. The scope (organization, OU, account) is derived from the shape of each value. |
| `resources` | Array of `{arn, type}` where `type` uses RAM notation: `ec2:TransitGateway`, `ec2:Subnet`, `route53resolver:ResolverRule`, `ec2:IpamPool`, `ec2:PrefixList`, and others. What losing a share of each type means is modelled per type in docs/aws-behaviour.md. |

## StackSet

| Field | Notes |
| --- | --- |
| `name`, `administration_account_id`, `description` | As returned by CloudFormation. |
| `permission_model` | `SERVICE_MANAGED` or `SELF_MANAGED`. Only service-managed StackSets follow OU membership. |
| `auto_deployment`, `retain_stacks_on_account_removal` | Auto-deployment settings. |
| `target_ous`, `target_accounts`, `regions` | Deployment targets. |
| `id` | The StackSet ID. Optional. |
| `instances` | The StackSet's deployments (version 3): `{account_id, region, stack_id, status, organizational_unit_id}`. `stack_id` is the ID of the stack in the target account and joins the instance to that account's `workloads.stacks`, which is how a stack is known to be a StackSet instance rather than guessed from its name. |

## Coverage

What the collector inspected to produce the snapshot. Without it, an empty
list cannot be told from a list that was never read, so the evaluator treats
every domain as unknown and the required ones become REVIEW findings.

| Field | Notes |
| --- | --- |
| `collector_version` | The orgshift build that wrote the records, or `fixture` or `manual`. |
| `asserted_complete` | For hand-written snapshots: the author confirms every list is complete and every empty list confirmed empty. Stands in for records on every domain that has none; an explicit record still wins. |
| `asserted_by` | Who or what asserted completeness. |
| `domains` | Array of records, see below. Several records per domain are normal (one per account that owns shares, one per account whose regions failed); the worst status wins. |

Each record:

| Field | Notes |
| --- | --- |
| `domain` | One of `organization`, `tree`, `account_tags`, `enabled_regions`, `policies.scp`, `policies.rcp`, `policies.tag`, `policies.backup`, `delegated_administrators`, `trusted_access`, `resource_shares`, `organization_trails`, `config_aggregators`, `stack_sets`, `control_tower`, `control_tower.enrolled_accounts`, `identity_center`, and the per-account workload domains `workloads.stacks`, `workloads.resources`, `workloads.policies`. |
| `status` | `observed` (calls succeeded, items found), `empty` (calls succeeded, nothing there), `skipped` (a `--skip` flag), `unsupported` (this collector does not read the domain, or the API does not exist here), `partial` (some pages read, then a failure), `access_denied`, `error` (anything else, including a lookup in a region where the service does not answer). Only `observed` and `empty` mean the lists can be trusted. |
| `account_id` | The account the calls were made from (shares) or about (regions, tags); empty for organization-wide calls. |
| `region` | The endpoint region for regional domains. |
| `collected_at` | RFC 3339. |
| `operations` | The API operations called. |
| `items`, `pages` | Observations recorded and pages read. |
| `retries` | Throttling retries the collector performed for the domain beyond the SDK's own. |
| `error` | The API error (with its code) for `partial`, `access_denied` and `error`. Required for those statuses. |
| `reason` | Why a domain is `skipped`, `unsupported` or `empty` (for example "policy type not enabled at the root", or the wrong-region hint). A record restored from a checkpoint by a resumed collection says so here. |

Which domains a simulation requires depends on the move: a same-organization
move needs the tree, the enabled policy types, the moving account's regions,
shares, StackSets and Control Tower; a cross-organization move also needs
delegated administrators, trusted access, trails, Config aggregators and
Identity Center on both sides. The result's `coverage` matrix lists every
domain with its status on each side and whether it was required.

## Account workloads

`workloads.<account-id>` is what was read inside one member account through
the member inspection role. It holds configuration facts only: no template
bodies, no parameter or output values, no resource contents. Each inspected
account has one coverage record per workload domain; an account without
records was not inspected, whatever other accounts' records say.

| Field | Notes |
| --- | --- |
| `regions` | The Regions that were inspected. |
| `stacks` | CloudFormation stacks, see below. |
| `resources` | A sample of the account's resources: `{arn, type, region, tags, stack}`. `type` uses the `service:type` notation of tag policies (`ec2:instance`, `s3:bucket`). `stack` is the stack the resource belongs to: the collector takes it from the `aws:cloudformation:stack-name` tag CloudFormation puts on the resources it creates (for resource types that propagate stack tags), and the tag stays in `tags`. A sample by design: `resources_truncated` says the cap was reached. |
| `resource_source` | `tagging-api` (the Resource Groups Tagging API returns resources that are tagged or were tagged once, never untagged ones), `resource-explorer` (returns untagged resources too and stops at the first 1,000 results of a query) or `manual`. |
| `resource_policies` | The resource-based policies that reference organization identity, see below. Policies that do not are counted in `policies_inspected` and not kept. |
| `collected_at` | RFC 3339. |

Each stack:

| Field | Notes |
| --- | --- |
| `name`, `id`, `region`, `status`, `description`, `tags`, `created_at`, `updated_at` | As returned by `DescribeStacks`. |
| `termination_protection` | `EnableTerminationProtection`. |
| `parent_id` | Set on nested stacks. |
| `resource_types` | Count of the stack's resources per CloudFormation type (`{"AWS::IAM::Role": 3}`). |
| `outputs` | `{key, export_name}`: output keys and export names. Output values are not stored. |
| `imports` | `{export_name, exporting_stack}`: `Fn::ImportValue` dependencies, which CloudFormation limits to the same account and Region. |
| `external_outputs` | `{stack_name, output_name, region, role_arn, account_id}`: `Fn::GetStackOutput` references, which can cross accounts and Regions through the role and are resolved at deploy time only. |
| `references` | `{kind, id, account_id, via}`: identifiers of resources outside the stack that its parameters or template name (`subnet`, `transit-gateway`, `vpc`, `resolver-rule`, `prefix-list`, `arn`), with where each was found. Only identifiers are kept, never other parameter values. |
| `stack_set` | `{name, id, evidence}` when the stack is linked to a StackSet: `evidence` is `stack-instance` (its ID is in the StackSet's instance list) or `stack-name` (its name starts with `StackSet-`, the form AWS's examples show, which is not a documented rule). |

Each resource policy:

| Field | Notes |
| --- | --- |
| `kind` | `s3-bucket-policy`, `iam-role-trust-policy` or `template-policy` (found in a stack's template). |
| `resource_arn`, `resource`, `stack` | What the policy protects: an ARN, or for a template policy the logical ID and the stack. |
| `source` | The operation it was read with. |
| `document` | The policy as IAM JSON, for policies read from the service. Template policies can contain intrinsic functions and carry `conditions` only. |
| `conditions` | The conditions on organization keys found in it: `{sid, effect, operator, key, values, dynamic}`. The keys are `aws:PrincipalOrgID`, `aws:PrincipalOrgPaths`, `aws:ResourceOrgID`, `aws:ResourceOrgPaths`, `aws:SourceOrgID` and `aws:SourceOrgPaths`; `dynamic` marks a value computed in a template. |

Deployment provenance (Control Tower, a StackSet, a plain stack, a
Terraform-style tag convention, unknown) is not stored: `orgshift workloads`
and the evaluator compute it from this block every time and name the
evidence for each classification.

## Control Tower

Present when AWS Control Tower governs the organization. The collector fills
it from the Control Tower and Control Catalog APIs in the landing zone's home
region; it can also be written by hand.

| Field | Notes |
| --- | --- |
| `landing_zone_arn`, `version`, `latest_available_version`, `status`, `drift_status` | As returned by `GetLandingZone`. |
| `home_region`, `governed_regions` | Where the landing zone lives and which regions its controls are deployed to. |
| `auto_enrollment` | `enabled` when the landing zone's remediation types include `INHERITANCE_DRIFT` (accounts moved into a registered OU are enrolled and accounts moved out are unenrolled by Control Tower itself), `disabled` when the landing zone was read and the setting is off, empty when unknown. The Control Tower findings branch on it. |
| `audit_account_id`, `log_archive_account_id` | The shared accounts the landing zone created. Moving either is a NO-GO. |
| `registered_ous` | Array of `{ou_id, baseline_version, status, drift_status}`: the OUs with the Control Tower baseline enabled. |
| `enrolled_accounts` | Array of `{account_id, source, status, drift_status, parent_ou_id, vended_by_account_factory, provisioned_product}`. The collector fills it from `ListEnabledBaselines` (child enabled baselines whose target is an account; `source` is `baseline`) and records the `control_tower.enrolled_accounts` coverage domain. When that domain is `observed` or `empty`, an account that is not listed is not enrolled, whatever its OU. Only when the domain was never collected and the list is empty does the evaluator assume that accounts in registered OUs are enrolled, and it says so. `vended_by_account_factory` and `provisioned_product` are not visible through the API; set them by hand (`source: manual`) where they matter. |
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

A cross-organization move removes every assignment on the account and the
provisioned roles go with the instance's control over the account; the
evaluator reports both and matches permission sets in the two instances by
name. Inside one organization the block is informational only.

## Account usage

Per-account data about how the account is used. Only needed for the accounts
you plan to move. Keyed by account ID under `usage`.

### `actions`

One entry per IAM action that principals in the account perform.

| Field | Notes |
| --- | --- |
| `action` | `service:Action`. Wildcards are accepted, for example `dynamodb:*` for an import that only knows the service was used. |
| `resource` | Optional ARN or ARN pattern. When empty the resource is unknown and statements that are scoped to specific resources produce a REVIEW instead of a verdict. For RCPs, a resource whose ARN names another account routes the evaluation to that account's RCPs (the resource owner's policies apply). |
| `regions` | Optional. Defaults to the account's `enabled_regions`. Services with a single global endpoint (IAM, Organizations, Route 53, CloudFront, Support, and similar) are evaluated in `us-east-1`. For `sts` actions name the Region of the endpoint in use, or `"global"` for `sts.amazonaws.com` (evaluated as `us-east-1`); an `sts` entry without regions leaves the Region unknown, and a policy that looks at `aws:RequestedRegion` then gives a REVIEW rather than a guess. |
| `principal_arn`, `principal_tags` | Optional caller description. Needed for `aws:PrincipalArn` and `aws:PrincipalTag/*` conditions; without them those conditions produce a REVIEW. A `principal_arn` under `role/aws-service-role/` is a service-linked role, which SCPs and RCPs do not restrict: the entry is listed as exempt and not evaluated. |
| `source` | `manual` or `iam-last-accessed`. |
| `last_used`, `note` | Free text. |

Entries can be typed by hand or imported from an IAM last-accessed export
(`aws iam get-service-last-accessed-details … > export.json`, then
`orgshift simulate --last-accessed export.json`). Services with tracked
actions become one entry per action; services without tracked actions become
`service:*`. Actions in use that create transit gateway attachments or
resources in shared subnets also decide how severe the loss of a share is.

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
tags, join date and enabled regions), policies with targets, resource shares
(with the retain-on-leave flag), delegated administrators, trusted-access
services, the Control Tower block (landing zone with auto-enrollment,
registered OUs, enrolled accounts and enabled controls; not Account Factory
provenance), the Identity Center block (instance, permission sets with their
policies and provisioned accounts, account assignments with principal names)
and the coverage block for every domain. Organization trails, Config
aggregators, StackSets and the workload inventory are recorded as
`unsupported` by this collector version and can be added by hand; usage is
left empty. Every failure is a coverage record, not an empty list.

## Example

Three complete, fictional examples are produced by
`orgshift fixtures --out ./fixtures`: two organizations collected
completely, and the first one as a collector with narrower permissions and
the wrong region would have recorded it.
