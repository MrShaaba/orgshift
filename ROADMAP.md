# Roadmap

## Milestone plan (PoC brief, November 2026)

The brief for the AWS proof of concept is worked in milestones. After each
one vet, staticcheck and the tests run, the work is committed and pushed, and
the summary says what to try.

- **M1 (done, 2026-11-01):** Section 2, the audit findings with regression
  tests and fuzzing, plus Section 4, the collection completeness model.
- **M2 (done, 2026-11-02):** Section 3, onboarding configuration, IAM
  templates and the permission preflight, plus bounded concurrency,
  retries, resumable collection and the move to Go 1.24.
- **M3 (done, 2026-11-02):** Sections 6 and 7 for the same-organization and
  cross-organization paths: the scenario overlay and staged evaluation, the
  five layers, the transfer-procedure model, the impact categories and
  declared critical operations, end-to-end fixtures, CLI and UI.
- **M4 (done, 2026-11-05):** the workload layer. A read-only workload
  inventory of member accounts, deployment provenance with its evidence,
  the Workloads check, the workload layer evaluated at every stage and the
  recreate strategy listing what must be redeployed; fixtures, CLI and UI.
- **M5 (done, 2026-11-05):** correctness before features. Four defects
  found by a review at `9dbfdee`, each reproduced against HEAD with a
  failing test and then fixed: SCP and RCP exemptions per side, regional
  STS, malformed policies and policy variables, and the transfer procedure
  (direct transfer, eligibility). No new features.
- **M6 (planned):** the focused SCP comparison report.
- **M7 (planned):** the remaining collectors.
- **M8 to M10 (planned):** the network workstream: inventory, then
  configuration-derived reachability, then behaviour across the stages of
  a migration.
- **Later:** Section 9, then the rest of Section 5 and the items below.

## Next up: about 114 hours

Remaining work, sized. The milestones come first and in order; the items
after them are independent of each other. Details for each are in the
sections below. Re-sized after M5: the network item, which was a six-hour
note about the validation stages, is now the three milestones M8 to M10;
the organization trail and Config aggregator collection and the KMS and
Secrets Manager policies moved from the smaller items and the workload
follow-ups into M7.

| Item | Hours |
| --- | --- |
| M6: focused SCP comparison report | 14 |
| M7: remaining collectors, with active and planned permissions separated | 16 |
| M8: network inventory (transit gateways, peering, RAM, DXGW, VPN, VPC and subnet routes) | 16 |
| M9: configuration-derived reachability (endpoints, DNS, ingress, egress, inspection, return paths) | 18 |
| M10: network behaviour during transfer, coexistence, cutover and rollback | 14 |
| Workload dependency graph across accounts | 5 |
| Snapshot diff: two snapshots of one organization taken at different times | 4 |
| Actions in use from CloudTrail and CloudTrail Lake | 4 |
| Backup policy and AI opt-out policy comparison | 4 |
| Workload inventory follow-ups (delegated-administrator StackSets, further resource policies, Account Factory provenance) | 3.5 |
| Section 9: stable finding identifiers, severities and redaction | 3 |
| HTML report bundle | 3 |
| Identity Center group-membership import | 3 |
| IAM Access Analyzer policy validation | 3 |
| Smaller items | 3.5 |
| **Total** | **114** |

Hard rule for the development sessions: never run `orgshift collect`, the
AWS CLI or any AWS SDK call against a real account; fixtures and mocks only.
Live collection is run by the owner. The server on 8080 is left alone.

### M5 outcome

A review at `9dbfdee` found four defects. HEAD had moved since (StackSet
and workload collection, the wildcard change in `43d374f`), so each was
first reproduced against HEAD with a failing test. None had been fixed in
the meantime; parts of the fourth were already right and are listed. Every
fix turned its reproduction into a test of the correct behaviour.

1. **SCP exemptions, per side** (`cc3d2a5`). SCPs do not apply to the
   management account or to service-linked roles. Before: a call by
   `AWSServiceRoleForAutoScaling` under a target-root deny was NO-GO, and a
   source management account that becomes a destination member under the
   same deny at both roots was "already denied today". After: calls by
   service-linked roles are not evaluated and are listed in an INFO
   finding; each side is asked separately whether its SCPs apply, so the
   second case is a new destination restriction (NO-GO, "becomes denied
   after the move"). The management-account prerequisite blocker stays a
   separate finding. The same per-side rule holds for RCPs and the
   resources of a management account.
2. **Regional STS** (`36e5848`). Before: `sts` was in the set of services
   always evaluated in `us-east-1`, so a call to a regional endpoint was
   judged in the wrong Region in both directions. After: the Region the
   usage entry names is used, `global` stands for the global endpoint
   (which counts as `us-east-1`), and an entry that names none is REVIEW
   (missing evidence) when a policy looks at the Region, not a guess.
3. **Policy validation and variables** (`cc09c43`). Before: a statement
   with both `Action` and `NotAction` or both `Resource` and `NotResource`
   was accepted, a missing `Resource` was read as `"*"`, a policy variable
   in `Resource` was a definite non-match (and a definite match in
   `NotResource`), and one unparseable policy aborted the collection.
   After: such a policy is recorded as malformed with the reason, the
   collection continues, and every check that depends on it is REVIEW; an
   SCP or RCP statement without a resource element is malformed, per the
   syntax pages, instead of being given a `"*"`; a variable is resolved
   from the request context when it can be and is unknown otherwise, for
   Allow and Deny, `Resource` and `NotResource`.
4. **Transfer procedure** (`d9ba683`). Before: one sequence, leave and
   then join, with its standalone interval presented as part of every move
   between organizations; no evaluator finding for a source deny of
   `organizations:LeaveOrganization`; nothing about the landing at the
   destination root; no eligibility checks beyond the two below. After:
   transfer model `2026-11-05` with three procedures kept apart (direct
   transfer by default, leave-and-rejoin on request, management account),
   the leave permission evaluated against the source chain, the interval at
   the destination root reported with what it exposes, and the eligibility
   requirements of the migration page, each confirmed, failed or reported
   as not confirmed. Runbooks, scenarios (`membership.method`), stage
   findings, OU moves, reports, UI, docs and goldens follow.
   Already right at HEAD and kept: the four-day rule for created accounts
   and the delegated-administrator blocker (both NO-GO), the
   management-account sequence (remove every member, delete the
   organization, then accept), the note that `OrganizationAccountAccessRole`
   is kept (now a REVIEW with a step to delete it), and a runbook step for
   the `LeaveOrganization` deny (it was derived in the runbook only, as a
   REVIEW, and offered removal by the management account as a way round).

Snapshot schema stays at 3 and the result schema at 4: the new fields
(`policies[].malformed`, `organization.created_at`,
`organization.seller_of_record`, `accounts[].root_mfa_enabled`,
`subject.transfer_method`) are optional additions. The organization's
creation date and the Seller of Record are returned by no Organizations
API and are entered by hand; root MFA is not collected yet (see the smaller
items).

### M4 outcome

Workload inventory (read-only collection):

- Snapshot schema 3 adds `workloads`, a per-account block, and three
  coverage domains recorded per inspected account: `workloads.stacks`,
  `workloads.resources` and `workloads.policies`. Version 2 files load
  without it, and a completeness assertion made at version 2 does not
  cover the new domains. `stack_sets` gains each StackSet's stack
  instances.
- For every account under `member_inspection.accounts` the collector
  assumes the member inspection role and reads, per workload Region: the
  CloudFormation stacks (status, tags, resource types and counts, output
  keys and export names, imports, termination protection), a resource
  sample with tags, and the role trust policies. From the management
  account it reads the StackSets administered there with their permission
  model, target OUs, automatic deployment and
  `RetainStacksOnAccountRemoval` settings and their stack instances.
- The resource sample comes from Resource Explorer when the account has an
  aggregator index and its default view can be searched, otherwise from the
  Resource Groups Tagging API; `resource_source` records which, and a
  fallback says why.
- Templates are parsed in memory (JSON or YAML with the short forms of the
  intrinsic functions) for `Fn::GetStackOutput` references, identifiers of
  infrastructure taken from outside the stack and policy conditions on
  organization identity. Template bodies, output values and parameter
  values are never stored; a test looks for them in the snapshot.
- Every new operation is in the catalog, the IAM templates and
  docs/permissions.md, and the catalog tests still refuse any write. All
  calls are free except two: S3 bills every request, so `s3:ListBuckets`
  and `s3:GetBucketPolicy` are billable reads behind
  `billable.bucket_policies` / `--with-bucket-policies`, off by default.
  Off, no S3 client is built and no S3 call is made (tested), the policies
  domain carries a `skipped` record and the layer reads partially
  evaluated. The member role's default policy does not grant the S3
  actions; they are a separate opt-in policy.
- The preflight probes one page of each read inside the named accounts and
  the StackSet reads in the management account; the billed reads only with
  the opt-in.

Deployment provenance (`internal/workload`):

- Every stack and sampled resource is classified as Control Tower or
  Account Factory, a service-managed StackSet, a self-managed StackSet, a
  StackSet whose permission model is unknown, a plain stack, a
  Terraform-style tag convention, or unknown. Each classification names its
  evidence and a confidence: an instance record is a fact (high), a stack
  name or a tag is a convention (medium), and unknown is a valid answer
  that the reports keep visible (low). Provenance is computed from the
  snapshot each time, never stored.

Evaluation of the workload layer:

- A `workloads` check on the verdict board (`result_schema_version` 4, the
  `workload-behaviour` model dated 2026-11-05) reports: service-managed
  StackSet instances that are deleted, retained or left in an undocumented
  state when the account leaves the organization or the StackSet's target
  OUs; self-managed and unidentified StackSets; imports between stacks;
  `Fn::GetStackOutput` references to other accounts, with the
  `sts:AssumeRole` call they imply evaluated against the SCP and RCP chains
  as a derived operation; stacks on subnets or transit gateways of RAM
  shares the account loses (a blocker when the stack keeps creating
  resources there, such as an Auto Scaling group); bucket and trust
  policies evaluated with the policy engine before and after the move (a
  Deny that starts applying to the account's own principals is NO-GO), and
  conditions found in templates. The tag check uses the collected sample.
- The three workload domains are in the coverage matrix and required on the
  source side of a cross-organization move, so the layer reads evaluated,
  partially evaluated or not evaluated and a GO is not issued without the
  inventory. Inside one organization a missing inventory is said, not
  required.
- Stage reports (`stages_schema_version` 2) carry the layer's level and
  what the Workloads check found at every stage. The inventory travels with
  the account into the destination state without the stacks a StackSet
  deletes on leaving, so later stages check each new position against what
  is left. A relocation stage lists what has to be brought into the other
  account.
- Strategy comparison: the recreate strategy carries a redeployment plan
  from the inventory, grouped by provenance (redeployable from a template
  or pipeline, recreated by Control Tower or a StackSet, manual or unknown)
  with counts, the dependencies that constrain a redeployment (import
  order, cross-account outputs, networking from outside the template,
  stateful resources, policies tied to the organization) and the unknowns.
  It is an inventory with counts, not an estimate of effort.
- The runbook has steps for each workload finding: keep or replace an
  instance before its StackSet deletes it, move a stack off shared
  networking, change a bucket or trust policy and close the transition
  afterwards, decide where a cross-account output comes from.

Fixtures, CLI and UI:

- Larkspur and Fernhill carry planted workload problems: a service-managed
  StackSet instance that is deleted on leaving, a cross-stack export, a
  cross-account stack output, a bucket policy on `aws:PrincipalOrgID` that
  locks the account out, an app with an Auto Scaling group on shared
  subnets, resources without the cost-center tag, Terraform-tagged
  resources, Control Tower baseline stacks and a StackSet instance nobody
  in the organization administers. Golden tests and one assertion per
  problem cover them; a third scenario fixture exercises the recreate
  strategy.
- `orgshift workloads --snapshot FILE [--account ID]` prints the inventory
  and the provenance (text, JSON, Markdown).
- The result page has a Workloads panel and the stage page one per stage,
  with the redeployment table on the recreate strategy.

Checked against the documentation and recorded in docs/aws-behaviour.md.
Three things could not be confirmed there and are reported as such rather
than assumed: what a StackSet does with an instance when automatic
deployment is off, the answer of `ListImports` for an export nobody
imports, and the S3 error code for a bucket without a policy.

Found on the way, outside the workload layer: the fuzz smoke test in CI
produced an ARN-shaped pattern on which the policy engine's matching
algorithms disagreed. IAM matches wildcards per component for the ARN
operators, anywhere in the string for the string operators, and lets a `*`
that ends a component cross the colon in the `Resource` element; the engine
matched per component everywhere, so a Deny whose `Resource` pattern left a
component out was read as not matching. The engine now follows the three
rules, answers unknown where the documentation is silent, and the fuzz
property checks the modes against each other. No fixture verdict changed.

Not done, and where it is listed:

- The collection code has only run against mocks, as the hard rule
  requires. The first run against a real account is the owner's; the
  preflight shows what is denied before anything is collected.
- StackSets administered by a CloudFormation delegated administrator, KMS,
  SQS, SNS and other resource policies, and Account Factory provenance:
  "Workload inventory follow-ups" below.
- Dependencies between accounts (which accounts have to move together):
  "Workload dependency graph" below.
- Network paths behind the shared subnets and transit gateways: Section 8
  of the brief, now the network milestones M8 to M10.

### M1 outcome

Audit findings (Section 2), each reproduced with a failing test first:

- Policy caches keyed by policy ID alone: the source organization's document
  stood in for a target policy with the same ID (`TestPolicyCacheIsNamespacedPerSnapshot`
  showed a silent GO). The cache key is now organization, policy ID and a
  content fingerprint.
- Malformed policy documents: a document that is valid JSON but not a valid
  policy made the evaluator dereference a missing statement. Validation now
  parses every SCP and RCP (and checks tag and backup policy shape) with
  the statement at fault in the message; the evaluator treats an
  unparseable policy as unknown in both directions (REVIEW, never an
  implicit allow or deny); the glob matcher is non-recursive and polynomial;
  fuzz targets cover the parser, the matcher, the snapshot loader and the
  evaluator (`go test -fuzz`).
- RCP applicability: the hardcoded five services became a versioned model of
  the 62 services on the AWS page (`rcp-applicability` 2026-11-01), with
  the exemptions (management account, service-linked roles, AWS managed
  keys, `kms:RetireGrant`), resource-owner routing (the owner's RCPs apply,
  the caller's organization changes), and an INFO finding naming every
  action that was not evaluated because its service is outside the model.
- Collection failures read as absence: see Section 4 below.
- Assumptions reviewed with the documentation (docs/aws-behaviour.md):
  enrolment is read from `ListEnabledBaselines` instead of inferred from the
  OU; auto-enrollment is read from the landing zone and the findings branch
  on it; Identity Center wording follows the Organizations page; RAM losses
  use a per-resource-type behaviour model (`ram-behaviour` 2026-11-01)
  instead of "networking share lost = outage"; delegated administration and
  the four-day rule are blockers; account tags deleted and the retained
  management role are reported.

Completeness (Section 4):

- Snapshot schema 2 adds a `coverage` block: per domain, account, region,
  timestamp, operations, items, pages and a status (observed, empty,
  skipped, unsupported, partial, access_denied, error). Version 1 files
  load with unknown coverage.
- The collector records every domain, isolates failures per domain, drops a
  half-read policy type instead of keeping it, classifies access denied,
  and treats an empty Control Tower or Identity Center answer as an error
  when trusted access shows the service is in use (wrong region).
- The evaluator defines the required domains per scenario, adds a REVIEW
  finding to the check that depends on each incomplete one, marks the check
  with `coverage_gaps`, leads the board with a coverage check and exports
  the matrix (`coverage` in the JSON, a table in Markdown and the UI). A GO
  is only issued when every required domain is complete, and the GO text
  says what was and was not assessed.
- The runbook starts with "collect the missing evidence" steps for every
  gap.
- A third fixture, Larkspur Holdings (partial collection), shows all of it.

### M3 outcome

Staged simulation (Section 6):

- A scenario overlay (`internal/scenario`, YAML or JSON, `orgshift scenario
  example` and `scenario check`) describes a migration as stages across
  five layers kept separate: organization membership, OU placement, Control
  Tower governance, network connectivity (RAM shares) and workload
  relocation. Proposed OUs, policies and shares live only in the overlay;
  the snapshots are never modified and every report lists proposed objects
  apart from collected ones.
- `orgshift stages` derives the state after every stage (a validated copy of
  the organization's snapshot with the proposed objects and the account
  placed), evaluates the transition into each stage with the full verdict
  board, adds the stage's own findings (the standalone window and the
  invitation, what a proposed OU inherits and that an inherited explicit
  deny cannot be overridden, enrollment prerequisites and declarations,
  shares created or withdrawn, validation points, workload relocation), and
  compares the transfer strategy with creating destination accounts and
  migrating the workloads (prerequisites, risks, unknowns, reversal limits).
- Management-account constraints and the transfer procedure come from the
  official pages, versioned as the `transfer-procedure` model (2026-11-02):
  standalone-account information, the four-day rule, delegated
  administration, invitations (one organization at a time, 15 days,
  policies apply at once), deleting the organization to free a management
  account, decommissioning a landing zone first, and the Control Tower
  enrollment prerequisites.
- Two scenario fixtures ship with `orgshift fixtures` and the UI: Payments
  production into Fernhill through a transitional Legacy OU and enrollment
  (cross-organization), and the Fernhill sandbox account into a proposed
  Transitional OU under Business Units, registration, enrollment and
  tightening (same organization). Golden tests cover both.
- The UI's "Stage a migration" panel takes a scenario file or a fixture
  scenario, shows the timeline, the current versus proposed hierarchy with
  proposed nodes marked, each stage's layers, state, findings and transition
  board, and the strategy comparison; JSON and Markdown exports.

Policy and impact evaluation (Section 7):

- Every finding carries an impact category (known restriction, declared
  impact, potential impact, unsupported evaluation, missing evidence,
  informational), a confidence and, for findings about an operation, its
  source (observed or declared); the result counts the categories
  (`result_schema_version` 3).
- User-declared critical operations (`critical_operations` in the scenario,
  `simulate --critical-operations`) are evaluated next to the observed usage.
- `aws:PrincipalOrgPaths` and `aws:ResourceOrgPaths` are evaluated with the
  organization paths before and after the move; the result records both.
- Standing limitations are repeated on every result: an SCP or RCP allow is
  not an IAM grant, which policy elements are not evaluated, what tag
  policies do and do not do, what the RAM model covers.

Left for later milestones at the time: workload inventory and deployment
provenance behind the recreate strategy and the workload layer (done in
M4); network-path reasoning behind the validation stage (Section 8, now
M8 to M10); stable finding identifiers and redaction (Section 9).

### M2 outcome

Onboarding (Section 3):

- One configuration file (`internal/config`, YAML or JSON, `orgshift config
  example` and `config check`) describes the source and destination
  management access, the member inspection role, the network and security
  accounts, the Control Tower home region, the Identity Center region (and
  optionally its delegated administrator) and the workload regions.
  Credentials come from profiles, Identity Center sessions (`sso_session`,
  cached token) or the management credentials, with optional assume-role
  chains (`internal/awsaccess`). Unknown fields are errors.
- Every credential is verified with `sts:GetCallerIdentity` against the
  account the configuration names; `collect` refuses to run on a mismatch
  and the preflight reports it without probing further.
- The operation allowlist became a catalog (`internal/collector/operations.go`)
  that classifies every operation orgshift calls or plans to call by
  semantics (read, read-billable, session) and responsibility; tests refuse
  any write or write verb, any billable read without an opt-in, any call not
  in the catalog and any catalog entry nothing calls.
- IAM templates (`internal/iamtemplates`, `orgshift iam-templates`,
  docs/iam) generate one role per responsibility from the catalog: trust
  policy, permissions policy with a justification for every `Resource: "*"`,
  the account it goes in, the delegated-administrator alternative (an
  Organizations delegation policy example; none for Control Tower; the
  Identity Center delegated administrator) and the planned operations of
  later milestones, listed but not granted.
- The preflight (`internal/preflight`, `orgshift preflight`) tries the
  cheapest read of every collection domain plus `sts:AssumeRole` into the
  member role, classifies each call as available, denied, error or unknown,
  and renders the result in the coverage matrix layout (text, Markdown and
  JSON, `schema_version` 1) with the action and identity to grant for every
  denial. Exit code 2 when not ready.
- The collector runs per-item calls with bounded concurrency in a stable
  order, retries throttling with full-jitter backoff on top of the SDK's
  adaptive mode and records the retries per domain, and writes a checkpoint
  after every completed step so a rerun restores the completed domains and
  reads only the failed ones.
- Go 1.24 and the current AWS SDK modules; the collector now reads
  `RetainSharingOnAccountLeaveOrganization` from each share's configuration
  and the RAM behaviour model uses it.

## Items the first pass deliberately left out

None of them changes the ground rules: read-only, offline simulation, no
real organization data in the repo.

Done since the first pass:

- Moving a whole OU at once (`simulate --ou`, the UI picker, per-account
  rollups, attachments carried or flagged for recreation, golden scenarios
  for Workloads into Fernhill Business Units and Production to the root).
- Control Tower awareness (`control_tower` snapshot block collected
  read-only, guardrail SCPs labelled, the Control Tower check for
  unenrolment, enrolment, registered-to-registered moves, shared accounts
  and Account Factory provenance, controls that start or stop applying,
  golden scenario for fernhill-retail-prod leaving its registered OU).
  Enrolled accounts are now read from the child enabled baselines (M1);
  Account Factory provenance still is not.
- Identity Center impact for cross-organization moves (`identity_center`
  snapshot block collected read-only with permission sets, provisioned
  accounts and assignments with principal names; the IAM Identity Center
  check listing every assignment on the account, matching permission sets
  by name and reporting the `AWSReservedSSO_*` roles that go with the
  instance, stale ones included; golden scenario for larkspur-data-prod into
  Fernhill Retail). Left open: group memberships are not collected and the
  role suffix is only known inside the member account.
- The migration runbook (`internal/runbook`, `simulate --format runbook`,
  the checklist panel and the "Export runbook" button in the UI): blockers
  grouped by the policy statement to review, shares and delegations to
  re-create, the `LeaveOrganization` deny found in the source chain, the
  move in order, the checks afterwards and a rollback from the source
  chain; OU runbooks recreate the tree and embed one checklist per account.
  Golden tests on every fixture scenario. Left open: the runbook knows
  Organizations, RAM, Control Tower and Identity Center; CloudTrail Lake
  import and Access Analyzer validation would add steps of their own.

## M6: focused SCP comparison report (14 h)

A report about one thing: what the SCPs of the two positions restrict, and
how that differs. It is built for a reviewer who has to sign off the
guardrail change, and it says at the top and in every export what it is
not: not IAM authorization (an SCP allow grants nothing) and not a
statement that the migration as a whole is safe.

- Ancestry before and after: every level from the root to the account on
  both sides, with what is attached at each level and what reaches the
  account by inheritance, told apart. (2 h)
- Added and removed restrictions at statement level, not only for the
  actions in the usage list: denies that start, denies that stop, and
  denies that change scope, each with its conditional exceptions
  (`ArnNotLike` on a break-glass role, Region lists, tag conditions) spelt
  out as who or what is excepted. (3.5 h)
- Allow-list intersections: where a level replaces `FullAWSAccess`, the
  set of actions that survives every level, before and after, and what
  falls out of it. (2.5 h)
- Declared critical operations and declared recovery operations (the
  calls needed to undo the move or to break glass), each evaluated at both
  positions and at the destination root. (1.5 h)
- Provenance for every line (policy, statement, level, snapshot,
  collection time, Control Tower guardrail or customer policy) and the
  unknowns kept as unknowns: malformed policies, unresolved variables,
  conditions that depend on context, coverage gaps. (1.5 h)
- `orgshift scp-report` with text, Markdown and JSON, and a panel in the
  UI. (2 h)
- Fixtures, goldens and documentation. (1 h)

## M7: remaining collectors (16 h)

Read-only collection that the checks already ask for. Every operation is
classified in the catalog first; anything a service bills per request goes
behind an opt-in that is off by default, with a test that the call is not
made without it. Exercised with mocks only.

- StackSet operation status: the latest operations and their results per
  StackSet, so a StackSet that is mid-operation or failed in the account
  is seen before the move. (2 h)
- Scoped resource-policy discovery, for conditions on organization
  identity and for principals outside the account, limited to the accounts
  and Regions already configured and to a stated maximum per service:
  - KMS key policies. (3 h)
  - Secrets Manager resource policies. Metadata and policy only: no call
    that returns a secret value is in the catalog, and a test looks for
    one. (2.5 h)
  - EventBridge event bus policies. (1.5 h)
  - IAM: role trust policies beyond the current sample, with the scope
    and the cut-off recorded in coverage. (2 h)
- Organization trails and Config aggregators, which coverage records as
  unsupported today. (2 h)
- Active and planned permissions separated: the catalog, the IAM
  templates, `docs/permissions.md` and the preflight say for each action
  whether a collector uses it now or a later milestone will, so a role can
  be granted exactly what runs. (2 h)
- Coverage domains, fixtures and documentation. (1 h)

## M8: network inventory (16 h)

The first of three network milestones. It collects and models; it draws no
conclusions about reachability yet.

- A `network` block in the snapshot with its coverage domains and
  validation, per account and Region. (2.5 h)
- Transit gateways: attachments, route table associations, propagations
  and the effective routes of each route table, static and propagated,
  blackholes included. (4 h)
- VPC peering, the RAM shares behind shared transit gateways and subnets
  joined to their owners, Direct Connect gateways and their associations,
  and Site-to-Site VPN connections. (3.5 h)
- VPC and subnet route tables (main and explicit associations) and the
  prefix lists they use. (3 h)
- Catalog entries, IAM templates, preflight probes and mocks for all of
  it. (2 h)
- Fixture topologies for both organizations and an `orgshift network`
  inventory view. (1 h)

## M9: configuration-derived reachability (18 h)

What the collected configuration says can reach what. Everything in this
milestone is derived from configuration and is labelled so; it is never
presented as observed traffic.

- A route evaluation engine: longest prefix match from the subnet route
  table through the transit gateway route table to the next attachment,
  with blackholes, loops and hops that cannot be resolved reported as
  such. (5 h)
- Centralised endpoints and DNS: interface and gateway endpoints with
  their policies (conditions on organization identity included), private
  hosted zone associations, Resolver endpoints and rules. (4 h)
- Ingress, egress and inspection: paths through inspection VPCs and
  firewall endpoints, NAT and internet gateways, and the appliance-mode
  setting of the attachments in between. (3.5 h)
- Return-path symmetry: for each path, whether the way back passes the
  same inspection point, and where it cannot be told. (2.5 h)
- Two evidence classes kept apart in the schema, the findings and the
  reports: configuration-derived reachability, and observed traffic, which
  is only ever imported from a file the operator supplies and is never
  merged into the first. (2 h)
- Fixture topologies and fuzzing of the route matcher. (1 h)

## M10: network behaviour across the migration (14 h)

What happens to the paths of M9 at each stage, replacing the generic
reminder of the validation stages.

- The network state per stage: at the transfer (the account at the
  destination root), during coexistence, at cutover and on rollback: what
  shares, attachments, propagations, endpoint policies and DNS
  associations do at each, verified against the AWS documentation per
  resource type and recorded in `docs/aws-behaviour.md`. (4.5 h)
- Paths before and after each stage, and the ones that break, appear or
  change their inspection point. (3 h)
- The validation stage lists the paths to test, and the runbook gains the
  network steps. (2.5 h)
- A network panel in the UI and sections in the reports. (2.5 h)
- Goldens and documentation. (1.5 h)

## Workload dependency graph across accounts (5 h)

- Build a graph from the inventories of several accounts: imports and
  exports, `Fn::GetStackOutput` roles, resource policies that name another
  account or the organization, shared subnets and transit gateways with
  their owners, and the inbound access of the usage block.
- Answer which accounts have to move together, in what order, and which
  edges break when only one of them moves; mark edges that rest on a
  convention or on missing evidence.
- `orgshift graph --snapshot FILE [--account ID] --format text|json|dot`
  and a view in the UI.

## Snapshot diff: two snapshots taken at different times (4 h)

- `orgshift diff --old A.json --new B.json` for two snapshots of the same
  organization: the tree, policy documents and attachments, shares,
  StackSets and instances, Control Tower and Identity Center, the workload
  inventory (stacks that appeared or went, policy conditions that changed)
  and coverage that got better or worse.
- Say which earlier verdicts the changes invalidate, so a plan that was GO
  last week is re-simulated only where something moved.
- Text, JSON and Markdown, and an exit code for use in a schedule.

## HTML report bundle (3 h)

- `--format html --out DIR` on `simulate` and `stages`: one self-contained
  page (styles embedded, no server, no external requests) with the verdict
  board, coverage, the workload panel, the runbook and the diff, for
  reviewers who do not run the tool.
- Reuse the UI templates so the bundle and the UI cannot drift.
- Goes with the redaction of Section 9: account IDs and names masked on
  request.

## Identity Center group-membership import (3 h)

- Import group memberships (`identitystore:ListGroupMemberships` through
  the identity-center role, or a CSV or SCIM export) so the Identity Center
  check lists the people who lose access, not only the groups.
- Match users between the two identity stores by user name or email where
  the operator asks for it, and report who has no counterpart in the
  destination.
- The identity store calls are free; the catalog entries come first.

## Workload inventory follow-ups (3.5 h)

- StackSets administered by a CloudFormation delegated administrator:
  `CallAs` DELEGATED_ADMIN through an access block of their own. (1 h)
- Further resource policies read from the service for conditions on
  organization identity: SQS, SNS, ECR and Lambda (KMS, Secrets Manager
  and EventBridge are in M7). Each call is classified in the catalog
  first, and any the service bills goes behind an opt-in. (1.5 h)
- Account Factory provenance with `servicecatalog:SearchProvisionedProducts`,
  so "Control Tower or Account Factory" is told apart. (1 h)

## Actions in use from CloudTrail and CloudTrail Lake (opt-in, cost warning) (4 h)

- `orgshift collect --with-cloudtrail-lake --event-data-store … --days 90`
  runs one aggregated query (`eventSource`, `eventName`, `awsRegion`,
  `userIdentity.accountId`) and converts it to `usage.actions` with regions
  filled in. The flag already exists and refuses until this lands.
- Print the estimated scanned volume and require confirmation; CloudTrail
  Lake bills per TB scanned.
- Plain CloudTrail (`LookupEvents`) as a free but slow alternative for
  management events in the last 90 days.
- Record `source: cloudtrail-lake` on the entries so the UI can show where
  each action came from.

## IAM Access Analyzer policy validation (3 h)

- Run `access-analyzer:ValidatePolicy` (policy type `SERVICE_CONTROL_POLICY`
  and `RESOURCE_CONTROL_POLICY`) over every policy in the target chain and
  attach findings (errors, security warnings, suggestions) to the diff view.
- Use `CheckNoNewAccess` between the source and target effective policies
  where the API supports it, as a second opinion on the offline evaluator.
- Keep it behind `--with-access-analyzer`; the calls are free but need live
  credentials, which the simulator otherwise never requires.

## Backup policy and AI opt-out policy comparison (4 h)

- Merge backup policies along both chains with the same inheritance
  operators as tag policies and diff plans, rules, vault names, regions and
  selections. Flag selections that point at IAM roles the account does not
  have.
- Add `AISERVICES_OPT_OUT_POLICY` to the schema, the collector and the diff,
  with a per-service opt-out comparison.
- Add `DECLARATIVE_POLICY_EC2`, `CHATBOT_POLICY` and `SECURITYHUB_POLICY` to
  the chain display so nothing attached is invisible, even before they are
  evaluated.

## Section 9: stable finding identifiers, severities and redaction (3 h)

- A stable identifier per finding, derived from the check, the kind of
  finding and its subject, so two runs can be compared and a finding can be
  acknowledged.
- A severity next to the status, and redaction of account IDs, names and
  ARNs in exports on request.

## Smaller items (3.5 h)

- Collect `root_mfa_enabled` from the IAM account summary through the
  member inspection role, so the root MFA requirement of a transfer is
  confirmed without a hand-entered field. The organization's creation date
  and the Seller of Record stay manual: no API returns them. (1 h)
- Evaluate `aws:SourceVpc`, `aws:SourceIp` and `aws:CalledVia` conditions
  when the usage entry supplies them, instead of returning REVIEW. (2 h)
- A `--fail-on review` switch for CI so a REVIEW can be made blocking. (0.5 h)
