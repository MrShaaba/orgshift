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
- **Later:** Section 8, the network paths behind the validation stages;
  Section 9; then the rest of Section 5 and the items below.

## Next up: about 44 hours

Remaining work, sized. Details for each item are in the sections below.

| Item | Hours |
| --- | --- |
| Section 8: network-path reasoning behind the validation stages | 6 |
| Workload dependency graph across accounts | 5 |
| Snapshot diff: two snapshots of one organization taken at different times | 4 |
| Actions in use from CloudTrail and CloudTrail Lake | 4 |
| Backup policy and AI opt-out policy comparison | 4 |
| Workload inventory follow-ups (delegated-administrator StackSets, more resource policies, Account Factory provenance) | 4 |
| Section 9: stable finding identifiers, severities and redaction | 3 |
| HTML report bundle | 3 |
| Identity Center group-membership import | 3 |
| IAM Access Analyzer policy validation | 3 |
| Smaller items | 4.5 |
| **Total** | **43.5** |

Hard rule for the development sessions: never run `orgshift collect`, the
AWS CLI or any AWS SDK call against a real account; fixtures and mocks only.
Live collection is run by the owner. The server on 8080 is left alone.

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

Not done, and where it is listed:

- The collection code has only run against mocks, as the hard rule
  requires. The first run against a real account is the owner's; the
  preflight shows what is denied before anything is collected.
- StackSets administered by a CloudFormation delegated administrator, KMS,
  SQS, SNS and other resource policies, and Account Factory provenance:
  "Workload inventory follow-ups" below.
- Dependencies between accounts (which accounts have to move together):
  "Workload dependency graph" below.
- Network paths behind the shared subnets and transit gateways: Section 8.

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
M4); network-path reasoning behind the validation stage (Section 8); stable
finding identifiers and redaction (Section 9).

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

## Section 8: network-path reasoning behind the validation stages (6 h)

- Read, through the member and network roles, the transit gateway
  attachments, VPCs and subnets (shared ones included), route tables,
  peerings, prefix lists and Resolver rule associations the catalog already
  lists as planned.
- Join them with the workload inventory: which stack's resources sit in
  which subnet, which routes leave through a shared transit gateway, which
  names resolve through a shared Resolver rule.
- Report per stage which paths exist before and after, so the validation
  stage lists paths to test instead of a generic reminder.

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

## Workload inventory follow-ups (4 h)

- StackSets administered by a CloudFormation delegated administrator:
  `CallAs` DELEGATED_ADMIN through an access block of their own. (1 h)
- More resource policies read from the service for conditions on
  organization identity: KMS key policies, SQS, SNS, Secrets Manager, ECR
  and Lambda. Each call is classified in the catalog first, and any the
  service bills goes behind an opt-in. (2 h)
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

## Smaller items (4.5 h)

- Collect organization trails and Config aggregators in `orgshift collect`
  (free `Describe` calls, with the catalog test extended). Until then the
  coverage block records them as unsupported. StackSets and the tagged
  resource sample, which were on this list, are collected since M4. (2 h)
- Evaluate `aws:SourceVpc`, `aws:SourceIp` and `aws:CalledVia` conditions
  when the usage entry supplies them, instead of returning REVIEW. (2 h)
- A `--fail-on review` switch for CI so a REVIEW can be made blocking. (0.5 h)
