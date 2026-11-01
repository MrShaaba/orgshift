# Roadmap

## Milestone plan (PoC brief, November 2026)

The brief for the AWS proof of concept is worked in milestones. After each
one vet, staticcheck and the tests run, the work is committed and pushed, and
the summary says what to try.

- **M1 (done, 2026-11-01):** Section 2, the audit findings with regression
  tests and fuzzing, plus Section 4, the collection completeness model.
- **M2:** Section 3, onboarding configuration, IAM templates and the
  permission preflight.
- **M3:** Sections 6 and 7 for the same-organization and cross-organization
  paths, with end-to-end fixtures and the CLI and UI.
- **M4 and later:** Section 5 beyond Organizations, Control Tower and
  Identity Center; then Section 8; then the rest.

Hard rule for the development sessions: never run `orgshift collect`, the
AWS CLI or any AWS SDK call against a real account; fixtures and mocks only.
Live collection is run by the owner. The server on 8080 is left alone.

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

Left for later milestones: bounded concurrency and resumable collection
(M2, with the onboarding configuration); the scenario overlay file that
keeps proposed changes apart from the immutable snapshot (M3, with the stage
model); reading `RetainSharingOnAccountLeaveOrganization` from RAM (the SDK
module that exposes it requires Go 1.24).

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

## Actions in use from CloudTrail and CloudTrail Lake (opt-in, cost warning)

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

## IAM Access Analyzer policy validation

- Run `access-analyzer:ValidatePolicy` (policy type `SERVICE_CONTROL_POLICY`
  and `RESOURCE_CONTROL_POLICY`) over every policy in the target chain and
  attach findings (errors, security warnings, suggestions) to the diff view.
- Use `CheckNoNewAccess` between the source and target effective policies
  where the API supports it, as a second opinion on the offline evaluator.
- Keep it behind `--with-access-analyzer`; the calls are free but need live
  credentials, which the simulator otherwise never requires.

## Backup policy and AI opt-out policy comparison

- Merge backup policies along both chains with the same inheritance
  operators as tag policies and diff plans, rules, vault names, regions and
  selections. Flag selections that point at IAM roles the account does not
  have.
- Add `AISERVICES_OPT_OUT_POLICY` to the schema, the collector and the diff,
  with a per-service opt-out comparison.
- Add `DECLARATIVE_POLICY_EC2`, `CHATBOT_POLICY` and `SECURITYHUB_POLICY` to
  the chain display so nothing attached is invisible, even before they are
  evaluated.

## Smaller items

- Collect organization trails, Config aggregators and StackSets in
  `orgshift collect` (free `Describe`/`List` calls, with the allowlist test
  extended). Until then the coverage block records them as unsupported.
- Collect a tagged resource sample with `tag:GetResources` for tag policy
  checks.
- Evaluate `aws:SourceVpc`, `aws:SourceIp` and `aws:CalledVia` conditions
  when the usage entry supplies them, instead of returning REVIEW.
- A `--fail-on review` switch for CI so a REVIEW can be made blocking.
- Stable finding identifiers and severities on every finding (Section 9 of
  the brief).
