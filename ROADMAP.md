# Roadmap

Items the first pass deliberately left out, as concrete pieces of work. None
of them changes the ground rules: read-only, offline simulation, no real
organization data in the repo.

Done since the first pass:

- Moving a whole OU at once (`simulate --ou`, the UI picker, per-account
  rollups, attachments carried or flagged for recreation, golden scenarios
  for Workloads into Fernhill Business Units and Production to the root).
- Control Tower awareness (`control_tower` snapshot block collected
  read-only, guardrail SCPs labelled, the Control Tower check for
  unenrolment, enrolment, registered-to-registered moves, shared accounts
  and Account Factory provenance, controls that start or stop applying,
  golden scenario for fernhill-retail-prod leaving its registered OU). Left
  open: enrolled accounts cannot be collected with `List`/`Describe`/`Get`
  calls, so they stay a hand-written list.
- Identity Center impact for cross-organization moves (`identity_center`
  snapshot block collected read-only with permission sets, provisioned
  accounts and assignments with principal names; the IAM Identity Center
  check listing every assignment on the account, matching permission sets
  by name and reporting the `AWSReservedSSO_*` roles that are deleted,
  stale ones included; golden scenario for larkspur-data-prod into
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
  extended).
- Collect a tagged resource sample with `tag:GetResources` for tag policy
  checks.
- Evaluate `aws:SourceVpc`, `aws:SourceIp` and `aws:CalledVia` conditions
  when the usage entry supplies them, instead of returning REVIEW.
- A `--fail-on review` switch for CI so a REVIEW can be made blocking.
