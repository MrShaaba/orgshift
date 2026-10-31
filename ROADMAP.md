# Roadmap

Items the first pass deliberately left out, as concrete pieces of work. None
of them changes the ground rules: read-only, offline simulation, no real
organization data in the repo.

## Moving a whole OU at once

- Accept an OU as the subject (`--ou ou-…` and the UI picker) and evaluate
  every account under it, recursively, against the target position.
- Roll results up per account and for the OU as a whole: the OU verdict is
  the worst account verdict, with a table of accounts and their blocking
  findings.
- Carry the OU's own policy attachments to the target when the move is
  inside one organization; when it is a cross-organization move, note that
  the OU and its attachments cannot move and must be recreated.
- Golden-file scenario: move Larkspur `Workloads` into Fernhill `Business
  Units`.

## Control Tower awareness

- Snapshot fields for Control Tower: landing zone presence, enrolled
  accounts, registered OUs, enabled controls per OU.
- Treat preventive guardrails as SCPs (they already appear as
  `aws-guardrails-*` policies) and label them as Control Tower managed in the
  chain and diff views.
- Flag moves out of a registered OU (the account becomes unenrolled) and
  into one (enrolment and Account Factory provisioning run), including
  detective controls that start reporting.
- Note Account Factory impact when the source account was vended by it.

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

## Identity Center impact for cross-organization moves

- Snapshot fields for IAM Identity Center: instance, permission sets and
  assignments per account.
- For a cross-organization move list every permission set assignment on the
  account (users and groups) that disappears when it leaves, and whether
  the target organization has a matching permission set name.
- Report the `AWSReservedSSO_*` roles that will be deleted from the account.

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

## Migration runbook generated from the findings

- Turn the findings into an ordered checklist: re-share networking
  resources with the account directly, re-delegate administration, lift the
  `LeaveOrganization` deny, satisfy standalone prerequisites, accept the
  invitation, verify the trail and Config coverage, re-tag resources, and
  so on.
- Export it as Markdown next to the existing JSON and Markdown reports, with
  the evidence links kept.
- Include a rollback section (move back, re-attach policies) built from the
  source chain.

## Smaller items

- Collect organization trails, Config aggregators and StackSets in
  `orgshift collect` (free `Describe`/`List` calls, with the allowlist test
  extended).
- Collect a tagged resource sample with `tag:GetResources` for tag policy
  checks.
- Evaluate `aws:SourceVpc`, `aws:SourceIp` and `aws:CalledVia` conditions
  when the usage entry supplies them, instead of returning REVIEW.
- A `--fail-on review` switch for CI so a REVIEW can be made blocking.
