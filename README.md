# orgshift

A go / no-go simulator for moving AWS accounts between organizational units
and between organizations. It reads snapshots of the source and destination
setup, works out what changes for the account, and gives a **GO / REVIEW /
NO-GO** verdict with every blocker explained and the networking dependencies
called out.

![orgshift result for the fixture move](docs/screenshot.png)

## What it does

Moving an account to another OU changes which service control policies,
resource control policies, tag policies and backup policies apply to it.
Moving it to another organization changes more: organization-scoped RAM
shares (transit gateways, subnets, Resolver rules, IPAM pools, prefix
lists), delegated administration, the organization trail, Config aggregation
and service-managed StackSets stop applying. orgshift simulates the move
offline and reports:

- **SCPs and RCPs**: the effective policy at the source path and at the
  target path, root to account, with allow lists intersected and denies
  accumulated. Every action the account uses is evaluated against both, per
  region, and each action that is allowed today but denied after the move is
  reported with the policy and statement that cause it. Conditions on
  `aws:RequestedRegion`, `aws:PrincipalOrgID`, `aws:PrincipalAccount`,
  `aws:PrincipalArn`, `aws:PrincipalTag/*`, `aws:ResourceAccount` and
  `aws:PrincipalIsAWSService` are evaluated; anything the tool cannot decide
  offline comes back as REVIEW rather than a guess.
- **Inbound access**: principals outside the account that call into it are
  checked against the destination's resource control policies.
- **Tag policies**: the effective tag policy at the target, merged with the
  `@@assign` / `@@append` / `@@remove` operators, and the sampled resources
  whose keys or values would be non-compliant, with the enforced resource
  types.
- **Cross-organization moves**: lost RAM shares (networking shares are a
  NO-GO), delegated-administrator roles, the organization trail, Config
  aggregation, StackSets, trusted access gaps and the standalone-account
  prerequisites.
- **Verdict**: NO-GO if any action in use becomes denied or a networking
  share is lost; REVIEW for anything unevaluable or for tag non-compliance;
  GO otherwise. Every finding carries its evidence, and the result exports
  as JSON and Markdown.
- **Whole-OU moves**: pick an OU instead of an account and every nested OU
  and account is evaluated at its new position. The OU verdict is the worst
  account verdict, with a per-account rollup table (blocking and review
  counts, the blocking findings) and the full board for each account.
  Inside one organization the OU's attachments travel with it; across
  organizations the OU tree cannot move and is reported as something to
  recreate, with the accounts evaluated under recreated OUs that carry only
  the AWS managed defaults.
- **Control Tower**: when a snapshot carries a landing zone, the verdict
  board gets a Control Tower check. Leaving a registered OU (or the
  organization) is flagged as unenrolling the account, with the guardrail
  SCPs and detective controls that stop; entering a registered OU lists what
  enrolment needs; moving between registered OUs has to go through Account
  Factory; moving the audit or log archive account is a NO-GO. Accounts
  vended by Account Factory get a note about their provisioned product, and
  the `aws-guardrails-*` SCPs are labelled as Control Tower managed in the
  chain, diff and tree views.
- **Migration runbook**: every result comes with an ordered checklist
  generated from the findings. Before the move: each denied action grouped
  by the SCP or RCP statement that causes it, with the exact change to
  review and the statement as evidence, tags to fix, delegated
  administration to hand over, Control Tower unenrolment, the
  `LeaveOrganization` deny to lift, the standalone prerequisites. Then what
  does not travel and has to be re-created: RAM shares re-shared with the
  account directly, permission sets prepared in the target Identity Center,
  StackSets, trusted access. Then the move itself (invite, leave, accept,
  move; or the Account Factory flow when Control Tower requires it), the
  checks afterwards (position, shares, CloudTrail and Config coverage,
  assignments, flagged actions, a fresh simulation) and a rollback built
  from the source chain. Whole-OU moves get the OU-level steps (the tree is
  recreated, policies attached, accounts moved one by one) plus one
  checklist per account. The UI renders it as a checklist that remembers
  ticks in the browser; it exports as Markdown and JSON. It is a document:
  every command is for you to review and run by hand, and orgshift still
  never writes to AWS. The phases and the JSON shape are in
  [docs/runbook.md](docs/runbook.md).
- **IAM Identity Center**: when a snapshot carries an Identity Center
  instance, a cross-organization move lists every account assignment on the
  account (users and groups per permission set), says whether the target
  instance has a permission set of the same name and how its settings
  differ, and reports the `AWSReservedSSO_*` roles that are deleted from the
  account, including roles still provisioned without an assignment. All of
  it is REVIEW with the assignment and permission set as evidence; inside
  one organization the check is a quiet GO.

## Who it is for

This is a personal tool for planning moves in AWS organizations I run. It is
built to be safe to point at a real organization: the collector only ever
calls `List`, `Describe` and `Get` operations behind an explicit allowlist
that the tests enforce, and the simulator itself never needs AWS access.

## Stack

Go 1.23, a single binary. `aws-sdk-go-v2` for the read-only collector,
`html/template` and HTMX for the UI (static files embedded with `embed`, no
Node build step), `go test` with golden-file tests on fixture organizations,
`go vet` and `staticcheck`.

## Quick start with the fixtures

```sh
go build -o orgshift ./cmd/orgshift

# two fictional organizations with problems planted in them
./orgshift fixtures --out fixtures

# move the payments account from Larkspur Holdings to Fernhill Group
./orgshift simulate \
  --from fixtures/larkspur-holdings.json \
  --to fixtures/fernhill-group.json \
  --account 111111111115 --target-ou ou-fern-pay1

# the same move inside one organization, as Markdown
./orgshift simulate --from fixtures/larkspur-holdings.json \
  --account 111111111117 --target-ou ou-lark-prod --format markdown

# Fernhill runs Control Tower: take an enrolled account out of its
# registered OU and see what unenrolling it means
./orgshift simulate --from fixtures/fernhill-group.json \
  --account 222222222225 --target-ou ou-fern-sand

# the data platform account into Fernhill Retail: three Identity Center
# assignments and three AWSReservedSSO_* roles go away with it
./orgshift simulate \
  --from fixtures/larkspur-holdings.json \
  --to fixtures/fernhill-group.json \
  --account 111111111118 --target-ou ou-fern-ret

# move the whole Workloads OU (two nested OUs, three accounts) into
# Fernhill's Business Units; --target-ou is the new parent
./orgshift simulate \
  --from fixtures/larkspur-holdings.json \
  --to fixtures/fernhill-group.json \
  --ou ou-lark-work --target-ou ou-fern-bu

# the migration runbook for the payments move, as a Markdown checklist
./orgshift simulate \
  --from fixtures/larkspur-holdings.json \
  --to fixtures/fernhill-group.json \
  --account 111111111115 --target-ou ou-fern-pay1 \
  --format runbook --out payments-runbook.md
```

`simulate` exits 0 for GO, 2 for REVIEW and 3 for NO-GO, so it can gate a
pipeline. `--format json|markdown` and `--out` write the full report;
`--format runbook` (Markdown) and `--format runbook-json` write the
migration runbook instead.

### The web UI

```sh
./orgshift serve            # http://127.0.0.1:8080, fixtures preloaded
./orgshift serve --from a.json --to b.json
```

Load two snapshots (or the fixtures), pick the account and the target OU,
and the page shows the verdict board with expandable explanations, the
migration runbook as a checklist (ticks are remembered by the browser, the
"Export runbook" button writes it as Markdown), the two organization trees
side by side with the policy chain highlighted and the account drawn at its
future position, the "what changes" diff of effective policies, and export
buttons.

Switch "What moves" to "a whole OU" to move an OU instead: the result opens
with the per-account rollup table, the OU's own findings (what travels with
it, what has to be recreated), the subtree drawn at its new position and the
inherited-policy diff at the OU, followed by a collapsible verdict board per
account.

## Using it on a real organization

1. Collect a snapshot of each organization with read-only credentials:

   ```sh
   ./orgshift collect --profile source-mgmt --name "Source Org" --out snapshots/source.json
   ./orgshift collect --profile target-mgmt --name "Target Org" --out snapshots/target.json
   ```

   The minimal IAM policy and the list of operations are in
   [docs/permissions.md](docs/permissions.md). RAM only shows shares owned by
   the calling account, so pass `--ram-profiles network` for accounts that own
   the shares you care about. If the organization runs Control Tower, set
   `--region` to the landing zone's home region so the registered OUs and
   enabled controls are collected (`--skip-control-tower` turns that off).
   The same goes for IAM Identity Center: with `--region` set to the
   instance's region the permission sets and account assignments are
   collected (`--skip-identity-center` turns that off). Optional data sources that cost money
   (CloudTrail Lake, Config advanced queries) are behind opt-in flags that are
   off by default and refused until they are implemented.

2. Tell orgshift what the account does. Add `usage.<account-id>.actions`,
   `inbound_access` and `tagged_resources` to the source snapshot (the format
   is in [docs/snapshot.md](docs/snapshot.md)), or import an IAM last-accessed
   export:

   ```sh
   aws iam generate-service-last-accessed-details --arn arn:aws:iam::111111111115:role/App --granularity ACTION_LEVEL
   aws iam get-service-last-accessed-details --job-id … > last-accessed.json
   ./orgshift simulate --from snapshots/source.json --to snapshots/target.json \
     --account 111111111115 --target-ou ou-xxxx-yyyy --last-accessed last-accessed.json
   ```

3. Read the verdict, work through the runbook (fix what it lists before
   the move, re-create what does not travel), collect again, repeat until
   GO. The runbook's commands are for you to run; orgshift only reads.

`snapshots/`, `*.snapshot.json` and `.env` are ignored by git so real data
does not end up in the repository.

## Assumptions worth knowing

- Actions in use are assumed to be performed by IAM roles of the account
  unless `principal_arn` says otherwise. This lets the common root-user deny
  be evaluated instead of turning every action into a REVIEW.
- Actions without explicit regions are evaluated in every region the
  account has enabled; global services are evaluated in `us-east-1`.
- A cross-organization move drops policies attached directly to the account
  and attaches the target's AWS managed defaults, which is what Organizations
  does when an account joins.
- Only SCPs, RCPs and tag policies are evaluated. Backup policies are shown
  in the chain and the diff; comparing them is on the roadmap.
- Without a `control_tower.enrolled_accounts` list, an account whose parent
  OU is registered with Control Tower is assumed to be enrolled, and the
  finding says so. The collector cannot fill that list read-only.
- The `AWSReservedSSO_*` role names end in a random suffix that only IAM in
  the member account knows, so they are reported as patterns
  (`AWSReservedSSO_<permission set>_*`). Permission sets in the two
  instances are matched by name; users and groups are never matched, since
  the identity stores are different directories.

## Repository layout

```
cmd/orgshift          CLI: fixtures, simulate, serve, collect
internal/snapshot     versioned snapshot schema, loader, validation
internal/policy       IAM policy parsing and tri-state statement matching
internal/evaluator    effective policies, tag policies, cross-org checks, verdict
internal/fixtures     the Larkspur Holdings and Fernhill Group generator
internal/runbook      migration runbook built from a result: fix, re-create, move, check, roll back
internal/report       JSON, Markdown and text rendering, runbook Markdown
internal/usage        actions-in-use files and IAM last-accessed import
internal/web          html/template + HTMX UI, embedded static files
internal/collector    read-only AWS collector behind an operation allowlist
docs/                 snapshot schema, permissions, runbook, screenshot
```

## Development

```sh
go vet ./... && go run honnef.co/go/tools/cmd/staticcheck@2024.1.1 ./... && go test ./...
go test ./internal/evaluator ./internal/runbook ./internal/report -update   # refresh golden files after reviewing a change
```

See [ROADMAP.md](ROADMAP.md) for what comes next.

## License

MIT, see [LICENSE](LICENSE).
