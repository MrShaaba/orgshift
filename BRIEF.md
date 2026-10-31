# Brief: orgshift, a go/no-go simulator for moving AWS accounts and OUs

**Project type:** local infrastructure-analysis tool with a web UI · **Stack:** Go 1.23,
aws-sdk-go-v2 (read-only), html/template and HTMX, go test

## Why this exists

Moving an AWS account, or a whole OU, from one OU to another changes which service control
policies (SCPs), resource control policies (RCPs), tag policies and other organization policies
apply to it. Moving it to a different organization changes even more: org-based RAM shares, org
trails, delegated administrators and service-managed StackSets all stop applying. Today I work
this out by hand. This is my own tool, for planning moves in AWS organizations I run. I want a
tool that reads the source and destination setup and gives a
**GO / REVIEW / NO-GO** call, with every blocker explained and the networking dependencies
called out.

## How it works

1. **Collect (read-only, optional):** `orgshift collect` uses read-only credentials for the
   source and destination management accounts, or delegated-admin accounts, and writes a JSON
   snapshot. Only list, describe and get calls are allowed.
2. **Simulate (offline):** `orgshift simulate --from snapshot-a.json --to snapshot-b.json
   --account <id> --target-ou <ou>` or `orgshift serve` loads the snapshots and evaluates the
   move. It never needs live access, so it works entirely from snapshots and fixtures.

## Stack

- Go 1.23, a single binary. A collector package, an evaluator package and a web package.
- The web UI is server-rendered with `html/template` and HTMX, with static files embedded using
  `embed`. There is no Node build step.
- Testing is done with `go test`, including golden-file tests on fixture organizations.
  Lint with `go vet` and `staticcheck`.

## First pass: build this now

1. **Snapshot schema:** versioned and documented in `docs/snapshot.md`. It covers:
   - the organization root and OU tree, accounts and their parents
   - policies of types SCP, RCP, TAG and BACKUP, their documents and targets
   - account tags and enabled or opt-in regions
   - RAM resource shares (owner, principals, whether they are shared to the org or an OU, and
     the resource types: TGW, subnets, Resolver rules, IPAM pools and prefix lists)
   - delegated administrators and trusted-access services
   - for the account being moved: a list of "actions in use", which can be entered by hand or
     imported from an IAM last-accessed JSON export
2. **Fixtures:** a seeded generator that produces two fictional organizations, for example a
   legacy org "Larkspur Holdings" and a target org "Fernhill Group". Plant realistic problems in
   them:
   - a region-deny SCP at the target OU
   - an SCP denying `ec2:CreateVpc` or `iam:CreateUser`
   - an RCP that blocks external principals the account relies on
   - a tag policy enforcing a `cost-center` tag the account's resources don't have
   - a TGW attachment and subnets that reach the account through an org-scoped RAM share
3. **Evaluator:**
   - **SCPs and RCPs:** compute the effective policy at the source path and at the target path,
     walking from the root through each OU to the account. Allow lists intersect and deny
     statements add up. Evaluate the account's actions in use against both. Report each action
     that is allowed now but denied after the move, with the policy and statement that cause it.
     Support `Action`/`NotAction`, wildcards, `Resource` and common condition keys such as
     `aws:RequestedRegion`, `aws:PrincipalOrgID` and `aws:PrincipalTag`. When a condition can't
     be evaluated, return REVIEW instead of guessing.
   - **Tag policies:** the effective tag policy at the target, with keys and values that would
     be non-compliant and the enforced resource types.
   - **Cross-org moves:** list what breaks when the account leaves the organization: org-scoped
     RAM shares (especially networking), delegated-admin roles, the org trail, Config
     aggregation and service-managed StackSets.
   - **Verdict:** NO-GO if any action in use becomes denied or a networking share is lost;
     REVIEW for anything unevaluable or tag non-compliance; GO otherwise. Every finding carries
     its evidence.
4. **Web UI:**
   - load two snapshots, or the fixtures
   - pick an account or OU and the target OU
   - see a side-by-side OU tree with the policy chain at the source and the target
   - a verdict board with GO / REVIEW / NO-GO per check and expandable explanations
   - a "what changes" diff of effective policies
   - export the result as JSON and Markdown
5. **Collector skeleton:** implement the Organizations and RAM read-only calls behind an
   explicit allowlist of API operations. Add a test that fails if any non-read operation is
   referenced. Document the minimal read-only IAM policy in `docs/permissions.md`. Note which
   optional data sources can cost money, such as CloudTrail Lake queries or AWS Config
   aggregator queries, and keep those behind opt-in flags that are off by default.
6. **Repo basics:** a README (what it does, who it is for, stack, quick start using the fixtures
   and a screenshot), an MIT LICENSE under "Bello Mohammed", `.gitignore` (including
   `snapshots/`, `*.snapshot.json` and `.env`), and GitHub Actions running vet, staticcheck,
   tests and build.
7. **ROADMAP.md:** put everything listed under "Later" below there, as concrete items.

## Later: list in ROADMAP.md, do not build now

- Moving a whole OU at once, with per-account rollups
- Control Tower awareness: enrolled accounts, guardrails as SCPs, and Account Factory impact
- Importing actions in use from CloudTrail or CloudTrail Lake (opt-in, with a cost warning)
- IAM Access Analyzer policy validation for the effective policies
- Identity Center permission set and assignment impact for cross-org moves
- Backup policy and AI opt-out policy comparison
- A step-by-step migration runbook generated from the findings

## Ground rules

- **Read-only, always.** The tool never writes to AWS: no move, attach, create or delete calls.
  This is enforced in code and in tests.
- No snapshots of real organizations go into the repo, its tests or its docs. Fixtures are
  fictional, with example account IDs such as `111111111111` and `222222222222`.
- Everything runs locally. Do not deploy anything, do not create cloud resources and do not
  add infrastructure-as-code. Ignore any global instructions about AWS tagging, alarms or CDK
  for this repository.
- No secrets anywhere. Credentials come only from the standard AWS profile chain at runtime.
- Write the code from scratch. Do not copy code from any other project.
- Work in small steps. Commit each working step with a clear message, and run vet and tests
  before each commit.
- When the first pass is done, tell me exactly what to try in the browser.
