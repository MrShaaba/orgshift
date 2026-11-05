# Onboarding: configuration, IAM roles, preflight, collection

Reading a real organization takes four steps, all driven by one
configuration file and all read-only:

1. **Describe the access** in `orgshift.yaml` (or JSON): how orgshift reaches
   each organization, which account every credential must belong to, where
   Control Tower and Identity Center live, which regions the workloads use.
2. **Create the IAM roles** from the templates `orgshift iam-templates`
   generates for that configuration (docs/iam has the placeholder version).
3. **Run the preflight**: `orgshift preflight --config orgshift.yaml` tries
   the cheapest read call of every collection domain and reports, in the
   coverage matrix layout, what is available, denied or unknown.
4. **Collect**: `orgshift collect --config orgshift.yaml --side source --out
   snapshots/source.json`, then the same for the destination, then
   `orgshift simulate`.

Every credential is checked with `sts:GetCallerIdentity` against the account
the configuration names before anything is read; a mismatch stops the
command. Nothing in the configuration is a secret: it names profiles,
sessions and roles, never keys. Keep real account IDs out of version control
if your organization treats them as such (`orgshift.yaml`, `orgshift.json`,
`*.checkpoint.json` and `snapshots/` are in `.gitignore`).

## The configuration file

`orgshift config example` prints an annotated example; `orgshift config check
--config FILE` validates a file offline and prints what it resolves to
(`--format json` for the configuration with defaults applied). Unknown fields
are errors, so a typo never silently disables something.

```yaml
schema_version: 1
source:
  name: Larkspur Holdings
  management:
    account_id: "111111111111"
    region: us-east-1
    profile: larkspur-mgmt
    assume_role:
      - role_arn: arn:aws:iam::111111111111:role/OrgshiftOrgRead
  control_tower:
    home_region: us-east-1
  identity_center:
    region: us-east-1
  member_inspection:
    role_name: OrgshiftMemberRead
    accounts: ["111111111115"]
    sample: 5
  network:
    - label: network account
      account_id: "111111111120"
      from: management
      assume_role:
        - role_arn: arn:aws:iam::111111111120:role/OrgshiftNetworkRead
  workload_regions: [us-east-1, eu-west-1]
destination:
  name: Fernhill Group
  management:
    account_id: "222222222222"
    region: eu-west-1
    sso_session: fernhill
    sso_region: eu-west-1
    sso_role_name: OrgshiftOrgRead
```

| Key | Meaning |
| --- | --- |
| `schema_version` | `1`. |
| `source`, `destination` | The organization the account leaves and the one it joins. Omit `destination` for a move inside one organization. |
| `<side>.name` | Friendly organization name stored in the snapshot. |
| `<side>.management` | An access block (below) for the management account or an Organizations delegated administrator. Reads Organizations, the regions of every account and the management account's own RAM shares. `region` is required here and is the default for the other access blocks. |
| `<side>.control_tower` | `home_region` (the landing zone APIs answer only there; defaults to the management region) and `enabled` (default true). |
| `<side>.identity_center` | `region` (the instance APIs answer only there), `enabled`, and an optional `access` block for the delegated administrator account (`from: management` plus `assume_role`). |
| `<side>.member_inspection` | `role_name` of the role present in every member account, optional `external_id`, `accounts` and `sample`. `accounts` are the accounts whose workload inventory is read (name the accounts you plan to move); the preflight always tries the role there and probes one page of each workload read. `sample` is how many more accounts the preflight tries the role in (default 5, `0` none, `-1` all within a 25-call budget). |
| `<side>.network` | Access blocks for the accounts that own shared networking. RAM lists only the caller's own shares, so each owner is read with its own credentials. |
| `<side>.security` | Access blocks for the audit and log archive accounts. The preflight verifies their identity; a later milestone reads organization trails and Config aggregators through them. |
| `<side>.workload_regions` | Regions the workloads run in. The workload inventory is read in each of them (default: the management region); later milestones scope network-path reasoning to them. |
| `<side>.workloads` | Tunes the workload inventory: `resource_source` (`auto`, `tagging-api` or `resource-explorer`; `auto` uses Resource Explorer when the account has an aggregator index and a searchable default view, otherwise the Resource Groups Tagging API, and the snapshot records which was used) and the per-account caps `max_stacks` (500), `max_resources` (1000), `max_roles` (2000), `max_buckets` (200). |
| `<side>.skip` | Coverage domains not to collect: `enabled_regions`, `resource_shares`, `control_tower`, `identity_center`, `stack_sets`, `workloads`. Recorded as `skipped`. |
| `collection.concurrency` | Parallel per-item calls (account tags, regions, shares, permission sets). Default 4, maximum 32. |
| `collection.retry_attempts` | SDK attempts per call in adaptive retry mode. Default 8. The collector retries throttling on top with full-jitter backoff. |
| `collection.timeout` | Whole-run timeout, default `10m`. |
| `collection.checkpoint` | Write `<out>.checkpoint.json` after every completed step and resume from it. Default true. |
| `billable.bucket_policies` | Opt-in for the bucket policies of the inspected accounts (`s3:ListBuckets`, `s3:GetBucketPolicy`). S3 bills every request: one LIST request per account and one request per bucket in the workload Regions. Off by default; `--with-bucket-policies` turns it on for one run. Off, the workload layer reads partially evaluated. |
| `billable.cloudtrail_lake`, `billable.config_queries` | Opt-ins for reads AWS bills that are not implemented yet. Off by default; `collect` refuses to run with either on. |
| `templates.role_prefix` | Prefix of the generated role names, default `Orgshift`. |
| `templates.trusted_principal_arns` | Who may assume the management-account roles: the operator role or user that runs orgshift. |
| `templates.external_id` | Required in the trust policies of the management-account roles when set. |

### Access blocks

An access block says how one credential is obtained and which account it
must belong to.

| Key | Meaning |
| --- | --- |
| `account_id` | Required. The account the final credentials must belong to; `sts:GetCallerIdentity` is compared with it. |
| `region` | Endpoint region; defaults to the side's management region. |
| `profile` | A shared-configuration profile. SSO profiles, assume-role profiles and credential_process profiles all work. |
| `sso_session` | An `sso-session` name from `~/.aws/config`. Log in with `aws sso login --sso-session NAME`; orgshift uses the cached token to fetch credentials for `sso_role_name` in `sso_account_id` (defaults to `account_id`). `sso_region` is required; `sso_start_url` is optional. |
| `from: management` | Start from the side's management credentials. Only for `network`, `security` and `identity_center.access`, and needs at least one `assume_role` hop. |
| (nothing) | The default credential chain: environment variables, the default profile, an instance or container role. |
| `assume_role` | A chain of `{role_arn, external_id, session_name, duration}` hops applied in order on top of the base credentials. |
| `label` | Name used in messages ("network account"). |

`profile`, `sso_session` and `from` are mutually exclusive.

## IAM roles

`orgshift iam-templates --config orgshift.yaml --out docs/iam` writes one role
per collector responsibility with the account IDs and operator principals
from the configuration (`--side destination` for the other organization);
without `--config` the templates carry placeholders. Each template has a
trust policy, a permissions policy, the account it goes in, the
delegated-administrator alternative where AWS offers one, a justification
for every statement whose Resource is `*`, the operations later milestones
will add (listed, not granted), and the `aws iam create-role` commands.

| Responsibility | Role | Account |
| --- | --- | --- |
| `org-management` | `OrgshiftOrgRead` | Management account (or a delegated administrator with a resource-based delegation policy for the tree and policy reads). Assumes the member and network roles. |
| `control-tower` | `OrgshiftControlTowerRead` | Management account, home region. No delegated administrator exists for the Control Tower APIs. |
| `identity-center` | `OrgshiftIdentityCenterRead` | Management account or the Identity Center delegated administrator. |
| `member-inspection` | `OrgshiftMemberRead` | Every member account (at least the ones named under `member_inspection.accounts`). Reads the workload inventory; the S3 statement for bucket policies is a separate opt-in policy. |
| `network` | `OrgshiftNetworkRead` | Each account that owns shared networking. |

The actions come from the operation catalog (`internal/collector/operations.go`),
which classifies every operation orgshift calls or plans to call as a free
read, a read AWS bills (behind an opt-in) or a session operation; a test
refuses any write. See [permissions.md](permissions.md) for the full list.

## Preflight

```sh
orgshift preflight --config orgshift.yaml                      # both sides, text
orgshift preflight --config orgshift.yaml --side source --format markdown --out preflight.md
orgshift preflight --config orgshift.yaml --format json --out preflight.json
```

For each side the preflight verifies every credential's identity, then
tries the cheapest read of each collection domain in dependency order (one
page, one item): the organization, the root and one OU and account, trusted
access, the management account's tags, one account's regions, one policy
per type (described and its targets listed), delegated administrators, the
first resource share of each RAM credential with its principals and
resources, the landing zone chain down to one control, the Identity Center
chain down to one assignment's principal name, and `sts:AssumeRole` into
the member inspection role for the configured accounts plus a sample.

| Status | Meaning |
| --- | --- |
| `available` | The call succeeded. |
| `denied` | The credentials lack the permission. Blocking; the report names the action and the identity to grant it to. |
| `error` | The call failed for another reason, including an empty Control Tower or Identity Center answer in a region where trusted access shows the service is in use. Blocking. |
| `mismatch` | The credentials belong to another account than configured. Blocking; nothing else is probed with them. |
| `skipped` | Turned off in the configuration. Not required. |
| `unknown` | Not tried: nothing existed to try against (no delegated administrator, no share, no policy of the type, no account named for inspection), a call it depends on failed, the read is a billed one whose opt-in is off (bucket policies), or this build does not collect the domain (trails, Config aggregators). Only the second case blocks. |

The matrix has the evaluation's coverage-matrix rows (domain, what it
decides, which check depends on it) plus a `member_inspection` row, with
one column per side. The JSON result (`schema_version` 1) carries every
probe with its operation, status, detail, account, region and duration, the
identity checks, the per-domain results and the blocking list. Exit codes:
0 ready, 2 not ready, 1 error.

## Collection

```sh
orgshift collect --config orgshift.yaml --side source --out snapshots/source.json
orgshift collect --config orgshift.yaml --side destination --out snapshots/destination.json
```

- **Identity first.** Every credential is verified before any read; a
  mismatch is fatal. The identities are printed.
- **Bounded concurrency.** Per-item calls (one account's tags or regions,
  one share's principals and resources, one policy's document and targets,
  one permission set's policies and assignments) run `collection.concurrency`
  at a time; results are written back in a stable order so two runs produce
  the same snapshot.
- **Retries.** The SDK retries each call in adaptive mode up to
  `collection.retry_attempts`; the collector retries throttling errors on
  top (five attempts, full-jitter backoff from 500 ms to 20 s) and records
  the retries it performed on the domain's coverage record (`retries`).
- **Checkpoint and resume.** After every step whose coverage records are all
  observed or empty, the run state is written to `<out>.checkpoint.json`. A
  rerun with the same output path restores the completed steps (their
  coverage records say `restored from the checkpoint written at ...`) and
  reads only the steps that were denied, partial, skipped or never reached.
  A checkpoint is ignored when it was written by another build, for another
  region or organization, or more than 24 hours ago, and it is removed once
  every domain is complete (`--keep-checkpoint` keeps it; `--fresh` ignores
  and deletes it; `--no-checkpoint` turns the mechanism off).
- **Legacy flags.** `orgshift collect --profile NAME --expect-account ID
  --out FILE` runs without a configuration file; `--expect-account` is
  required because the identity check always runs. Without a configuration
  no member account is inspected.

### The workload inventory

For every account under `member_inspection.accounts` the collector assumes
the member inspection role from the management credentials and reads, in
each of `workload_regions`:

- the CloudFormation stacks: status, tags, resource types and counts,
  output keys and export names, imports, termination protection; the
  template is read in memory for `Fn::GetStackOutput` references to other
  accounts, identifiers of infrastructure the stack takes from outside
  (subnets, transit gateways) and policy conditions on organization
  identity, and is never stored;
- a resource sample with tags, from Resource Explorer when the account has
  an aggregator index, otherwise from the Resource Groups Tagging API (which
  never returns resources that were never tagged);
- the trust policy of every role, kept only when it is conditioned on the
  organization ID or path;
- with `billable.bucket_policies` or `--with-bucket-policies`, the bucket
  policies, kept on the same condition. This is the one billed read; see
  [permissions.md](permissions.md#what-the-workload-inventory-costs).

From the management account it also reads the StackSets administered there
and their stack instances, which is how a stack in a member account is known
to be a StackSet instance and what happens to it when the account leaves.

Each inspected account gets one coverage record per workload domain
(`workloads.stacks`, `workloads.resources`, `workloads.policies`). A denied
call in one domain does not hide what the others read, an account whose role
cannot be assumed is recorded as `access_denied`, and an account that is not
in the organization is recorded as an error for that account only.
`orgshift workloads --snapshot FILE` lists what was read with the
deployment provenance of every stack and resource.

The snapshot's `coverage` block records every domain, including the ones
that were skipped, denied or not collected by this build, so a simulation
knows what it is missing. See [snapshot.md](snapshot.md).
