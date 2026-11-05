# Staged migrations: the scenario overlay

A migration is a sequence of proposed states, not one before/after
comparison. `orgshift stages` reads a **scenario overlay** (YAML or JSON),
derives the state after every stage, evaluates the transition into each
stage with the same verdict board as `orgshift simulate`, and compares the
transfer strategy with creating destination accounts and migrating the
workloads. The snapshots stay immutable: every derived state is an in-memory
copy, and the objects the scenario proposes (OUs, policies, shares) are
listed apart from collected ones in every report and marked in the UI.

```sh
orgshift scenario example > plan.yaml          # annotated example to edit
orgshift scenario check --scenario plan.yaml   # shape only, offline
orgshift stages --scenario plan.yaml --from snapshots/source.json --to snapshots/destination.json
orgshift stages --scenario plan.yaml --format markdown --out plan.md
orgshift stages --scenario plan.yaml --format json --out plan.json
```

Exit codes follow the worst stage: 0 GO, 2 REVIEW, 3 NO-GO, 1 error. The
UI has the same under "3. Stage a migration" (upload a scenario file or use
the two that ship with the fixtures).

## The five layers

Every stage may change any of these, and every report keeps them apart:

| Layer | Stage key | What changes |
| --- | --- | --- |
| membership | `membership.organization` | which organization the account belongs to: `source` or `destination`. Entering the destination is the cross-organization transition; the account lands at the root unless the same stage places it. |
| placement | `placement.parent`, `policies.attach/detach` | the root or OU the account sits in (existing or proposed) and the policy attachments made at the stage (progressive tightening). |
| governance | `governance.enrolled`, `governance.register_ou`, declarations | Control Tower: enrolling or unenrolling the account, registering an OU, and the enrollment prerequisites the collector cannot see. |
| network | `network.recreate_shares`, `network.remove_shares`, `network.validated` | RAM shares created in the destination or withdrawn in the source, and the validation point. |
| workload | `workload.relocate`, `workload.target_account` | workload relocation into another account (the recreate strategy). Evaluated at every stage from the account's workload inventory (stacks, resource sample, resource policies) and marked `evaluated`, `partially-evaluated` or `not-evaluated` according to its coverage. |

A stage that changes no layer is a verification point: the transition
compares the state with itself and inventories what applies to the account
there (useful as the first stage, "current membership and governance").

## The file

```yaml
schema_version: 1
name: Payments production into Fernhill, staged
account: "111111111115"
strategy: transfer                   # or recreate
source: larkspur-holdings.json       # optional, relative to this file; CLI flags override
destination: fernhill-group.json
critical_operations:                 # evaluated at every stage next to the observed usage
  - action: ec2:CreateTransitGatewayVpcAttachment
    regions: [eu-west-1]
    reason: disaster recovery attaches the standby VPC
proposed:                            # objects that do not exist in the snapshots
  organizational_units:
    - {id: ou-proposed-legacy, name: Legacy, parent: r-fern, policies: [p-fern0002]}
  policies:
    - id: p-proposed-tighten
      name: Fernhill-Payments-Tightening
      type: SERVICE_CONTROL_POLICY
      document: {Version: "2012-10-17", Statement: [{Effect: Deny, Action: iam:CreateUser, Resource: "*"}]}
  resource_shares:
    - name: fernhill-payments-transit
      owner_account: "222222222222"
      principals: ["111111111115"]
      allow_external_principals: true
      resources: [{arn: "arn:aws:ec2:eu-west-1:222222222222:transit-gateway/tgw-0fernhill000000001", type: ec2:TransitGateway}]
stages:
  - {id: current, title: Current source membership and governance}
  - {id: prerequisites, title: Prerequisites, network: {recreate_shares: [fernhill-payments-transit]}}
  - {id: enter, title: Destination entry at the root, membership: {organization: destination}}
  - {id: legacy, title: Transitional Legacy OU, placement: {parent: ou-proposed-legacy}}
  - {id: validate, title: Validation, network: {validated: true}, verify: [attachment created, assignments granted]}
  - {id: enroll, title: Enrollment, placement: {parent: ou-fern-pay1}, governance: {enrolled: true, execution_role_present: true}}
  - {id: tighten, title: Tightening, policies: {attach: [{policy: p-proposed-tighten, target: "111111111115"}]}}
```

| Key | Meaning |
| --- | --- |
| `account` | The account that moves. |
| `strategy` | `transfer` (move the account) or `recreate` (new accounts, migrate workloads). Both are always compared; the selected one is marked. |
| `critical_operations[]` | `action`, optional `resource`, `regions`, `principal_arn`, `principal_tags`, and a required `reason`. Declared operations are evaluated like observed ones and their findings say `declared`. Historical API activity alone misses deployments, recovery, scaling and rarely used operations; declare them here. |
| `proposed.organizational_units[]` | `id` (synthetic, must not exist in the snapshot), `name`, `parent` (existing or proposed), `policies` attached from creation (existing or proposed IDs), `register` (registered with Control Tower from creation). Organizations attaches the AWS managed defaults to a new OU; the derived state does too. |
| `proposed.policies[]` | `id`, `name`, `type`, `description`, `document` (a YAML mapping or a JSON string). SCP and RCP documents are parsed and validated like collected ones. |
| `proposed.resource_shares[]` | `name`, `owner_account`, `principals`, `resources` (`arn`, `type`), `allow_external_principals`, `retain_sharing_on_account_leave_organization`. A share exists from the stage whose `network.recreate_shares` names it. |
| `stages[].governance.execution_role_present`, `config_resources_removed` | Declarations about the enrollment prerequisites. Unset is unknown (REVIEW), true is satisfied (INFO), false blocks the stage (NO-GO). |
| `stages[].verify[]` | Checks the operator performs at the stage. Reported in the plan, never performed. A `validated: true` stage without them is reported as missing evidence. |

Unknown keys are errors. References to roots, OUs, policies and accounts are
checked against the snapshots when the scenario runs: a proposed OU whose
ID exists in the snapshot, a parent that exists in neither, or a destination
stage without a destination snapshot stop the run before anything is
evaluated.

## What the derivation does

- **Entering the destination** copies the destination snapshot, adds every
  proposed OU and policy, the proposed shares created so far, and the
  account: without its tags (Organizations deletes them on leaving), with
  `joined_method` INVITED, with the AWS managed defaults attached, with its
  usage and declared operations carried over. The transition into that stage
  is the cross-organization evaluation.
- **Placement** moves the account under the given parent in the current
  organization's derived snapshot. A proposed OU inherits every policy
  attached above it; the stage finding lists them and names the explicit
  denies, which nothing attached to the OU or the account can override.
- **Governance** adds a `PROPOSED` enrolment record (source `manual`) or a
  `PROPOSED` registered OU. Enrolling into an unregistered OU or the root,
  or without a landing zone, is NO-GO; the prerequisites finding says which
  declarations are satisfied, missing or declared unsatisfied (transfer
  procedure model, see docs/aws-behaviour.md).
- **Network** adds the named proposed shares (status `PROPOSED`) to the
  organization that owns them or removes withdrawn shares; the RAM check of
  the transition then reports what becomes available or is lost.
- **Workload** marks the state as relocated and adds a finding that lists
  what has to be brought into the other account, grouped by deployment
  provenance (redeployable from a template or pipeline, recreated by
  Control Tower or a StackSet, manual or unknown) with counts, what
  constrains the redeployment and what the inventory cannot say. Without an
  inventory for the account the finding is missing evidence: the
  relocation is declared, not evaluated.
- The workload inventory travels with the account. When the account enters
  another organization, the derived state carries its inventory without
  the stacks a service-managed StackSet deletes on leaving (automatic
  deployment on, stacks not retained), so the stages after entry check the
  tag policies of each new position against what is still there.

Each derived snapshot passes the same validation as a collected one.

## The report

`stages_schema_version` 2. Per stage: `layers` (five entries, `changed` and
a summary; the workload entry also has `evaluation` and a `detail` with the
inventory counts and what the workloads check found at that stage), `state` (organization, path, parent, enrolled, governed,
proposed shares present, proposed nodes on the path, workload relocated),
`findings` (the stage's own, each with an impact category), `transition`
(the full `orgshift simulate` result for the move from the previous state,
`result_schema_version` 4), `verify` and `verdict`. The report also carries
the proposed objects, the declared critical operations, the two strategies
with prerequisites, risks, remaining unknowns and reversal limitations, the
models used and the standing limitations of the offline evaluation.

The recreate strategy carries `redeploy`: the redeployment plan built from
the workload inventory of the account. It has the evaluation level, one
entry per provenance group with counts (stacks, resources in stacks,
sampled resources outside any stack) and the items with their provenance
and confidence, the dependencies that constrain a redeployment (import
order, cross-account stack outputs, networking taken from outside the
template, stateful resources, policies tied to organization identity, what
the source's platform deployed) and the unknowns. It is an inventory with
counts, not an estimate of effort, and "unknown" stays visible in it.

The derived snapshots themselves are never exported; the UI draws the final
one next to the current hierarchy with proposed nodes marked.

## Impact categories (Section 7)

Every finding, in single simulations and in stages, carries a `category`,
a `confidence` and, for findings about an operation, a `source`:

| Category | Meaning |
| --- | --- |
| `known-restriction` | A policy or control restricts something, and nothing declared or observed depends on it, or it is restricted today already. |
| `declared-impact` | A restriction or change hits an operation the account performs (observed usage), one the operator declared as critical, or the migration operation itself. |
| `potential-impact` | An operation may be affected but deciding it needs context the snapshot does not carry (a request value in a condition, a behaviour AWS does not document, an operator decision). |
| `unsupported-evaluation` | The offline evaluator does not model this (an operator, a policy variable, a resource owned outside both snapshots). |
| `missing-evidence` | The input lacks what the check needs (no usage list, no resource sample, an incompletely collected domain, a validation point without steps). |
| `informational` | A change that is neither a restriction nor a problem. |

`source` is `observed` (from the snapshot's usage) or `declared` (a
critical operation). `confidence` is `high` for decisions made from an
explicit statement or a documented rule, `medium` for potential impact and
unsupported evaluations, `low` for missing evidence.

The condition keys evaluated with explicit context now include
`aws:PrincipalOrgPaths` and `aws:ResourceOrgPaths`, built from the
organization ID, root and OU path before and after each transition (the
result's `subject.source_org_path` and `target_org_path`). The standing
limitations are repeated on every result: an SCP or RCP allow is not an IAM
grant; identity policies, resource policies, permissions boundaries and
session policies are not evaluated; tag policies report compliance on the
sampled resources and enforce only for the listed resource types and never
require a tag at creation on their own; RAM data-plane continuity is
modelled, not tested.
