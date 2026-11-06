# The migration runbook

Every simulation result can be turned into a runbook: an ordered checklist
of what to do before, during and after the move, and how to undo it. It is
built from the verdict board, so every step points back at the check and
the finding it came from and carries the same evidence.

The runbook is a document. Its commands are AWS CLI calls written out for
an operator to review and run by hand, with real IDs from the snapshots
where they are known and `<angle brackets>` where a value only exists once
something has been created. orgshift never runs any of them and never
writes to AWS.

## Where to get it

- UI: the "Migration runbook" panel on every result page, rendered as a
  checklist. Ticks are stored in the browser's localStorage under the
  query of the result, so reloading the same move keeps them; nothing is
  sent anywhere. "Export runbook" downloads the Markdown; `/runbook.json`
  with the same query gives the JSON.
- CLI: `orgshift simulate … --format runbook` (Markdown) or
  `--format runbook-json`. The exit code is still the verdict's.

## Phases

1. **Before the move: fix the blockers and make the decisions.** Every
   NO-GO and REVIEW finding that has to be settled while the account is
   still at its current position. Denied actions are grouped by the SCP or
   RCP statement that denies them, with the level it is attached at, the
   actions and regions affected, the exact change to review (edit the
   statement, detach the policy, or stop using the actions; for a Control
   Tower guardrail, disable the control instead) and the statement JSON as
   evidence. Conditions that could not be decided offline are decisions.
   Also here: enforced tag non-compliance to fix while tagging is still
   allowed, delegated administration to hand over, the organization trail
   or Config aggregator the account owns, Control Tower unenrolment,
   references to the `AWSReservedSSO_*` roles to find, stale permission
   sets to deprovision, and the transfer itself: a deny on
   `organizations:LeaveOrganization` in the source SCP chain (a blocker for
   a direct transfer, with the statement as evidence; with leave-and-rejoin
   the management account can remove the account instead), the plan for
   the interval at the destination root, the root MFA decision, each
   eligibility requirement that is not met (organization younger than seven
   days, Seller of Record mismatch, closed or suspended account, created
   account younger than four days) as a blocker of its own, and one step
   listing the requirements the snapshots cannot confirm. The standalone
   prerequisites appear only with the leave-and-rejoin method. A management
   account gets a single stop step: it has no single-account runbook.
2. **Before the move: re-create what does not travel.** RAM shares
   re-shared with the account ID directly (with external principals
   allowed for a different organization), the account's own shares offered
   to the old organization, permission sets to create or review in the
   target Identity Center instance (with the `create-permission-set` and
   attach calls built from the source permission set), StackSets to
   replace, trusted access to enable, the `AWSControlTowerExecution` role a
   later enrolment needs.
3. **The move.** Inside one organization a single `move-account`, or the
   Account Factory update flow when Control Tower governs the account.
   Across organizations, by direct transfer (the default): invite from the
   target, accept the handshake inside the account (which takes it out of
   the source and into the target root in one step; no
   `leave-organization`), move from the target root into the target OU.
   With `--transfer-method leave-and-rejoin`: invite, leave the source (or
   be removed by its management account), accept, move.
4. **After the move: checks.** The account's parent and the policies that
   reach it, share invitations to accept, CloudTrail and Config coverage,
   Control Tower enrolment and the controls that start applying, Identity
   Center assignments to create (with the identity store lookups per user
   or group), references to the old roles to update, the flagged requests
   to exercise, and a fresh collect-and-simulate that should come back GO.
5. **Rollback.** Built from the source side of the result: move back (or,
   across organizations, have the source invite the account back and
   accept: another direct transfer, blocked by a deny on
   `organizations:LeaveOrganization` in the target's chain, which the step
   names when there is one), re-attach the policies that were
   attached directly to the account, re-create the Identity Center
   assignments in the source instance from the snapshot's principal IDs,
   re-delegate, re-enroll, and verify the original policy chain, which is
   recorded as evidence root to account.

Whole-OU moves add OU-level phases in front of the per-account checklists:
Organizations has no call that moves an OU, so the tree is created again
under the new parent (customer-managed policies are recreated first across
organizations, with their documents as evidence), the same policies are
attached, the accounts are moved one by one, the empty source OUs are
deleted, and registered OUs are deregistered before and registered again
after. Each account's own checklist then defers to the OU for the move and
the rollback.

## JSON shape

```json
{
  "tool": "orgshift",
  "runbook_schema_version": 1,
  "subject": { "account_id": "111111111115", "...": "same as the result" },
  "verdict": "NO-GO",
  "summary": "53 steps: 12 before the move (4 blocking), …",
  "phases": [
    {
      "id": "before",
      "title": "Before the move: fix the blockers and make the decisions",
      "intro": "…",
      "steps": [
        {
          "id": "before-1",
          "title": "SCP Fernhill-EU-Only-Regions / DenyOutsideEU denies 15 actions after the move",
          "detail": "…",
          "status": "NO-GO",
          "kind": "policy-change",
          "where": "management account 222222222221 of Fernhill Group",
          "check": "scp",
          "finding": "15 findings with the same cause",
          "actions": ["ec2:RunInstances", "…"],
          "commands": ["aws organizations describe-policy --policy-id p-fern0002 --query Content --output text", "…"],
          "evidence": [{ "kind": "policy-statement", "side": "target", "policy_id": "p-fern0002", "statement": "DenyOutsideEU", "statement_json": {} }]
        }
      ]
    }
  ],
  "notes": ["Generated from a snapshot simulation. …"]
}
```

Phase IDs are `before`, `recreate`, `move`, `after` and `rollback`. A
step's `status` is the status of the finding it comes from (NO-GO blocks
the move, REVIEW needs a decision, INFO is optional) and is absent on
routine steps such as the move itself. `kind` is one of `blocker`,
`policy-change`, `decision`, `input`, `tags`, `resource-share`,
`delegated-admin`, `logging`, `stackset`, `trusted-access`,
`prerequisite`, `control-tower`, `identity-center`,
`organizational-unit`, `workload`, `resource-policy`, `move`, `check` and
`rollback`.

The Workloads check adds steps of its own (check `workloads`): before the
move, keep or replace a stack before its StackSet deletes it, move a stack
that keeps creating resources off shared networking, change a bucket or
trust policy so it names the destination organization, and decide where a
stack reads a cross-account output from; with what does not travel, plan
the stacks that only sit on shared networking; afterwards, confirm what
became of the StackSet instance, adopt the stacks a StackSet left behind,
take the former organization out of the policies that were widened for the
transition and check that the cross-account output still resolves. A
missing workload inventory is a collection step that names the account to
add under `member_inspection.accounts`.

An OU runbook has the same shape with an `ou_id`/`ou_name` subject, its
step IDs prefixed `ou-`, and an `accounts` list holding one account
runbook per account in the rollup order.
