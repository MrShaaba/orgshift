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
   sets to deprovision, the standalone prerequisites, and any unconditional
   deny on `organizations:LeaveOrganization` found in the source SCP chain
   (lift it, or let the management account remove the account).
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
   Across organizations: invite from the target, leave the source (or be
   removed by its management account), accept the handshake, move from the
   target root into the target OU.
4. **After the move: checks.** The account's parent and the policies that
   reach it, share invitations to accept, CloudTrail and Config coverage,
   Control Tower enrolment and the controls that start applying, Identity
   Center assignments to create (with the identity store lookups per user
   or group), references to the old roles to update, the flagged requests
   to exercise, and a fresh collect-and-simulate that should come back GO.
5. **Rollback.** Built from the source side of the result: move back (or
   leave, re-invite, accept, move), re-attach the policies that were
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
`organizational-unit`, `move`, `check` and `rollback`.

An OU runbook has the same shape with an `ou_id`/`ou_name` subject, its
step IDs prefixed `ou-`, and an `accounts` list holding one account
runbook per account in the rollup order.
