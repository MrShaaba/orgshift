# Permissions for `orgshift collect`

The collector is read-only by construction:

- every API operation it may call is listed in `internal/collector/allowlist.go`;
- `TestOnlyAllowlistedOperationsAreReferenced` fails if any source file in
  the collector package calls an operation that is not on that list, and
  `TestAllowlistRejectsWriteVerbs` fails if the list ever contains a verb other
  than `List`, `Describe` or `Get`;
- the rest of the tool (`simulate`, `serve`) never touches AWS at all.

Credentials come from the standard AWS credential chain (`--profile`,
environment variables, SSO, instance roles). orgshift stores no credentials
and writes none into snapshots.

## Minimal IAM policy

Attach this to the role or user you run the collector with, in the
management account or in an account that is a delegated administrator for
Organizations. The action list is exactly the allowlist.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "OrgshiftReadOnly",
      "Effect": "Allow",
      "Action": [
        "account:ListRegions",
        "organizations:DescribeOrganization",
        "organizations:DescribePolicy",
        "organizations:ListAWSServiceAccessForOrganization",
        "organizations:ListAccountsForParent",
        "organizations:ListDelegatedAdministrators",
        "organizations:ListDelegatedServicesForAccount",
        "organizations:ListOrganizationalUnitsForParent",
        "organizations:ListPolicies",
        "organizations:ListRoots",
        "organizations:ListTagsForResource",
        "organizations:ListTargetsForPolicy",
        "ram:GetResourceShares",
        "ram:ListPrincipals",
        "ram:ListResources"
      ],
      "Resource": "*"
    }
  ]
}
```

Notes:

- `account:ListRegions` for member accounts requires trusted access for
  `account.amazonaws.com` in the organization. If the call fails for an
  account the collector logs a warning and leaves `enabled_regions` empty;
  pass `--skip-regions` to avoid the calls entirely.
- RAM only lists shares owned by the calling account. If your transit
  gateway, subnets or resolver rules are shared from a network account, run
  the collector with `--ram-profiles network-account-profile` so those shares
  are included. Each extra profile needs the three `ram:*` actions above.
- The AWS managed `ReadOnlyAccess` or `AWSOrganizationsReadOnlyAccess`
  policies also cover these calls, but are far broader than needed.

## What is not collected, and why

| Data | Status | Cost |
| --- | --- | --- |
| Organization trails, Config aggregators, StackSets | Not collected in this version; add them to the snapshot by hand (see `docs/snapshot.md`). On the roadmap. | Free API calls when added. |
| Actions in use | Entered by hand or imported from an IAM last-accessed export with `orgshift simulate --last-accessed export.json`. Generating that export (`aws iam generate-service-last-accessed-details`) is free. | Free. |
| Actions in use from CloudTrail Lake | `--with-cloudtrail-lake` exists but is refused in this version. | Billed per TB of event data scanned per query. Will stay opt-in and off by default. |
| Resource inventories from Config advanced queries | `--with-config-queries` exists but is refused in this version. | Billed per advanced query against an aggregator. Will stay opt-in and off by default. |
| Resource tags for tag policy checks | Entered by hand under `usage.tagged_resources`. The Resource Groups Tagging API (`tag:GetResources`) is a free candidate source for a later version. | Free. |

Nothing in orgshift calls `MoveAccount`, `AttachPolicy`, `DetachPolicy`,
`CreateOrganizationalUnit`, `InviteAccountToOrganization`,
`LeaveOrganization` or any other write operation, and the tests keep it that
way.
