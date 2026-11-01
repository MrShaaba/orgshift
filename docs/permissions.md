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
        "controlcatalog:GetControl",
        "controltower:GetLandingZone",
        "controltower:ListEnabledBaselines",
        "controltower:ListEnabledControls",
        "controltower:ListLandingZones",
        "identitystore:DescribeGroup",
        "identitystore:DescribeUser",
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
        "ram:ListResources",
        "sso:DescribePermissionSet",
        "sso:GetInlinePolicyForPermissionSet",
        "sso:GetPermissionsBoundaryForPermissionSet",
        "sso:ListAccountAssignments",
        "sso:ListAccountsForProvisionedPermissionSet",
        "sso:ListCustomerManagedPolicyReferencesInPermissionSet",
        "sso:ListInstances",
        "sso:ListManagedPoliciesInPermissionSet",
        "sso:ListPermissionSets"
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
- The Control Tower landing zone APIs answer only in the landing zone's
  home region, so run the collector with `--region` set to it. If
  `ListLandingZones` fails or finds nothing the collector logs a line and
  writes the snapshot without a `control_tower` block; `--skip-control-tower`
  avoids the five calls entirely. `controlcatalog:GetControl` is used to
  name each enabled control and record whether it is preventive, detective
  or proactive; without it controls are kept by identifier only.
- The IAM Identity Center APIs answer only in the instance's region, so
  run the collector with `--region` set to it (usually the same region as
  the Control Tower home region). If `ListInstances` fails or finds nothing
  the collector logs a line and writes the snapshot without an
  `identity_center` block; `--skip-identity-center` avoids the eleven calls
  entirely. Assignments are listed per account each permission set is
  provisioned in (`ListAccountsForProvisionedPermissionSet`, then
  `ListAccountAssignments`), so the number of calls grows with permission
  sets times accounts. `identitystore:DescribeUser` and `DescribeGroup`
  only turn principal IDs into names; without them assignments are recorded
  by ID.
- The AWS managed `ReadOnlyAccess` or `AWSOrganizationsReadOnlyAccess`
  policies also cover these calls, but are far broader than needed.

## What is not collected, and why

| Data | Status | Cost |
| --- | --- | --- |
| Organization trails, Config aggregators, StackSets | Not collected in this version; add them to the snapshot by hand (see `docs/snapshot.md`). On the roadmap. | Free API calls when added. |
| Control Tower enrolled accounts and Account Factory provenance | Not collected: Service Catalog only exposes provisioned products through `SearchProvisionedProducts`, which is outside the `List`/`Describe`/`Get` rule. Accounts in registered OUs are assumed enrolled; list `control_tower.enrolled_accounts` by hand to be exact. | Free. |
| Identity Center group memberships and the exact `AWSReservedSSO_*` role names | Not collected. Memberships would need `identitystore:ListGroupMemberships` per group and do not change the verdict; the role suffix is only visible to IAM inside each member account, so roles are reported as `AWSReservedSSO_<permission set>_*`. | Free. |
| Actions in use | Entered by hand or imported from an IAM last-accessed export with `orgshift simulate --last-accessed export.json`. Generating that export (`aws iam generate-service-last-accessed-details`) is free. | Free. |
| Actions in use from CloudTrail Lake | `--with-cloudtrail-lake` exists but is refused in this version. | Billed per TB of event data scanned per query. Will stay opt-in and off by default. |
| Resource inventories from Config advanced queries | `--with-config-queries` exists but is refused in this version. | Billed per advanced query against an aggregator. Will stay opt-in and off by default. |
| Resource tags for tag policy checks | Entered by hand under `usage.tagged_resources`. The Resource Groups Tagging API (`tag:GetResources`) is a free candidate source for a later version. | Free. |

Nothing in orgshift calls `MoveAccount`, `AttachPolicy`, `DetachPolicy`,
`CreateOrganizationalUnit`, `InviteAccountToOrganization`,
`LeaveOrganization`, `EnableControl`, `DisableControl`, `EnableBaseline`,
`UpdateLandingZone`, `CreateAccountAssignment`, `DeleteAccountAssignment`,
`ProvisionPermissionSet` or any other write operation, and the tests keep it
that way.
