# orgshift runbook: larkspur-payments-prod (111111111115)

Move from **Larkspur Holdings** (`o-larkspur0001`) Root / Workloads / Production to **Fernhill Group** (`o-fernhill0001`) Root / Business Units / Payments.

**Verdict NO-GO.** 73 steps: 18 before the move (6 blocking), 13 to re-create, 4 for the move itself, 32 checks afterwards and 6 to roll back.

> Generated from a snapshot simulation. Every command is for an operator to review and run by hand; orgshift never writes to AWS.

## 1. Before the move: fix the blockers and make the decisions

Everything here is settled while the account is still at its current position. NO-GO steps block the move; REVIEW steps need a decision or a check by hand.

- [ ] **1.1** `NO-GO` SCP Fernhill-EU-Only-Regions / DenyOutsideEU denies 15 actions after the move
  _Where:_ management account 222222222221 of Fernhill Group

  Attached at OU Business Units (ou-fern-bu) in the target organization. Allowed today; after the move it denies: cloudwatch:PutMetricData in ap-southeast-1, us-east-1; dynamodb:* in ap-southeast-1, us-east-1; ec2:CreateTransitGatewayVpcAttachment in ap-southeast-1, us-east-1; ec2:CreateVpc in ap-southeast-1, us-east-1; ec2:DescribeInstances in ap-southeast-1, us-east-1; ec2:RunInstances in ap-southeast-1, us-east-1; ec2:TerminateInstances in ap-southeast-1, us-east-1; kms:Decrypt in ap-southeast-1, us-east-1; lambda:InvokeFunction in ap-southeast-1, us-east-1; logs:CreateLogGroup in ap-southeast-1, us-east-1; rds:CreateDBInstance in us-east-1; rds:DescribeDBInstances in ap-southeast-1, us-east-1; s3:GetObject in ap-southeast-1, us-east-1; s3:PutObject in ap-southeast-1, us-east-1; secretsmanager:GetSecretValue in ap-southeast-1, us-east-1. The change to review: edit statement DenyOutsideEU so it no longer covers account 111111111115 (for example a Condition on aws:PrincipalAccount, or a narrower Action or Resource list), detach Fernhill-EU-Only-Regions from OU Business Units (ou-fern-bu), or stop using the actions before the move.

  actions `cloudwatch:PutMetricData`, `dynamodb:*`, `ec2:CreateTransitGatewayVpcAttachment`, `ec2:CreateVpc`, `ec2:DescribeInstances`, `ec2:RunInstances`, `ec2:TerminateInstances`, `kms:Decrypt`, `lambda:InvokeFunction`, `logs:CreateLogGroup`, `rds:CreateDBInstance`, `rds:DescribeDBInstances`, `s3:GetObject`, `s3:PutObject`, `secretsmanager:GetSecretValue`

  _From the scp check: 15 findings with the same cause._

  ```sh
  aws organizations describe-policy --policy-id p-fern0002 --query Content --output text
  # after editing the document by hand:
  aws organizations update-policy --policy-id p-fern0002 --content file://Fernhill-EU-Only-Regions.json
  ```

  - Evidence (policy-statement): target, SCP `Fernhill-EU-Only-Regions` (p-fern0002), statement DenyOutsideEU, at OU Business Units (ou-fern-bu)

    ```json
    {
      "Sid": "DenyOutsideEU",
      "Effect": "Deny",
      "NotAction": [
        "iam:*",
        "sts:*",
        "organizations:*",
        "support:*",
        "budgets:*",
        "cloudfront:*",
        "route53:*",
        "waf:*",
        "health:*",
        "account:*",
        "access-analyzer:*",
        "trustedadvisor:*"
      ],
      "Resource": "*",
      "Condition": {
        "StringNotEquals": {
          "aws:RequestedRegion": [
            "eu-west-1",
            "eu-central-1"
          ]
        }
      }
    }
    ```

- [ ] **1.2** `NO-GO` SCP Fernhill-Payments-Controls / CentralNetworkingOnly denies 2 actions after the move
  _Where:_ management account 222222222221 of Fernhill Group

  Attached at OU Payments (ou-fern-pay1) in the target organization. Allowed today; after the move it denies: ec2:CreateTransitGatewayVpcAttachment in eu-west-1; ec2:CreateVpc in eu-west-1. The change to review: edit statement CentralNetworkingOnly so it no longer covers account 111111111115 (for example a Condition on aws:PrincipalAccount, or a narrower Action or Resource list), detach Fernhill-Payments-Controls from OU Payments (ou-fern-pay1), or stop using the actions before the move.

  actions `ec2:CreateTransitGatewayVpcAttachment`, `ec2:CreateVpc`

  _From the scp check: 2 findings with the same cause._

  ```sh
  aws organizations describe-policy --policy-id p-fern0003 --query Content --output text
  # after editing the document by hand:
  aws organizations update-policy --policy-id p-fern0003 --content file://Fernhill-Payments-Controls.json
  ```

  - Evidence (policy-statement): target, SCP `Fernhill-Payments-Controls` (p-fern0003), statement CentralNetworkingOnly, at OU Payments (ou-fern-pay1)

    ```json
    {
      "Sid": "CentralNetworkingOnly",
      "Effect": "Deny",
      "Action": [
        "ec2:CreateVpc",
        "ec2:DeleteVpc",
        "ec2:CreateInternetGateway",
        "ec2:AttachInternetGateway",
        "ec2:CreateVpcPeeringConnection",
        "ec2:CreateTransitGatewayVpcAttachment"
      ],
      "Resource": "*"
    }
    ```

- [ ] **1.3** `NO-GO` SCP Fernhill-Root-Guardrails / NoIAMUsers denies 1 action after the move
  _Where:_ management account 222222222221 of Fernhill Group

  Attached at root Root (r-fern) in the target organization. Allowed today; after the move it denies: iam:CreateUser. The change to review: edit statement NoIAMUsers so it no longer covers account 111111111115 (for example a Condition on aws:PrincipalAccount, or a narrower Action or Resource list), detach Fernhill-Root-Guardrails from root Root (r-fern), or stop using the actions before the move.

  actions `iam:CreateUser`

  _From the scp check: iam:CreateUser becomes denied after the move._

  ```sh
  aws organizations describe-policy --policy-id p-fern0001 --query Content --output text
  # after editing the document by hand:
  aws organizations update-policy --policy-id p-fern0001 --content file://Fernhill-Root-Guardrails.json
  ```

  - Evidence (policy-statement): target, SCP `Fernhill-Root-Guardrails` (p-fern0001), statement NoIAMUsers, at root Root (r-fern)

    ```json
    {
      "Sid": "NoIAMUsers",
      "Effect": "Deny",
      "Action": [
        "iam:CreateUser",
        "iam:CreateAccessKey",
        "iam:CreateLoginProfile"
      ],
      "Resource": "*"
    }
    ```

- [ ] **1.4** `REVIEW` Decide whether SCP Fernhill-Payments-Controls / TerminateNeedsPlatformTag applies to 1 action
  _Where:_ management account 222222222221 of Fernhill Group

  Attached at OU Payments (ou-fern-pay1). Cannot be decided offline: StringNotEquals aws:PrincipalTag/team cannot be evaluated: the value of aws:PrincipalTag/team is not known for this account. Affected: ec2:TerminateInstances in eu-west-1. Check the condition against the real callers; if it matches, treat this as a blocker and edit statement TerminateNeedsPlatformTag so it no longer covers account 111111111115 (for example a Condition on aws:PrincipalAccount, or a narrower Action or Resource list), detach Fernhill-Payments-Controls from OU Payments (ou-fern-pay1), or stop using the actions before the move. If it does not, record the decision here.

  actions `ec2:TerminateInstances`; regions eu-west-1

  _From the scp check: ec2:TerminateInstances needs review after the move._

  ```sh
  aws organizations describe-policy --policy-id p-fern0003 --query Content --output text
  # after editing the document by hand:
  aws organizations update-policy --policy-id p-fern0003 --content file://Fernhill-Payments-Controls.json
  ```

  - Evidence (policy-statement): target, SCP `Fernhill-Payments-Controls` (p-fern0003), statement TerminateNeedsPlatformTag, at OU Payments (ou-fern-pay1)
    StringNotEquals aws:PrincipalTag/team cannot be evaluated: the value of aws:PrincipalTag/team is not known for this account

    ```json
    {
      "Sid": "TerminateNeedsPlatformTag",
      "Effect": "Deny",
      "Action": [
        "ec2:TerminateInstances",
        "rds:DeleteDBInstance"
      ],
      "Resource": "*",
      "Condition": {
        "StringNotEquals": {
          "aws:PrincipalTag/team": "platform"
        }
      }
    }
    ```

- [ ] **1.5** `NO-GO` RCP Fernhill-Block-External-Principals / EnforceOrgIdentities denies 4 requests after the move
  _Where:_ management account 222222222221 of Fernhill Group

  Attached at OU Business Units (ou-fern-bu) in the target organization. Allowed today; after the move it denies: kms:Decrypt by arn:aws:iam::111111111118:role/DataPlatformIngest in us-east-1; s3:GetObject by 999999999999 in ap-southeast-1, eu-west-1, us-east-1; s3:ListBucket by 999999999999 in ap-southeast-1, eu-west-1, us-east-1; sts:AssumeRole by arn:aws:iam::111111111118:role/DataPlatformIngest. The change to review: edit statement EnforceOrgIdentities so these principals are exempt (for example list their organization in the aws:PrincipalOrgID condition, or exempt the resource), detach Fernhill-Block-External-Principals from OU Business Units (ou-fern-bu), or move the callers inside the target organization.

  actions `kms:Decrypt`, `s3:GetObject`, `s3:ListBucket`, `sts:AssumeRole`

  _From the rcp check: 4 findings with the same cause._

  ```sh
  aws organizations describe-policy --policy-id p-fern0006 --query Content --output text
  # after editing the document by hand:
  aws organizations update-policy --policy-id p-fern0006 --content file://Fernhill-Block-External-Principals.json
  ```

  - Evidence (policy-statement): target, RCP `Fernhill-Block-External-Principals` (p-fern0006), statement EnforceOrgIdentities, at OU Business Units (ou-fern-bu)

    ```json
    {
      "Sid": "EnforceOrgIdentities",
      "Effect": "Deny",
      "Principal": "*",
      "Action": [
        "s3:*",
        "sts:AssumeRole",
        "sts:SetContext",
        "kms:*",
        "sqs:*",
        "secretsmanager:*"
      ],
      "Resource": "*",
      "Condition": {
        "StringNotEqualsIfExists": {
          "aws:PrincipalOrgID": "o-fernhill0001"
        },
        "BoolIfExists": {
          "aws:PrincipalIsAWSService": "false"
        }
      }
    }
    ```

- [ ] **1.6** `REVIEW` Decide whether RCP Fernhill-Block-External-Principals / EnforceOrgIdentities applies to 1 request
  _Where:_ management account 222222222221 of Fernhill Group

  Attached at OU Business Units (ou-fern-bu). Cannot be decided offline: StringNotEqualsIfExists aws:PrincipalOrgID cannot be evaluated: the value of aws:PrincipalOrgID is not known for this account. Affected: sqs:SendMessage by 888888888888 in us-east-1. Check the condition against the real callers; if it matches, treat this as a blocker and edit statement EnforceOrgIdentities so these principals are exempt (for example list their organization in the aws:PrincipalOrgID condition, or exempt the resource), detach Fernhill-Block-External-Principals from OU Business Units (ou-fern-bu), or move the callers inside the target organization. If it does not, record the decision here.

  actions `sqs:SendMessage`; principal `888888888888`; resource `arn:aws:sqs:us-east-1:111111111115:fraud-events`; regions us-east-1

  _From the rcp check: sqs:SendMessage by 888888888888 needs review after the move._

  ```sh
  aws organizations describe-policy --policy-id p-fern0006 --query Content --output text
  # after editing the document by hand:
  aws organizations update-policy --policy-id p-fern0006 --content file://Fernhill-Block-External-Principals.json
  ```

  - Evidence (policy-statement): target, RCP `Fernhill-Block-External-Principals` (p-fern0006), statement EnforceOrgIdentities, at OU Business Units (ou-fern-bu)
    StringNotEqualsIfExists aws:PrincipalOrgID cannot be evaluated: the value of aws:PrincipalOrgID is not known for this account

    ```json
    {
      "Sid": "EnforceOrgIdentities",
      "Effect": "Deny",
      "Principal": "*",
      "Action": [
        "s3:*",
        "sts:AssumeRole",
        "sts:SetContext",
        "kms:*",
        "sqs:*",
        "secretsmanager:*"
      ],
      "Resource": "*",
      "Condition": {
        "StringNotEqualsIfExists": {
          "aws:PrincipalOrgID": "o-fernhill0001"
        },
        "BoolIfExists": {
          "aws:PrincipalIsAWSService": "false"
        }
      }
    }
    ```

- [ ] **1.7** `REVIEW` Re-tag before the move: cost-center: ec2:instance resources use the key "Cost-Center" instead of "cost-center"
  _Where:_ account larkspur-payments-prod (111111111115)

  The target tag policy (Fernhill-Cost-Allocation, Fernhill-Payments-Cost-Centers) fixes the key capitalization. The policy enforces this for ec2:instance: after the move, tag operations that would leave such a resource non-compliant are rejected (enforcement on supported operations); the existing tags themselves are not changed. Affected: 3 resource(s), for example arn:aws:ec2:us-east-1:111111111115:instance/i-f10bba738feab223b, arn:aws:ec2:us-east-1:111111111115:instance/i-c532d94e1b98a3356, arn:aws:ec2:us-east-1:111111111115:instance/i-f5e303bf12e951c05. Do it before the move: afterwards the target tag policy rejects non-compliant tag operations on these resource types, so the fix itself is blocked.

  resource `arn:aws:ec2:us-east-1:111111111115:instance/i-f10bba738feab223b, arn:aws:ec2:us-east-1:111111111115:instance/i-c532d94e1b98a3356, arn:aws:ec2:us-east-1:111111111115:instance/i-f5e303bf12e951c05`

  _From the tags check: cost-center: ec2:instance resources use the key "Cost-Center" instead of "cost-center"._

  ```sh
  aws resourcegroupstaggingapi tag-resources --resource-arn-list arn:aws:ec2:us-east-1:111111111115:instance/i-f10bba738feab223b arn:aws:ec2:us-east-1:111111111115:instance/i-c532d94e1b98a3356 arn:aws:ec2:us-east-1:111111111115:instance/i-f5e303bf12e951c05 --tags <Key>=<allowed value>
  ```

  - Evidence (tag-compliance): target
    arn:aws:ec2:us-east-1:111111111115:instance/i-f10bba738feab223b
    arn:aws:ec2:us-east-1:111111111115:instance/i-c532d94e1b98a3356
    arn:aws:ec2:us-east-1:111111111115:instance/i-f5e303bf12e951c05

- [ ] **1.8** `REVIEW` Re-tag before the move: cost-center: rds:db resources use the value "PAY-01" which is not allowed
  _Where:_ account larkspur-payments-prod (111111111115)

  Allowed values (Fernhill-Cost-Allocation, Fernhill-Payments-Cost-Centers): CC-1001, CC-1002, CC-2001, CC-2002, CC-3001, CC-3002. The policy enforces this for rds:db: after the move, tag operations that would leave such a resource non-compliant are rejected (enforcement on supported operations); the existing tags themselves are not changed. Affected: 1 resource(s), for example arn:aws:rds:us-east-1:111111111115:db:payments-ledger. Do it before the move: afterwards the target tag policy rejects non-compliant tag operations on these resource types, so the fix itself is blocked.

  resource `arn:aws:rds:us-east-1:111111111115:db:payments-ledger`

  _From the tags check: cost-center: rds:db resources use the value "PAY-01" which is not allowed._

  ```sh
  aws resourcegroupstaggingapi tag-resources --resource-arn-list arn:aws:rds:us-east-1:111111111115:db:payments-ledger --tags <Key>=<allowed value>
  ```

  - Evidence (tag-compliance): target
    arn:aws:rds:us-east-1:111111111115:db:payments-ledger

- [ ] **1.9** `REVIEW` Make the account able to stand alone
  _Where:_ account larkspur-payments-prod (111111111115), signed in as root or an administrator

  Before it can leave, the account needs its own verified contact information, a payment method and a support plan choice; Organizations fails the removal with ConstraintViolationException until they are in place (with Enterprise Support, a billing case can arrange the standalone period instead of a payment method per account). It then has to be invited by the target management account 222222222221 and accept the invitation: an account belongs to one organization at a time, so it leaves first; the invitation must be answered within 15 days; the policies attached to the target root and the OU it lands in apply at once; the target's organization trail covers it automatically and Config, GuardDuty or Security Hub may be enabled automatically for new members, so account-level trails and detectors may double charges; Organizations does not create OrganizationAccountAccessRole for an invited account. SCPs in the source that deny organizations:LeaveOrganization must be lifted for the move, or the source management account removes the account instead. The account also loses access to the cost and usage data of its time in the source organization and is no longer covered by the source organization's agreements. Transfer procedure model 2026-11-02. Contact information, alternate contacts and the payment method can be checked with the Account API; identity verification and the support plan are done in the console.

  _From the org-services check: Standalone account prerequisites and invitation._

  ```sh
  aws account get-contact-information
  aws account get-alternate-contact --alternate-contact-type BILLING
  # console: Billing and Cost Management → Payment preferences; Account → Identity verification; Support → Support plan
  ```

- [ ] **1.10** `REVIEW` Lift the deny on organizations:LeaveOrganization in SCP Larkspur-Baseline-Guardrails / DenyLeaveOrganization, or let the management account remove the account
  _Where:_ management account 111111111111 of Larkspur Holdings

  SCP Larkspur-Baseline-Guardrails (p-lark0001) is attached at root Root (r-lark) and denies organizations:LeaveOrganization without a condition, so leave-organization run from inside the account fails. Either detach the policy or edit the statement for the duration of the move and put it back afterwards, or run remove-account-from-organization from the management account, which SCPs do not restrict.

  actions `organizations:LeaveOrganization`

  _From the org-services check: Standalone account prerequisites and invitation._

  ```sh
  aws organizations describe-policy --policy-id p-lark0001 --query Content --output text
  aws organizations remove-account-from-organization --account-id 111111111115   # the alternative that needs no policy change
  ```

  - Evidence (policy-statement): source, SCP `Larkspur-Baseline-Guardrails` (p-lark0001), statement DenyLeaveOrganization, at root Root (r-lark)
    Deny organizations:LeaveOrganization

- [ ] **1.11** `REVIEW` Find what references the 4 AWSReservedSSO_* role(s) of the account
  _Where:_ account larkspur-payments-prod (111111111115)

  When the account leaves the organization, Identity Center cleans up the resources it created in the account; the documentation names the service-linked role, and the IAM roles provisioned for permission sets (path /aws-reserved/sso.amazonaws.com/us-east-1/) go with the instance's control over the account, so plan for them to disappear and confirm in IAM after the move. Anything that names these roles breaks: resource and trust policies, KMS key policies, S3 bucket policies, EKS access entries, pipelines and tools that assume them, and CloudTrail history keeps the old ARNs. The target instance provisions new roles with a different random suffix, so references have to be updated, not restored. The exact suffix is only visible in IAM; offline the roles are known by their pattern. 1 of them (AWSReservedSSO_DataPlatformOperator_*) are provisioned without any assignment and are already unused; deprovisioning the permission set from the account before the move removes them cleanly. List the exact role ARNs now, while they exist, and search for them so the references can be updated after the move.

  _From the identity-center check: 4 AWSReservedSSO\_* role(s) are deleted from the account: AWSReservedSSO\_AdministratorAccess\_*, AWSReservedSSO\_PaymentsEngineer\_*, AWSReservedSSO\_ReadOnlyAccess\_*, AWSReservedSSO\_DataPlatformOperator\_*._

  ```sh
  aws iam list-roles --path-prefix /aws-reserved/sso.amazonaws.com/us-east-1/ --query "Roles[].Arn"
  # search bucket, key, topic, queue and secret policies, EKS access entries, role trust policies and CI configuration for AWSReservedSSO_
  ```

  - Evidence (reserved-role): source, `AWSReservedSSO_AdministratorAccess_*`
    role for permission set AdministratorAccess (arn:aws:sso:::permissionSet/ssoins-larkspur00000001/ps-lark00000001) under /aws-reserved/sso.amazonaws.com/us-east-1/; 1 assignment(s) on the account

  - Evidence (reserved-role): source, `AWSReservedSSO_PaymentsEngineer_*`
    role for permission set PaymentsEngineer (arn:aws:sso:::permissionSet/ssoins-larkspur00000001/ps-lark00000002) under /aws-reserved/sso.amazonaws.com/us-east-1/; 2 assignment(s) on the account

  - Evidence (reserved-role): source, `AWSReservedSSO_ReadOnlyAccess_*`
    role for permission set ReadOnlyAccess (arn:aws:sso:::permissionSet/ssoins-larkspur00000001/ps-lark00000003) under /aws-reserved/sso.amazonaws.com/us-east-1/; 1 assignment(s) on the account

  - Evidence (reserved-role): source, `AWSReservedSSO_DataPlatformOperator_*`
    role for permission set DataPlatformOperator (arn:aws:sso:::permissionSet/ssoins-larkspur00000001/ps-lark00000004) under /aws-reserved/sso.amazonaws.com/us-east-1/; 0 assignment(s) on the account; provisioned without an assignment (stale)

- [ ] **1.12** `REVIEW` Deprovision the stale permission set(s) from the account: DataPlatformOperator
  _Where:_ Identity Center of Larkspur Holdings (o-larkspur0001) (account 111111111111, us-east-1)

  These permission sets are provisioned in the account without any assignment, so their roles are unused. Removing them now deletes the roles cleanly and keeps them out of the reference search above.

  _From the identity-center check: 4 AWSReservedSSO\_* role(s) are deleted from the account: AWSReservedSSO\_AdministratorAccess\_*, AWSReservedSSO\_PaymentsEngineer\_*, AWSReservedSSO\_ReadOnlyAccess\_*, AWSReservedSSO\_DataPlatformOperator\_*._

  ```sh
  aws sso-admin list-accounts-for-provisioned-permission-set --instance-arn arn:aws:sso:::instance/ssoins-larkspur00000001 --permission-set-arn arn:aws:sso:::permissionSet/ssoins-larkspur00000001/ps-lark00000004
  # Identity Center console → Permission sets → DataPlatformOperator → AWS accounts → remove 111111111115
  ```

- [ ] **1.13** `NO-GO` Change the policy of arn:aws:s3:::larkspur-payments-settlement-files to name the destination organization
  _Where:_ account larkspur-payments-prod (111111111115)

  Statement ReadFromTheOrganization (Allow): it stops admitting the account's own principals (StringEquals aws:PrincipalOrgID o-larkspur0001); inside one account an identity policy can still grant the access, so whether anything breaks depends on policies this check does not read; it keeps admitting principals of o-larkspur0001, the organization the account leaves, and does not admit principals of o-fernhill0001 (StringEquals aws:PrincipalOrgID o-larkspur0001). Statement DataPerimeter (Deny): it denies s3:* to the account's own principals after the move: today they are exempt (StringNotEqualsIfExists aws:PrincipalOrgID o-larkspur0001, o-acquirer0001), afterwards they are not; principals of o-larkspur0001 stay exempt from it while principals of o-fernhill0001, the account's new organization, are denied (StringNotEqualsIfExists aws:PrincipalOrgID o-larkspur0001, o-acquirer0001). A Deny in a resource policy applies to principals of the resource's own account too, so the applications in this account lose the resource the moment the account changes organization. Change the policy to name the destination organization (or both, for the transition) before the move.

  resource `arn:aws:s3:::larkspur-payments-settlement-files`

  _From the workloads check: Bucket policy of arn:aws:s3:::larkspur-payments-settlement-files denies the account's own principals after the move._

  ```sh
  aws s3api get-bucket-policy --bucket larkspur-payments-settlement-files --query Policy --output text > larkspur-payments-settlement-files-policy.json
  # edit the condition on organization identity so it admits the destination as well for the transition: today it names o-larkspur0001, the account will be in o-fernhill0001 (path o-fernhill0001/r-fern/ou-fern-bu/ou-fern-pay1/)
  aws s3api put-bucket-policy --bucket larkspur-payments-settlement-files --policy file://larkspur-payments-settlement-files-policy.json
  ```

  - Evidence (resource-policy): source, statement ReadFromTheOrganization, `arn:aws:s3:::larkspur-payments-settlement-files`
    read with s3:GetBucketPolicy

    ```json
    {
      "Sid": "ReadFromTheOrganization",
      "Effect": "Allow",
      "Principal": "*",
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::larkspur-payments-settlement-files/*",
      "Condition": {
        "StringEquals": {
          "aws:PrincipalOrgID": "o-larkspur0001"
        }
      }
    }
    ```

  - Evidence (resource-policy): source, statement DataPerimeter, `arn:aws:s3:::larkspur-payments-settlement-files`
    read with s3:GetBucketPolicy

    ```json
    {
      "Sid": "DataPerimeter",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": [
        "arn:aws:s3:::larkspur-payments-settlement-files",
        "arn:aws:s3:::larkspur-payments-settlement-files/*"
      ],
      "Condition": {
        "StringNotEqualsIfExists": {
          "aws:PrincipalOrgID": [
            "o-larkspur0001",
            "o-acquirer0001"
          ]
        },
        "BoolIfExists": {
          "aws:PrincipalIsAWSService": "false"
        }
      }
    }
    ```

- [ ] **1.14** `NO-GO` Move stack payments-api off the shared networking before the account leaves
  _Where:_ account larkspur-payments-prod (111111111115)

  It references subnet-e056c922dbb17986a, subnet-1d0f03c495e44a0e4 (parameter AppSubnetIds), shared by account 111111111112 with organization o-larkspur0001. What the documentation says happens when the share ends: existing participant resources continue to run in the subnet; no new resources can be created in it, while existing ones can still be modified, described and deleted (subnets can only be shared inside one organization). The stack contains AWS::AutoScaling::AutoScalingGroup, which launches instances into its subnets whenever it scales or replaces one. Those launches need to create resources in the subnet, which fails once the share ends: what is running keeps running, and nothing can be replaced or scaled out. A stack update that replaces a resource in the subnet fails for the same reason. Sharing them again is not a way out: this resource type can only be shared inside one organization, so the workload has to move to networking of the destination before the account leaves. Redeploying the stack with subnets and attachments the account owns, or that the destination shares with it, is the fix; the parameters named above are where the stack takes them from.

  regions us-east-1

  _From the workloads check: Stack payments-api sits on 2 subnets shared through larkspur-core-network, which the account loses._

  ```sh
  aws cloudformation describe-stack-resources --stack-name payments-api --region us-east-1 --query 'StackResources[].[ResourceType,LogicalResourceId,PhysicalResourceId]' --output table
  aws ec2 describe-subnets --subnet-ids subnet-e056c922dbb17986a subnet-1d0f03c495e44a0e4 --region us-east-1 --query 'Subnets[].[SubnetId,OwnerId,VpcId,AvailabilityZone]' --output table
  ```

  - Evidence (stack-reference): source, `payments-api`
    region us-east-1, status UPDATE_COMPLETE, 7 resource(s): AWS::AutoScaling::AutoScalingGroup x1, AWS::EC2::LaunchTemplate x1, AWS::ElasticLoadBalancingV2::LoadBalancer x1, AWS::ElasticLoadBalancingV2::TargetGroup x1, AWS::IAM::Role x2, AWS::Logs::LogGroup x1
    provenance: plain CloudFormation stack (high confidence): a CloudFormation stack whose name and ID match no StackSet instance; whatever pipeline deploys it is not collected
    references subnet-e056c922dbb17986a, subnet-1d0f03c495e44a0e4 (parameter AppSubnetIds)

  - Evidence (resource-share): source, `arn:aws:ram:us-east-1:111111111112:resource-share/06a7aefe6fddce828`
    owner 111111111112; principals: organization o-larkspur0001; allow external principals false
    ec2:TransitGateway  arn:aws:ec2:us-east-1:111111111112:transit-gateway/tgw-54924a77a3120b1ad
    ec2:Subnet  arn:aws:ec2:us-east-1:111111111112:subnet/subnet-e056c922dbb17986a
    ec2:Subnet  arn:aws:ec2:us-east-1:111111111112:subnet/subnet-1d0f03c495e44a0e4
    route53resolver:ResolverRule  arn:aws:route53resolver:us-east-1:111111111112:resolver-rule/rslvr-rr-66e02e8ff78976d8b

- [ ] **1.15** `REVIEW` Keep or replace stack StackSet-larkspur-baseline-roles-6dca20c6-dd9c-f808-0285-15666f7b21b9 before StackSet larkspur-baseline-roles deletes it
  _Where:_ administration account 111111111111

  StackSet larkspur-baseline-roles is service-managed with automatic deployment on and RetainStacksOnAccountRemoval off. When an account is removed from a target organization or OU, StackSets deletes its stack instances and their resources: here AWS::IAM::ManagedPolicy x1, AWS::IAM::Role x3. Whatever in the account uses them stops working at that moment, and the resources are not there for a rollback either. Before the move, either turn RetainStacksOnAccountRemoval on for the StackSet (the stack then stays in the account, detached from the StackSet and no longer updated) or make sure the destination deploys an equivalent. Turning retention on is a setting of the whole StackSet and applies to every account that leaves its targets from then on.

  regions us-east-1

  _From the workloads check: StackSet instance StackSet-larkspur-baseline-roles-6dca20c6-dd9c-f808-0285-15666f7b21b9 is deleted when the account leaves the organization: 4 resource(s)._

  ```sh
  aws cloudformation describe-stack-resources --stack-name StackSet-larkspur-baseline-roles-6dca20c6-dd9c-f808-0285-15666f7b21b9 --region us-east-1 --query 'StackResources[].[ResourceType,LogicalResourceId,PhysicalResourceId]' --output table   # in the account: what the instance contains
  aws cloudformation describe-stack-set --stack-set-name larkspur-baseline-roles --query StackSet.AutoDeployment
  # to keep the stack in the account when it leaves (add --capabilities and --parameters as the StackSet needs them):
  aws cloudformation update-stack-set --stack-set-name larkspur-baseline-roles --use-previous-template --auto-deployment Enabled=true,RetainStacksOnAccountRemoval=true
  ```

  - Evidence (stack-instance): source, `StackSet-larkspur-baseline-roles-6dca20c6-dd9c-f808-0285-15666f7b21b9`
    region us-east-1, status UPDATE_COMPLETE, 4 resource(s): AWS::IAM::ManagedPolicy x1, AWS::IAM::Role x3
    provenance: service-managed StackSet (high confidence): the stack ID is listed as an instance of StackSet larkspur-baseline-roles (permission model SERVICE_MANAGED, administered from 111111111111)
    StackSet larkspur-baseline-roles: service-managed, auto-deployment true, retain stacks on account removal false, targets ou-lark-work; the stack ID is one of the StackSet's instances

- [ ] **1.16** `REVIEW` Change the policy of resource AppLogSubscriptionRole of stack payments-api to name the destination organization
  _Where:_ account larkspur-payments-prod (111111111115)

  Allow ForAnyValue:StringLike aws:PrincipalOrgPaths o-larkspur0001/r-lark/ou-lark-sec/*: names o-larkspur0001, the organization the account leaves. Only the organization conditions are kept from a template, not the statement around them, so who is admitted or denied cannot be evaluated here: review the resource in the template of stack payments-api and update the value before the next deployment.

  _From the workloads check: Template policy for resource AppLogSubscriptionRole of stack payments-api is conditioned on organization identity that changes with the move._

  ```sh
  aws cloudformation get-template --stack-name payments-api --region us-east-1 --query TemplateBody
  # change the value in the template's source and deploy it through the stack's usual pipeline
  ```

  - Evidence (resource-policy): source, `resource AppLogSubscriptionRole of stack payments-api`
    found in the template read with cloudformation:GetTemplate

- [ ] **1.17** `REVIEW` Change the policy of arn:aws:iam::111111111115:role/DataExportReader to name the destination organization
  _Where:_ account larkspur-payments-prod (111111111115)

  Statement DataPlatformFromTheOrganization (Allow): it keeps admitting principals of o-larkspur0001, the organization the account leaves, and does not admit principals of o-fernhill0001 (StringEquals aws:PrincipalOrgID o-larkspur0001). Decide whether principals of the former organization should keep assuming the role, and note that the destination's RCPs also apply to sts:AssumeRole on it (the RCP check evaluates the inbound entries of the usage list). Change the policy to name the destination organization (or both, for the transition) before the move.

  resource `arn:aws:iam::111111111115:role/DataExportReader`

  _From the workloads check: Trust policy of arn:aws:iam::111111111115:role/DataExportReader stays tied to the organization the account leaves._

  ```sh
  aws iam get-role --role-name DataExportReader --query Role.AssumeRolePolicyDocument > DataExportReader-trust.json
  # edit the condition on organization identity so it admits the destination as well for the transition: today it names o-larkspur0001, the account will be in o-fernhill0001 (path o-fernhill0001/r-fern/ou-fern-bu/ou-fern-pay1/)
  aws iam update-assume-role-policy --role-name DataExportReader --policy-document file://DataExportReader-trust.json
  ```

  - Evidence (resource-policy): source, statement DataPlatformFromTheOrganization, `arn:aws:iam::111111111115:role/DataExportReader`
    read with iam:ListRoles

    ```json
    {
      "Sid": "DataPlatformFromTheOrganization",
      "Effect": "Allow",
      "Principal": {
        "AWS": "*"
      },
      "Action": "sts:AssumeRole",
      "Condition": {
        "StringEquals": {
          "aws:PrincipalOrgID": "o-larkspur0001"
        },
        "ArnLike": {
          "aws:PrincipalArn": "arn:aws:iam::*:role/DataPlatformIngest"
        }
      }
    }
    ```

- [ ] **1.18** `REVIEW` Decide where stack payments-api reads its cross-account output from after the move
  _Where:_ account 111111111113

  The reference uses Fn::GetStackOutput through role arn:aws:iam::111111111113:role/CfnOutputReader in account 111111111113, which stays in organization o-larkspur0001. It is a weak reference: the value is resolved when the consuming stack is created or updated and nothing changes at the moment of the move. The next update of payments-api resolves it again, across organizations by then: CloudFormation's execution role in this account has to assume arn:aws:iam::111111111113:role/CfnOutputReader, which the role's trust policy (in the other account, not collected here), the destination's SCPs on this account and the RCPs of the role's organization decide. The sts:AssumeRole call was evaluated as a derived operation: see the SCP and RCP checks for a denial. If the value changes or the producing stack is deleted, this stack is not told; plan where the value comes from once the accounts are in different organizations. Either keep the reference (the role's trust policy has to admit this account by ID rather than by organization) or replace it with a parameter that carries the value.

  actions `sts:AssumeRole`; resource `arn:aws:iam::111111111113:role/CfnOutputReader`; regions us-east-1

  _From the workloads check: Stack payments-api reads output LogDestinationArn of stack shared-observability in account 111111111113._

  ```sh
  aws iam get-role --role-name CfnOutputReader --query Role.AssumeRolePolicyDocument   # in account 111111111113: does the trust name account 111111111115, or the organization?
  ```

  - Evidence (stack-output-reference): source, `payments-api`
    region us-east-1, status UPDATE_COMPLETE, 7 resource(s): AWS::AutoScaling::AutoScalingGroup x1, AWS::EC2::LaunchTemplate x1, AWS::ElasticLoadBalancingV2::LoadBalancer x1, AWS::ElasticLoadBalancingV2::TargetGroup x1, AWS::IAM::Role x2, AWS::Logs::LogGroup x1
    provenance: plain CloudFormation stack (high confidence): a CloudFormation stack whose name and ID match no StackSet instance; whatever pipeline deploys it is not collected
    Fn::GetStackOutput: stack shared-observability, output LogDestinationArn, region us-east-1, role arn:aws:iam::111111111113:role/CfnOutputReader

## 2. Before the move: re-create what does not travel

Shares, delegations, permission sets and stacks that are scoped to the account's current position do not follow it. Prepare the replacements now so nothing is interrupted.

- [ ] **2.1** `NO-GO` Re-share larkspur-core-network with the account directly: ec2:Subnet, ec2:TransitGateway, route53resolver:ResolverRule
  _Where:_ owner account 111111111112

  Owner 111111111112 shares larkspur-core-network (ec2:Subnet, ec2:TransitGateway, route53resolver:ResolverRule) with arn:aws:organizations::111111111111:organization/o-larkspur0001 today. After the move those principals no longer cover the account. Ask the owner to add account 111111111115 as a principal before the move so nothing attached to these resources is interrupted. The account will be outside the organization, so the share has to allow external principals and the account has to accept an invitation. The documentation says traffic or a declared operation stops with this share, so the move stays NO-GO until it is done: Shared by account 111111111112 with organization o-larkspur0001. It is scoped to the source organization or one of its OUs and stops applying when the account leaves. What the documentation says happens: ec2:Subnet: existing participant resources continue to run in the subnet; no new resources can be created in it, while existing ones can still be modified, described and deleted (subnets can only be shared inside one organization). Potentially affected: ec2:RunInstances, rds:CreateDBInstance in use may target the shared resources; confirm. ec2:Subnet can only be shared inside one organization, so it cannot be re-shared with the account once it has left. ec2:TransitGateway: existing transit gateway attachments remain functional; the account can no longer describe the transit gateway or create new attachments, and either side can delete the attachments. The account uses ec2:CreateTransitGatewayVpcAttachment, which needs the share: that stops working. route53resolver:ResolverRule: traffic is affected at once, the rule's associations with the account's VPCs are removed and Resolver answers those queries from the remaining rules at once (an OU-scoped rule keeps its associations only when it is also shared with the destination OU). Ask the owner to re-share the resources with the account directly before the move, with external principals allowed, and accept the invitation after the move.

  resource `arn:aws:ram:us-east-1:111111111112:resource-share/06a7aefe6fddce828`

  _From the ram check: Networking share larkspur-core-network is lost: ec2:Subnet, ec2:TransitGateway, route53resolver:ResolverRule._

  ```sh
  aws ram update-resource-share --resource-share-arn arn:aws:ram:us-east-1:111111111112:resource-share/06a7aefe6fddce828 --allow-external-principals
  aws ram associate-resource-share --resource-share-arn arn:aws:ram:us-east-1:111111111112:resource-share/06a7aefe6fddce828 --principals 111111111115
  ```

  - Evidence (resource-share): source, `arn:aws:ram:us-east-1:111111111112:resource-share/06a7aefe6fddce828`
    owner 111111111112; principals: organization o-larkspur0001; allow external principals false
    ec2:TransitGateway  arn:aws:ec2:us-east-1:111111111112:transit-gateway/tgw-54924a77a3120b1ad
    ec2:Subnet  arn:aws:ec2:us-east-1:111111111112:subnet/subnet-e056c922dbb17986a
    ec2:Subnet  arn:aws:ec2:us-east-1:111111111112:subnet/subnet-1d0f03c495e44a0e4
    route53resolver:ResolverRule  arn:aws:route53resolver:us-east-1:111111111112:resolver-rule/rslvr-rr-66e02e8ff78976d8b

- [ ] **2.2** `REVIEW` Re-share larkspur-ipam with the account directly: ec2:IpamPool
  _Where:_ owner account 111111111112

  Owner 111111111112 shares larkspur-ipam (ec2:IpamPool) with arn:aws:organizations::111111111111:organization/o-larkspur0001 today. After the move those principals no longer cover the account. Ask the owner to add account 111111111115 as a principal before the move so nothing attached to these resources is interrupted. The account will be outside the organization, so the share has to allow external principals and the account has to accept an invitation.

  resource `arn:aws:ram:us-east-1:111111111112:resource-share/01364b18a31c4fdca`

  _From the ram check: Networking share larkspur-ipam is lost: ec2:IpamPool._

  ```sh
  aws ram update-resource-share --resource-share-arn arn:aws:ram:us-east-1:111111111112:resource-share/01364b18a31c4fdca --allow-external-principals
  aws ram associate-resource-share --resource-share-arn arn:aws:ram:us-east-1:111111111112:resource-share/01364b18a31c4fdca --principals 111111111115
  ```

  - Evidence (resource-share): source, `arn:aws:ram:us-east-1:111111111112:resource-share/01364b18a31c4fdca`
    owner 111111111112; principals: organization o-larkspur0001; allow external principals false
    ec2:IpamPool  arn:aws:ec2::111111111112:ipam-pool/ipam-pool-8afc13dafc2e5d265

- [ ] **2.3** `REVIEW` Re-share larkspur-workload-prefix-lists with the account directly: ec2:PrefixList
  _Where:_ owner account 111111111112

  Owner 111111111112 shares larkspur-workload-prefix-lists (ec2:PrefixList) with arn:aws:organizations::111111111111:ou/o-larkspur0001/ou-lark-work today. After the move those principals no longer cover the account. Ask the owner to add account 111111111115 as a principal before the move so nothing attached to these resources is interrupted. The account will be outside the organization, so the share has to allow external principals and the account has to accept an invitation.

  resource `arn:aws:ram:us-east-1:111111111112:resource-share/0479521366b778243`

  _From the ram check: Networking share larkspur-workload-prefix-lists is lost: ec2:PrefixList._

  ```sh
  aws ram update-resource-share --resource-share-arn arn:aws:ram:us-east-1:111111111112:resource-share/0479521366b778243 --allow-external-principals
  aws ram associate-resource-share --resource-share-arn arn:aws:ram:us-east-1:111111111112:resource-share/0479521366b778243 --principals 111111111115
  ```

  - Evidence (resource-share): source, `arn:aws:ram:us-east-1:111111111112:resource-share/0479521366b778243`
    owner 111111111112; principals: OU ou-lark-work; allow external principals false
    ec2:PrefixList  arn:aws:ec2:us-east-1:111111111112:prefix-list/pl-071c30c49f742a6da

- [ ] **2.4** `REVIEW` Re-share larkspur-license-config with the account directly: license-manager:LicenseConfiguration
  _Where:_ owner account 111111111113

  Owner 111111111113 shares larkspur-license-config (license-manager:LicenseConfiguration) with 111111111115, 111111111118 today. After the move those principals no longer cover the account. Ask the owner to add account 111111111115 as a principal before the move so nothing attached to these resources is interrupted. The account will be outside the organization, so the share has to allow external principals and the account has to accept an invitation.

  resource `arn:aws:ram:us-east-1:111111111113:resource-share/016cff3e3072e28ed`

  _From the ram check: Share larkspur-license-config is lost: license-manager:LicenseConfiguration._

  ```sh
  aws ram update-resource-share --resource-share-arn arn:aws:ram:us-east-1:111111111113:resource-share/016cff3e3072e28ed --allow-external-principals
  aws ram associate-resource-share --resource-share-arn arn:aws:ram:us-east-1:111111111113:resource-share/016cff3e3072e28ed --principals 111111111115
  ```

  - Evidence (resource-share): source, `arn:aws:ram:us-east-1:111111111113:resource-share/016cff3e3072e28ed`
    owner 111111111113; principals: account 111111111115, account 111111111118; allow external principals false
    license-manager:LicenseConfiguration  arn:aws:license-manager:us-east-1:111111111113:license-configuration:lic-4fba2a7c40f73ab7

- [ ] **2.5** `REVIEW` Replace what StackSet larkspur-baseline-roles deploys into the account
  _Where:_ administration account 111111111111

  Service-managed StackSets deploy by OU. Audit and break-glass IAM roles for workload accounts. Check what those stacks provide (roles, Config recorders, GuardDuty membership) before moving. The workloads check lists the instances found in this account and what each contains. Decide: redeploy the template by hand in the account, add the account to a self-managed StackSet, or accept the loss.

  _From the org-services check: StackSet larkspur-baseline-roles stops targeting the account; stack instances are deleted from the account._

  ```sh
  aws cloudformation list-stack-instances --stack-set-name larkspur-baseline-roles --stack-instance-account 111111111115
  aws cloudformation describe-stack-set --stack-set-name larkspur-baseline-roles --query StackSet.TemplateBody --output text
  ```

  - Evidence (stackset): source, `larkspur-baseline-roles`
    admin 111111111111; targets OUs ou-lark-work accounts ; regions us-east-1; auto-deployment true; retain on removal false

- [ ] **2.6** `REVIEW` Replace what StackSet larkspur-config-recorder deploys into the account
  _Where:_ administration account 111111111111

  Service-managed StackSets deploy by OU. AWS Config recorder and delivery channel. Check what those stacks provide (roles, Config recorders, GuardDuty membership) before moving. The workloads check lists the instances found in this account and what each contains. Decide: redeploy the template by hand in the account, add the account to a self-managed StackSet, or accept the loss.

  _From the org-services check: StackSet larkspur-config-recorder stops targeting the account; stack instances are detached but the stacks are retained in the account (retain\_stacks\_on\_account\_removal)._

  ```sh
  aws cloudformation list-stack-instances --stack-set-name larkspur-config-recorder --stack-instance-account 111111111115
  aws cloudformation describe-stack-set --stack-set-name larkspur-config-recorder --query StackSet.TemplateBody --output text
  ```

  - Evidence (stackset): source, `larkspur-config-recorder`
    admin 111111111111; targets OUs r-lark accounts ; regions us-east-1,eu-west-1,ap-southeast-1; auto-deployment true; retain on removal true

- [ ] **2.7** `REVIEW` Enable trusted access in Fernhill Group (o-fernhill0001) for: account.amazonaws.com
  _Where:_ management account 222222222221 of Fernhill Group

  Organization-integrated features of these services (for example organization-wide GuardDuty, RAM sharing with the organization, service-managed StackSets) are not available in the target organization until trusted access is enabled there. Only for the integrations the account relies on; enabling trusted access is an organization-wide setting.

  _From the org-services check: Trusted access is not enabled in the target for: account.amazonaws.com._

  ```sh
  aws organizations enable-aws-service-access --service-principal account.amazonaws.com
  ```

- [ ] **2.8** `REVIEW` Create the AWSControlTowerExecution role in the account, trusting management account 222222222221
  _Where:_ account larkspur-payments-prod (111111111115)

  Account Factory assumes this role to enroll an existing account. It needs AdministratorAccess and a trust policy for the target management account. Also make sure no Config recorder or delivery channel of the account's own conflicts in the governed regions.

  _From the control-tower check: Target OU Payments is registered with Control Tower; the account has to be enrolled._

  ```sh
  aws iam create-role --role-name AWSControlTowerExecution --assume-role-policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::222222222221:root"},"Action":"sts:AssumeRole"}]}'
  aws iam attach-role-policy --role-name AWSControlTowerExecution --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
  aws configservice describe-configuration-recorders   # per governed region
  ```

- [ ] **2.9** `REVIEW` Review permission set AdministratorAccess in the target instance before re-assigning it
  _Where:_ Identity Center of Fernhill Group (o-fernhill0001) (account 222222222221, eu-west-1)

  Account assignments exist only for accounts inside the organization that owns the instance. When the account leaves o-larkspur0001, Identity Center cleans up its metadata and resources for the account and a standalone account no longer works with Identity Center, so these 1 assignment(s) stop granting access at once. The target instance has a permission set with the same name; re-assign the principals to it once the account has joined. They are matched by name only: identity store d-fern0000001 is a different directory, so the users and groups are different objects there. Same name, different settings: session duration PT1H vs PT2H.

  _From the identity-center check: Permission set AdministratorAccess: 1 assignment(s) removed when the account leaves (group Platform-Admins)._

  ```sh
  aws sso-admin describe-permission-set --instance-arn arn:aws:sso:::instance/ssoins-fernhill00000001 --permission-set-arn arn:aws:sso:::permissionSet/ssoins-fernhill00000001/ps-fern00000001
  aws sso-admin list-managed-policies-in-permission-set --instance-arn arn:aws:sso:::instance/ssoins-fernhill00000001 --permission-set-arn arn:aws:sso:::permissionSet/ssoins-fernhill00000001/ps-fern00000001
  aws sso-admin get-inline-policy-for-permission-set --instance-arn arn:aws:sso:::instance/ssoins-fernhill00000001 --permission-set-arn arn:aws:sso:::permissionSet/ssoins-fernhill00000001/ps-fern00000001
  ```

  - Evidence (account-assignment): source, `ba31fe89-32df-0f24-6b40-1c6f590a40ff`
    group Platform-Admins has permission set AdministratorAccess in account 111111111115

  - Evidence (permission-set): source, `arn:aws:sso:::permissionSet/ssoins-larkspur00000001/ps-lark00000001`
    AdministratorAccess
    Full access for the platform team
    session duration PT1H
    managed policies: arn:aws:iam::aws:policy/AdministratorAccess
    provisioned in 8 account(s)

  - Evidence (permission-set): target, `arn:aws:sso:::permissionSet/ssoins-fernhill00000001/ps-fern00000001`
    AdministratorAccess
    Platform team break-glass
    session duration PT2H
    managed policies: arn:aws:iam::aws:policy/AdministratorAccess
    provisioned in 7 account(s)

- [ ] **2.10** `REVIEW` Create permission set PaymentsEngineer in the target instance
  _Where:_ Identity Center of Fernhill Group (o-fernhill0001) (account 222222222221, eu-west-1)

  Account assignments exist only for accounts inside the organization that owns the instance. When the account leaves o-larkspur0001, Identity Center cleans up its metadata and resources for the account and a standalone account no longer works with Identity Center, so these 2 assignment(s) stop granting access at once. The target instance has no permission set named PaymentsEngineer. Create one there (or choose an equivalent) before re-assigning the 2 principal(s), who have to exist in identity store d-fern0000001 under the target instance.

  _From the identity-center check: Permission set PaymentsEngineer: 2 assignment(s) removed when the account leaves (group Payments-Engineers, user oncall.payments)._

  ```sh
  aws sso-admin create-permission-set --instance-arn arn:aws:sso:::instance/ssoins-fernhill00000001 --name PaymentsEngineer --description "Day-to-day operations in the payments accounts" --session-duration PT8H
  aws sso-admin attach-customer-managed-policy-reference-to-permission-set --instance-arn arn:aws:sso:::instance/ssoins-fernhill00000001 --permission-set-arn <ARN returned by create-permission-set> --customer-managed-policy-reference Name=LarkspurPaymentsEngineer,Path=/larkspur/   # the policy must exist in the account
  aws sso-admin put-inline-policy-to-permission-set --instance-arn arn:aws:sso:::instance/ssoins-fernhill00000001 --permission-set-arn <ARN returned by create-permission-set> --inline-policy file://PaymentsEngineer-inline.json   # the inline policy is in the evidence below
  ```

  - Evidence (account-assignment): source, `c3055d88-cb7d-f258-9c41-70aefb8af533`
    group Payments-Engineers has permission set PaymentsEngineer in account 111111111115

  - Evidence (account-assignment): source, `79d949b7-eef8-371b-7b6d-f030997b6ac4`
    user oncall.payments has permission set PaymentsEngineer in account 111111111115

  - Evidence (permission-set): source, `arn:aws:sso:::permissionSet/ssoins-larkspur00000001/ps-lark00000002`
    PaymentsEngineer
    Day-to-day operations in the payments accounts
    session duration PT8H
    customer managed policies (must exist in the account): /larkspur/LarkspurPaymentsEngineer
    has an inline policy
    provisioned in 2 account(s)

    ```json
    {
      "Version": "2012-10-17",
      "Statement": [
        {
          "Sid": "NoIAMChanges",
          "Effect": "Deny",
          "Action": [
            "iam:Create*",
            "iam:Delete*",
            "iam:Put*",
            "iam:Attach*",
            "iam:Detach*"
          ],
          "Resource": "*"
        }
      ]
    }
    ```

- [ ] **2.11** `REVIEW` Review permission set ReadOnlyAccess in the target instance before re-assigning it
  _Where:_ Identity Center of Fernhill Group (o-fernhill0001) (account 222222222221, eu-west-1)

  Account assignments exist only for accounts inside the organization that owns the instance. When the account leaves o-larkspur0001, Identity Center cleans up its metadata and resources for the account and a standalone account no longer works with Identity Center, so these 1 assignment(s) stop granting access at once. The target instance has a permission set with the same name; re-assign the principals to it once the account has joined. They are matched by name only: identity store d-fern0000001 is a different directory, so the users and groups are different objects there. Same name, different settings: managed policies only in the target: arn:aws:iam::aws:policy/job-function/ViewOnlyAccess; session duration PT8H vs PT12H.

  _From the identity-center check: Permission set ReadOnlyAccess: 1 assignment(s) removed when the account leaves (group Security-Auditors)._

  ```sh
  aws sso-admin describe-permission-set --instance-arn arn:aws:sso:::instance/ssoins-fernhill00000001 --permission-set-arn arn:aws:sso:::permissionSet/ssoins-fernhill00000001/ps-fern00000002
  aws sso-admin list-managed-policies-in-permission-set --instance-arn arn:aws:sso:::instance/ssoins-fernhill00000001 --permission-set-arn arn:aws:sso:::permissionSet/ssoins-fernhill00000001/ps-fern00000002
  aws sso-admin get-inline-policy-for-permission-set --instance-arn arn:aws:sso:::instance/ssoins-fernhill00000001 --permission-set-arn arn:aws:sso:::permissionSet/ssoins-fernhill00000001/ps-fern00000002
  ```

  - Evidence (account-assignment): source, `fd2d8b09-2a71-ec4a-cc89-1ddb07a87174`
    group Security-Auditors has permission set ReadOnlyAccess in account 111111111115

  - Evidence (permission-set): source, `arn:aws:sso:::permissionSet/ssoins-larkspur00000001/ps-lark00000003`
    ReadOnlyAccess
    Audit access
    session duration PT8H
    managed policies: arn:aws:iam::aws:policy/ReadOnlyAccess
    provisioned in 7 account(s)

  - Evidence (permission-set): target, `arn:aws:sso:::permissionSet/ssoins-fernhill00000001/ps-fern00000002`
    ReadOnlyAccess
    Audit and security review
    session duration PT12H
    managed policies: arn:aws:iam::aws:policy/ReadOnlyAccess, arn:aws:iam::aws:policy/job-function/ViewOnlyAccess
    provisioned in 6 account(s)

- [ ] **2.12** `REVIEW` Plan stack payments-ledger-db off the shared networking it references
  _Where:_ account larkspur-payments-prod (111111111115)

  It references subnet-e056c922dbb17986a, subnet-1d0f03c495e44a0e4 (parameter DatabaseSubnetIds), shared by account 111111111112 with organization o-larkspur0001. What the documentation says happens when the share ends: existing participant resources continue to run in the subnet; no new resources can be created in it, while existing ones can still be modified, described and deleted (subnets can only be shared inside one organization). A stack update that replaces a resource in the subnet fails for the same reason. Sharing them again is not a way out: this resource type can only be shared inside one organization, so the workload has to move to networking of the destination before the account leaves. Redeploying the stack with subnets and attachments the account owns, or that the destination shares with it, is the fix; the parameters named above are where the stack takes them from.

  regions us-east-1

  _From the workloads check: Stack payments-ledger-db sits on 2 subnets shared through larkspur-core-network, which the account loses._

  ```sh
  aws cloudformation describe-stack-resources --stack-name payments-ledger-db --region us-east-1 --query 'StackResources[].[ResourceType,LogicalResourceId,PhysicalResourceId]' --output table
  aws ec2 describe-subnets --subnet-ids subnet-e056c922dbb17986a subnet-1d0f03c495e44a0e4 --region us-east-1 --query 'Subnets[].[SubnetId,OwnerId,VpcId,AvailabilityZone]' --output table
  ```

  - Evidence (stack-reference): source, `payments-ledger-db`
    region us-east-1, status UPDATE_COMPLETE, 3 resource(s): AWS::RDS::DBInstance x1, AWS::RDS::DBSubnetGroup x1, AWS::SecretsManager::Secret x1
    provenance: plain CloudFormation stack (high confidence): a CloudFormation stack whose name and ID match no StackSet instance; whatever pipeline deploys it is not collected
    references subnet-e056c922dbb17986a, subnet-1d0f03c495e44a0e4 (parameter DatabaseSubnetIds)

  - Evidence (resource-share): source, `arn:aws:ram:us-east-1:111111111112:resource-share/06a7aefe6fddce828`
    owner 111111111112; principals: organization o-larkspur0001; allow external principals false
    ec2:TransitGateway  arn:aws:ec2:us-east-1:111111111112:transit-gateway/tgw-54924a77a3120b1ad
    ec2:Subnet  arn:aws:ec2:us-east-1:111111111112:subnet/subnet-e056c922dbb17986a
    ec2:Subnet  arn:aws:ec2:us-east-1:111111111112:subnet/subnet-1d0f03c495e44a0e4
    route53resolver:ResolverRule  arn:aws:route53resolver:us-east-1:111111111112:resolver-rule/rslvr-rr-66e02e8ff78976d8b

- [ ] **2.13** `REVIEW` Plan stack payments-network off the shared networking it references
  _Where:_ account larkspur-payments-prod (111111111115)

  It references tgw-54924a77a3120b1ad (parameter TransitGatewayId), shared by account 111111111112 with organization o-larkspur0001. What the documentation says happens when the share ends: existing transit gateway attachments remain functional; the account can no longer describe the transit gateway or create new attachments, and either side can delete the attachments. The stack owns the attachment: it keeps carrying traffic, but a stack update that replaces it, or redeploying the stack, fails because the account can no longer create attachments to this transit gateway. Redeploying the stack with subnets and attachments the account owns, or that the destination shares with it, is the fix; the parameters named above are where the stack takes them from.

  regions us-east-1

  _From the workloads check: Stack payments-network sits on a transit gateway shared through larkspur-core-network, which the account loses._

  ```sh
  aws cloudformation describe-stack-resources --stack-name payments-network --region us-east-1 --query 'StackResources[].[ResourceType,LogicalResourceId,PhysicalResourceId]' --output table
  ```

  - Evidence (stack-reference): source, `payments-network`
    region us-east-1, status UPDATE_COMPLETE, 9 resource(s): AWS::EC2::Route x4, AWS::EC2::SecurityGroup x3, AWS::EC2::TransitGatewayAttachment x1, AWS::EC2::VPC x1
    provenance: plain CloudFormation stack (high confidence): a CloudFormation stack whose name and ID match no StackSet instance; whatever pipeline deploys it is not collected
    references tgw-54924a77a3120b1ad (parameter TransitGatewayId)

  - Evidence (resource-share): source, `arn:aws:ram:us-east-1:111111111112:resource-share/06a7aefe6fddce828`
    owner 111111111112; principals: organization o-larkspur0001; allow external principals false
    ec2:TransitGateway  arn:aws:ec2:us-east-1:111111111112:transit-gateway/tgw-54924a77a3120b1ad
    ec2:Subnet  arn:aws:ec2:us-east-1:111111111112:subnet/subnet-e056c922dbb17986a
    ec2:Subnet  arn:aws:ec2:us-east-1:111111111112:subnet/subnet-1d0f03c495e44a0e4
    route53resolver:ResolverRule  arn:aws:route53resolver:us-east-1:111111111112:resolver-rule/rslvr-rr-66e02e8ff78976d8b

## 3. The move

Run these in order. Between leaving and accepting the invitation the account is standalone, with no SCPs and no organization features; keep that window short.

- [ ] **3.1** Invite the account into Fernhill Group (o-fernhill0001)
  _Where:_ management account 222222222221 of Fernhill Group

  The invitation (a handshake) is valid for 15 days. Send it before the account leaves so the standalone window is short.

  ```sh
  aws organizations invite-account-to-organization --target Id=111111111115,Type=ACCOUNT --notes "Move of larkspur-payments-prod planned with orgshift"
  ```

- [ ] **3.2** Leave Larkspur Holdings (o-larkspur0001)
  _Where:_ account larkspur-payments-prod (111111111115), or management account 111111111111 of Larkspur Holdings

  Run leave-organization from inside the account, or remove it from the management account (which SCPs do not restrict). Both need the standalone prerequisites to be in place. From this moment no SCP, RCP or tag policy of the source applies, organization-scoped shares stop reaching the account and Identity Center deletes its assignments and roles.

  ```sh
  aws organizations leave-organization   # run inside the account
  aws organizations remove-account-from-organization --account-id 111111111115   # alternative, run by the management account
  ```

- [ ] **3.3** Accept the invitation
  _Where:_ account larkspur-payments-prod (111111111115)

  The account joins Fernhill Group (o-fernhill0001) at its root with the AWS managed default policies attached. Everything on the verdict board that applies at the target position applies from the next step on.

  ```sh
  aws organizations list-handshakes-for-account --query "Handshakes[?State=='OPEN'].[Id,Action]" --output table
  aws organizations accept-handshake --handshake-id <handshake ID from the previous command>
  ```

- [ ] **3.4** Move the account from the root to OU Payments (ou-fern-pay1)
  _Where:_ management account 222222222221 of Fernhill Group

  Until this call the account sits at the target root with only the policies attached there.

  ```sh
  aws organizations move-account --account-id 111111111115 --source-parent-id r-fern --destination-parent-id ou-fern-pay1
  ```

## 4. After the move: checks

Confirm what the simulation predicted and finish what could only be done once the account is at its new position.

- [ ] **4.1** Confirm the account sits under OU Payments (ou-fern-pay1) and the expected policies reach it
  _Where:_ management account 222222222221 of Fernhill Group

  The parent must be ou-fern-pay1. The policies listed for the account should match the target chain of the simulation (added: SCP Fernhill-Root-Guardrails, SCP Fernhill-EU-Only-Regions, SCP aws-guardrails-kjwqpf, SCP Fernhill-Payments-Controls, RCP Fernhill-Block-External-Principals, TAG Fernhill-Cost-Allocation, TAG Fernhill-Payments-Cost-Centers, BACKUP Fernhill-Core-Backups).

  ```sh
  aws organizations list-parents --child-id 111111111115
  aws organizations list-policies-for-target --target-id 111111111115 --filter SERVICE_CONTROL_POLICY
  aws organizations list-policies-for-target --target-id 111111111115 --filter RESOURCE_CONTROL_POLICY
  aws organizations list-policies-for-target --target-id 111111111115 --filter TAG_POLICY
  aws organizations list-policies-for-target --target-id 111111111115 --filter BACKUP_POLICY
  ```

- [ ] **4.2** `INFO` Tag to the target standard: cost-center: ec2:instance resources carry no cost-center tag
  _Where:_ account larkspur-payments-prod (111111111115)

  Tag policies do not require a tag to be present, so this does not block the move, but these resources fall outside the target standard (Fernhill-Cost-Allocation, Fernhill-Payments-Cost-Centers). Affected: 2 resource(s), for example arn:aws:ec2:us-east-1:111111111115:instance/i-c5aafe82c7111d6b7, arn:aws:ec2:us-east-1:111111111115:instance/i-5ec8c6966cdcd7b5e. Not enforced, so this can wait until after the move.

  _From the tags check: cost-center: ec2:instance resources carry no cost-center tag._

  - Evidence (tag-compliance): target
    arn:aws:ec2:us-east-1:111111111115:instance/i-c5aafe82c7111d6b7
    arn:aws:ec2:us-east-1:111111111115:instance/i-5ec8c6966cdcd7b5e

- [ ] **4.3** `INFO` Tag to the target standard: cost-center: ec2:volume resources carry no cost-center tag
  _Where:_ account larkspur-payments-prod (111111111115)

  Tag policies do not require a tag to be present, so this does not block the move, but these resources fall outside the target standard (Fernhill-Cost-Allocation, Fernhill-Payments-Cost-Centers). Affected: 1 resource(s), for example arn:aws:ec2:us-east-1:111111111115:volume/vol-d56035a7aad3c0ccb. Not enforced, so this can wait until after the move.

  _From the tags check: cost-center: ec2:volume resources carry no cost-center tag._

  - Evidence (tag-compliance): target
    arn:aws:ec2:us-east-1:111111111115:volume/vol-d56035a7aad3c0ccb

- [ ] **4.4** `INFO` Tag to the target standard: cost-center: iam:role resources carry no cost-center tag
  _Where:_ account larkspur-payments-prod (111111111115)

  Tag policies do not require a tag to be present, so this does not block the move, but these resources fall outside the target standard (Fernhill-Cost-Allocation, Fernhill-Payments-Cost-Centers). Affected: 2 resource(s), for example arn:aws:iam::111111111115:role/larkspur-audit, arn:aws:iam::111111111115:role/larkspur-break-glass. Not enforced, so this can wait until after the move.

  _From the tags check: cost-center: iam:role resources carry no cost-center tag._

  - Evidence (tag-compliance): target
    arn:aws:iam::111111111115:role/larkspur-audit
    arn:aws:iam::111111111115:role/larkspur-break-glass

- [ ] **4.5** `INFO` Tag to the target standard: cost-center: lambda:function resources carry no cost-center tag
  _Where:_ account larkspur-payments-prod (111111111115)

  Tag policies do not require a tag to be present, so this does not block the move, but these resources fall outside the target standard (Fernhill-Cost-Allocation, Fernhill-Payments-Cost-Centers). Affected: 1 resource(s), for example arn:aws:lambda:us-east-1:111111111115:function:settlement-notifier. Not enforced, so this can wait until after the move.

  _From the tags check: cost-center: lambda:function resources carry no cost-center tag._

  - Evidence (tag-compliance): target
    arn:aws:lambda:us-east-1:111111111115:function:settlement-notifier

- [ ] **4.6** `INFO` Tag to the target standard: cost-center: sqs:queue resources carry no cost-center tag
  _Where:_ account larkspur-payments-prod (111111111115)

  Tag policies do not require a tag to be present, so this does not block the move, but these resources fall outside the target standard (Fernhill-Cost-Allocation, Fernhill-Payments-Cost-Centers). Affected: 1 resource(s), for example arn:aws:sqs:us-east-1:111111111115:fraud-events. Not enforced, so this can wait until after the move.

  _From the tags check: cost-center: sqs:queue resources carry no cost-center tag._

  - Evidence (tag-compliance): target
    arn:aws:sqs:us-east-1:111111111115:fraud-events

- [ ] **4.7** `INFO` Tag to the target standard: environment: ec2:volume resources carry no environment tag
  _Where:_ account larkspur-payments-prod (111111111115)

  Tag policies do not require a tag to be present, so this does not block the move, but these resources fall outside the target standard (Fernhill-Cost-Allocation). Affected: 1 resource(s), for example arn:aws:ec2:us-east-1:111111111115:volume/vol-d56035a7aad3c0ccb. Not enforced, so this can wait until after the move.

  _From the tags check: environment: ec2:volume resources carry no environment tag._

  - Evidence (tag-compliance): target
    arn:aws:ec2:us-east-1:111111111115:volume/vol-d56035a7aad3c0ccb

- [ ] **4.8** `INFO` Tag to the target standard: environment: iam:role resources carry no environment tag
  _Where:_ account larkspur-payments-prod (111111111115)

  Tag policies do not require a tag to be present, so this does not block the move, but these resources fall outside the target standard (Fernhill-Cost-Allocation). Affected: 2 resource(s), for example arn:aws:iam::111111111115:role/larkspur-audit, arn:aws:iam::111111111115:role/larkspur-break-glass. Not enforced, so this can wait until after the move.

  _From the tags check: environment: iam:role resources carry no environment tag._

  - Evidence (tag-compliance): target
    arn:aws:iam::111111111115:role/larkspur-audit
    arn:aws:iam::111111111115:role/larkspur-break-glass

- [ ] **4.9** `INFO` Tag to the target standard: environment: sqs:queue resources carry no environment tag
  _Where:_ account larkspur-payments-prod (111111111115)

  Tag policies do not require a tag to be present, so this does not block the move, but these resources fall outside the target standard (Fernhill-Cost-Allocation). Affected: 1 resource(s), for example arn:aws:sqs:us-east-1:111111111115:fraud-events. Not enforced, so this can wait until after the move.

  _From the tags check: environment: sqs:queue resources carry no environment tag._

  - Evidence (tag-compliance): target
    arn:aws:sqs:us-east-1:111111111115:fraud-events

- [ ] **4.10** Accept the invitation for share larkspur-core-network and confirm the resources
  _Where:_ account larkspur-payments-prod (111111111115)

  Outside the owner's organization the share arrives as an invitation. Accept it, then check that the ec2:Subnet, ec2:TransitGateway, route53resolver:ResolverRule are listed and that what is attached to them still works.

  _From the ram check: Networking share larkspur-core-network is lost: ec2:Subnet, ec2:TransitGateway, route53resolver:ResolverRule._

  ```sh
  aws ram get-resource-share-invitations --query "resourceShareInvitations[?resourceShareName=='larkspur-core-network']"
  aws ram accept-resource-share-invitation --resource-share-invitation-arn <invitation ARN from the previous command>
  aws ram list-resources --resource-owner OTHER-ACCOUNTS --resource-share-arns arn:aws:ram:us-east-1:111111111112:resource-share/06a7aefe6fddce828
  ```

- [ ] **4.11** Accept the invitation for share larkspur-ipam and confirm the resources
  _Where:_ account larkspur-payments-prod (111111111115)

  Outside the owner's organization the share arrives as an invitation. Accept it, then check that the ec2:IpamPool are listed and that what is attached to them still works.

  _From the ram check: Networking share larkspur-ipam is lost: ec2:IpamPool._

  ```sh
  aws ram get-resource-share-invitations --query "resourceShareInvitations[?resourceShareName=='larkspur-ipam']"
  aws ram accept-resource-share-invitation --resource-share-invitation-arn <invitation ARN from the previous command>
  aws ram list-resources --resource-owner OTHER-ACCOUNTS --resource-share-arns arn:aws:ram:us-east-1:111111111112:resource-share/01364b18a31c4fdca
  ```

- [ ] **4.12** Accept the invitation for share larkspur-workload-prefix-lists and confirm the resources
  _Where:_ account larkspur-payments-prod (111111111115)

  Outside the owner's organization the share arrives as an invitation. Accept it, then check that the ec2:PrefixList are listed and that what is attached to them still works.

  _From the ram check: Networking share larkspur-workload-prefix-lists is lost: ec2:PrefixList._

  ```sh
  aws ram get-resource-share-invitations --query "resourceShareInvitations[?resourceShareName=='larkspur-workload-prefix-lists']"
  aws ram accept-resource-share-invitation --resource-share-invitation-arn <invitation ARN from the previous command>
  aws ram list-resources --resource-owner OTHER-ACCOUNTS --resource-share-arns arn:aws:ram:us-east-1:111111111112:resource-share/0479521366b778243
  ```

- [ ] **4.13** Accept the invitation for share larkspur-license-config and confirm the resources
  _Where:_ account larkspur-payments-prod (111111111115)

  Outside the owner's organization the share arrives as an invitation. Accept it, then check that the license-manager:LicenseConfiguration are listed and that what is attached to them still works.

  _From the ram check: Share larkspur-license-config is lost: license-manager:LicenseConfiguration._

  ```sh
  aws ram get-resource-share-invitations --query "resourceShareInvitations[?resourceShareName=='larkspur-license-config']"
  aws ram accept-resource-share-invitation --resource-share-invitation-arn <invitation ARN from the previous command>
  aws ram list-resources --resource-owner OTHER-ACCOUNTS --resource-share-arns arn:aws:ram:us-east-1:111111111113:resource-share/016cff3e3072e28ed
  ```

- [ ] **4.14** `INFO` Share fernhill-core-network becomes available: ec2:TransitGateway, route53resolver:ResolverRule
  _Where:_ account larkspur-payments-prod (111111111115)

  Shared by account 222222222222 with organization o-fernhill0001 in the target organization. New attachments must be created by hand; nothing is attached automatically.

  _From the ram check: Share fernhill-core-network becomes available after the move: ec2:TransitGateway, route53resolver:ResolverRule._

  ```sh
  aws ram list-resources --resource-owner OTHER-ACCOUNTS --resource-share-arns arn:aws:ram:eu-west-1:222222222222:resource-share/09521366b77824316
  ```

  - Evidence (resource-share): target, `arn:aws:ram:eu-west-1:222222222222:resource-share/09521366b77824316`
    owner 222222222222; principals: organization o-fernhill0001; allow external principals false
    ec2:TransitGateway  arn:aws:ec2:eu-west-1:222222222222:transit-gateway/tgw-6a7aefe6fddce8281
    route53resolver:ResolverRule  arn:aws:route53resolver:eu-west-1:222222222222:resolver-rule/rslvr-rr-364b18a31c4fdca47

- [ ] **4.15** `INFO` Confirm StackSet fernhill-baseline deployed its stack instances to the account
  _Where:_ administration account 222222222221

  Baseline IAM roles and GuardDuty membership. Stack instances are created automatically when auto-deployment is on.

  _From the org-services check: StackSet fernhill-baseline in the target organization starts targeting the account._

  ```sh
  aws cloudformation list-stack-instances --stack-set-name fernhill-baseline --stack-instance-account 111111111115
  ```

  - Evidence (stackset): target, `fernhill-baseline`
    admin 222222222221; targets OUs ou-fern-bu; regions eu-west-1

- [ ] **4.16** Confirm CloudTrail coverage
  _Where:_ account larkspur-payments-prod (111111111115)

  Organization trail(s) larkspur-org-trail stop logging the account the moment it leaves. Trail(s) fernhill-org-trail (bucket fernhill-log-archive) of the target cover it once it has joined; confirm events arrive there. Between leaving and joining nothing logs management events unless the account has a trail of its own.

  _From the org-services check._

  ```sh
  aws cloudtrail describe-trails --include-shadow-trails
  aws cloudtrail lookup-events --max-results 5   # the most recent management events should be minutes old
  ```

  - Evidence (org-trail): source, `arn:aws:cloudtrail:us-east-1:111111111114:trail/larkspur-org-trail`
    bucket larkspur-cloudtrail-archive, home region us-east-1

  - Evidence (org-trail): target, `arn:aws:cloudtrail:eu-west-1:222222222224:trail/fernhill-org-trail`

- [ ] **4.17** Confirm AWS Config aggregation
  _Where:_ account larkspur-payments-prod (111111111115)

  Aggregator(s) larkspur-org-aggregator of the source stop receiving the account's configuration and compliance data. Aggregator(s) fernhill-org-aggregator in the target pick it up once it has joined and the recorder in the account is running; confirm the account appears as a source.

  _From the org-services check._

  ```sh
  aws configservice describe-configuration-recorder-status
  aws configservice describe-configuration-aggregator-sources-status --configuration-aggregator-name <target aggregator>   # in the aggregator account
  ```

  - Evidence (config-aggregator): source, `larkspur-org-aggregator`

  - Evidence (config-aggregator): target, `fernhill-org-aggregator`

- [ ] **4.18** `INFO` Confirm the target's delegated administrators enrol the account
  _Where:_ management account 222222222221 of Fernhill Group

  In the target organization: 222222222223 administers access-analyzer.amazonaws.com; 222222222223 administers guardduty.amazonaws.com; 222222222223 administers securityhub.amazonaws.com. Each administrator's auto-enable settings decide whether the account is enrolled on joining; check the service consoles for the new member.

  _From the org-services check._

  ```sh
  aws organizations list-delegated-administrators
  ```

- [ ] **4.19** `INFO` Confirm the Control Tower controls that start applying at Payments
  _Where:_ management account 222222222221 of Fernhill Group

  1 proactive control(s) start applying at Payments: CT.S3.PR.1. 3 preventive control(s) start applying at Payments: AWS-GR_CLOUDTRAIL_ENABLED, AWS-GR_CONFIG_ENABLED, AWS-GR_RESTRICT_ROOT_USER_ACCESS_KEYS. 4 detective control(s) start applying at Payments: AWS-GR_ENCRYPTED_VOLUMES, AWS-GR_RDS_STORAGE_ENCRYPTED, AWS-GR_RESTRICTED_SSH, AWS-GR_S3_BUCKET_PUBLIC_READ_PROHIBITED. Preventive controls apply through the OU's SCPs at once; detective and proactive ones report once the account is enrolled.

  _From the control-tower check._

  ```sh
  aws controltower list-enabled-controls --target-identifier <ARN of OU ou-fern-pay1>
  ```

  - Evidence (enabled-control): target, `arn:aws:controlcatalog:::control/7f3kq9x2m1pz8r4v6t0nb5cy`
    CT.S3.PR.1: Require that an Amazon S3 bucket has block public access settings configured
    proactive control on OU ou-fern-pay1; status SUCCEEDED, drift IN_SYNC; implemented as AWS::CloudFormation::Hook

  - Evidence (enabled-control): target, `arn:aws:controltower:eu-west-1::control/AWS-GR_CLOUDTRAIL_ENABLED`
    Disallow changes to CloudTrail set up by AWS Control Tower
    preventive control on OU ou-fern-bu; status SUCCEEDED, drift IN_SYNC; implemented as AWS::Organizations::Policy

  - Evidence (enabled-control): target, `arn:aws:controltower:eu-west-1::control/AWS-GR_CONFIG_ENABLED`
    Disallow changes to AWS Config set up by AWS Control Tower
    preventive control on OU ou-fern-bu; status SUCCEEDED, drift IN_SYNC; implemented as AWS::Organizations::Policy

  - Evidence (enabled-control): target, `arn:aws:controltower:eu-west-1::control/AWS-GR_RESTRICT_ROOT_USER_ACCESS_KEYS`
    Disallow creation of access keys for the root user
    preventive control on OU ou-fern-bu; status SUCCEEDED, drift IN_SYNC; implemented as AWS::Organizations::Policy

  - Evidence (enabled-control): target, `arn:aws:controltower:eu-west-1::control/AWS-GR_ENCRYPTED_VOLUMES`
    Detect whether encryption is enabled for Amazon EBS volumes attached to Amazon EC2 instances
    detective control on OU ou-fern-bu; status SUCCEEDED, drift IN_SYNC; implemented as AWS::Config::ConfigRule

  - Evidence (enabled-control): target, `arn:aws:controltower:eu-west-1::control/AWS-GR_RESTRICTED_SSH`
    Detect whether unrestricted incoming SSH traffic is allowed
    detective control on OU ou-fern-bu; status SUCCEEDED, drift IN_SYNC; implemented as AWS::Config::ConfigRule

  - Evidence (enabled-control): target, `arn:aws:controltower:eu-west-1::control/AWS-GR_RDS_STORAGE_ENCRYPTED`
    Detect whether storage encryption is enabled for Amazon RDS database instances
    detective control on OU ou-fern-bu; status SUCCEEDED, drift IN_SYNC; implemented as AWS::Config::ConfigRule

  - Evidence (enabled-control): target, `arn:aws:controltower:eu-west-1::control/AWS-GR_S3_BUCKET_PUBLIC_READ_PROHIBITED`
    Detect whether public read access to Amazon S3 buckets is allowed
    detective control on OU ou-fern-pay1; status SUCCEEDED, drift IN_SYNC; implemented as AWS::Config::ConfigRule

- [ ] **4.20** `REVIEW` Enroll the account in Control Tower from Account Factory (OU Payments)
  _Where:_ management account 222222222221 of Fernhill Group (Account Factory)

  Moving into a registered OU applies the OU's SCPs at once (the 3 preventive guardrail SCP(s) on the chain are attached to the OUs), but the 4 detective control(s) do not report and the baseline is not deployed until the account is enrolled. Enrolment is done from Account Factory (enroll account) and needs an AWSControlTowerExecution role in the account that trusts management account 222222222221, no Config recorder or delivery channel of the account's own in the governed regions (eu-west-1, eu-central-1), and an email address and name that Account Factory can register. The account has to have joined o-fernhill0001 before it can be enrolled.

  _From the control-tower check: Target OU Payments is registered with Control Tower; the account has to be enrolled._

  ```sh
  # Control Tower console → Account Factory → Enroll account → larkspur-payments-prod, OU OU Payments (ou-fern-pay1)
  ```

  - Evidence (landing-zone): target, `arn:aws:controltower:eu-west-1:222222222221:landingzone/FERNHILLLZ000001`
    version 3.3, status ACTIVE, drift IN_SYNC; home region eu-west-1; governed regions eu-west-1, eu-central-1; auto-enrollment disabled

  - Evidence (registered-ou): target, `ou-fern-pay1`
    OU Payments registered: baseline 4.0, status SUCCEEDED, drift IN_SYNC

- [ ] **4.21** Update references to the deleted AWSReservedSSO_* roles with the ARNs the target instance provisions
  _Where:_ account larkspur-payments-prod (111111111115)

  The new roles have a different random suffix. Replace the old ARNs found before the move in resource policies, key policies, EKS access entries and tooling.

  _From the identity-center check: 4 AWSReservedSSO\_* role(s) are deleted from the account: AWSReservedSSO\_AdministratorAccess\_*, AWSReservedSSO\_PaymentsEngineer\_*, AWSReservedSSO\_ReadOnlyAccess\_*, AWSReservedSSO\_DataPlatformOperator\_*._

  ```sh
  aws iam list-roles --path-prefix /aws-reserved/sso.amazonaws.com/ --query "Roles[].Arn"
  ```

- [ ] **4.22** `REVIEW` Assign AdministratorAccess to group Platform-Admins for the account in the target instance
  _Where:_ Identity Center of Fernhill Group (o-fernhill0001) (account 222222222221, eu-west-1)

  Users and groups in identity store d-fern0000001 are different objects from the source ones, so look each one up by name first; create it there if it is missing. Identity Center then provisions a new AWSReservedSSO_AdministratorAccess_* role in the account.

  _From the identity-center check: Permission set AdministratorAccess: 1 assignment(s) removed when the account leaves (group Platform-Admins)._

  ```sh
  aws identitystore list-groups --identity-store-id d-fern0000001 --filters AttributePath=DisplayName,AttributeValue="Platform-Admins" --query "Groups[].GroupId" --output text
  aws sso-admin create-account-assignment --instance-arn arn:aws:sso:::instance/ssoins-fernhill00000001 --target-id 111111111115 --target-type AWS_ACCOUNT --permission-set-arn arn:aws:sso:::permissionSet/ssoins-fernhill00000001/ps-fern00000001 --principal-type GROUP --principal-id <ID from the previous command>
  ```

- [ ] **4.23** `REVIEW` Assign PaymentsEngineer to group Payments-Engineers, user oncall.payments for the account in the target instance
  _Where:_ Identity Center of Fernhill Group (o-fernhill0001) (account 222222222221, eu-west-1)

  Users and groups in identity store d-fern0000001 are different objects from the source ones, so look each one up by name first; create it there if it is missing. Identity Center then provisions a new AWSReservedSSO_PaymentsEngineer_* role in the account.

  _From the identity-center check: Permission set PaymentsEngineer: 2 assignment(s) removed when the account leaves (group Payments-Engineers, user oncall.payments)._

  ```sh
  aws identitystore list-groups --identity-store-id d-fern0000001 --filters AttributePath=DisplayName,AttributeValue="Payments-Engineers" --query "Groups[].GroupId" --output text
  aws sso-admin create-account-assignment --instance-arn arn:aws:sso:::instance/ssoins-fernhill00000001 --target-id 111111111115 --target-type AWS_ACCOUNT --permission-set-arn <ARN of permission set PaymentsEngineer in the target> --principal-type GROUP --principal-id <ID from the previous command>
  aws identitystore list-users --identity-store-id d-fern0000001 --filters AttributePath=UserName,AttributeValue="oncall.payments" --query "Users[].UserId" --output text
  aws sso-admin create-account-assignment --instance-arn arn:aws:sso:::instance/ssoins-fernhill00000001 --target-id 111111111115 --target-type AWS_ACCOUNT --permission-set-arn <ARN of permission set PaymentsEngineer in the target> --principal-type USER --principal-id <ID from the previous command>
  ```

- [ ] **4.24** `REVIEW` Assign ReadOnlyAccess to group Security-Auditors for the account in the target instance
  _Where:_ Identity Center of Fernhill Group (o-fernhill0001) (account 222222222221, eu-west-1)

  Users and groups in identity store d-fern0000001 are different objects from the source ones, so look each one up by name first; create it there if it is missing. Identity Center then provisions a new AWSReservedSSO_ReadOnlyAccess_* role in the account.

  _From the identity-center check: Permission set ReadOnlyAccess: 1 assignment(s) removed when the account leaves (group Security-Auditors)._

  ```sh
  aws identitystore list-groups --identity-store-id d-fern0000001 --filters AttributePath=DisplayName,AttributeValue="Security-Auditors" --query "Groups[].GroupId" --output text
  aws sso-admin create-account-assignment --instance-arn arn:aws:sso:::instance/ssoins-fernhill00000001 --target-id 111111111115 --target-type AWS_ACCOUNT --permission-set-arn arn:aws:sso:::permissionSet/ssoins-fernhill00000001/ps-fern00000002 --principal-type GROUP --principal-id <ID from the previous command>
  ```

- [ ] **4.25** `REVIEW` Take o-larkspur0001 out of the policy of arn:aws:s3:::larkspur-payments-settlement-files once nothing there needs it
  _Where:_ account larkspur-payments-prod (111111111115)

  A condition that names both organizations is a transition state: it keeps admitting every principal of the organization the account left. Remove the former organization when the consumers that stayed behind no longer need the resource, or replace it with the specific accounts that do.

  resource `arn:aws:s3:::larkspur-payments-settlement-files`

  _From the workloads check: Bucket policy of arn:aws:s3:::larkspur-payments-settlement-files denies the account's own principals after the move._

- [ ] **4.26** `REVIEW` Confirm what became of stack StackSet-larkspur-baseline-roles-6dca20c6-dd9c-f808-0285-15666f7b21b9
  _Where:_ account larkspur-payments-prod (111111111115)

  With retention on, the stack is still there and no longer belongs to the StackSet; with retention off, it and its resources are gone and whatever replaced them has to be in place.

  regions us-east-1

  _From the workloads check: StackSet instance StackSet-larkspur-baseline-roles-6dca20c6-dd9c-f808-0285-15666f7b21b9 is deleted when the account leaves the organization: 4 resource(s)._

  ```sh
  aws cloudformation describe-stacks --stack-name StackSet-larkspur-baseline-roles-6dca20c6-dd9c-f808-0285-15666f7b21b9 --region us-east-1 --query 'Stacks[0].StackStatus'
  ```

- [ ] **4.27** `REVIEW` Take o-larkspur0001 out of the policy of arn:aws:iam::111111111115:role/DataExportReader once nothing there needs it
  _Where:_ account larkspur-payments-prod (111111111115)

  A condition that names both organizations is a transition state: it keeps admitting every principal of the organization the account left. Remove the former organization when the consumers that stayed behind no longer need the resource, or replace it with the specific accounts that do.

  resource `arn:aws:iam::111111111115:role/DataExportReader`

  _From the workloads check: Trust policy of arn:aws:iam::111111111115:role/DataExportReader stays tied to the organization the account leaves._

- [ ] **4.28** `REVIEW` Confirm stack payments-api still resolves its cross-account output
  _Where:_ account larkspur-payments-prod (111111111115)

  The reference is resolved only when the stack is created or updated, so nothing fails until the next deployment. Create a change set for the stack with its template unchanged, check that it is created without an access error, and delete it without executing it.

  regions us-east-1

  _From the workloads check: Stack payments-api reads output LogDestinationArn of stack shared-observability in account 111111111113._

  ```sh
  aws cloudformation describe-stacks --stack-name payments-api --region us-east-1 --query 'Stacks[0].[StackStatus,LastUpdatedTime]'
  ```

- [ ] **4.29** `INFO` Adopt or replace stack StackSet-larkspur-config-recorder-680f0561-2c45-0d1a-65b0-f6639c86913b, which StackSet larkspur-config-recorder left behind
  _Where:_ account larkspur-payments-prod (111111111115)

  RetainStacksOnAccountRemoval is on, so when the account leaves the organization the stack and its 3 resource(s) are kept in their current state and are no longer part of the StackSet: nobody updates them from then on. Adopt the stack in the destination or replace it. The stack is an ordinary stack of the account from now on: keep it under the account's own deployment, or delete it once the destination's baseline provides the same.

  regions eu-west-1

  _From the workloads check: StackSet instance StackSet-larkspur-config-recorder-680f0561-2c45-0d1a-65b0-f6639c86913b stays in the account, detached from StackSet larkspur-config-recorder._

  ```sh
  aws cloudformation describe-stacks --stack-name StackSet-larkspur-config-recorder-680f0561-2c45-0d1a-65b0-f6639c86913b --region eu-west-1 --query 'Stacks[0].[StackStatus,LastUpdatedTime]'
  aws cloudformation describe-stack-resources --stack-name StackSet-larkspur-config-recorder-680f0561-2c45-0d1a-65b0-f6639c86913b --region eu-west-1 --query 'StackResources[].[ResourceType,LogicalResourceId,PhysicalResourceId]' --output table
  ```

  - Evidence (stack-instance): source, `StackSet-larkspur-config-recorder-680f0561-2c45-0d1a-65b0-f6639c86913b`
    region eu-west-1, status CREATE_COMPLETE, 3 resource(s): AWS::Config::ConfigurationRecorder x1, AWS::Config::DeliveryChannel x1, AWS::IAM::Role x1
    provenance: service-managed StackSet (high confidence): the stack ID is listed as an instance of StackSet larkspur-config-recorder (permission model SERVICE_MANAGED, administered from 111111111111)
    StackSet larkspur-config-recorder: service-managed, auto-deployment true, retain stacks on account removal true, targets r-lark; the stack ID is one of the StackSet's instances

- [ ] **4.30** `INFO` Adopt or replace stack StackSet-larkspur-config-recorder-847f2bc4-f94d-ee77-28f6-0f769702dd36, which StackSet larkspur-config-recorder left behind
  _Where:_ account larkspur-payments-prod (111111111115)

  RetainStacksOnAccountRemoval is on, so when the account leaves the organization the stack and its 3 resource(s) are kept in their current state and are no longer part of the StackSet: nobody updates them from then on. Adopt the stack in the destination or replace it. The stack is an ordinary stack of the account from now on: keep it under the account's own deployment, or delete it once the destination's baseline provides the same.

  regions us-east-1

  _From the workloads check: StackSet instance StackSet-larkspur-config-recorder-847f2bc4-f94d-ee77-28f6-0f769702dd36 stays in the account, detached from StackSet larkspur-config-recorder._

  ```sh
  aws cloudformation describe-stacks --stack-name StackSet-larkspur-config-recorder-847f2bc4-f94d-ee77-28f6-0f769702dd36 --region us-east-1 --query 'Stacks[0].[StackStatus,LastUpdatedTime]'
  aws cloudformation describe-stack-resources --stack-name StackSet-larkspur-config-recorder-847f2bc4-f94d-ee77-28f6-0f769702dd36 --region us-east-1 --query 'StackResources[].[ResourceType,LogicalResourceId,PhysicalResourceId]' --output table
  ```

  - Evidence (stack-instance): source, `StackSet-larkspur-config-recorder-847f2bc4-f94d-ee77-28f6-0f769702dd36`
    region us-east-1, status CREATE_COMPLETE, 3 resource(s): AWS::Config::ConfigurationRecorder x1, AWS::Config::DeliveryChannel x1, AWS::IAM::Role x1
    provenance: service-managed StackSet (high confidence): the stack ID is listed as an instance of StackSet larkspur-config-recorder (permission model SERVICE_MANAGED, administered from 111111111111)
    StackSet larkspur-config-recorder: service-managed, auto-deployment true, retain stacks on account removal true, targets r-lark; the stack ID is one of the StackSet's instances

- [ ] **4.31** Exercise the 24 flagged request(s) from the account
  _Where:_ account larkspur-payments-prod (111111111115)

  These were denied or undecidable in the simulation. After the policy changes above and the move, confirm each one works (a dry run or a read of the resource is enough): cloudwatch:PutMetricData in ap-southeast-1, us-east-1; dynamodb:* in ap-southeast-1, us-east-1; ec2:CreateTransitGatewayVpcAttachment in ap-southeast-1, us-east-1; ec2:CreateTransitGatewayVpcAttachment in eu-west-1; ec2:CreateVpc in ap-southeast-1, us-east-1; ec2:CreateVpc in eu-west-1; ec2:DescribeInstances in ap-southeast-1, us-east-1; ec2:RunInstances in ap-southeast-1, us-east-1; ec2:TerminateInstances in ap-southeast-1, us-east-1; iam:CreateUser; kms:Decrypt in ap-southeast-1, us-east-1; lambda:InvokeFunction in ap-southeast-1, us-east-1; logs:CreateLogGroup in ap-southeast-1, us-east-1; rds:CreateDBInstance in us-east-1; rds:DescribeDBInstances in ap-southeast-1, us-east-1; s3:GetObject in ap-southeast-1, us-east-1; s3:PutObject in ap-southeast-1, us-east-1; secretsmanager:GetSecretValue in ap-southeast-1, us-east-1; ec2:TerminateInstances in eu-west-1; kms:Decrypt by arn:aws:iam::111111111118:role/DataPlatformIngest in us-east-1; s3:GetObject by 999999999999 in ap-southeast-1, eu-west-1, us-east-1; s3:ListBucket by 999999999999 in ap-southeast-1, eu-west-1, us-east-1; sts:AssumeRole by arn:aws:iam::111111111118:role/DataPlatformIngest; sqs:SendMessage by 888888888888 in us-east-1.

  ```sh
  # for each action, run the real call once from the principal that uses it, or check CloudTrail for AccessDenied events after a day
  ```

- [ ] **4.32** Collect a fresh snapshot and simulate the account at its new position
  _Where:_ management account 222222222221 of Fernhill Group

  With the account inside the target organization, a simulation of the account against its own parent compares it with itself and should come back GO, which closes the runbook.

  ```sh
  orgshift collect --profile <target management profile> --out <target snapshot>
  orgshift simulate --from <target snapshot> --account 111111111115 --target-ou ou-fern-pay1
  ```

## 5. Rollback

If something breaks, this puts the account back where it was. Built from the source policy chain of the simulation.

- [ ] **5.1** Leave Fernhill Group (o-fernhill0001) again
  _Where:_ account larkspur-payments-prod (111111111115), or management account 222222222221 of Fernhill Group

  Leave the target organization the same way the account left the source, or have the target management account remove it. The target chain denies organizations:LeaveOrganization (Fernhill-Root-Guardrails / DenyLeaveOrganization at root Root (r-fern)), so use remove-account-from-organization from the target management account.

  ```sh
  aws organizations leave-organization   # run inside the account
  aws organizations remove-account-from-organization --account-id 111111111115   # alternative, run by the target management account
  ```

- [ ] **5.2** Re-invite the account into Larkspur Holdings (o-larkspur0001) and accept
  _Where:_ management account 111111111111 of Larkspur Holdings, then account larkspur-payments-prod (111111111115)

  The account comes back at the source root with the AWS managed defaults only.

  ```sh
  aws organizations invite-account-to-organization --target Id=111111111115,Type=ACCOUNT
  aws organizations list-handshakes-for-account --query "Handshakes[?State=='OPEN'].[Id,Action]" --output table
  aws organizations accept-handshake --handshake-id <handshake ID>
  ```

- [ ] **5.3** Move the account back to OU Production (ou-lark-prod)
  _Where:_ management account 111111111111 of Larkspur Holdings

  Restores the original chain of OU attachments.

  ```sh
  aws organizations move-account --account-id 111111111115 --source-parent-id r-lark --destination-parent-id ou-lark-prod
  ```

- [ ] **5.4** Re-create the 4 Identity Center assignment(s) in the source instance
  _Where:_ Identity Center of Larkspur Holdings (o-larkspur0001) (account 111111111111, us-east-1)

  The source identity store still has the users and groups; the principal IDs below come from the snapshot. New AWSReservedSSO_* roles are provisioned with new suffixes, so references to the old ARNs do not come back by themselves.

  ```sh
  aws sso-admin create-account-assignment --instance-arn arn:aws:sso:::instance/ssoins-larkspur00000001 --target-id 111111111115 --target-type AWS_ACCOUNT --permission-set-arn arn:aws:sso:::permissionSet/ssoins-larkspur00000001/ps-lark00000001 --principal-type GROUP --principal-id ba31fe89-32df-0f24-6b40-1c6f590a40ff   # group Platform-Admins
  aws sso-admin create-account-assignment --instance-arn arn:aws:sso:::instance/ssoins-larkspur00000001 --target-id 111111111115 --target-type AWS_ACCOUNT --permission-set-arn arn:aws:sso:::permissionSet/ssoins-larkspur00000001/ps-lark00000002 --principal-type GROUP --principal-id c3055d88-cb7d-f258-9c41-70aefb8af533   # group Payments-Engineers
  aws sso-admin create-account-assignment --instance-arn arn:aws:sso:::instance/ssoins-larkspur00000001 --target-id 111111111115 --target-type AWS_ACCOUNT --permission-set-arn arn:aws:sso:::permissionSet/ssoins-larkspur00000001/ps-lark00000002 --principal-type USER --principal-id 79d949b7-eef8-371b-7b6d-f030997b6ac4   # user oncall.payments
  aws sso-admin create-account-assignment --instance-arn arn:aws:sso:::instance/ssoins-larkspur00000001 --target-id 111111111115 --target-type AWS_ACCOUNT --permission-set-arn arn:aws:sso:::permissionSet/ssoins-larkspur00000001/ps-lark00000003 --principal-type GROUP --principal-id fd2d8b09-2a71-ec4a-cc89-1ddb07a87174   # group Security-Auditors
  ```

- [ ] **5.5** Organization-scoped shares and the organization trail cover the account again on their own
  Shares offered to the source organization or its OUs, the organization trail, the Config aggregator and service-managed StackSets follow membership and need no action. Shares that owners narrowed to the account ID keep working as well.

- [ ] **5.6** Verify the original policy chain reaches the account again
  _Where:_ management account 111111111111 of Larkspur Holdings

  Compare with the source chain recorded by the simulation, root to account.

  ```sh
  aws organizations list-policies-for-target --target-id 111111111115 --filter SERVICE_CONTROL_POLICY
  aws organizations list-policies-for-target --target-id 111111111115 --filter RESOURCE_CONTROL_POLICY
  aws organizations list-policies-for-target --target-id 111111111115 --filter TAG_POLICY
  aws organizations list-policies-for-target --target-id 111111111115 --filter BACKUP_POLICY
  ```

  - Evidence (source-chain): source
    root Root (r-lark): FullAWSAccess (p-FullAWSAccess), Larkspur-Baseline-Guardrails (p-lark0001)
    OU Workloads (ou-lark-work): FullAWSAccess (p-FullAWSAccess), Larkspur-Allowed-Regions (p-lark0002)
    OU Production (ou-lark-prod): FullAWSAccess (p-FullAWSAccess)
    account larkspur-payments-prod (111111111115): FullAWSAccess (p-FullAWSAccess)

  - Evidence (source-chain): source
    root Root (r-lark): RCPFullAWSAccess (p-RCPFullAWSAccess)
    OU Workloads (ou-lark-work): RCPFullAWSAccess (p-RCPFullAWSAccess)
    OU Production (ou-lark-prod): RCPFullAWSAccess (p-RCPFullAWSAccess)
    account larkspur-payments-prod (111111111115): RCPFullAWSAccess (p-RCPFullAWSAccess)

  - Evidence (source-chain): source
    root Root (r-lark): Larkspur-Tagging-Standard (p-lark0004)
    OU Workloads (ou-lark-work): none
    OU Production (ou-lark-prod): none
    account larkspur-payments-prod (111111111115): none

  - Evidence (source-chain): source
    root Root (r-lark): none
    OU Workloads (ou-lark-work): none
    OU Production (ou-lark-prod): Larkspur-Daily-Backups (p-lark0005)
    account larkspur-payments-prod (111111111115): none

