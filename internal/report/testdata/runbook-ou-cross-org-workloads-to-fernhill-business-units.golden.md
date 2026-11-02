# orgshift runbook: OU Workloads (ou-lark-work)

Move from **Larkspur Holdings** (`o-larkspur0001`) Root to **Fernhill Group** (`o-fernhill0001`) Root / Business Units, with 2 nested OU(s) and 3 account(s).

**Verdict NO-GO.** 24 OU-level steps and 3 account runbook(s): 3 NO-GO, 0 REVIEW, 0 GO. Clear every account's blockers before the OU tree is recreated.

> Generated from a snapshot simulation. Every command is for an operator to review and run by hand; orgshift never writes to AWS.

> Organizations has no call that moves an OU. The OU tree is created again under the new parent, the policies are attached to the new OUs and the accounts are moved one by one; new OU IDs are placeholders in angle brackets until they exist.

> Recreated OUs keep their source IDs in this report as placeholders; the target organization assigns new IDs.

## Accounts

| Verdict | Account | Steps | Blocking |
|---|---|---|---|
| NO-GO | larkspur-data-prod (`111111111118`) | 33 | 2 |
| NO-GO | larkspur-payments-dev (`111111111116`) | 29 | 1 |
| NO-GO | larkspur-payments-prod (`111111111115`) | 40 | 3 |

## 1. Before the move: the OU tree

What has to be settled for the OUs themselves. Every account's own blockers are in its runbook below and have to be cleared first.

- [ ] **1.1** `NO-GO` Clear the blockers of 3 account(s) first
  The OU verdict is the worst account verdict. Work through the first phase of each account runbook below: larkspur-data-prod (111111111118): athena:StartQueryExecution becomes denied after the move; ec2:CreateTransitGatewayVpcAttachment becomes denied after the move; ec2:RunInstances becomes denied after the move; glue:StartJobRun becomes denied after the move; kms:Decrypt becomes denied after the move; s3:GetObject becomes denied after the move; s3:PutObject becomes denied after the move; s3:PutObject by arn:aws:iam::111111111115:role/SettlementExporter becomes denied after the move; Networking share larkspur-core-network is lost: ec2:Subnet, ec2:TransitGateway, route53resolver:ResolverRule | larkspur-payments-dev (111111111116): ec2:CreateVpc becomes denied after the move; ec2:RunInstances becomes denied after the move; lambda:* becomes denied after the move; Networking share larkspur-core-network is lost: ec2:Subnet, ec2:TransitGateway, route53resolver:ResolverRule | larkspur-payments-prod (111111111115): cloudwatch:PutMetricData becomes denied after the move; dynamodb:* becomes denied after the move; ec2:CreateTransitGatewayVpcAttachment becomes denied after the move; ec2:CreateVpc becomes denied after the move; ec2:DescribeInstances becomes denied after the move; ec2:RunInstances becomes denied after the move; ec2:TerminateInstances becomes denied after the move; iam:CreateUser becomes denied after the move; kms:Decrypt becomes denied after the move; lambda:InvokeFunction becomes denied after the move; logs:CreateLogGroup becomes denied after the move; rds:CreateDBInstance becomes denied after the move; rds:DescribeDBInstances becomes denied after the move; s3:GetObject becomes denied after the move; s3:PutObject becomes denied after the move; secretsmanager:GetSecretValue becomes denied after the move; kms:Decrypt by arn:aws:iam::111111111118:role/DataPlatformIngest becomes denied after the move; s3:GetObject by 999999999999 becomes denied after the move; s3:ListBucket by 999999999999 becomes denied after the move; sts:AssumeRole by arn:aws:iam::111111111118:role/DataPlatformIngest becomes denied after the move; Networking share larkspur-core-network is lost: ec2:Subnet, ec2:TransitGateway, route53resolver:ResolverRule.

- [ ] **1.2** `REVIEW` Agree the target layout: OU Workloads with 2 nested OU(s) under OU Business Units (ou-fern-bu)
  _Where:_ management account 222222222221 of Fernhill Group

  Organizations moves accounts, never OUs, across organizations. Each of the 3 account(s) leaves o-larkspur0001 on its own, is invited into o-fernhill0001 and is then placed into OUs you create by hand under Business Units (ou-fern-bu). 3 customer-managed policy attachment(s) on the OU tree do not travel: the policies must be recreated in the target organization and attached to the new OUs, or dropped on purpose. The per-account verdicts below assume the recreated OUs start with only the AWS managed defaults attached. Decide which of the customer-managed policies are recreated as they are, merged into the target's own policies, or dropped on purpose; the steps below assume they are recreated unchanged.

  - Evidence (ou-attachments): source, `ou-lark-work`
    OU Workloads: SCP Larkspur-Allowed-Regions

  - Evidence (ou-attachments): source, `ou-lark-dev`
    OU Development: SCP Larkspur-Dev-Guardrails

  - Evidence (ou-attachments): source, `ou-lark-prod`
    OU Production: BACKUP Larkspur-Daily-Backups

## 2. Before the move: create the new OU tree

Organizations cannot move an OU, so the tree is built again under the new parent with the same attachments before any account moves.

- [ ] **2.1** `REVIEW` Create policy Larkspur-Allowed-Regions (SCP) in Fernhill Group (o-fernhill0001)
  _Where:_ management account 222222222221 of Fernhill Group

  Attached to Workloads in the source tree. Policies do not travel between organizations; the document is in the evidence. The target root must have the SCP type enabled.

  ```sh
  aws organizations create-policy --name Larkspur-Allowed-Regions --type SERVICE_CONTROL_POLICY --description "recreated from Larkspur Holdings (o-larkspur0001)" --content file://Larkspur-Allowed-Regions.json
  ```

  - Evidence (policy-document): source, SCP `Larkspur-Allowed-Regions` (p-lark0002)

    ```json
    {
      "Version": "2012-10-17",
      "Statement": [
        {
          "Sid": "DenyOutsideApprovedRegions",
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
            "account:*"
          ],
          "Resource": "*",
          "Condition": {
            "StringNotEquals": {
              "aws:RequestedRegion": [
                "us-east-1",
                "eu-west-1",
                "ap-southeast-1"
              ]
            }
          }
        }
      ]
    }
    ```

- [ ] **2.2** `REVIEW` Create policy Larkspur-Dev-Guardrails (SCP) in Fernhill Group (o-fernhill0001)
  _Where:_ management account 222222222221 of Fernhill Group

  Attached to Development in the source tree. Policies do not travel between organizations; the document is in the evidence. The target root must have the SCP type enabled.

  ```sh
  aws organizations create-policy --name Larkspur-Dev-Guardrails --type SERVICE_CONTROL_POLICY --description "recreated from Larkspur Holdings (o-larkspur0001)" --content file://Larkspur-Dev-Guardrails.json
  ```

  - Evidence (policy-document): source, SCP `Larkspur-Dev-Guardrails` (p-lark0006)

    ```json
    {
      "Version": "2012-10-17",
      "Statement": [
        {
          "Sid": "NoCommitments",
          "Effect": "Deny",
          "Action": [
            "ec2:PurchaseReservedInstancesOffering",
            "ec2:ModifyReservedInstances",
            "savingsplans:CreateSavingsPlan",
            "rds:PurchaseReservedDBInstancesOffering"
          ],
          "Resource": "*"
        }
      ]
    }
    ```

- [ ] **2.3** `REVIEW` Create policy Larkspur-Daily-Backups (BACKUP) in Fernhill Group (o-fernhill0001)
  _Where:_ management account 222222222221 of Fernhill Group

  Attached to Production in the source tree. Policies do not travel between organizations; the document is in the evidence. The target root must have the BACKUP type enabled.

  ```sh
  aws organizations create-policy --name Larkspur-Daily-Backups --type BACKUP_POLICY --description "recreated from Larkspur Holdings (o-larkspur0001)" --content file://Larkspur-Daily-Backups.json
  ```

  - Evidence (policy-document): source, BACKUP `Larkspur-Daily-Backups` (p-lark0005)

    ```json
    {
      "plans": {
        "larkspur-daily": {
          "regions": {
            "@@assign": [
              "us-east-1",
              "eu-west-1"
            ]
          },
          "rules": {
            "daily": {
              "schedule_expression": {
                "@@assign": "cron(0 3 ? * * *)"
              },
              "target_backup_vault_name": {
                "@@assign": "Default"
              },
              "lifecycle": {
                "delete_after_days": {
                  "@@assign": "35"
                }
              }
            }
          },
          "selections": {
            "tags": {
              "prod": {
                "iam_role_arn": {
                  "@@assign": "arn:aws:iam::$account:role/LarkspurBackupRole"
                },
                "tag_key": {
                  "@@assign": "environment"
                },
                "tag_value": {
                  "@@assign": [
                    "production"
                  ]
                }
              }
            }
          }
        }
      }
    }
    ```

- [ ] **2.4** Create OU Workloads under OU Business Units (ou-fern-bu)
  _Where:_ management account 222222222221 of Fernhill Group

  The source OU Workloads (ou-lark-work) keeps existing until its accounts have moved. Note the new ID; the later steps refer to it as <ID of the new Workloads OU>.

  ```sh
  aws organizations create-organizational-unit --parent-id ou-fern-bu --name "Workloads"
  ```

- [ ] **2.5** Attach to the new Workloads OU: SCP Larkspur-Allowed-Regions
  _Where:_ management account 222222222221 of Fernhill Group

  Same attachments as the source OU, so the accounts see the same chain below the moved OU once they arrive. The AWS managed defaults are attached automatically.

  ```sh
  aws organizations attach-policy --policy-id <ID of the recreated Larkspur-Allowed-Regions> --target-id <ID of the new Workloads OU>
  ```

- [ ] **2.6** Create OU Development under the new Workloads OU
  _Where:_ management account 222222222221 of Fernhill Group

  The source OU Development (ou-lark-dev) keeps existing until its accounts have moved. Note the new ID; the later steps refer to it as <ID of the new Development OU>.

  ```sh
  aws organizations create-organizational-unit --parent-id <ID of the new Workloads OU> --name "Development"
  ```

- [ ] **2.7** Attach to the new Development OU: SCP Larkspur-Dev-Guardrails
  _Where:_ management account 222222222221 of Fernhill Group

  Same attachments as the source OU, so the accounts see the same chain below the moved OU once they arrive. The AWS managed defaults are attached automatically.

  ```sh
  aws organizations attach-policy --policy-id <ID of the recreated Larkspur-Dev-Guardrails> --target-id <ID of the new Development OU>
  ```

- [ ] **2.8** Create OU Production under the new Workloads OU
  _Where:_ management account 222222222221 of Fernhill Group

  The source OU Production (ou-lark-prod) keeps existing until its accounts have moved. Note the new ID; the later steps refer to it as <ID of the new Production OU>.

  ```sh
  aws organizations create-organizational-unit --parent-id <ID of the new Workloads OU> --name "Production"
  ```

- [ ] **2.9** Attach to the new Production OU: BACKUP Larkspur-Daily-Backups
  _Where:_ management account 222222222221 of Fernhill Group

  Same attachments as the source OU, so the accounts see the same chain below the moved OU once they arrive. The AWS managed defaults are attached automatically.

  ```sh
  aws organizations attach-policy --policy-id <ID of the recreated Larkspur-Daily-Backups> --target-id <ID of the new Production OU>
  ```

## 3. The move

Each account leaves on its own and joins the target organization; its runbook has the exact sequence. Once it has accepted the invitation, move it into its new OU.

- [ ] **3.1** Move the 3 account(s) one by one: invite, leave, accept
  _Where:_ management account 222222222221 of Fernhill Group, then each account

  Follow the move phase of each account runbook below, in whatever order limits the standalone time. Accounts: larkspur-data-prod (111111111118), larkspur-payments-dev (111111111116), larkspur-payments-prod (111111111115).

  ```sh
  aws organizations invite-account-to-organization --target Id=<account ID>,Type=ACCOUNT
  aws organizations leave-organization   # inside each account, or remove-account-from-organization from the source management account
  aws organizations accept-handshake --handshake-id <handshake ID>   # inside each account
  ```

- [ ] **3.2** Move larkspur-payments-dev (111111111116) from the target root into the new Development OU
  _Where:_ management account 222222222221 of Fernhill Group

  After accepting the invitation the account sits at the target root.

  ```sh
  aws organizations move-account --account-id 111111111116 --source-parent-id r-fern --destination-parent-id <ID of the new Development OU>
  ```

- [ ] **3.3** Move larkspur-data-prod (111111111118) from the target root into the new Production OU
  _Where:_ management account 222222222221 of Fernhill Group

  After accepting the invitation the account sits at the target root.

  ```sh
  aws organizations move-account --account-id 111111111118 --source-parent-id r-fern --destination-parent-id <ID of the new Production OU>
  ```

- [ ] **3.4** Move larkspur-payments-prod (111111111115) from the target root into the new Production OU
  _Where:_ management account 222222222221 of Fernhill Group

  After accepting the invitation the account sits at the target root.

  ```sh
  aws organizations move-account --account-id 111111111115 --source-parent-id r-fern --destination-parent-id <ID of the new Production OU>
  ```

## 4. After the move: checks

Confirm the tree, register it where Control Tower is involved and remove what is left behind.

- [ ] **4.1** Confirm the new tree under OU Business Units (ou-fern-bu) and every account's parent
  _Where:_ management account 222222222221 of Fernhill Group

  Every account should list its new OU as parent and the new OUs should carry the attachments from the steps above.

  ```sh
  aws organizations list-parents --child-id 111111111116
  aws organizations list-parents --child-id 111111111118
  aws organizations list-parents --child-id 111111111115
  aws organizations list-organizational-units-for-parent --parent-id ou-fern-bu
  ```

- [ ] **4.2** `INFO` The new parent Business Units is registered with Control Tower; register the moved OU too
  _Where:_ management account 222222222221 of Fernhill Group (Control Tower)

  Registration is not inherited. Nested OUs under a registered parent inherit its controls through the SCPs, but Control Tower only governs the accounts in an OU once that OU is registered itself. The per-account findings below list what enrolment needs.

  ```sh
  # Control Tower console → Organization → the new Workloads OU → Register OU
  ```

  - Evidence (registered-ou): target, `ou-fern-bu`
    OU Business Units registered: baseline 4.0, status SUCCEEDED, drift IN_SYNC

- [ ] **4.3** Delete the 3 empty source OU(s)
  _Where:_ management account 111111111111 of Larkspur Holdings

  Once every account has left, the source OUs are empty. Delete the deepest ones first; their policy attachments go with them (the policies themselves stay in the source organization).

  ```sh
  aws organizations delete-organizational-unit --organizational-unit-id ou-lark-prod
  aws organizations delete-organizational-unit --organizational-unit-id ou-lark-dev
  aws organizations delete-organizational-unit --organizational-unit-id ou-lark-work
  ```

- [ ] **4.4** Collect a fresh snapshot and simulate the new OU against its own parent
  _Where:_ management account 222222222221 of Fernhill Group

  With the tree in place, a simulation of the new OU against its current parent compares it with itself and should come back GO.

  ```sh
  orgshift collect --profile <target management profile> --out <target snapshot>
  orgshift simulate --from <target snapshot> --ou <ID of the new Workloads OU> --target-ou ou-fern-bu
  ```

## 5. Rollback

Puts the OU tree back where it was. Built from the source attachments of the simulation.

- [ ] **5.1** Move every account back: follow the rollback of each account runbook
  _Where:_ each account, then management account 111111111111 of Larkspur Holdings

  Each account leaves the target organization, is re-invited into the source and moved under the recreated source OUs below.

- [ ] **5.2** Recreate OU Workloads under root Root (r-lark) with its attachments
  _Where:_ management account 111111111111 of Larkspur Holdings

  If the source OU Workloads (ou-lark-work) still exists, skip the creation and reuse it. The policies still exist in the source organization.

  ```sh
  aws organizations create-organizational-unit --parent-id r-lark --name "Workloads"   # only if Workloads (ou-lark-work) was already deleted
  aws organizations attach-policy --policy-id p-lark0002 --target-id <ID of the new Workloads OU>
  ```

- [ ] **5.3** Recreate OU Development under the recreated Workloads OU with its attachments
  _Where:_ management account 111111111111 of Larkspur Holdings

  If the source OU Development (ou-lark-dev) still exists, skip the creation and reuse it. The policies still exist in the source organization.

  ```sh
  aws organizations create-organizational-unit --parent-id <ID of the new Workloads OU> --name "Development"   # only if Development (ou-lark-dev) was already deleted
  aws organizations attach-policy --policy-id p-lark0006 --target-id <ID of the new Development OU>
  ```

- [ ] **5.4** Recreate OU Production under the recreated Workloads OU with its attachments
  _Where:_ management account 111111111111 of Larkspur Holdings

  If the source OU Production (ou-lark-prod) still exists, skip the creation and reuse it. The policies still exist in the source organization.

  ```sh
  aws organizations create-organizational-unit --parent-id <ID of the new Workloads OU> --name "Production"   # only if Production (ou-lark-prod) was already deleted
  aws organizations attach-policy --policy-id p-lark0005 --target-id <ID of the new Production OU>
  ```

- [ ] **5.5** Delete the new OUs once they are empty
  _Where:_ management account 222222222221 of Fernhill Group

  Deepest first; the attachments go with them.

  ```sh
  aws organizations delete-organizational-unit --organizational-unit-id <new OU ID>
  ```

## Account larkspur-data-prod (`111111111118`): NO-GO

33 steps: 6 before the move (2 blocking), 10 to re-create, 1 for the move itself, 15 checks afterwards and 1 to roll back.

### 1. Before the move: fix the blockers and make the decisions

Everything here is settled while the account is still at its current position. NO-GO steps block the move; REVIEW steps need a decision or a check by hand.

- [ ] **1.1** `NO-GO` SCP Fernhill-EU-Only-Regions / DenyOutsideEU denies 7 actions after the move
  _Where:_ management account 222222222221 of Fernhill Group

  Attached at OU Business Units (ou-fern-bu) in the target organization. Allowed today; after the move it denies: athena:StartQueryExecution in us-east-1; ec2:CreateTransitGatewayVpcAttachment in us-east-1; ec2:RunInstances in us-east-1; glue:StartJobRun in us-east-1; kms:Decrypt in us-east-1; s3:GetObject in us-east-1; s3:PutObject in us-east-1. The change to review: edit statement DenyOutsideEU so it no longer covers account 111111111118 (for example a Condition on aws:PrincipalAccount, or a narrower Action or Resource list), detach Fernhill-EU-Only-Regions from OU Business Units (ou-fern-bu), or stop using the actions before the move.

  actions `athena:StartQueryExecution`, `ec2:CreateTransitGatewayVpcAttachment`, `ec2:RunInstances`, `glue:StartJobRun`, `kms:Decrypt`, `s3:GetObject`, `s3:PutObject`

  _From the scp check: 7 findings with the same cause._

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

- [ ] **1.2** `NO-GO` RCP Fernhill-Block-External-Principals / EnforceOrgIdentities denies 1 request after the move
  _Where:_ management account 222222222221 of Fernhill Group

  Attached at OU Business Units (ou-fern-bu) in the target organization. Allowed today; after the move it denies: s3:PutObject by arn:aws:iam::111111111115:role/SettlementExporter in eu-west-1, us-east-1. The change to review: edit statement EnforceOrgIdentities so these principals are exempt (for example list their organization in the aws:PrincipalOrgID condition, or exempt the resource), detach Fernhill-Block-External-Principals from OU Business Units (ou-fern-bu), or move the callers inside the target organization.

  actions `s3:PutObject`; principal `arn:aws:iam::111111111115:role/SettlementExporter`; resource `arn:aws:s3:::larkspur-data-lake/ledger/*`; regions eu-west-1, us-east-1

  _From the rcp check: s3:PutObject by arn:aws:iam::111111111115:role/SettlementExporter becomes denied after the move._

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

- [ ] **1.3** `REVIEW` No tagged resources were provided for this account
  _Where:_ account larkspur-data-prod (111111111118)

  Add usage.tagged_resources to the source snapshot (for example from the Resource Groups Tagging API) to check compliance against the target tag policy.

  _From the tags check: No tagged resources were provided for this account._

  ```sh
  aws resourcegroupstaggingapi get-resources --resources-per-page 100   # sample to add as usage.tagged_resources
  ```

- [ ] **1.4** `REVIEW` Make the account able to stand alone
  _Where:_ account larkspur-data-prod (111111111118), signed in as root or an administrator

  Before it can leave, the account needs its own verified contact information, a payment method and a support plan choice; Organizations fails the removal with ConstraintViolationException until they are in place (with Enterprise Support, a billing case can arrange the standalone period instead of a payment method per account). It then has to be invited by the target management account 222222222221 and accept the invitation: an account belongs to one organization at a time, so it leaves first; the invitation must be answered within 15 days; the policies attached to the target root and the OU it lands in apply at once; the target's organization trail covers it automatically and Config, GuardDuty or Security Hub may be enabled automatically for new members, so account-level trails and detectors may double charges; Organizations does not create OrganizationAccountAccessRole for an invited account. SCPs in the source that deny organizations:LeaveOrganization must be lifted for the move, or the source management account removes the account instead. The account also loses access to the cost and usage data of its time in the source organization and is no longer covered by the source organization's agreements. Transfer procedure model 2026-11-02. Contact information, alternate contacts and the payment method can be checked with the Account API; identity verification and the support plan are done in the console.

  _From the org-services check: Standalone account prerequisites and invitation._

  ```sh
  aws account get-contact-information
  aws account get-alternate-contact --alternate-contact-type BILLING
  # console: Billing and Cost Management → Payment preferences; Account → Identity verification; Support → Support plan
  ```

- [ ] **1.5** `REVIEW` Lift the deny on organizations:LeaveOrganization in SCP Larkspur-Baseline-Guardrails / DenyLeaveOrganization, or let the management account remove the account
  _Where:_ management account 111111111111 of Larkspur Holdings

  SCP Larkspur-Baseline-Guardrails (p-lark0001) is attached at root Root (r-lark) and denies organizations:LeaveOrganization without a condition, so leave-organization run from inside the account fails. Either detach the policy or edit the statement for the duration of the move and put it back afterwards, or run remove-account-from-organization from the management account, which SCPs do not restrict.

  actions `organizations:LeaveOrganization`

  _From the org-services check: Standalone account prerequisites and invitation._

  ```sh
  aws organizations describe-policy --policy-id p-lark0001 --query Content --output text
  aws organizations remove-account-from-organization --account-id 111111111118   # the alternative that needs no policy change
  ```

  - Evidence (policy-statement): source, SCP `Larkspur-Baseline-Guardrails` (p-lark0001), statement DenyLeaveOrganization, at root Root (r-lark)
    Deny organizations:LeaveOrganization

- [ ] **1.6** `REVIEW` Find what references the 3 AWSReservedSSO_* role(s) of the account
  _Where:_ account larkspur-data-prod (111111111118)

  When the account leaves the organization, Identity Center cleans up the resources it created in the account; the documentation names the service-linked role, and the IAM roles provisioned for permission sets (path /aws-reserved/sso.amazonaws.com/us-east-1/) go with the instance's control over the account, so plan for them to disappear and confirm in IAM after the move. Anything that names these roles breaks: resource and trust policies, KMS key policies, S3 bucket policies, EKS access entries, pipelines and tools that assume them, and CloudTrail history keeps the old ARNs. The target instance provisions new roles with a different random suffix, so references have to be updated, not restored. The exact suffix is only visible in IAM; offline the roles are known by their pattern. List the exact role ARNs now, while they exist, and search for them so the references can be updated after the move.

  _From the identity-center check: 3 AWSReservedSSO\_* role(s) are deleted from the account: AWSReservedSSO\_AdministratorAccess\_*, AWSReservedSSO\_ReadOnlyAccess\_*, AWSReservedSSO\_DataPlatformOperator\_*._

  ```sh
  aws iam list-roles --path-prefix /aws-reserved/sso.amazonaws.com/us-east-1/ --query "Roles[].Arn"
  # search bucket, key, topic, queue and secret policies, EKS access entries, role trust policies and CI configuration for AWSReservedSSO_
  ```

  - Evidence (reserved-role): source, `AWSReservedSSO_AdministratorAccess_*`
    role for permission set AdministratorAccess (arn:aws:sso:::permissionSet/ssoins-larkspur00000001/ps-lark00000001) under /aws-reserved/sso.amazonaws.com/us-east-1/; 1 assignment(s) on the account

  - Evidence (reserved-role): source, `AWSReservedSSO_ReadOnlyAccess_*`
    role for permission set ReadOnlyAccess (arn:aws:sso:::permissionSet/ssoins-larkspur00000001/ps-lark00000003) under /aws-reserved/sso.amazonaws.com/us-east-1/; 1 assignment(s) on the account

  - Evidence (reserved-role): source, `AWSReservedSSO_DataPlatformOperator_*`
    role for permission set DataPlatformOperator (arn:aws:sso:::permissionSet/ssoins-larkspur00000001/ps-lark00000004) under /aws-reserved/sso.amazonaws.com/us-east-1/; 1 assignment(s) on the account

### 2. Before the move: re-create what does not travel

Shares, delegations, permission sets and stacks that are scoped to the account's current position do not follow it. Prepare the replacements now so nothing is interrupted.

- [ ] **2.1** `NO-GO` Re-share larkspur-core-network with the account directly: ec2:Subnet, ec2:TransitGateway, route53resolver:ResolverRule
  _Where:_ owner account 111111111112

  Owner 111111111112 shares larkspur-core-network (ec2:Subnet, ec2:TransitGateway, route53resolver:ResolverRule) with arn:aws:organizations::111111111111:organization/o-larkspur0001 today. After the move those principals no longer cover the account. Ask the owner to add account 111111111118 as a principal before the move so nothing attached to these resources is interrupted. The account will be outside the organization, so the share has to allow external principals and the account has to accept an invitation. The documentation says traffic or a declared operation stops with this share, so the move stays NO-GO until it is done: Shared by account 111111111112 with organization o-larkspur0001. It is scoped to the source organization or one of its OUs and stops applying when the account leaves. What the documentation says happens: ec2:Subnet: existing participant resources continue to run in the subnet; no new resources can be created in it, while existing ones can still be modified, described and deleted (subnets can only be shared inside one organization). Potentially affected: ec2:RunInstances in use may target the shared resources; confirm. ec2:Subnet can only be shared inside one organization, so it cannot be re-shared with the account once it has left. ec2:TransitGateway: existing transit gateway attachments remain functional; the account can no longer describe the transit gateway or create new attachments, and either side can delete the attachments. The account uses ec2:CreateTransitGatewayVpcAttachment, which needs the share: that stops working. route53resolver:ResolverRule: traffic is affected at once, the rule's associations with the account's VPCs are removed and Resolver answers those queries from the remaining rules at once (an OU-scoped rule keeps its associations only when it is also shared with the destination OU). Ask the owner to re-share the resources with the account directly before the move, with external principals allowed, and accept the invitation after the move.

  resource `arn:aws:ram:us-east-1:111111111112:resource-share/06a7aefe6fddce828`

  _From the ram check: Networking share larkspur-core-network is lost: ec2:Subnet, ec2:TransitGateway, route53resolver:ResolverRule._

  ```sh
  aws ram update-resource-share --resource-share-arn arn:aws:ram:us-east-1:111111111112:resource-share/06a7aefe6fddce828 --allow-external-principals
  aws ram associate-resource-share --resource-share-arn arn:aws:ram:us-east-1:111111111112:resource-share/06a7aefe6fddce828 --principals 111111111118
  ```

  - Evidence (resource-share): source, `arn:aws:ram:us-east-1:111111111112:resource-share/06a7aefe6fddce828`
    owner 111111111112; principals: organization o-larkspur0001; allow external principals false
    ec2:TransitGateway  arn:aws:ec2:us-east-1:111111111112:transit-gateway/tgw-54924a77a3120b1ad
    ec2:Subnet  arn:aws:ec2:us-east-1:111111111112:subnet/subnet-e056c922dbb17986a
    ec2:Subnet  arn:aws:ec2:us-east-1:111111111112:subnet/subnet-1d0f03c495e44a0e4
    route53resolver:ResolverRule  arn:aws:route53resolver:us-east-1:111111111112:resolver-rule/rslvr-rr-66e02e8ff78976d8b

- [ ] **2.2** `REVIEW` Re-share larkspur-ipam with the account directly: ec2:IpamPool
  _Where:_ owner account 111111111112

  Owner 111111111112 shares larkspur-ipam (ec2:IpamPool) with arn:aws:organizations::111111111111:organization/o-larkspur0001 today. After the move those principals no longer cover the account. Ask the owner to add account 111111111118 as a principal before the move so nothing attached to these resources is interrupted. The account will be outside the organization, so the share has to allow external principals and the account has to accept an invitation.

  resource `arn:aws:ram:us-east-1:111111111112:resource-share/01364b18a31c4fdca`

  _From the ram check: Networking share larkspur-ipam is lost: ec2:IpamPool._

  ```sh
  aws ram update-resource-share --resource-share-arn arn:aws:ram:us-east-1:111111111112:resource-share/01364b18a31c4fdca --allow-external-principals
  aws ram associate-resource-share --resource-share-arn arn:aws:ram:us-east-1:111111111112:resource-share/01364b18a31c4fdca --principals 111111111118
  ```

  - Evidence (resource-share): source, `arn:aws:ram:us-east-1:111111111112:resource-share/01364b18a31c4fdca`
    owner 111111111112; principals: organization o-larkspur0001; allow external principals false
    ec2:IpamPool  arn:aws:ec2::111111111112:ipam-pool/ipam-pool-8afc13dafc2e5d265

- [ ] **2.3** `REVIEW` Re-share larkspur-workload-prefix-lists with the account directly: ec2:PrefixList
  _Where:_ owner account 111111111112

  Owner 111111111112 shares larkspur-workload-prefix-lists (ec2:PrefixList) with arn:aws:organizations::111111111111:ou/o-larkspur0001/ou-lark-work today. After the move those principals no longer cover the account. Ask the owner to add account 111111111118 as a principal before the move so nothing attached to these resources is interrupted. The account will be outside the organization, so the share has to allow external principals and the account has to accept an invitation.

  resource `arn:aws:ram:us-east-1:111111111112:resource-share/0479521366b778243`

  _From the ram check: Networking share larkspur-workload-prefix-lists is lost: ec2:PrefixList._

  ```sh
  aws ram update-resource-share --resource-share-arn arn:aws:ram:us-east-1:111111111112:resource-share/0479521366b778243 --allow-external-principals
  aws ram associate-resource-share --resource-share-arn arn:aws:ram:us-east-1:111111111112:resource-share/0479521366b778243 --principals 111111111118
  ```

  - Evidence (resource-share): source, `arn:aws:ram:us-east-1:111111111112:resource-share/0479521366b778243`
    owner 111111111112; principals: OU ou-lark-work; allow external principals false
    ec2:PrefixList  arn:aws:ec2:us-east-1:111111111112:prefix-list/pl-071c30c49f742a6da

- [ ] **2.4** `REVIEW` Re-share larkspur-license-config with the account directly: license-manager:LicenseConfiguration
  _Where:_ owner account 111111111113

  Owner 111111111113 shares larkspur-license-config (license-manager:LicenseConfiguration) with 111111111115, 111111111118 today. After the move those principals no longer cover the account. Ask the owner to add account 111111111118 as a principal before the move so nothing attached to these resources is interrupted. The account will be outside the organization, so the share has to allow external principals and the account has to accept an invitation.

  resource `arn:aws:ram:us-east-1:111111111113:resource-share/016cff3e3072e28ed`

  _From the ram check: Share larkspur-license-config is lost: license-manager:LicenseConfiguration._

  ```sh
  aws ram update-resource-share --resource-share-arn arn:aws:ram:us-east-1:111111111113:resource-share/016cff3e3072e28ed --allow-external-principals
  aws ram associate-resource-share --resource-share-arn arn:aws:ram:us-east-1:111111111113:resource-share/016cff3e3072e28ed --principals 111111111118
  ```

  - Evidence (resource-share): source, `arn:aws:ram:us-east-1:111111111113:resource-share/016cff3e3072e28ed`
    owner 111111111113; principals: account 111111111115, account 111111111118; allow external principals false
    license-manager:LicenseConfiguration  arn:aws:license-manager:us-east-1:111111111113:license-configuration:lic-4fba2a7c40f73ab7

- [ ] **2.5** `REVIEW` Replace what StackSet larkspur-baseline-roles deploys into the account
  _Where:_ administration account 111111111111

  Service-managed StackSets deploy by OU. Audit and break-glass IAM roles for workload accounts. Check what those stacks provide (roles, Config recorders, GuardDuty membership) before moving. Decide: redeploy the template by hand in the account, add the account to a self-managed StackSet, or accept the loss.

  _From the org-services check: StackSet larkspur-baseline-roles stops targeting the account; stack instances are deleted from the account._

  ```sh
  aws cloudformation list-stack-instances --stack-set-name larkspur-baseline-roles --stack-instance-account 111111111118
  aws cloudformation describe-stack-set --stack-set-name larkspur-baseline-roles --query StackSet.TemplateBody --output text
  ```

  - Evidence (stackset): source, `larkspur-baseline-roles`
    admin 111111111111; targets OUs ou-lark-work accounts ; regions us-east-1; auto-deployment true; retain on removal false

- [ ] **2.6** `REVIEW` Replace what StackSet larkspur-config-recorder deploys into the account
  _Where:_ administration account 111111111111

  Service-managed StackSets deploy by OU. AWS Config recorder and delivery channel. Check what those stacks provide (roles, Config recorders, GuardDuty membership) before moving. Decide: redeploy the template by hand in the account, add the account to a self-managed StackSet, or accept the loss.

  _From the org-services check: StackSet larkspur-config-recorder stops targeting the account; stack instances are detached but the stacks are retained in the account (retain\_stacks\_on\_account\_removal)._

  ```sh
  aws cloudformation list-stack-instances --stack-set-name larkspur-config-recorder --stack-instance-account 111111111118
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

- [ ] **2.8** `REVIEW` Review permission set AdministratorAccess in the target instance before re-assigning it
  _Where:_ Identity Center of Fernhill Group (o-fernhill0001) (account 222222222221, eu-west-1)

  Account assignments exist only for accounts inside the organization that owns the instance. When the account leaves o-larkspur0001, Identity Center cleans up its metadata and resources for the account and a standalone account no longer works with Identity Center, so these 1 assignment(s) stop granting access at once. The target instance has a permission set with the same name; re-assign the principals to it once the account has joined. They are matched by name only: identity store d-fern0000001 is a different directory, so the users and groups are different objects there. Same name, different settings: session duration PT1H vs PT2H.

  _From the identity-center check: Permission set AdministratorAccess: 1 assignment(s) removed when the account leaves (group Platform-Admins)._

  ```sh
  aws sso-admin describe-permission-set --instance-arn arn:aws:sso:::instance/ssoins-fernhill00000001 --permission-set-arn arn:aws:sso:::permissionSet/ssoins-fernhill00000001/ps-fern00000001
  aws sso-admin list-managed-policies-in-permission-set --instance-arn arn:aws:sso:::instance/ssoins-fernhill00000001 --permission-set-arn arn:aws:sso:::permissionSet/ssoins-fernhill00000001/ps-fern00000001
  aws sso-admin get-inline-policy-for-permission-set --instance-arn arn:aws:sso:::instance/ssoins-fernhill00000001 --permission-set-arn arn:aws:sso:::permissionSet/ssoins-fernhill00000001/ps-fern00000001
  ```

  - Evidence (account-assignment): source, `ba31fe89-32df-0f24-6b40-1c6f590a40ff`
    group Platform-Admins has permission set AdministratorAccess in account 111111111118

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

- [ ] **2.9** `REVIEW` Create permission set DataPlatformOperator in the target instance
  _Where:_ Identity Center of Fernhill Group (o-fernhill0001) (account 222222222221, eu-west-1)

  Account assignments exist only for accounts inside the organization that owns the instance. When the account leaves o-larkspur0001, Identity Center cleans up its metadata and resources for the account and a standalone account no longer works with Identity Center, so these 1 assignment(s) stop granting access at once. The target instance has no permission set named DataPlatformOperator. Create one there (or choose an equivalent) before re-assigning the 1 principal(s), who have to exist in identity store d-fern0000001 under the target instance.

  _From the identity-center check: Permission set DataPlatformOperator: 1 assignment(s) removed when the account leaves (group Data-Platform)._

  ```sh
  aws sso-admin create-permission-set --instance-arn arn:aws:sso:::instance/ssoins-fernhill00000001 --name DataPlatformOperator --description "Glue and Athena operations" --session-duration PT4H
  aws sso-admin attach-managed-policy-to-permission-set --instance-arn arn:aws:sso:::instance/ssoins-fernhill00000001 --permission-set-arn <ARN returned by create-permission-set> --managed-policy-arn arn:aws:iam::aws:policy/AmazonAthenaFullAccess
  aws sso-admin attach-managed-policy-to-permission-set --instance-arn arn:aws:sso:::instance/ssoins-fernhill00000001 --permission-set-arn <ARN returned by create-permission-set> --managed-policy-arn arn:aws:iam::aws:policy/AWSGlueConsoleFullAccess
  aws sso-admin put-permissions-boundary-to-permission-set --instance-arn arn:aws:sso:::instance/ssoins-fernhill00000001 --permission-set-arn <ARN returned by create-permission-set> --permissions-boundary <arn:aws:iam::aws:policy/PowerUserAccess>
  ```

  - Evidence (account-assignment): source, `44693b45-1be8-872e-dd8a-3ced7bc68516`
    group Data-Platform has permission set DataPlatformOperator in account 111111111118

  - Evidence (permission-set): source, `arn:aws:sso:::permissionSet/ssoins-larkspur00000001/ps-lark00000004`
    DataPlatformOperator
    Glue and Athena operations
    session duration PT4H
    managed policies: arn:aws:iam::aws:policy/AmazonAthenaFullAccess, arn:aws:iam::aws:policy/AWSGlueConsoleFullAccess
    permissions boundary arn:aws:iam::aws:policy/PowerUserAccess
    provisioned in 2 account(s)

- [ ] **2.10** `REVIEW` Review permission set ReadOnlyAccess in the target instance before re-assigning it
  _Where:_ Identity Center of Fernhill Group (o-fernhill0001) (account 222222222221, eu-west-1)

  Account assignments exist only for accounts inside the organization that owns the instance. When the account leaves o-larkspur0001, Identity Center cleans up its metadata and resources for the account and a standalone account no longer works with Identity Center, so these 1 assignment(s) stop granting access at once. The target instance has a permission set with the same name; re-assign the principals to it once the account has joined. They are matched by name only: identity store d-fern0000001 is a different directory, so the users and groups are different objects there. Same name, different settings: managed policies only in the target: arn:aws:iam::aws:policy/job-function/ViewOnlyAccess; session duration PT8H vs PT12H.

  _From the identity-center check: Permission set ReadOnlyAccess: 1 assignment(s) removed when the account leaves (group Security-Auditors)._

  ```sh
  aws sso-admin describe-permission-set --instance-arn arn:aws:sso:::instance/ssoins-fernhill00000001 --permission-set-arn arn:aws:sso:::permissionSet/ssoins-fernhill00000001/ps-fern00000002
  aws sso-admin list-managed-policies-in-permission-set --instance-arn arn:aws:sso:::instance/ssoins-fernhill00000001 --permission-set-arn arn:aws:sso:::permissionSet/ssoins-fernhill00000001/ps-fern00000002
  aws sso-admin get-inline-policy-for-permission-set --instance-arn arn:aws:sso:::instance/ssoins-fernhill00000001 --permission-set-arn arn:aws:sso:::permissionSet/ssoins-fernhill00000001/ps-fern00000002
  ```

  - Evidence (account-assignment): source, `fd2d8b09-2a71-ec4a-cc89-1ddb07a87174`
    group Security-Auditors has permission set ReadOnlyAccess in account 111111111118

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

### 3. The move

Run these in order. Between leaving and accepting the invitation the account is standalone, with no SCPs and no organization features; keep that window short.

- [ ] **3.1** Moved together with OU Workloads
  The account does not move on its own; the move steps are in the OU part of the runbook.

### 4. After the move: checks

Confirm what the simulation predicted and finish what could only be done once the account is at its new position.

- [ ] **4.1** Accept the invitation for share larkspur-core-network and confirm the resources
  _Where:_ account larkspur-data-prod (111111111118)

  Outside the owner's organization the share arrives as an invitation. Accept it, then check that the ec2:Subnet, ec2:TransitGateway, route53resolver:ResolverRule are listed and that what is attached to them still works.

  _From the ram check: Networking share larkspur-core-network is lost: ec2:Subnet, ec2:TransitGateway, route53resolver:ResolverRule._

  ```sh
  aws ram get-resource-share-invitations --query "resourceShareInvitations[?resourceShareName=='larkspur-core-network']"
  aws ram accept-resource-share-invitation --resource-share-invitation-arn <invitation ARN from the previous command>
  aws ram list-resources --resource-owner OTHER-ACCOUNTS --resource-share-arns arn:aws:ram:us-east-1:111111111112:resource-share/06a7aefe6fddce828
  ```

- [ ] **4.2** Accept the invitation for share larkspur-ipam and confirm the resources
  _Where:_ account larkspur-data-prod (111111111118)

  Outside the owner's organization the share arrives as an invitation. Accept it, then check that the ec2:IpamPool are listed and that what is attached to them still works.

  _From the ram check: Networking share larkspur-ipam is lost: ec2:IpamPool._

  ```sh
  aws ram get-resource-share-invitations --query "resourceShareInvitations[?resourceShareName=='larkspur-ipam']"
  aws ram accept-resource-share-invitation --resource-share-invitation-arn <invitation ARN from the previous command>
  aws ram list-resources --resource-owner OTHER-ACCOUNTS --resource-share-arns arn:aws:ram:us-east-1:111111111112:resource-share/01364b18a31c4fdca
  ```

- [ ] **4.3** Accept the invitation for share larkspur-workload-prefix-lists and confirm the resources
  _Where:_ account larkspur-data-prod (111111111118)

  Outside the owner's organization the share arrives as an invitation. Accept it, then check that the ec2:PrefixList are listed and that what is attached to them still works.

  _From the ram check: Networking share larkspur-workload-prefix-lists is lost: ec2:PrefixList._

  ```sh
  aws ram get-resource-share-invitations --query "resourceShareInvitations[?resourceShareName=='larkspur-workload-prefix-lists']"
  aws ram accept-resource-share-invitation --resource-share-invitation-arn <invitation ARN from the previous command>
  aws ram list-resources --resource-owner OTHER-ACCOUNTS --resource-share-arns arn:aws:ram:us-east-1:111111111112:resource-share/0479521366b778243
  ```

- [ ] **4.4** Accept the invitation for share larkspur-license-config and confirm the resources
  _Where:_ account larkspur-data-prod (111111111118)

  Outside the owner's organization the share arrives as an invitation. Accept it, then check that the license-manager:LicenseConfiguration are listed and that what is attached to them still works.

  _From the ram check: Share larkspur-license-config is lost: license-manager:LicenseConfiguration._

  ```sh
  aws ram get-resource-share-invitations --query "resourceShareInvitations[?resourceShareName=='larkspur-license-config']"
  aws ram accept-resource-share-invitation --resource-share-invitation-arn <invitation ARN from the previous command>
  aws ram list-resources --resource-owner OTHER-ACCOUNTS --resource-share-arns arn:aws:ram:us-east-1:111111111113:resource-share/016cff3e3072e28ed
  ```

- [ ] **4.5** `INFO` Share fernhill-core-network becomes available: ec2:TransitGateway, route53resolver:ResolverRule
  _Where:_ account larkspur-data-prod (111111111118)

  Shared by account 222222222222 with organization o-fernhill0001 in the target organization. New attachments must be created by hand; nothing is attached automatically.

  _From the ram check: Share fernhill-core-network becomes available after the move: ec2:TransitGateway, route53resolver:ResolverRule._

  ```sh
  aws ram list-resources --resource-owner OTHER-ACCOUNTS --resource-share-arns arn:aws:ram:eu-west-1:222222222222:resource-share/09521366b77824316
  ```

  - Evidence (resource-share): target, `arn:aws:ram:eu-west-1:222222222222:resource-share/09521366b77824316`
    owner 222222222222; principals: organization o-fernhill0001; allow external principals false
    ec2:TransitGateway  arn:aws:ec2:eu-west-1:222222222222:transit-gateway/tgw-6a7aefe6fddce8281
    route53resolver:ResolverRule  arn:aws:route53resolver:eu-west-1:222222222222:resolver-rule/rslvr-rr-364b18a31c4fdca47

- [ ] **4.6** `INFO` Confirm StackSet fernhill-baseline deployed its stack instances to the account
  _Where:_ administration account 222222222221

  Baseline IAM roles and GuardDuty membership. Stack instances are created automatically when auto-deployment is on.

  _From the org-services check: StackSet fernhill-baseline in the target organization starts targeting the account._

  ```sh
  aws cloudformation list-stack-instances --stack-set-name fernhill-baseline --stack-instance-account 111111111118
  ```

  - Evidence (stackset): target, `fernhill-baseline`
    admin 222222222221; targets OUs ou-fern-bu; regions eu-west-1

- [ ] **4.7** Confirm CloudTrail coverage
  _Where:_ account larkspur-data-prod (111111111118)

  Organization trail(s) larkspur-org-trail stop logging the account the moment it leaves. Trail(s) fernhill-org-trail (bucket fernhill-log-archive) of the target cover it once it has joined; confirm events arrive there. Between leaving and joining nothing logs management events unless the account has a trail of its own.

  _From the org-services check._

  ```sh
  aws cloudtrail describe-trails --include-shadow-trails
  aws cloudtrail lookup-events --max-results 5   # the most recent management events should be minutes old
  ```

  - Evidence (org-trail): source, `arn:aws:cloudtrail:us-east-1:111111111114:trail/larkspur-org-trail`
    bucket larkspur-cloudtrail-archive, home region us-east-1

  - Evidence (org-trail): target, `arn:aws:cloudtrail:eu-west-1:222222222224:trail/fernhill-org-trail`

- [ ] **4.8** Confirm AWS Config aggregation
  _Where:_ account larkspur-data-prod (111111111118)

  Aggregator(s) larkspur-org-aggregator of the source stop receiving the account's configuration and compliance data. Aggregator(s) fernhill-org-aggregator in the target pick it up once it has joined and the recorder in the account is running; confirm the account appears as a source.

  _From the org-services check._

  ```sh
  aws configservice describe-configuration-recorder-status
  aws configservice describe-configuration-aggregator-sources-status --configuration-aggregator-name <target aggregator>   # in the aggregator account
  ```

  - Evidence (config-aggregator): source, `larkspur-org-aggregator`

  - Evidence (config-aggregator): target, `fernhill-org-aggregator`

- [ ] **4.9** `INFO` Confirm the target's delegated administrators enrol the account
  _Where:_ management account 222222222221 of Fernhill Group

  In the target organization: 222222222223 administers access-analyzer.amazonaws.com; 222222222223 administers guardduty.amazonaws.com; 222222222223 administers securityhub.amazonaws.com. Each administrator's auto-enable settings decide whether the account is enrolled on joining; check the service consoles for the new member.

  _From the org-services check._

  ```sh
  aws organizations list-delegated-administrators
  ```

- [ ] **4.10** `INFO` Confirm the Control Tower controls that start applying at Production
  _Where:_ management account 222222222221 of Fernhill Group

  3 detective control(s) start applying at Production: AWS-GR_ENCRYPTED_VOLUMES, AWS-GR_RDS_STORAGE_ENCRYPTED, AWS-GR_RESTRICTED_SSH. 3 preventive control(s) start applying at Production: AWS-GR_CLOUDTRAIL_ENABLED, AWS-GR_CONFIG_ENABLED, AWS-GR_RESTRICT_ROOT_USER_ACCESS_KEYS. Preventive controls apply through the OU's SCPs at once; detective and proactive ones report once the account is enrolled.

  _From the control-tower check._

  ```sh
  aws controltower list-enabled-controls --target-identifier <ARN of OU ou-lark-prod>
  ```

  - Evidence (enabled-control): target, `arn:aws:controltower:eu-west-1::control/AWS-GR_ENCRYPTED_VOLUMES`
    Detect whether encryption is enabled for Amazon EBS volumes attached to Amazon EC2 instances
    detective control on OU ou-fern-bu; status SUCCEEDED, drift IN_SYNC; implemented as AWS::Config::ConfigRule

  - Evidence (enabled-control): target, `arn:aws:controltower:eu-west-1::control/AWS-GR_RESTRICTED_SSH`
    Detect whether unrestricted incoming SSH traffic is allowed
    detective control on OU ou-fern-bu; status SUCCEEDED, drift IN_SYNC; implemented as AWS::Config::ConfigRule

  - Evidence (enabled-control): target, `arn:aws:controltower:eu-west-1::control/AWS-GR_RDS_STORAGE_ENCRYPTED`
    Detect whether storage encryption is enabled for Amazon RDS database instances
    detective control on OU ou-fern-bu; status SUCCEEDED, drift IN_SYNC; implemented as AWS::Config::ConfigRule

  - Evidence (enabled-control): target, `arn:aws:controltower:eu-west-1::control/AWS-GR_CLOUDTRAIL_ENABLED`
    Disallow changes to CloudTrail set up by AWS Control Tower
    preventive control on OU ou-fern-bu; status SUCCEEDED, drift IN_SYNC; implemented as AWS::Organizations::Policy

  - Evidence (enabled-control): target, `arn:aws:controltower:eu-west-1::control/AWS-GR_CONFIG_ENABLED`
    Disallow changes to AWS Config set up by AWS Control Tower
    preventive control on OU ou-fern-bu; status SUCCEEDED, drift IN_SYNC; implemented as AWS::Organizations::Policy

  - Evidence (enabled-control): target, `arn:aws:controltower:eu-west-1::control/AWS-GR_RESTRICT_ROOT_USER_ACCESS_KEYS`
    Disallow creation of access keys for the root user
    preventive control on OU ou-fern-bu; status SUCCEEDED, drift IN_SYNC; implemented as AWS::Organizations::Policy

- [ ] **4.11** Update references to the deleted AWSReservedSSO_* roles with the ARNs the target instance provisions
  _Where:_ account larkspur-data-prod (111111111118)

  The new roles have a different random suffix. Replace the old ARNs found before the move in resource policies, key policies, EKS access entries and tooling.

  _From the identity-center check: 3 AWSReservedSSO\_* role(s) are deleted from the account: AWSReservedSSO\_AdministratorAccess\_*, AWSReservedSSO\_ReadOnlyAccess\_*, AWSReservedSSO\_DataPlatformOperator\_*._

  ```sh
  aws iam list-roles --path-prefix /aws-reserved/sso.amazonaws.com/ --query "Roles[].Arn"
  ```

- [ ] **4.12** `REVIEW` Assign AdministratorAccess to group Platform-Admins for the account in the target instance
  _Where:_ Identity Center of Fernhill Group (o-fernhill0001) (account 222222222221, eu-west-1)

  Users and groups in identity store d-fern0000001 are different objects from the source ones, so look each one up by name first; create it there if it is missing. Identity Center then provisions a new AWSReservedSSO_AdministratorAccess_* role in the account.

  _From the identity-center check: Permission set AdministratorAccess: 1 assignment(s) removed when the account leaves (group Platform-Admins)._

  ```sh
  aws identitystore list-groups --identity-store-id d-fern0000001 --filters AttributePath=DisplayName,AttributeValue="Platform-Admins" --query "Groups[].GroupId" --output text
  aws sso-admin create-account-assignment --instance-arn arn:aws:sso:::instance/ssoins-fernhill00000001 --target-id 111111111118 --target-type AWS_ACCOUNT --permission-set-arn arn:aws:sso:::permissionSet/ssoins-fernhill00000001/ps-fern00000001 --principal-type GROUP --principal-id <ID from the previous command>
  ```

- [ ] **4.13** `REVIEW` Assign DataPlatformOperator to group Data-Platform for the account in the target instance
  _Where:_ Identity Center of Fernhill Group (o-fernhill0001) (account 222222222221, eu-west-1)

  Users and groups in identity store d-fern0000001 are different objects from the source ones, so look each one up by name first; create it there if it is missing. Identity Center then provisions a new AWSReservedSSO_DataPlatformOperator_* role in the account.

  _From the identity-center check: Permission set DataPlatformOperator: 1 assignment(s) removed when the account leaves (group Data-Platform)._

  ```sh
  aws identitystore list-groups --identity-store-id d-fern0000001 --filters AttributePath=DisplayName,AttributeValue="Data-Platform" --query "Groups[].GroupId" --output text
  aws sso-admin create-account-assignment --instance-arn arn:aws:sso:::instance/ssoins-fernhill00000001 --target-id 111111111118 --target-type AWS_ACCOUNT --permission-set-arn <ARN of permission set DataPlatformOperator in the target> --principal-type GROUP --principal-id <ID from the previous command>
  ```

- [ ] **4.14** `REVIEW` Assign ReadOnlyAccess to group Security-Auditors for the account in the target instance
  _Where:_ Identity Center of Fernhill Group (o-fernhill0001) (account 222222222221, eu-west-1)

  Users and groups in identity store d-fern0000001 are different objects from the source ones, so look each one up by name first; create it there if it is missing. Identity Center then provisions a new AWSReservedSSO_ReadOnlyAccess_* role in the account.

  _From the identity-center check: Permission set ReadOnlyAccess: 1 assignment(s) removed when the account leaves (group Security-Auditors)._

  ```sh
  aws identitystore list-groups --identity-store-id d-fern0000001 --filters AttributePath=DisplayName,AttributeValue="Security-Auditors" --query "Groups[].GroupId" --output text
  aws sso-admin create-account-assignment --instance-arn arn:aws:sso:::instance/ssoins-fernhill00000001 --target-id 111111111118 --target-type AWS_ACCOUNT --permission-set-arn arn:aws:sso:::permissionSet/ssoins-fernhill00000001/ps-fern00000002 --principal-type GROUP --principal-id <ID from the previous command>
  ```

- [ ] **4.15** Exercise the 8 flagged request(s) from the account
  _Where:_ account larkspur-data-prod (111111111118)

  These were denied or undecidable in the simulation. After the policy changes above and the move, confirm each one works (a dry run or a read of the resource is enough): athena:StartQueryExecution in us-east-1; ec2:CreateTransitGatewayVpcAttachment in us-east-1; ec2:RunInstances in us-east-1; glue:StartJobRun in us-east-1; kms:Decrypt in us-east-1; s3:GetObject in us-east-1; s3:PutObject in us-east-1; s3:PutObject by arn:aws:iam::111111111115:role/SettlementExporter in eu-west-1, us-east-1.

  ```sh
  # for each action, run the real call once from the principal that uses it, or check CloudTrail for AccessDenied events after a day
  ```

### 5. Rollback

If something breaks, this puts the account back where it was. Built from the source policy chain of the simulation.

- [ ] **5.1** Rolled back together with OU Workloads
  The rollback of the OU recreates the original OUs and moves every account back; the account's own policies to re-attach are listed below.

  - Evidence (source-chain): source
    root Root (r-lark): FullAWSAccess (p-FullAWSAccess), Larkspur-Baseline-Guardrails (p-lark0001)
    OU Workloads (ou-lark-work): FullAWSAccess (p-FullAWSAccess), Larkspur-Allowed-Regions (p-lark0002)
    OU Production (ou-lark-prod): FullAWSAccess (p-FullAWSAccess)
    account larkspur-data-prod (111111111118): FullAWSAccess (p-FullAWSAccess)

  - Evidence (source-chain): source
    root Root (r-lark): RCPFullAWSAccess (p-RCPFullAWSAccess)
    OU Workloads (ou-lark-work): RCPFullAWSAccess (p-RCPFullAWSAccess)
    OU Production (ou-lark-prod): RCPFullAWSAccess (p-RCPFullAWSAccess)
    account larkspur-data-prod (111111111118): RCPFullAWSAccess (p-RCPFullAWSAccess)

  - Evidence (source-chain): source
    root Root (r-lark): Larkspur-Tagging-Standard (p-lark0004)
    OU Workloads (ou-lark-work): none
    OU Production (ou-lark-prod): none
    account larkspur-data-prod (111111111118): none

  - Evidence (source-chain): source
    root Root (r-lark): none
    OU Workloads (ou-lark-work): none
    OU Production (ou-lark-prod): Larkspur-Daily-Backups (p-lark0005)
    account larkspur-data-prod (111111111118): none

## Account larkspur-payments-dev (`111111111116`): NO-GO

29 steps: 6 before the move (1 blocking), 8 to re-create, 1 for the move itself, 13 checks afterwards and 1 to roll back.

### 1. Before the move: fix the blockers and make the decisions

Everything here is settled while the account is still at its current position. NO-GO steps block the move; REVIEW steps need a decision or a check by hand.

- [ ] **1.1** `NO-GO` SCP Fernhill-EU-Only-Regions / DenyOutsideEU denies 3 actions after the move
  _Where:_ management account 222222222221 of Fernhill Group

  Attached at OU Business Units (ou-fern-bu) in the target organization. Allowed today; after the move it denies: ec2:CreateVpc in us-east-1; ec2:RunInstances in us-east-1; lambda:* in us-east-1. The change to review: edit statement DenyOutsideEU so it no longer covers account 111111111116 (for example a Condition on aws:PrincipalAccount, or a narrower Action or Resource list), detach Fernhill-EU-Only-Regions from OU Business Units (ou-fern-bu), or stop using the actions before the move.

  actions `ec2:CreateVpc`, `ec2:RunInstances`, `lambda:*`

  _From the scp check: 3 findings with the same cause._

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

- [ ] **1.2** `REVIEW` No tagged resources were provided for this account
  _Where:_ account larkspur-payments-dev (111111111116)

  Add usage.tagged_resources to the source snapshot (for example from the Resource Groups Tagging API) to check compliance against the target tag policy.

  _From the tags check: No tagged resources were provided for this account._

  ```sh
  aws resourcegroupstaggingapi get-resources --resources-per-page 100   # sample to add as usage.tagged_resources
  ```

- [ ] **1.3** `REVIEW` Make the account able to stand alone
  _Where:_ account larkspur-payments-dev (111111111116), signed in as root or an administrator

  Before it can leave, the account needs its own verified contact information, a payment method and a support plan choice; Organizations fails the removal with ConstraintViolationException until they are in place (with Enterprise Support, a billing case can arrange the standalone period instead of a payment method per account). It then has to be invited by the target management account 222222222221 and accept the invitation: an account belongs to one organization at a time, so it leaves first; the invitation must be answered within 15 days; the policies attached to the target root and the OU it lands in apply at once; the target's organization trail covers it automatically and Config, GuardDuty or Security Hub may be enabled automatically for new members, so account-level trails and detectors may double charges; Organizations does not create OrganizationAccountAccessRole for an invited account. SCPs in the source that deny organizations:LeaveOrganization must be lifted for the move, or the source management account removes the account instead. The account also loses access to the cost and usage data of its time in the source organization and is no longer covered by the source organization's agreements. Transfer procedure model 2026-11-02. Contact information, alternate contacts and the payment method can be checked with the Account API; identity verification and the support plan are done in the console.

  _From the org-services check: Standalone account prerequisites and invitation._

  ```sh
  aws account get-contact-information
  aws account get-alternate-contact --alternate-contact-type BILLING
  # console: Billing and Cost Management → Payment preferences; Account → Identity verification; Support → Support plan
  ```

- [ ] **1.4** `REVIEW` Lift the deny on organizations:LeaveOrganization in SCP Larkspur-Baseline-Guardrails / DenyLeaveOrganization, or let the management account remove the account
  _Where:_ management account 111111111111 of Larkspur Holdings

  SCP Larkspur-Baseline-Guardrails (p-lark0001) is attached at root Root (r-lark) and denies organizations:LeaveOrganization without a condition, so leave-organization run from inside the account fails. Either detach the policy or edit the statement for the duration of the move and put it back afterwards, or run remove-account-from-organization from the management account, which SCPs do not restrict.

  actions `organizations:LeaveOrganization`

  _From the org-services check: Standalone account prerequisites and invitation._

  ```sh
  aws organizations describe-policy --policy-id p-lark0001 --query Content --output text
  aws organizations remove-account-from-organization --account-id 111111111116   # the alternative that needs no policy change
  ```

  - Evidence (policy-statement): source, SCP `Larkspur-Baseline-Guardrails` (p-lark0001), statement DenyLeaveOrganization, at root Root (r-lark)
    Deny organizations:LeaveOrganization

- [ ] **1.5** `REVIEW` Find what references the 3 AWSReservedSSO_* role(s) of the account
  _Where:_ account larkspur-payments-dev (111111111116)

  When the account leaves the organization, Identity Center cleans up the resources it created in the account; the documentation names the service-linked role, and the IAM roles provisioned for permission sets (path /aws-reserved/sso.amazonaws.com/us-east-1/) go with the instance's control over the account, so plan for them to disappear and confirm in IAM after the move. Anything that names these roles breaks: resource and trust policies, KMS key policies, S3 bucket policies, EKS access entries, pipelines and tools that assume them, and CloudTrail history keeps the old ARNs. The target instance provisions new roles with a different random suffix, so references have to be updated, not restored. The exact suffix is only visible in IAM; offline the roles are known by their pattern. 1 of them (AWSReservedSSO_ReadOnlyAccess_*) are provisioned without any assignment and are already unused; deprovisioning the permission set from the account before the move removes them cleanly. List the exact role ARNs now, while they exist, and search for them so the references can be updated after the move.

  _From the identity-center check: 3 AWSReservedSSO\_* role(s) are deleted from the account: AWSReservedSSO\_AdministratorAccess\_*, AWSReservedSSO\_PaymentsEngineer\_*, AWSReservedSSO\_ReadOnlyAccess\_*._

  ```sh
  aws iam list-roles --path-prefix /aws-reserved/sso.amazonaws.com/us-east-1/ --query "Roles[].Arn"
  # search bucket, key, topic, queue and secret policies, EKS access entries, role trust policies and CI configuration for AWSReservedSSO_
  ```

  - Evidence (reserved-role): source, `AWSReservedSSO_AdministratorAccess_*`
    role for permission set AdministratorAccess (arn:aws:sso:::permissionSet/ssoins-larkspur00000001/ps-lark00000001) under /aws-reserved/sso.amazonaws.com/us-east-1/; 1 assignment(s) on the account

  - Evidence (reserved-role): source, `AWSReservedSSO_PaymentsEngineer_*`
    role for permission set PaymentsEngineer (arn:aws:sso:::permissionSet/ssoins-larkspur00000001/ps-lark00000002) under /aws-reserved/sso.amazonaws.com/us-east-1/; 1 assignment(s) on the account

  - Evidence (reserved-role): source, `AWSReservedSSO_ReadOnlyAccess_*`
    role for permission set ReadOnlyAccess (arn:aws:sso:::permissionSet/ssoins-larkspur00000001/ps-lark00000003) under /aws-reserved/sso.amazonaws.com/us-east-1/; 0 assignment(s) on the account; provisioned without an assignment (stale)

- [ ] **1.6** `REVIEW` Deprovision the stale permission set(s) from the account: ReadOnlyAccess
  _Where:_ Identity Center of Larkspur Holdings (o-larkspur0001) (account 111111111111, us-east-1)

  These permission sets are provisioned in the account without any assignment, so their roles are unused. Removing them now deletes the roles cleanly and keeps them out of the reference search above.

  _From the identity-center check: 3 AWSReservedSSO\_* role(s) are deleted from the account: AWSReservedSSO\_AdministratorAccess\_*, AWSReservedSSO\_PaymentsEngineer\_*, AWSReservedSSO\_ReadOnlyAccess\_*._

  ```sh
  aws sso-admin list-accounts-for-provisioned-permission-set --instance-arn arn:aws:sso:::instance/ssoins-larkspur00000001 --permission-set-arn arn:aws:sso:::permissionSet/ssoins-larkspur00000001/ps-lark00000003
  # Identity Center console → Permission sets → ReadOnlyAccess → AWS accounts → remove 111111111116
  ```

### 2. Before the move: re-create what does not travel

Shares, delegations, permission sets and stacks that are scoped to the account's current position do not follow it. Prepare the replacements now so nothing is interrupted.

- [ ] **2.1** `NO-GO` Re-share larkspur-core-network with the account directly: ec2:Subnet, ec2:TransitGateway, route53resolver:ResolverRule
  _Where:_ owner account 111111111112

  Owner 111111111112 shares larkspur-core-network (ec2:Subnet, ec2:TransitGateway, route53resolver:ResolverRule) with arn:aws:organizations::111111111111:organization/o-larkspur0001 today. After the move those principals no longer cover the account. Ask the owner to add account 111111111116 as a principal before the move so nothing attached to these resources is interrupted. The account will be outside the organization, so the share has to allow external principals and the account has to accept an invitation. The documentation says traffic or a declared operation stops with this share, so the move stays NO-GO until it is done: Shared by account 111111111112 with organization o-larkspur0001. It is scoped to the source organization or one of its OUs and stops applying when the account leaves. What the documentation says happens: ec2:Subnet: existing participant resources continue to run in the subnet; no new resources can be created in it, while existing ones can still be modified, described and deleted (subnets can only be shared inside one organization). Potentially affected: ec2:RunInstances in use may target the shared resources; confirm. ec2:Subnet can only be shared inside one organization, so it cannot be re-shared with the account once it has left. ec2:TransitGateway: existing transit gateway attachments remain functional; the account can no longer describe the transit gateway or create new attachments, and either side can delete the attachments. route53resolver:ResolverRule: traffic is affected at once, the rule's associations with the account's VPCs are removed and Resolver answers those queries from the remaining rules at once (an OU-scoped rule keeps its associations only when it is also shared with the destination OU). Ask the owner to re-share the resources with the account directly before the move, with external principals allowed, and accept the invitation after the move.

  resource `arn:aws:ram:us-east-1:111111111112:resource-share/06a7aefe6fddce828`

  _From the ram check: Networking share larkspur-core-network is lost: ec2:Subnet, ec2:TransitGateway, route53resolver:ResolverRule._

  ```sh
  aws ram update-resource-share --resource-share-arn arn:aws:ram:us-east-1:111111111112:resource-share/06a7aefe6fddce828 --allow-external-principals
  aws ram associate-resource-share --resource-share-arn arn:aws:ram:us-east-1:111111111112:resource-share/06a7aefe6fddce828 --principals 111111111116
  ```

  - Evidence (resource-share): source, `arn:aws:ram:us-east-1:111111111112:resource-share/06a7aefe6fddce828`
    owner 111111111112; principals: organization o-larkspur0001; allow external principals false
    ec2:TransitGateway  arn:aws:ec2:us-east-1:111111111112:transit-gateway/tgw-54924a77a3120b1ad
    ec2:Subnet  arn:aws:ec2:us-east-1:111111111112:subnet/subnet-e056c922dbb17986a
    ec2:Subnet  arn:aws:ec2:us-east-1:111111111112:subnet/subnet-1d0f03c495e44a0e4
    route53resolver:ResolverRule  arn:aws:route53resolver:us-east-1:111111111112:resolver-rule/rslvr-rr-66e02e8ff78976d8b

- [ ] **2.2** `REVIEW` Re-share larkspur-ipam with the account directly: ec2:IpamPool
  _Where:_ owner account 111111111112

  Owner 111111111112 shares larkspur-ipam (ec2:IpamPool) with arn:aws:organizations::111111111111:organization/o-larkspur0001 today. After the move those principals no longer cover the account. Ask the owner to add account 111111111116 as a principal before the move so nothing attached to these resources is interrupted. The account will be outside the organization, so the share has to allow external principals and the account has to accept an invitation.

  resource `arn:aws:ram:us-east-1:111111111112:resource-share/01364b18a31c4fdca`

  _From the ram check: Networking share larkspur-ipam is lost: ec2:IpamPool._

  ```sh
  aws ram update-resource-share --resource-share-arn arn:aws:ram:us-east-1:111111111112:resource-share/01364b18a31c4fdca --allow-external-principals
  aws ram associate-resource-share --resource-share-arn arn:aws:ram:us-east-1:111111111112:resource-share/01364b18a31c4fdca --principals 111111111116
  ```

  - Evidence (resource-share): source, `arn:aws:ram:us-east-1:111111111112:resource-share/01364b18a31c4fdca`
    owner 111111111112; principals: organization o-larkspur0001; allow external principals false
    ec2:IpamPool  arn:aws:ec2::111111111112:ipam-pool/ipam-pool-8afc13dafc2e5d265

- [ ] **2.3** `REVIEW` Re-share larkspur-workload-prefix-lists with the account directly: ec2:PrefixList
  _Where:_ owner account 111111111112

  Owner 111111111112 shares larkspur-workload-prefix-lists (ec2:PrefixList) with arn:aws:organizations::111111111111:ou/o-larkspur0001/ou-lark-work today. After the move those principals no longer cover the account. Ask the owner to add account 111111111116 as a principal before the move so nothing attached to these resources is interrupted. The account will be outside the organization, so the share has to allow external principals and the account has to accept an invitation.

  resource `arn:aws:ram:us-east-1:111111111112:resource-share/0479521366b778243`

  _From the ram check: Networking share larkspur-workload-prefix-lists is lost: ec2:PrefixList._

  ```sh
  aws ram update-resource-share --resource-share-arn arn:aws:ram:us-east-1:111111111112:resource-share/0479521366b778243 --allow-external-principals
  aws ram associate-resource-share --resource-share-arn arn:aws:ram:us-east-1:111111111112:resource-share/0479521366b778243 --principals 111111111116
  ```

  - Evidence (resource-share): source, `arn:aws:ram:us-east-1:111111111112:resource-share/0479521366b778243`
    owner 111111111112; principals: OU ou-lark-work; allow external principals false
    ec2:PrefixList  arn:aws:ec2:us-east-1:111111111112:prefix-list/pl-071c30c49f742a6da

- [ ] **2.4** `REVIEW` Replace what StackSet larkspur-baseline-roles deploys into the account
  _Where:_ administration account 111111111111

  Service-managed StackSets deploy by OU. Audit and break-glass IAM roles for workload accounts. Check what those stacks provide (roles, Config recorders, GuardDuty membership) before moving. Decide: redeploy the template by hand in the account, add the account to a self-managed StackSet, or accept the loss.

  _From the org-services check: StackSet larkspur-baseline-roles stops targeting the account; stack instances are deleted from the account._

  ```sh
  aws cloudformation list-stack-instances --stack-set-name larkspur-baseline-roles --stack-instance-account 111111111116
  aws cloudformation describe-stack-set --stack-set-name larkspur-baseline-roles --query StackSet.TemplateBody --output text
  ```

  - Evidence (stackset): source, `larkspur-baseline-roles`
    admin 111111111111; targets OUs ou-lark-work accounts ; regions us-east-1; auto-deployment true; retain on removal false

- [ ] **2.5** `REVIEW` Replace what StackSet larkspur-config-recorder deploys into the account
  _Where:_ administration account 111111111111

  Service-managed StackSets deploy by OU. AWS Config recorder and delivery channel. Check what those stacks provide (roles, Config recorders, GuardDuty membership) before moving. Decide: redeploy the template by hand in the account, add the account to a self-managed StackSet, or accept the loss.

  _From the org-services check: StackSet larkspur-config-recorder stops targeting the account; stack instances are detached but the stacks are retained in the account (retain\_stacks\_on\_account\_removal)._

  ```sh
  aws cloudformation list-stack-instances --stack-set-name larkspur-config-recorder --stack-instance-account 111111111116
  aws cloudformation describe-stack-set --stack-set-name larkspur-config-recorder --query StackSet.TemplateBody --output text
  ```

  - Evidence (stackset): source, `larkspur-config-recorder`
    admin 111111111111; targets OUs r-lark accounts ; regions us-east-1,eu-west-1,ap-southeast-1; auto-deployment true; retain on removal true

- [ ] **2.6** `REVIEW` Enable trusted access in Fernhill Group (o-fernhill0001) for: account.amazonaws.com
  _Where:_ management account 222222222221 of Fernhill Group

  Organization-integrated features of these services (for example organization-wide GuardDuty, RAM sharing with the organization, service-managed StackSets) are not available in the target organization until trusted access is enabled there. Only for the integrations the account relies on; enabling trusted access is an organization-wide setting.

  _From the org-services check: Trusted access is not enabled in the target for: account.amazonaws.com._

  ```sh
  aws organizations enable-aws-service-access --service-principal account.amazonaws.com
  ```

- [ ] **2.7** `REVIEW` Review permission set AdministratorAccess in the target instance before re-assigning it
  _Where:_ Identity Center of Fernhill Group (o-fernhill0001) (account 222222222221, eu-west-1)

  Account assignments exist only for accounts inside the organization that owns the instance. When the account leaves o-larkspur0001, Identity Center cleans up its metadata and resources for the account and a standalone account no longer works with Identity Center, so these 1 assignment(s) stop granting access at once. The target instance has a permission set with the same name; re-assign the principals to it once the account has joined. They are matched by name only: identity store d-fern0000001 is a different directory, so the users and groups are different objects there. Same name, different settings: session duration PT1H vs PT2H.

  _From the identity-center check: Permission set AdministratorAccess: 1 assignment(s) removed when the account leaves (group Platform-Admins)._

  ```sh
  aws sso-admin describe-permission-set --instance-arn arn:aws:sso:::instance/ssoins-fernhill00000001 --permission-set-arn arn:aws:sso:::permissionSet/ssoins-fernhill00000001/ps-fern00000001
  aws sso-admin list-managed-policies-in-permission-set --instance-arn arn:aws:sso:::instance/ssoins-fernhill00000001 --permission-set-arn arn:aws:sso:::permissionSet/ssoins-fernhill00000001/ps-fern00000001
  aws sso-admin get-inline-policy-for-permission-set --instance-arn arn:aws:sso:::instance/ssoins-fernhill00000001 --permission-set-arn arn:aws:sso:::permissionSet/ssoins-fernhill00000001/ps-fern00000001
  ```

  - Evidence (account-assignment): source, `ba31fe89-32df-0f24-6b40-1c6f590a40ff`
    group Platform-Admins has permission set AdministratorAccess in account 111111111116

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

- [ ] **2.8** `REVIEW` Create permission set PaymentsEngineer in the target instance
  _Where:_ Identity Center of Fernhill Group (o-fernhill0001) (account 222222222221, eu-west-1)

  Account assignments exist only for accounts inside the organization that owns the instance. When the account leaves o-larkspur0001, Identity Center cleans up its metadata and resources for the account and a standalone account no longer works with Identity Center, so these 1 assignment(s) stop granting access at once. The target instance has no permission set named PaymentsEngineer. Create one there (or choose an equivalent) before re-assigning the 1 principal(s), who have to exist in identity store d-fern0000001 under the target instance.

  _From the identity-center check: Permission set PaymentsEngineer: 1 assignment(s) removed when the account leaves (group Payments-Engineers)._

  ```sh
  aws sso-admin create-permission-set --instance-arn arn:aws:sso:::instance/ssoins-fernhill00000001 --name PaymentsEngineer --description "Day-to-day operations in the payments accounts" --session-duration PT8H
  aws sso-admin attach-customer-managed-policy-reference-to-permission-set --instance-arn arn:aws:sso:::instance/ssoins-fernhill00000001 --permission-set-arn <ARN returned by create-permission-set> --customer-managed-policy-reference Name=LarkspurPaymentsEngineer,Path=/larkspur/   # the policy must exist in the account
  aws sso-admin put-inline-policy-to-permission-set --instance-arn arn:aws:sso:::instance/ssoins-fernhill00000001 --permission-set-arn <ARN returned by create-permission-set> --inline-policy file://PaymentsEngineer-inline.json   # the inline policy is in the evidence below
  ```

  - Evidence (account-assignment): source, `c3055d88-cb7d-f258-9c41-70aefb8af533`
    group Payments-Engineers has permission set PaymentsEngineer in account 111111111116

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

### 3. The move

Run these in order. Between leaving and accepting the invitation the account is standalone, with no SCPs and no organization features; keep that window short.

- [ ] **3.1** Moved together with OU Workloads
  The account does not move on its own; the move steps are in the OU part of the runbook.

### 4. After the move: checks

Confirm what the simulation predicted and finish what could only be done once the account is at its new position.

- [ ] **4.1** Accept the invitation for share larkspur-core-network and confirm the resources
  _Where:_ account larkspur-payments-dev (111111111116)

  Outside the owner's organization the share arrives as an invitation. Accept it, then check that the ec2:Subnet, ec2:TransitGateway, route53resolver:ResolverRule are listed and that what is attached to them still works.

  _From the ram check: Networking share larkspur-core-network is lost: ec2:Subnet, ec2:TransitGateway, route53resolver:ResolverRule._

  ```sh
  aws ram get-resource-share-invitations --query "resourceShareInvitations[?resourceShareName=='larkspur-core-network']"
  aws ram accept-resource-share-invitation --resource-share-invitation-arn <invitation ARN from the previous command>
  aws ram list-resources --resource-owner OTHER-ACCOUNTS --resource-share-arns arn:aws:ram:us-east-1:111111111112:resource-share/06a7aefe6fddce828
  ```

- [ ] **4.2** Accept the invitation for share larkspur-ipam and confirm the resources
  _Where:_ account larkspur-payments-dev (111111111116)

  Outside the owner's organization the share arrives as an invitation. Accept it, then check that the ec2:IpamPool are listed and that what is attached to them still works.

  _From the ram check: Networking share larkspur-ipam is lost: ec2:IpamPool._

  ```sh
  aws ram get-resource-share-invitations --query "resourceShareInvitations[?resourceShareName=='larkspur-ipam']"
  aws ram accept-resource-share-invitation --resource-share-invitation-arn <invitation ARN from the previous command>
  aws ram list-resources --resource-owner OTHER-ACCOUNTS --resource-share-arns arn:aws:ram:us-east-1:111111111112:resource-share/01364b18a31c4fdca
  ```

- [ ] **4.3** Accept the invitation for share larkspur-workload-prefix-lists and confirm the resources
  _Where:_ account larkspur-payments-dev (111111111116)

  Outside the owner's organization the share arrives as an invitation. Accept it, then check that the ec2:PrefixList are listed and that what is attached to them still works.

  _From the ram check: Networking share larkspur-workload-prefix-lists is lost: ec2:PrefixList._

  ```sh
  aws ram get-resource-share-invitations --query "resourceShareInvitations[?resourceShareName=='larkspur-workload-prefix-lists']"
  aws ram accept-resource-share-invitation --resource-share-invitation-arn <invitation ARN from the previous command>
  aws ram list-resources --resource-owner OTHER-ACCOUNTS --resource-share-arns arn:aws:ram:us-east-1:111111111112:resource-share/0479521366b778243
  ```

- [ ] **4.4** `INFO` Share fernhill-core-network becomes available: ec2:TransitGateway, route53resolver:ResolverRule
  _Where:_ account larkspur-payments-dev (111111111116)

  Shared by account 222222222222 with organization o-fernhill0001 in the target organization. New attachments must be created by hand; nothing is attached automatically.

  _From the ram check: Share fernhill-core-network becomes available after the move: ec2:TransitGateway, route53resolver:ResolverRule._

  ```sh
  aws ram list-resources --resource-owner OTHER-ACCOUNTS --resource-share-arns arn:aws:ram:eu-west-1:222222222222:resource-share/09521366b77824316
  ```

  - Evidence (resource-share): target, `arn:aws:ram:eu-west-1:222222222222:resource-share/09521366b77824316`
    owner 222222222222; principals: organization o-fernhill0001; allow external principals false
    ec2:TransitGateway  arn:aws:ec2:eu-west-1:222222222222:transit-gateway/tgw-6a7aefe6fddce8281
    route53resolver:ResolverRule  arn:aws:route53resolver:eu-west-1:222222222222:resolver-rule/rslvr-rr-364b18a31c4fdca47

- [ ] **4.5** `INFO` Confirm StackSet fernhill-baseline deployed its stack instances to the account
  _Where:_ administration account 222222222221

  Baseline IAM roles and GuardDuty membership. Stack instances are created automatically when auto-deployment is on.

  _From the org-services check: StackSet fernhill-baseline in the target organization starts targeting the account._

  ```sh
  aws cloudformation list-stack-instances --stack-set-name fernhill-baseline --stack-instance-account 111111111116
  ```

  - Evidence (stackset): target, `fernhill-baseline`
    admin 222222222221; targets OUs ou-fern-bu; regions eu-west-1

- [ ] **4.6** Confirm CloudTrail coverage
  _Where:_ account larkspur-payments-dev (111111111116)

  Organization trail(s) larkspur-org-trail stop logging the account the moment it leaves. Trail(s) fernhill-org-trail (bucket fernhill-log-archive) of the target cover it once it has joined; confirm events arrive there. Between leaving and joining nothing logs management events unless the account has a trail of its own.

  _From the org-services check._

  ```sh
  aws cloudtrail describe-trails --include-shadow-trails
  aws cloudtrail lookup-events --max-results 5   # the most recent management events should be minutes old
  ```

  - Evidence (org-trail): source, `arn:aws:cloudtrail:us-east-1:111111111114:trail/larkspur-org-trail`
    bucket larkspur-cloudtrail-archive, home region us-east-1

  - Evidence (org-trail): target, `arn:aws:cloudtrail:eu-west-1:222222222224:trail/fernhill-org-trail`

- [ ] **4.7** Confirm AWS Config aggregation
  _Where:_ account larkspur-payments-dev (111111111116)

  Aggregator(s) larkspur-org-aggregator of the source stop receiving the account's configuration and compliance data. Aggregator(s) fernhill-org-aggregator in the target pick it up once it has joined and the recorder in the account is running; confirm the account appears as a source.

  _From the org-services check._

  ```sh
  aws configservice describe-configuration-recorder-status
  aws configservice describe-configuration-aggregator-sources-status --configuration-aggregator-name <target aggregator>   # in the aggregator account
  ```

  - Evidence (config-aggregator): source, `larkspur-org-aggregator`

  - Evidence (config-aggregator): target, `fernhill-org-aggregator`

- [ ] **4.8** `INFO` Confirm the target's delegated administrators enrol the account
  _Where:_ management account 222222222221 of Fernhill Group

  In the target organization: 222222222223 administers access-analyzer.amazonaws.com; 222222222223 administers guardduty.amazonaws.com; 222222222223 administers securityhub.amazonaws.com. Each administrator's auto-enable settings decide whether the account is enrolled on joining; check the service consoles for the new member.

  _From the org-services check._

  ```sh
  aws organizations list-delegated-administrators
  ```

- [ ] **4.9** `INFO` Confirm the Control Tower controls that start applying at Development
  _Where:_ management account 222222222221 of Fernhill Group

  3 detective control(s) start applying at Development: AWS-GR_ENCRYPTED_VOLUMES, AWS-GR_RDS_STORAGE_ENCRYPTED, AWS-GR_RESTRICTED_SSH. 3 preventive control(s) start applying at Development: AWS-GR_CLOUDTRAIL_ENABLED, AWS-GR_CONFIG_ENABLED, AWS-GR_RESTRICT_ROOT_USER_ACCESS_KEYS. Preventive controls apply through the OU's SCPs at once; detective and proactive ones report once the account is enrolled.

  _From the control-tower check._

  ```sh
  aws controltower list-enabled-controls --target-identifier <ARN of OU ou-lark-dev>
  ```

  - Evidence (enabled-control): target, `arn:aws:controltower:eu-west-1::control/AWS-GR_ENCRYPTED_VOLUMES`
    Detect whether encryption is enabled for Amazon EBS volumes attached to Amazon EC2 instances
    detective control on OU ou-fern-bu; status SUCCEEDED, drift IN_SYNC; implemented as AWS::Config::ConfigRule

  - Evidence (enabled-control): target, `arn:aws:controltower:eu-west-1::control/AWS-GR_RESTRICTED_SSH`
    Detect whether unrestricted incoming SSH traffic is allowed
    detective control on OU ou-fern-bu; status SUCCEEDED, drift IN_SYNC; implemented as AWS::Config::ConfigRule

  - Evidence (enabled-control): target, `arn:aws:controltower:eu-west-1::control/AWS-GR_RDS_STORAGE_ENCRYPTED`
    Detect whether storage encryption is enabled for Amazon RDS database instances
    detective control on OU ou-fern-bu; status SUCCEEDED, drift IN_SYNC; implemented as AWS::Config::ConfigRule

  - Evidence (enabled-control): target, `arn:aws:controltower:eu-west-1::control/AWS-GR_CLOUDTRAIL_ENABLED`
    Disallow changes to CloudTrail set up by AWS Control Tower
    preventive control on OU ou-fern-bu; status SUCCEEDED, drift IN_SYNC; implemented as AWS::Organizations::Policy

  - Evidence (enabled-control): target, `arn:aws:controltower:eu-west-1::control/AWS-GR_CONFIG_ENABLED`
    Disallow changes to AWS Config set up by AWS Control Tower
    preventive control on OU ou-fern-bu; status SUCCEEDED, drift IN_SYNC; implemented as AWS::Organizations::Policy

  - Evidence (enabled-control): target, `arn:aws:controltower:eu-west-1::control/AWS-GR_RESTRICT_ROOT_USER_ACCESS_KEYS`
    Disallow creation of access keys for the root user
    preventive control on OU ou-fern-bu; status SUCCEEDED, drift IN_SYNC; implemented as AWS::Organizations::Policy

- [ ] **4.10** Update references to the deleted AWSReservedSSO_* roles with the ARNs the target instance provisions
  _Where:_ account larkspur-payments-dev (111111111116)

  The new roles have a different random suffix. Replace the old ARNs found before the move in resource policies, key policies, EKS access entries and tooling.

  _From the identity-center check: 3 AWSReservedSSO\_* role(s) are deleted from the account: AWSReservedSSO\_AdministratorAccess\_*, AWSReservedSSO\_PaymentsEngineer\_*, AWSReservedSSO\_ReadOnlyAccess\_*._

  ```sh
  aws iam list-roles --path-prefix /aws-reserved/sso.amazonaws.com/ --query "Roles[].Arn"
  ```

- [ ] **4.11** `REVIEW` Assign AdministratorAccess to group Platform-Admins for the account in the target instance
  _Where:_ Identity Center of Fernhill Group (o-fernhill0001) (account 222222222221, eu-west-1)

  Users and groups in identity store d-fern0000001 are different objects from the source ones, so look each one up by name first; create it there if it is missing. Identity Center then provisions a new AWSReservedSSO_AdministratorAccess_* role in the account.

  _From the identity-center check: Permission set AdministratorAccess: 1 assignment(s) removed when the account leaves (group Platform-Admins)._

  ```sh
  aws identitystore list-groups --identity-store-id d-fern0000001 --filters AttributePath=DisplayName,AttributeValue="Platform-Admins" --query "Groups[].GroupId" --output text
  aws sso-admin create-account-assignment --instance-arn arn:aws:sso:::instance/ssoins-fernhill00000001 --target-id 111111111116 --target-type AWS_ACCOUNT --permission-set-arn arn:aws:sso:::permissionSet/ssoins-fernhill00000001/ps-fern00000001 --principal-type GROUP --principal-id <ID from the previous command>
  ```

- [ ] **4.12** `REVIEW` Assign PaymentsEngineer to group Payments-Engineers for the account in the target instance
  _Where:_ Identity Center of Fernhill Group (o-fernhill0001) (account 222222222221, eu-west-1)

  Users and groups in identity store d-fern0000001 are different objects from the source ones, so look each one up by name first; create it there if it is missing. Identity Center then provisions a new AWSReservedSSO_PaymentsEngineer_* role in the account.

  _From the identity-center check: Permission set PaymentsEngineer: 1 assignment(s) removed when the account leaves (group Payments-Engineers)._

  ```sh
  aws identitystore list-groups --identity-store-id d-fern0000001 --filters AttributePath=DisplayName,AttributeValue="Payments-Engineers" --query "Groups[].GroupId" --output text
  aws sso-admin create-account-assignment --instance-arn arn:aws:sso:::instance/ssoins-fernhill00000001 --target-id 111111111116 --target-type AWS_ACCOUNT --permission-set-arn <ARN of permission set PaymentsEngineer in the target> --principal-type GROUP --principal-id <ID from the previous command>
  ```

- [ ] **4.13** Exercise the 3 flagged request(s) from the account
  _Where:_ account larkspur-payments-dev (111111111116)

  These were denied or undecidable in the simulation. After the policy changes above and the move, confirm each one works (a dry run or a read of the resource is enough): ec2:CreateVpc in us-east-1; ec2:RunInstances in us-east-1; lambda:* in us-east-1.

  ```sh
  # for each action, run the real call once from the principal that uses it, or check CloudTrail for AccessDenied events after a day
  ```

### 5. Rollback

If something breaks, this puts the account back where it was. Built from the source policy chain of the simulation.

- [ ] **5.1** Rolled back together with OU Workloads
  The rollback of the OU recreates the original OUs and moves every account back; the account's own policies to re-attach are listed below.

  - Evidence (source-chain): source
    root Root (r-lark): FullAWSAccess (p-FullAWSAccess), Larkspur-Baseline-Guardrails (p-lark0001)
    OU Workloads (ou-lark-work): FullAWSAccess (p-FullAWSAccess), Larkspur-Allowed-Regions (p-lark0002)
    OU Development (ou-lark-dev): FullAWSAccess (p-FullAWSAccess), Larkspur-Dev-Guardrails (p-lark0006)
    account larkspur-payments-dev (111111111116): FullAWSAccess (p-FullAWSAccess)

  - Evidence (source-chain): source
    root Root (r-lark): RCPFullAWSAccess (p-RCPFullAWSAccess)
    OU Workloads (ou-lark-work): RCPFullAWSAccess (p-RCPFullAWSAccess)
    OU Development (ou-lark-dev): RCPFullAWSAccess (p-RCPFullAWSAccess)
    account larkspur-payments-dev (111111111116): RCPFullAWSAccess (p-RCPFullAWSAccess)

  - Evidence (source-chain): source
    root Root (r-lark): Larkspur-Tagging-Standard (p-lark0004)
    OU Workloads (ou-lark-work): none
    OU Development (ou-lark-dev): none
    account larkspur-payments-dev (111111111116): none

  - Evidence (source-chain): source
    root Root (r-lark): none
    OU Workloads (ou-lark-work): none
    OU Development (ou-lark-dev): none
    account larkspur-payments-dev (111111111116): none

## Account larkspur-payments-prod (`111111111115`): NO-GO

40 steps: 11 before the move (3 blocking), 10 to re-create, 1 for the move itself, 17 checks afterwards and 1 to roll back.

### 1. Before the move: fix the blockers and make the decisions

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

- [ ] **1.2** `NO-GO` SCP Fernhill-Root-Guardrails / NoIAMUsers denies 1 action after the move
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

- [ ] **1.3** `NO-GO` RCP Fernhill-Block-External-Principals / EnforceOrgIdentities denies 4 requests after the move
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

- [ ] **1.4** `REVIEW` Decide whether RCP Fernhill-Block-External-Principals / EnforceOrgIdentities applies to 1 request
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

- [ ] **1.5** `REVIEW` Re-tag before the move: cost-center: ec2:instance resources use the key "Cost-Center" instead of "cost-center"
  _Where:_ account larkspur-payments-prod (111111111115)

  The target tag policy (Fernhill-Cost-Allocation) fixes the key capitalization. The policy enforces this for ec2:instance: after the move, tag operations that would leave such a resource non-compliant are rejected (enforcement on supported operations); the existing tags themselves are not changed. Affected: 3 resource(s), for example arn:aws:ec2:us-east-1:111111111115:instance/i-f10bba738feab223b, arn:aws:ec2:us-east-1:111111111115:instance/i-c532d94e1b98a3356, arn:aws:ec2:us-east-1:111111111115:instance/i-f5e303bf12e951c05. Do it before the move: afterwards the target tag policy rejects non-compliant tag operations on these resource types, so the fix itself is blocked.

  resource `arn:aws:ec2:us-east-1:111111111115:instance/i-f10bba738feab223b, arn:aws:ec2:us-east-1:111111111115:instance/i-c532d94e1b98a3356, arn:aws:ec2:us-east-1:111111111115:instance/i-f5e303bf12e951c05`

  _From the tags check: cost-center: ec2:instance resources use the key "Cost-Center" instead of "cost-center"._

  ```sh
  aws resourcegroupstaggingapi tag-resources --resource-arn-list arn:aws:ec2:us-east-1:111111111115:instance/i-f10bba738feab223b arn:aws:ec2:us-east-1:111111111115:instance/i-c532d94e1b98a3356 arn:aws:ec2:us-east-1:111111111115:instance/i-f5e303bf12e951c05 --tags <Key>=<allowed value>
  ```

  - Evidence (tag-compliance): target
    arn:aws:ec2:us-east-1:111111111115:instance/i-f10bba738feab223b
    arn:aws:ec2:us-east-1:111111111115:instance/i-c532d94e1b98a3356
    arn:aws:ec2:us-east-1:111111111115:instance/i-f5e303bf12e951c05

- [ ] **1.6** `REVIEW` Re-tag before the move: cost-center: rds:db resources use the value "PAY-01" which is not allowed
  _Where:_ account larkspur-payments-prod (111111111115)

  Allowed values (Fernhill-Cost-Allocation): CC-1001, CC-1002, CC-2001, CC-2002. The policy enforces this for rds:db: after the move, tag operations that would leave such a resource non-compliant are rejected (enforcement on supported operations); the existing tags themselves are not changed. Affected: 1 resource(s), for example arn:aws:rds:us-east-1:111111111115:db:payments-ledger. Do it before the move: afterwards the target tag policy rejects non-compliant tag operations on these resource types, so the fix itself is blocked.

  resource `arn:aws:rds:us-east-1:111111111115:db:payments-ledger`

  _From the tags check: cost-center: rds:db resources use the value "PAY-01" which is not allowed._

  ```sh
  aws resourcegroupstaggingapi tag-resources --resource-arn-list arn:aws:rds:us-east-1:111111111115:db:payments-ledger --tags <Key>=<allowed value>
  ```

  - Evidence (tag-compliance): target
    arn:aws:rds:us-east-1:111111111115:db:payments-ledger

- [ ] **1.7** `REVIEW` Re-tag before the move: cost-center: s3:bucket resources use the value "CC-3001" which is not allowed
  _Where:_ account larkspur-payments-prod (111111111115)

  Allowed values (Fernhill-Cost-Allocation): CC-1001, CC-1002, CC-2001, CC-2002. The policy enforces this for s3:bucket: after the move, tag operations that would leave such a resource non-compliant are rejected (enforcement on supported operations); the existing tags themselves are not changed. Affected: 1 resource(s), for example arn:aws:s3:::larkspur-payments-settlement-files. Do it before the move: afterwards the target tag policy rejects non-compliant tag operations on these resource types, so the fix itself is blocked.

  resource `arn:aws:s3:::larkspur-payments-settlement-files`

  _From the tags check: cost-center: s3:bucket resources use the value "CC-3001" which is not allowed._

  ```sh
  aws resourcegroupstaggingapi tag-resources --resource-arn-list arn:aws:s3:::larkspur-payments-settlement-files --tags <Key>=<allowed value>
  ```

  - Evidence (tag-compliance): target
    arn:aws:s3:::larkspur-payments-settlement-files

- [ ] **1.8** `REVIEW` Make the account able to stand alone
  _Where:_ account larkspur-payments-prod (111111111115), signed in as root or an administrator

  Before it can leave, the account needs its own verified contact information, a payment method and a support plan choice; Organizations fails the removal with ConstraintViolationException until they are in place (with Enterprise Support, a billing case can arrange the standalone period instead of a payment method per account). It then has to be invited by the target management account 222222222221 and accept the invitation: an account belongs to one organization at a time, so it leaves first; the invitation must be answered within 15 days; the policies attached to the target root and the OU it lands in apply at once; the target's organization trail covers it automatically and Config, GuardDuty or Security Hub may be enabled automatically for new members, so account-level trails and detectors may double charges; Organizations does not create OrganizationAccountAccessRole for an invited account. SCPs in the source that deny organizations:LeaveOrganization must be lifted for the move, or the source management account removes the account instead. The account also loses access to the cost and usage data of its time in the source organization and is no longer covered by the source organization's agreements. Transfer procedure model 2026-11-02. Contact information, alternate contacts and the payment method can be checked with the Account API; identity verification and the support plan are done in the console.

  _From the org-services check: Standalone account prerequisites and invitation._

  ```sh
  aws account get-contact-information
  aws account get-alternate-contact --alternate-contact-type BILLING
  # console: Billing and Cost Management → Payment preferences; Account → Identity verification; Support → Support plan
  ```

- [ ] **1.9** `REVIEW` Lift the deny on organizations:LeaveOrganization in SCP Larkspur-Baseline-Guardrails / DenyLeaveOrganization, or let the management account remove the account
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

- [ ] **1.10** `REVIEW` Find what references the 4 AWSReservedSSO_* role(s) of the account
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

- [ ] **1.11** `REVIEW` Deprovision the stale permission set(s) from the account: DataPlatformOperator
  _Where:_ Identity Center of Larkspur Holdings (o-larkspur0001) (account 111111111111, us-east-1)

  These permission sets are provisioned in the account without any assignment, so their roles are unused. Removing them now deletes the roles cleanly and keeps them out of the reference search above.

  _From the identity-center check: 4 AWSReservedSSO\_* role(s) are deleted from the account: AWSReservedSSO\_AdministratorAccess\_*, AWSReservedSSO\_PaymentsEngineer\_*, AWSReservedSSO\_ReadOnlyAccess\_*, AWSReservedSSO\_DataPlatformOperator\_*._

  ```sh
  aws sso-admin list-accounts-for-provisioned-permission-set --instance-arn arn:aws:sso:::instance/ssoins-larkspur00000001 --permission-set-arn arn:aws:sso:::permissionSet/ssoins-larkspur00000001/ps-lark00000004
  # Identity Center console → Permission sets → DataPlatformOperator → AWS accounts → remove 111111111115
  ```

### 2. Before the move: re-create what does not travel

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

  Service-managed StackSets deploy by OU. Audit and break-glass IAM roles for workload accounts. Check what those stacks provide (roles, Config recorders, GuardDuty membership) before moving. Decide: redeploy the template by hand in the account, add the account to a self-managed StackSet, or accept the loss.

  _From the org-services check: StackSet larkspur-baseline-roles stops targeting the account; stack instances are deleted from the account._

  ```sh
  aws cloudformation list-stack-instances --stack-set-name larkspur-baseline-roles --stack-instance-account 111111111115
  aws cloudformation describe-stack-set --stack-set-name larkspur-baseline-roles --query StackSet.TemplateBody --output text
  ```

  - Evidence (stackset): source, `larkspur-baseline-roles`
    admin 111111111111; targets OUs ou-lark-work accounts ; regions us-east-1; auto-deployment true; retain on removal false

- [ ] **2.6** `REVIEW` Replace what StackSet larkspur-config-recorder deploys into the account
  _Where:_ administration account 111111111111

  Service-managed StackSets deploy by OU. AWS Config recorder and delivery channel. Check what those stacks provide (roles, Config recorders, GuardDuty membership) before moving. Decide: redeploy the template by hand in the account, add the account to a self-managed StackSet, or accept the loss.

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

- [ ] **2.8** `REVIEW` Review permission set AdministratorAccess in the target instance before re-assigning it
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

- [ ] **2.9** `REVIEW` Create permission set PaymentsEngineer in the target instance
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

- [ ] **2.10** `REVIEW` Review permission set ReadOnlyAccess in the target instance before re-assigning it
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

### 3. The move

Run these in order. Between leaving and accepting the invitation the account is standalone, with no SCPs and no organization features; keep that window short.

- [ ] **3.1** Moved together with OU Workloads
  The account does not move on its own; the move steps are in the OU part of the runbook.

### 4. After the move: checks

Confirm what the simulation predicted and finish what could only be done once the account is at its new position.

- [ ] **4.1** `INFO` Tag to the target standard: cost-center: ec2:instance resources carry no cost-center tag
  _Where:_ account larkspur-payments-prod (111111111115)

  Tag policies do not require a tag to be present, so this does not block the move, but these resources fall outside the target standard (Fernhill-Cost-Allocation). Affected: 2 resource(s), for example arn:aws:ec2:us-east-1:111111111115:instance/i-c5aafe82c7111d6b7, arn:aws:ec2:us-east-1:111111111115:instance/i-5ec8c6966cdcd7b5e. Not enforced, so this can wait until after the move.

  _From the tags check: cost-center: ec2:instance resources carry no cost-center tag._

  - Evidence (tag-compliance): target
    arn:aws:ec2:us-east-1:111111111115:instance/i-c5aafe82c7111d6b7
    arn:aws:ec2:us-east-1:111111111115:instance/i-5ec8c6966cdcd7b5e

- [ ] **4.2** `INFO` Tag to the target standard: cost-center: lambda:function resources carry no cost-center tag
  _Where:_ account larkspur-payments-prod (111111111115)

  Tag policies do not require a tag to be present, so this does not block the move, but these resources fall outside the target standard (Fernhill-Cost-Allocation). Affected: 1 resource(s), for example arn:aws:lambda:us-east-1:111111111115:function:settlement-notifier. Not enforced, so this can wait until after the move.

  _From the tags check: cost-center: lambda:function resources carry no cost-center tag._

  - Evidence (tag-compliance): target
    arn:aws:lambda:us-east-1:111111111115:function:settlement-notifier

- [ ] **4.3** Accept the invitation for share larkspur-core-network and confirm the resources
  _Where:_ account larkspur-payments-prod (111111111115)

  Outside the owner's organization the share arrives as an invitation. Accept it, then check that the ec2:Subnet, ec2:TransitGateway, route53resolver:ResolverRule are listed and that what is attached to them still works.

  _From the ram check: Networking share larkspur-core-network is lost: ec2:Subnet, ec2:TransitGateway, route53resolver:ResolverRule._

  ```sh
  aws ram get-resource-share-invitations --query "resourceShareInvitations[?resourceShareName=='larkspur-core-network']"
  aws ram accept-resource-share-invitation --resource-share-invitation-arn <invitation ARN from the previous command>
  aws ram list-resources --resource-owner OTHER-ACCOUNTS --resource-share-arns arn:aws:ram:us-east-1:111111111112:resource-share/06a7aefe6fddce828
  ```

- [ ] **4.4** Accept the invitation for share larkspur-ipam and confirm the resources
  _Where:_ account larkspur-payments-prod (111111111115)

  Outside the owner's organization the share arrives as an invitation. Accept it, then check that the ec2:IpamPool are listed and that what is attached to them still works.

  _From the ram check: Networking share larkspur-ipam is lost: ec2:IpamPool._

  ```sh
  aws ram get-resource-share-invitations --query "resourceShareInvitations[?resourceShareName=='larkspur-ipam']"
  aws ram accept-resource-share-invitation --resource-share-invitation-arn <invitation ARN from the previous command>
  aws ram list-resources --resource-owner OTHER-ACCOUNTS --resource-share-arns arn:aws:ram:us-east-1:111111111112:resource-share/01364b18a31c4fdca
  ```

- [ ] **4.5** Accept the invitation for share larkspur-workload-prefix-lists and confirm the resources
  _Where:_ account larkspur-payments-prod (111111111115)

  Outside the owner's organization the share arrives as an invitation. Accept it, then check that the ec2:PrefixList are listed and that what is attached to them still works.

  _From the ram check: Networking share larkspur-workload-prefix-lists is lost: ec2:PrefixList._

  ```sh
  aws ram get-resource-share-invitations --query "resourceShareInvitations[?resourceShareName=='larkspur-workload-prefix-lists']"
  aws ram accept-resource-share-invitation --resource-share-invitation-arn <invitation ARN from the previous command>
  aws ram list-resources --resource-owner OTHER-ACCOUNTS --resource-share-arns arn:aws:ram:us-east-1:111111111112:resource-share/0479521366b778243
  ```

- [ ] **4.6** Accept the invitation for share larkspur-license-config and confirm the resources
  _Where:_ account larkspur-payments-prod (111111111115)

  Outside the owner's organization the share arrives as an invitation. Accept it, then check that the license-manager:LicenseConfiguration are listed and that what is attached to them still works.

  _From the ram check: Share larkspur-license-config is lost: license-manager:LicenseConfiguration._

  ```sh
  aws ram get-resource-share-invitations --query "resourceShareInvitations[?resourceShareName=='larkspur-license-config']"
  aws ram accept-resource-share-invitation --resource-share-invitation-arn <invitation ARN from the previous command>
  aws ram list-resources --resource-owner OTHER-ACCOUNTS --resource-share-arns arn:aws:ram:us-east-1:111111111113:resource-share/016cff3e3072e28ed
  ```

- [ ] **4.7** `INFO` Share fernhill-core-network becomes available: ec2:TransitGateway, route53resolver:ResolverRule
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

- [ ] **4.8** `INFO` Confirm StackSet fernhill-baseline deployed its stack instances to the account
  _Where:_ administration account 222222222221

  Baseline IAM roles and GuardDuty membership. Stack instances are created automatically when auto-deployment is on.

  _From the org-services check: StackSet fernhill-baseline in the target organization starts targeting the account._

  ```sh
  aws cloudformation list-stack-instances --stack-set-name fernhill-baseline --stack-instance-account 111111111115
  ```

  - Evidence (stackset): target, `fernhill-baseline`
    admin 222222222221; targets OUs ou-fern-bu; regions eu-west-1

- [ ] **4.9** Confirm CloudTrail coverage
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

- [ ] **4.10** Confirm AWS Config aggregation
  _Where:_ account larkspur-payments-prod (111111111115)

  Aggregator(s) larkspur-org-aggregator of the source stop receiving the account's configuration and compliance data. Aggregator(s) fernhill-org-aggregator in the target pick it up once it has joined and the recorder in the account is running; confirm the account appears as a source.

  _From the org-services check._

  ```sh
  aws configservice describe-configuration-recorder-status
  aws configservice describe-configuration-aggregator-sources-status --configuration-aggregator-name <target aggregator>   # in the aggregator account
  ```

  - Evidence (config-aggregator): source, `larkspur-org-aggregator`

  - Evidence (config-aggregator): target, `fernhill-org-aggregator`

- [ ] **4.11** `INFO` Confirm the target's delegated administrators enrol the account
  _Where:_ management account 222222222221 of Fernhill Group

  In the target organization: 222222222223 administers access-analyzer.amazonaws.com; 222222222223 administers guardduty.amazonaws.com; 222222222223 administers securityhub.amazonaws.com. Each administrator's auto-enable settings decide whether the account is enrolled on joining; check the service consoles for the new member.

  _From the org-services check._

  ```sh
  aws organizations list-delegated-administrators
  ```

- [ ] **4.12** `INFO` Confirm the Control Tower controls that start applying at Production
  _Where:_ management account 222222222221 of Fernhill Group

  3 detective control(s) start applying at Production: AWS-GR_ENCRYPTED_VOLUMES, AWS-GR_RDS_STORAGE_ENCRYPTED, AWS-GR_RESTRICTED_SSH. 3 preventive control(s) start applying at Production: AWS-GR_CLOUDTRAIL_ENABLED, AWS-GR_CONFIG_ENABLED, AWS-GR_RESTRICT_ROOT_USER_ACCESS_KEYS. Preventive controls apply through the OU's SCPs at once; detective and proactive ones report once the account is enrolled.

  _From the control-tower check._

  ```sh
  aws controltower list-enabled-controls --target-identifier <ARN of OU ou-lark-prod>
  ```

  - Evidence (enabled-control): target, `arn:aws:controltower:eu-west-1::control/AWS-GR_ENCRYPTED_VOLUMES`
    Detect whether encryption is enabled for Amazon EBS volumes attached to Amazon EC2 instances
    detective control on OU ou-fern-bu; status SUCCEEDED, drift IN_SYNC; implemented as AWS::Config::ConfigRule

  - Evidence (enabled-control): target, `arn:aws:controltower:eu-west-1::control/AWS-GR_RESTRICTED_SSH`
    Detect whether unrestricted incoming SSH traffic is allowed
    detective control on OU ou-fern-bu; status SUCCEEDED, drift IN_SYNC; implemented as AWS::Config::ConfigRule

  - Evidence (enabled-control): target, `arn:aws:controltower:eu-west-1::control/AWS-GR_RDS_STORAGE_ENCRYPTED`
    Detect whether storage encryption is enabled for Amazon RDS database instances
    detective control on OU ou-fern-bu; status SUCCEEDED, drift IN_SYNC; implemented as AWS::Config::ConfigRule

  - Evidence (enabled-control): target, `arn:aws:controltower:eu-west-1::control/AWS-GR_CLOUDTRAIL_ENABLED`
    Disallow changes to CloudTrail set up by AWS Control Tower
    preventive control on OU ou-fern-bu; status SUCCEEDED, drift IN_SYNC; implemented as AWS::Organizations::Policy

  - Evidence (enabled-control): target, `arn:aws:controltower:eu-west-1::control/AWS-GR_CONFIG_ENABLED`
    Disallow changes to AWS Config set up by AWS Control Tower
    preventive control on OU ou-fern-bu; status SUCCEEDED, drift IN_SYNC; implemented as AWS::Organizations::Policy

  - Evidence (enabled-control): target, `arn:aws:controltower:eu-west-1::control/AWS-GR_RESTRICT_ROOT_USER_ACCESS_KEYS`
    Disallow creation of access keys for the root user
    preventive control on OU ou-fern-bu; status SUCCEEDED, drift IN_SYNC; implemented as AWS::Organizations::Policy

- [ ] **4.13** Update references to the deleted AWSReservedSSO_* roles with the ARNs the target instance provisions
  _Where:_ account larkspur-payments-prod (111111111115)

  The new roles have a different random suffix. Replace the old ARNs found before the move in resource policies, key policies, EKS access entries and tooling.

  _From the identity-center check: 4 AWSReservedSSO\_* role(s) are deleted from the account: AWSReservedSSO\_AdministratorAccess\_*, AWSReservedSSO\_PaymentsEngineer\_*, AWSReservedSSO\_ReadOnlyAccess\_*, AWSReservedSSO\_DataPlatformOperator\_*._

  ```sh
  aws iam list-roles --path-prefix /aws-reserved/sso.amazonaws.com/ --query "Roles[].Arn"
  ```

- [ ] **4.14** `REVIEW` Assign AdministratorAccess to group Platform-Admins for the account in the target instance
  _Where:_ Identity Center of Fernhill Group (o-fernhill0001) (account 222222222221, eu-west-1)

  Users and groups in identity store d-fern0000001 are different objects from the source ones, so look each one up by name first; create it there if it is missing. Identity Center then provisions a new AWSReservedSSO_AdministratorAccess_* role in the account.

  _From the identity-center check: Permission set AdministratorAccess: 1 assignment(s) removed when the account leaves (group Platform-Admins)._

  ```sh
  aws identitystore list-groups --identity-store-id d-fern0000001 --filters AttributePath=DisplayName,AttributeValue="Platform-Admins" --query "Groups[].GroupId" --output text
  aws sso-admin create-account-assignment --instance-arn arn:aws:sso:::instance/ssoins-fernhill00000001 --target-id 111111111115 --target-type AWS_ACCOUNT --permission-set-arn arn:aws:sso:::permissionSet/ssoins-fernhill00000001/ps-fern00000001 --principal-type GROUP --principal-id <ID from the previous command>
  ```

- [ ] **4.15** `REVIEW` Assign PaymentsEngineer to group Payments-Engineers, user oncall.payments for the account in the target instance
  _Where:_ Identity Center of Fernhill Group (o-fernhill0001) (account 222222222221, eu-west-1)

  Users and groups in identity store d-fern0000001 are different objects from the source ones, so look each one up by name first; create it there if it is missing. Identity Center then provisions a new AWSReservedSSO_PaymentsEngineer_* role in the account.

  _From the identity-center check: Permission set PaymentsEngineer: 2 assignment(s) removed when the account leaves (group Payments-Engineers, user oncall.payments)._

  ```sh
  aws identitystore list-groups --identity-store-id d-fern0000001 --filters AttributePath=DisplayName,AttributeValue="Payments-Engineers" --query "Groups[].GroupId" --output text
  aws sso-admin create-account-assignment --instance-arn arn:aws:sso:::instance/ssoins-fernhill00000001 --target-id 111111111115 --target-type AWS_ACCOUNT --permission-set-arn <ARN of permission set PaymentsEngineer in the target> --principal-type GROUP --principal-id <ID from the previous command>
  aws identitystore list-users --identity-store-id d-fern0000001 --filters AttributePath=UserName,AttributeValue="oncall.payments" --query "Users[].UserId" --output text
  aws sso-admin create-account-assignment --instance-arn arn:aws:sso:::instance/ssoins-fernhill00000001 --target-id 111111111115 --target-type AWS_ACCOUNT --permission-set-arn <ARN of permission set PaymentsEngineer in the target> --principal-type USER --principal-id <ID from the previous command>
  ```

- [ ] **4.16** `REVIEW` Assign ReadOnlyAccess to group Security-Auditors for the account in the target instance
  _Where:_ Identity Center of Fernhill Group (o-fernhill0001) (account 222222222221, eu-west-1)

  Users and groups in identity store d-fern0000001 are different objects from the source ones, so look each one up by name first; create it there if it is missing. Identity Center then provisions a new AWSReservedSSO_ReadOnlyAccess_* role in the account.

  _From the identity-center check: Permission set ReadOnlyAccess: 1 assignment(s) removed when the account leaves (group Security-Auditors)._

  ```sh
  aws identitystore list-groups --identity-store-id d-fern0000001 --filters AttributePath=DisplayName,AttributeValue="Security-Auditors" --query "Groups[].GroupId" --output text
  aws sso-admin create-account-assignment --instance-arn arn:aws:sso:::instance/ssoins-fernhill00000001 --target-id 111111111115 --target-type AWS_ACCOUNT --permission-set-arn arn:aws:sso:::permissionSet/ssoins-fernhill00000001/ps-fern00000002 --principal-type GROUP --principal-id <ID from the previous command>
  ```

- [ ] **4.17** Exercise the 21 flagged request(s) from the account
  _Where:_ account larkspur-payments-prod (111111111115)

  These were denied or undecidable in the simulation. After the policy changes above and the move, confirm each one works (a dry run or a read of the resource is enough): cloudwatch:PutMetricData in ap-southeast-1, us-east-1; dynamodb:* in ap-southeast-1, us-east-1; ec2:CreateTransitGatewayVpcAttachment in ap-southeast-1, us-east-1; ec2:CreateVpc in ap-southeast-1, us-east-1; ec2:DescribeInstances in ap-southeast-1, us-east-1; ec2:RunInstances in ap-southeast-1, us-east-1; ec2:TerminateInstances in ap-southeast-1, us-east-1; iam:CreateUser; kms:Decrypt in ap-southeast-1, us-east-1; lambda:InvokeFunction in ap-southeast-1, us-east-1; logs:CreateLogGroup in ap-southeast-1, us-east-1; rds:CreateDBInstance in us-east-1; rds:DescribeDBInstances in ap-southeast-1, us-east-1; s3:GetObject in ap-southeast-1, us-east-1; s3:PutObject in ap-southeast-1, us-east-1; secretsmanager:GetSecretValue in ap-southeast-1, us-east-1; kms:Decrypt by arn:aws:iam::111111111118:role/DataPlatformIngest in us-east-1; s3:GetObject by 999999999999 in ap-southeast-1, eu-west-1, us-east-1; s3:ListBucket by 999999999999 in ap-southeast-1, eu-west-1, us-east-1; sts:AssumeRole by arn:aws:iam::111111111118:role/DataPlatformIngest; sqs:SendMessage by 888888888888 in us-east-1.

  ```sh
  # for each action, run the real call once from the principal that uses it, or check CloudTrail for AccessDenied events after a day
  ```

### 5. Rollback

If something breaks, this puts the account back where it was. Built from the source policy chain of the simulation.

- [ ] **5.1** Rolled back together with OU Workloads
  The rollback of the OU recreates the original OUs and moves every account back; the account's own policies to re-attach are listed below.

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

