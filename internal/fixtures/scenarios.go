package fixtures

// Scenario fixtures: staged migrations over the fixture organizations, as
// the scenario overlay files `orgshift fixtures` writes next to the
// snapshots. They are text so the files and the tests use the same bytes.

// PaymentsToFernhillStagedName names the cross-organization scenario.
const PaymentsToFernhillStagedName = "Payments production into Fernhill, staged"

// SandboxToBusinessUnitsStagedName names the same-organization scenario.
const SandboxToBusinessUnitsStagedName = "Fernhill sandbox into Business Units, staged"

// PaymentsToFernhillStaged moves larkspur-payments-prod into Fernhill in
// seven stages: prerequisites (shared networking re-created in Fernhill),
// entry at the root, a proposed unregistered Legacy OU, a validation point,
// enrollment into the registered Payments OU and a tightening SCP.
const PaymentsToFernhillStaged = `schema_version: 1
name: Payments production into Fernhill, staged
description: >-
  Transfer larkspur-payments-prod (111111111115) from Larkspur Holdings into
  Fernhill Group through a transitional Legacy OU, then enroll it in Control
  Tower and tighten the policies. Proposed objects are created in Fernhill
  before the stage that uses them; nothing here exists in the snapshots.
account: "111111111115"
strategy: transfer
source: larkspur-holdings.json
destination: fernhill-group.json
critical_operations:
  - action: ec2:CreateTransitGatewayVpcAttachment
    regions: [eu-west-1]
    reason: disaster recovery attaches the standby VPC to the shared transit gateway
  - action: cloudformation:CreateStack
    reason: the deployment pipeline creates stacks in every release
  - action: rds:RestoreDBInstanceFromDBSnapshot
    regions: [eu-west-1]
    reason: ledger database recovery procedure
  - action: iam:CreateUser
    reason: the SFTP gateway rotation still creates an IAM user
proposed:
  organizational_units:
    - id: ou-proposed-legacy
      name: Legacy
      parent: r-fern
      policies: [p-fern0002]
    - id: ou-proposed-transit
      name: Transitional
      parent: ou-fern-bu
  policies:
    - id: p-proposed-tighten
      name: Fernhill-Payments-Tightening
      type: SERVICE_CONTROL_POLICY
      description: Denies IAM user creation and non-EU regions for the migrated payments account
      document:
        Version: "2012-10-17"
        Statement:
          - Sid: NoIAMUsersAtAll
            Effect: Deny
            Action: [iam:CreateUser, iam:CreateAccessKey]
            Resource: "*"
          - Sid: NoInstanceTypesOutsideCatalogue
            Effect: Deny
            Action: ec2:RunInstances
            Resource: arn:aws:ec2:*:*:instance/*
            Condition:
              StringNotLike:
                ec2:InstanceType: ["m6i.*", "r6i.*", "t3.*"]
  resource_shares:
    - name: fernhill-payments-transit
      owner_account: "222222222222"
      principals: ["111111111115"]
      allow_external_principals: true
      resources:
        - arn: arn:aws:ec2:eu-west-1:222222222222:transit-gateway/tgw-0fernhill000000001
          type: ec2:TransitGateway
stages:
  - id: current
    title: Current source membership and governance
    description: The account as collected in Larkspur Holdings, under Workloads / Production.
  - id: prerequisites
    title: Migration prerequisites and dependency preparation
    description: Fernhill's network account shares its transit gateway with the account directly; the account is still in Larkspur.
    network:
      recreate_shares: [fernhill-payments-transit]
    verify:
      - standalone-account information entered and verified for 111111111115
      - invitation sent from 222222222221 and still valid
      - delegated administrator roles checked for the account
  - id: enter
    title: Destination organization entry at the root
    description: The account leaves Larkspur and accepts Fernhill's invitation; it lands at the root.
    membership:
      organization: destination
  - id: legacy
    title: Placement into the transitional Legacy OU
    description: A proposed, unregistered OU under the root that carries the EU-only regions SCP.
    placement:
      parent: ou-proposed-legacy
  - id: validate
    title: Network, identity, logging and shared-service validation
    network:
      validated: true
    verify:
      - transit gateway attachment created and routes propagated
      - Identity Center assignments granted in Fernhill for the payments team
      - organization trail delivery confirmed for the account
      - settlement file transfers to the acquirer tested
  - id: enroll
    title: Control Tower enrollment into the Payments OU
    description: The account moves into the registered Payments OU and is enrolled through Account Factory.
    placement:
      parent: ou-fern-pay1
    governance:
      enrolled: true
      execution_role_present: true
  - id: tighten
    title: Progressive policy tightening
    description: The proposed tightening SCP is attached to the account itself.
    policies:
      attach:
        - policy: p-proposed-tighten
          target: "111111111115"
`

// SandboxToBusinessUnitsStaged moves fernhill-sandbox inside Fernhill: from
// the unregistered Sandbox OU into a proposed Transitional OU under the
// registered Business Units OU (which inherits the guardrail SCPs without
// being registered), then registers that OU and enrolls the account, then
// tightens.
const SandboxToBusinessUnitsStaged = `schema_version: 1
name: Fernhill sandbox into Business Units, staged
description: >-
  Move fernhill-sandbox (222222222227) from the unregistered Sandbox OU into a
  proposed Transitional OU under Business Units, register the OU and enroll
  the account, then attach a tightening policy. Same organization throughout.
account: "222222222227"
strategy: transfer
source: fernhill-group.json
critical_operations:
  - action: ec2:RunInstances
    regions: [eu-west-1]
    reason: the sandbox team launches instances daily
  - action: redshift:CreateCluster
    reason: analytics proof of concept planned for next quarter
proposed:
  organizational_units:
    - id: ou-proposed-transit
      name: Transitional
      parent: ou-fern-bu
  policies:
    - id: p-proposed-sandbox-exit
      name: Fernhill-Sandbox-Exit
      type: SERVICE_CONTROL_POLICY
      description: Keeps the former sandbox away from data warehouses until reviewed
      document:
        Version: "2012-10-17"
        Statement:
          - Sid: NoWarehouses
            Effect: Deny
            Action: ["redshift:*"]
            Resource: "*"
stages:
  - id: current
    title: Current placement and governance
  - id: transitional
    title: Placement into the proposed Transitional OU
    description: Unregistered, but under Business Units, so it inherits the guardrail SCPs and the EU-only regions policy.
    placement:
      parent: ou-proposed-transit
  - id: validate
    title: Validation of inherited controls
    network:
      validated: true
    verify:
      - sandbox pipelines still deploy with the inherited EU-only regions policy
  - id: govern
    title: Register the Transitional OU and enroll the account
    governance:
      register_ou: ou-proposed-transit
      enrolled: true
      execution_role_present: true
      config_resources_removed: true
  - id: tighten
    title: Progressive policy tightening
    policies:
      attach:
        - policy: p-proposed-sandbox-exit
          target: ou-proposed-transit
`

// PaymentsRecreatedInFernhillName names the recreate-strategy scenario.
const PaymentsRecreatedInFernhillName = "Payments production recreated in Fernhill"

// PaymentsRecreatedInFernhill is the recreate strategy for the same
// account: it stays where it is, a new account is vended in Fernhill and
// the workloads are redeployed into it. The relocation stage lists what
// has to be brought over, from the workload inventory.
const PaymentsRecreatedInFernhill = `schema_version: 1
name: Payments production recreated in Fernhill
description: >-
  The recreate strategy for larkspur-payments-prod (111111111115): the account
  stays in Larkspur Holdings, a new account is vended in Fernhill Group and
  the workloads are redeployed into it. The source account does not move, so
  every stage evaluates it where it is; the relocation stage lists what has to
  be brought into the new account.
account: "111111111115"
strategy: recreate
source: larkspur-holdings.json
destination: fernhill-group.json
stages:
  - id: current
    title: Current placement and governance
  - id: relocate
    title: Redeploy the workloads into the new Fernhill account
    workload:
      relocate: true
      target_account: "222222222229"
      note: vended by Account Factory under Business Units / Payments
  - id: cutover
    title: Cutover validation
    network:
      validated: true
    verify:
      - settlement files are written to and read from the bucket in the new account
      - the ledger database answers from the new account
      - the deployment pipeline targets the new account ID
`

// ScenarioFiles maps the scenario fixture file names to their contents.
func ScenarioFiles() map[string]string {
	return map[string]string{
		"scenario-payments-to-fernhill.yaml":    PaymentsToFernhillStaged,
		"scenario-fernhill-sandbox-staged.yaml": SandboxToBusinessUnitsStaged,
		"scenario-payments-recreate.yaml":       PaymentsRecreatedInFernhill,
	}
}
