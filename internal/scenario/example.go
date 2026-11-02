package scenario

// Example is an annotated scenario overlay. `orgshift scenario example`
// prints it; it uses the fixture organizations' identifiers.
const Example = `# orgshift scenario overlay: a staged migration proposal. Snapshots stay
# immutable; everything proposed here is applied to in-memory copies only.
schema_version: 1
name: Payments production into Fernhill, staged
description: Transfer through a transitional OU, then Control Tower enrollment and tightening.
account: "111111111115"       # the account that moves
strategy: transfer            # transfer (move the account) or recreate (new accounts, migrate workloads)
source: larkspur-holdings.json       # optional snapshot paths, relative to this file; CLI flags override
destination: fernhill-group.json     # omit for a move inside one organization

# Operations the account must keep performing, evaluated at every stage next
# to the observed usage. History alone misses deployments, recovery and
# scaling; declare them here.
critical_operations:
  - action: ec2:CreateTransitGatewayVpcAttachment
    regions: [eu-west-1]
    reason: disaster recovery attaches the standby VPC to the shared transit gateway
  - action: cloudformation:CreateStack
    reason: the deployment pipeline creates stacks in every release

# Objects that do not exist in the destination snapshot yet. They are
# created before the stage that uses them; the report lists them apart from
# collected objects.
proposed:
  organizational_units:
    - id: ou-proposed-legacy        # synthetic id used by the stages below
      name: Legacy
      parent: r-fern                # an existing root or OU, or another proposed OU
      policies: [p-fern0002]        # existing or proposed policies attached from creation
      # register: true              # registered with Control Tower from creation
  policies:
    - id: p-proposed-tighten
      name: Fernhill-Payments-Tightening
      type: SERVICE_CONTROL_POLICY
      document:                     # a YAML mapping or a JSON string
        Version: "2012-10-17"
        Statement:
          - Sid: NoIAMUsersAtAll
            Effect: Deny
            Action: [iam:CreateUser, iam:CreateAccessKey]
            Resource: "*"
  resource_shares:
    - name: fernhill-payments-transit
      owner_account: "222222222222"
      principals: ["111111111115"]
      allow_external_principals: true
      resources:
        - arn: arn:aws:ec2:eu-west-1:222222222222:transit-gateway/tgw-0fernhill000000001
          type: ec2:TransitGateway

# Stages, in order. Each one changes any of the five layers (membership,
# placement, governance, network, workload) or none (a verification point);
# every transition is evaluated with the full verdict board.
stages:
  - id: current
    title: Current source membership and governance
  - id: prerequisites
    title: Migration prerequisites and dependency preparation
    network:
      recreate_shares: [fernhill-payments-transit]
    verify:
      - standalone-account information entered and verified
      - invitation sent from the destination management account
  - id: enter
    title: Destination organization entry at the root
    membership:
      organization: destination     # source or destination
  - id: legacy
    title: Placement into the transitional Legacy OU
    placement:
      parent: ou-proposed-legacy
  - id: validate
    title: Network, identity, logging and shared-service validation
    network:
      validated: true
    verify:
      - transit gateway attachment created and routes propagated
      - Identity Center assignments granted in the destination
  - id: enroll
    title: Control Tower enrollment into the Payments OU
    placement:
      parent: ou-fern-pay1
    governance:
      enrolled: true
      execution_role_present: true        # declarations the collector cannot see
      # config_resources_removed: true
      # register_ou: ou-proposed-legacy   # register an OU at this stage
  - id: tighten
    title: Progressive policy tightening
    policies:
      attach:
        - policy: p-proposed-tighten
          target: "111111111115"
  # - id: relocate
  #   title: Workload relocation (recreate strategy)
  #   workload:
  #     relocate: true
  #     target_account: "222222222230"
`
