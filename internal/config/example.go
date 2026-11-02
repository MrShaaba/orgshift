package config

// Example is an annotated configuration for the fictional Larkspur Holdings
// to Fernhill Group move. `orgshift config example` prints it.
const Example = `# orgshift onboarding configuration. Nothing in this file is a secret: it names
# profiles, sessions, roles and the accounts they must belong to. Keep real
# account IDs out of version control if your organization treats them as such.
schema_version: 1

# The organization the account leaves.
source:
  name: Larkspur Holdings
  # Management access reads Organizations, the regions of every account and
  # the shares the management account owns. The identity behind it is checked
  # with sts:GetCallerIdentity against account_id before anything is read.
  management:
    account_id: "111111111111"
    region: us-east-1
    # One of: profile (any shared-config profile, SSO or not), sso_session
    # (an sso-session from ~/.aws/config, logged in with
    # "aws sso login --sso-session larkspur"), or nothing for the default
    # credential chain. assume_role hops are applied on top, in order.
    profile: larkspur-mgmt
    assume_role:
      - role_arn: arn:aws:iam::111111111111:role/OrgshiftOrgRead
        session_name: orgshift
  # The landing zone APIs answer only in the home region.
  control_tower:
    home_region: us-east-1
  # The Identity Center APIs answer only in the instance's region. "access"
  # may point at the delegated administrator instead of the management
  # account.
  identity_center:
    region: us-east-1
  # The role assumed in member accounts. Nothing in this build reads member
  # accounts yet; preflight verifies the role can be assumed in "accounts"
  # plus a sample of "sample" others (0 for none, -1 for all).
  member_inspection:
    role_name: OrgshiftMemberRead
    accounts: ["111111111115"]
    sample: 5
  # Accounts that own shared networking. RAM lists only the caller's own
  # shares, so each one is read with its own credentials: from the
  # management credentials through an assume_role, or from a profile.
  network:
    - label: network account
      account_id: "111111111120"
      from: management
      assume_role:
        - role_arn: arn:aws:iam::111111111120:role/OrgshiftNetworkRead
  # Audit and log archive accounts. Verified by preflight; read from M4.
  security:
    - label: audit account
      account_id: "111111111113"
      from: management
      assume_role:
        - role_arn: arn:aws:iam::111111111113:role/OrgshiftMemberRead
  workload_regions: [us-east-1, eu-west-1]
  # Coverage domains not to collect (recorded as skipped):
  # skip: [enabled_regions]

# The organization the account joins. Omit for a move inside one organization.
destination:
  name: Fernhill Group
  management:
    account_id: "222222222222"
    region: eu-west-1
    sso_session: fernhill
    sso_region: eu-west-1
    sso_role_name: OrgshiftOrgRead
  control_tower:
    home_region: eu-west-1
  identity_center:
    region: eu-west-1
  workload_regions: [eu-west-1]

collection:
  concurrency: 4        # parallel per-item calls (tags, regions, shares, permission sets)
  retry_attempts: 8     # SDK attempts per call, adaptive mode; the collector retries throttling on top
  timeout: 10m
  checkpoint: true      # write <out>.checkpoint.json after every completed step and resume from it

# Reads that AWS bills. Off by default; refused until implemented (ROADMAP.md).
billable:
  cloudtrail_lake: false
  config_queries: false

# Inputs for "orgshift iam-templates".
templates:
  role_prefix: Orgshift
  # Who may assume the management-account roles: the operator role or user
  # that runs orgshift.
  trusted_principal_arns:
    - arn:aws:iam::111111111111:role/PlatformOperators
  # external_id: choose-a-random-string
`
