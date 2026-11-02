// Package iamtemplates generates the IAM roles the collector needs, one per
// collector responsibility, from the operation catalog and the onboarding
// configuration: a trust policy, a permissions policy whose every Resource
// "*" carries a justification, a note on which account the role goes in,
// and the delegated-administrator alternative where AWS offers one. The
// generated files live under docs/iam and `orgshift iam-templates` rewrites
// them for a real configuration.
package iamtemplates

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/MrShaaba/orgshift/internal/collector"
	"github.com/MrShaaba/orgshift/internal/config"
)

// Placeholders used when no configuration is given.
const (
	PlaceholderManagementAccount = "<management-account-id>"
	PlaceholderOperatorARN       = "<operator-principal-arn>"
	PlaceholderNetworkAccount    = "<network-account-id>"
	PlaceholderDelegatedAccount  = "<delegated-administrator-account-id>"
)

// Statement is one statement of a permissions policy, with the reason its
// resource is what it is.
type Statement struct {
	Sid     string   `json:"sid"`
	Actions []string `json:"actions"`
	// Resource is "*" or one or more ARN patterns.
	Resource  []string       `json:"resource"`
	Condition map[string]any `json:"condition,omitempty"`
	// Justification is required when Resource contains "*": why the action
	// cannot or should not be narrowed, and what it can and cannot do.
	Justification string `json:"justification"`
}

// Template is one role.
type Template struct {
	ID       collector.Responsibility `json:"id"`
	RoleName string                   `json:"role_name"`
	Title    string                   `json:"title"`
	// Account says which account the role goes in and why.
	Account string `json:"account"`
	Purpose string `json:"purpose"`
	// Statements are rendered into PermissionsPolicy. Empty when this build
	// needs nothing in the account beyond assuming the role.
	Statements        []Statement     `json:"statements"`
	TrustPolicy       json.RawMessage `json:"trust_policy"`
	PermissionsPolicy json.RawMessage `json:"permissions_policy,omitempty"`
	// DelegatedAdministrator describes the alternative to the management
	// account, or why there is none.
	DelegatedAdministrator string `json:"delegated_administrator"`
	// DelegationPolicy is an example resource-based delegation policy for
	// the org-management role.
	DelegationPolicy json.RawMessage `json:"delegation_policy,omitempty"`
	// Planned lists the operations later milestones add to this role; they
	// are not in the permissions policy.
	Planned    []collector.Operation `json:"planned"`
	Notes      []string              `json:"notes,omitempty"`
	References []string              `json:"references"`
	// Commands create the role with the AWS CLI, for the operator to run.
	Commands []string `json:"commands"`
}

// Input selects the configuration side the templates are for.
type Input struct {
	// Config may be nil: placeholders are used instead of account IDs.
	Config *config.Config
	// Side is "source" (default) or "destination".
	Side string
}

// context is everything the generator takes from the configuration.
type context struct {
	mgmt        string
	operators   []string
	externalID  string
	prefix      string
	memberRole  string
	memberExtID string
	networks    []string // account IDs
	placeholder bool
	sideName    string
	orgName     string
}

func (in Input) context() (context, error) {
	c := context{prefix: config.DefaultRolePrefix, mgmt: PlaceholderManagementAccount, operators: []string{PlaceholderOperatorARN}, networks: []string{PlaceholderNetworkAccount}, placeholder: true, sideName: "source"}
	c.memberRole = c.prefix + "MemberRead"
	if in.Config == nil {
		return c, nil
	}
	name := in.Side
	if name == "" {
		name = "source"
	}
	side, err := in.Config.Side(name)
	if err != nil {
		return c, err
	}
	c.placeholder = false
	c.sideName = name
	c.orgName = side.Name
	c.mgmt = side.Management.AccountID
	c.prefix = in.Config.Templates.RolePrefix
	c.externalID = in.Config.Templates.ExternalID
	c.operators = in.Config.Templates.TrustedPrincipalARNs
	if len(c.operators) == 0 {
		c.operators = []string{PlaceholderOperatorARN}
	}
	c.memberRole = c.prefix + "MemberRead"
	if side.MemberInspection != nil {
		c.memberRole = side.MemberInspection.RoleName
		c.memberExtID = side.MemberInspection.ExternalID
	}
	c.networks = nil
	for _, n := range side.Network {
		c.networks = append(c.networks, n.AccountID)
	}
	if len(c.networks) == 0 {
		c.networks = []string{PlaceholderNetworkAccount}
	}
	return c, nil
}

func (c context) orgRole() string { return "arn:aws:iam::" + c.mgmt + ":role/" + c.prefix + "OrgRead" }

// References.
const (
	refSAROrganizations  = "https://docs.aws.amazon.com/service-authorization/latest/reference/list_awsorganizations.html"
	refSARAccount        = "https://docs.aws.amazon.com/service-authorization/latest/reference/list_awsaccountmanagement.html"
	refSARRAM            = "https://docs.aws.amazon.com/service-authorization/latest/reference/list_awsresourceaccessmanager.html"
	refSARControlTower   = "https://docs.aws.amazon.com/service-authorization/latest/reference/list_awscontroltower.html"
	refSARControlCatalog = "https://docs.aws.amazon.com/service-authorization/latest/reference/list_awscontrolcatalog.html"
	refSARSSO            = "https://docs.aws.amazon.com/service-authorization/latest/reference/list_awsiamidentitycentersuccessortoawssinglesign-on.html"
	refSARIdentityStore  = "https://docs.aws.amazon.com/service-authorization/latest/reference/list_awsidentitystore.html"
	refSARSTS            = "https://docs.aws.amazon.com/service-authorization/latest/reference/list_awssecuritytokenservice.html"
	refOrgDelegation     = "https://docs.aws.amazon.com/organizations/latest/userguide/orgs_delegate_policies.html"
	refOrgDelegationEx   = "https://docs.aws.amazon.com/organizations/latest/userguide/security_iam_resource-based-policy-examples.html"
	refAccountTrusted    = "https://docs.aws.amazon.com/accounts/latest/reference/using-orgs-trusted-access.html"
	refRAMSharing        = "https://docs.aws.amazon.com/ram/latest/userguide/getting-started-sharing.html"
	refCTAPI             = "https://docs.aws.amazon.com/controltower/latest/APIReference/Welcome.html"
	refIdCDelegated      = "https://docs.aws.amazon.com/singlesignon/latest/userguide/delegated-admin.html"
	refIAMConditionOrg   = "https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-keys.html#condition-keys-resourceorgid"
)

// Generate builds the five templates.
func Generate(in Input) ([]Template, error) {
	c, err := in.context()
	if err != nil {
		return nil, err
	}
	var out []Template
	for _, r := range collector.Responsibilities {
		t, err := c.template(r)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, nil
}

func (c context) template(r collector.Responsibility) (Template, error) {
	var t Template
	switch r {
	case collector.RoleOrgManagement:
		t = c.orgManagement()
	case collector.RoleControlTower:
		t = c.controlTower()
	case collector.RoleIdentityCenter:
		t = c.identityCenter()
	case collector.RoleMemberInspection:
		t = c.memberInspection()
	case collector.RoleNetwork:
		t = c.network()
	default:
		return t, fmt.Errorf("no template for %s", r)
	}
	t.ID = r
	t.Planned = collector.OperationsFor(r, true)
	if err := c.render(&t); err != nil {
		return t, err
	}
	if err := checkJustifications(t); err != nil {
		return t, err
	}
	return t, nil
}

// actions returns the used actions of a service for a responsibility.
func actions(r collector.Responsibility, service string) []string {
	var out []string
	for _, o := range collector.OperationsFor(r, false) {
		if o.Service == service && o.Kind != collector.KindSession {
			out = append(out, o.Action())
		}
	}
	sort.Strings(out)
	return out
}

func (c context) orgManagement() Template {
	roleName := c.prefix + "OrgRead"
	member := "arn:aws:iam::*:role/" + c.memberRole
	assumable := []string{member}
	for _, n := range c.networks {
		assumable = append(assumable, "arn:aws:iam::"+n+":role/"+c.prefix+"NetworkRead")
	}
	t := Template{
		RoleName: roleName,
		Title:    "Organizations, account regions and the management account's shares",
		Account:  fmt.Sprintf("The management account (%s). Organizations answers these calls only from the management account or a delegated administrator; see the alternative below.", c.mgmt),
		Purpose:  "Reads the organization, the OU tree, every policy type with its attachments, account tags, delegated administrators, trusted access, the enabled regions of every member account and the RAM shares the management account owns; assumes the member inspection and network roles.",
		Statements: []Statement{
			{Sid: "OrganizationsRead", Actions: actions(collector.RoleOrgManagement, "organizations"), Resource: []string{"*"},
				Justification: "DescribeOrganization, ListRoots, ListPolicies, ListDelegatedAdministrators and ListAWSServiceAccessForOrganization take no resource. The others accept root, OU, account and policy ARNs, but the collector walks the whole tree and every policy, so a resource list would have to name every OU and policy and change whenever one is added. All eleven return existing state and cannot change it."},
			{Sid: "AccountRegionsRead", Actions: actions(collector.RoleOrgManagement, "account"), Resource: []string{"*"},
				Justification: "ListRegions is called for every member account; the action supports the account resource (arn:aws:account::" + c.mgmt + ":account/o-<organization-id>/<member-id>), so replace * with arn:aws:account::" + c.mgmt + ":account/o-*/* if you prefer a pattern. Calling it for other accounts also requires trusted access for account.amazonaws.com in the organization."},
			{Sid: "OwnResourceSharesRead", Actions: actions(collector.RoleOrgManagement, "ram"), Resource: []string{"*"},
				Justification: "GetResourceShares with resourceOwner SELF takes no resource and lists only the shares this account owns; ListPrincipals and ListResources accept resource share ARNs, which are only known once GetResourceShares has answered. Nothing here can create, modify or accept a share."},
			{Sid: "AssumeCollectorRoles", Actions: []string{"sts:AssumeRole"}, Resource: assumable,
				Condition:     map[string]any{"StringEquals": map[string]any{"aws:ResourceOrgID": "${aws:PrincipalOrgID}"}},
				Justification: "Scoped to the member inspection role name in any account of the same organization (aws:ResourceOrgID must equal the caller's organization) and to the network roles. The role in the target account still has to trust this one."},
		},
		DelegatedAdministrator: "Organizations can delegate its read and policy operations to a member account with a resource-based delegation policy attached from the management account (aws organizations put-resource-policy). The example delegation policy below grants the tree and policy reads to " + c.prefix + "OrgRead in a delegated account (" + PlaceholderDelegatedAccount + "). Three things stay with the management account: ListDelegatedAdministrators, ListDelegatedServicesForAccount and ListAWSServiceAccessForOrganization are not documented as delegable (preflight reports them denied if so, and the collector records delegated_administrators and trusted_access as access_denied); account:ListRegions for other accounts needs the Account Management delegated administrator (account.amazonaws.com); and the management account's own RAM shares are listed only from the management account.",
		Notes: []string{
			"sts:GetCallerIdentity is called first to check that the credentials belong to account " + c.mgmt + "; it needs no permission.",
			"The AWS managed policies ReadOnlyAccess and AWSOrganizationsReadOnlyAccess also cover these calls but are far broader.",
		},
		References: []string{refSAROrganizations, refSARAccount, refSARRAM, refSARSTS, refOrgDelegation, refOrgDelegationEx, refAccountTrusted, refIAMConditionOrg},
	}
	delegation := policy{Version: "2012-10-17", Statement: []policyStatement{{
		Sid: "OrgshiftReadFromDelegatedAccount", Effect: "Allow",
		Principal: map[string]any{"AWS": "arn:aws:iam::" + PlaceholderDelegatedAccount + ":role/" + roleName},
		Action: []string{"organizations:DescribeOrganization", "organizations:ListRoots", "organizations:ListOrganizationalUnitsForParent", "organizations:ListAccountsForParent",
			"organizations:ListPolicies", "organizations:DescribePolicy", "organizations:ListTargetsForPolicy", "organizations:ListTagsForResource"},
		Resource: "*",
	}}}
	t.DelegationPolicy = mustJSON(delegation)
	t.TrustPolicy = c.operatorTrust()
	return t
}

func (c context) controlTower() Template {
	return Template{
		RoleName: c.prefix + "ControlTowerRead",
		Title:    "Control Tower landing zone, baselines and controls",
		Account:  fmt.Sprintf("The management account (%s), called in the landing zone's home region. AWS Control Tower has no delegated administrator for its APIs.", c.mgmt),
		Purpose:  "Reads the landing zone (version, drift, auto-enrollment, governed regions), the registered OUs and enrolled accounts from the enabled baselines, the controls enabled on each registered OU and their names and behaviours from the Control Catalog.",
		Statements: []Statement{
			{Sid: "ControlTowerRead", Actions: actions(collector.RoleControlTower, "controltower"), Resource: []string{"*"},
				Justification: "ListLandingZones, ListEnabledBaselines and ListEnabledControls take no resource. GetLandingZone accepts the landing zone ARN, which is only known after ListLandingZones answers, and an organization has one landing zone. None of the four can enable, disable or reset anything."},
			{Sid: "ControlCatalogRead", Actions: actions(collector.RoleControlTower, "controlcatalog"), Resource: []string{"*"},
				Justification: "GetControl accepts control ARNs (arn:aws:controlcatalog:::control/*), which are discovered from the enabled controls at collection time. The catalog is AWS reference data, identical for every account; the call only names and classifies controls."},
		},
		DelegatedAdministrator: "None. The landing zone, baseline and control operations are called from the management account; create this role there. Without it the collector records control_tower and control_tower.enrolled_accounts as access_denied and the Control Tower check reads REVIEW.",
		Notes: []string{
			"Set control_tower.home_region in the configuration: the APIs answer only there, and an empty answer elsewhere is recorded as an error when trusted access shows Control Tower is in use.",
		},
		References:  []string{refSARControlTower, refSARControlCatalog, refCTAPI},
		TrustPolicy: c.operatorTrust(),
	}
}

func (c context) identityCenter() Template {
	return Template{
		RoleName: c.prefix + "IdentityCenterRead",
		Title:    "IAM Identity Center instance, permission sets and assignments",
		Account:  fmt.Sprintf("The management account (%s), called in the instance's region, or the Identity Center delegated administrator account (see below).", c.mgmt),
		Purpose:  "Reads the instance and its identity store ID, every permission set with its managed, customer managed and inline policies and boundary, the accounts each is provisioned in, the assignments on those accounts, and the user and group names behind the assignment principals.",
		Statements: []Statement{
			{Sid: "IdentityCenterRead", Actions: actions(collector.RoleIdentityCenter, "sso"), Resource: []string{"*"},
				Justification: "ListInstances takes no resource. The eight others are scoped to the instance (arn:aws:sso:::instance/ssoins-*) and its permission sets (arn:aws:sso:::permissionSet/ssoins-*/ps-*); the instance ID is only known after ListInstances answers. Once you know it, replace * with those two patterns. None of the nine can create, provision or assign anything."},
			{Sid: "IdentityStoreNames", Actions: actions(collector.RoleIdentityCenter, "identitystore"), Resource: []string{"*"},
				Justification: "DescribeUser and DescribeGroup are scoped to the identity store (arn:aws:identitystore::<account>:identitystore/d-*) and its users and groups (arn:aws:identitystore:::user/* and group/*); the store ID comes from ListInstances. They only turn principal IDs into names; drop this statement to keep assignments by ID."},
		},
		DelegatedAdministrator: "Register a member account as the IAM Identity Center delegated administrator (service principal sso.amazonaws.com), create this role there and point identity_center.access in the configuration at it (from: management, assume_role). The delegated administrator cannot alter permission sets provisioned in the management account, and AWS does not document that it can read them; if they are missing or denied the identity_center coverage record says so and the Identity Center check reads REVIEW for moves that touch them.",
		Notes: []string{
			"Set identity_center.region in the configuration: the instance APIs answer only there.",
		},
		References:  []string{refSARSSO, refSARIdentityStore, refIdCDelegated},
		TrustPolicy: c.operatorTrust(),
	}
}

func (c context) memberInspection() Template {
	t := Template{
		RoleName:               c.memberRole,
		Title:                  "Member account inspection",
		Account:                "Every member account (deploy it with a StackSet or your account baseline). It trusts " + c.orgRole() + ".",
		Purpose:                "Reads what only the account itself can see: IAM last-accessed data for actions in use, networking state for path reasoning, the shares the account receives. This build calls nothing in member accounts; preflight assumes the role to prove the trust works, and sts:GetCallerIdentity needs no permission, so no permissions policy is attached yet. The planned operations below are what M4 adds.",
		DelegatedAdministrator: "Not applicable: the role lives in each member account. Accounts created by Organizations carry OrganizationAccountAccessRole and Control Tower accounts carry AWSControlTowerExecution, both full administrators; orgshift does not use them so its read-only scope stays explicit and auditable.",
		Notes: []string{
			"Name the role in member_inspection.role_name; preflight assumes it in the configured accounts plus a sample.",
		},
		References: []string{refSARSTS},
	}
	t.TrustPolicy = c.collectorTrust(c.memberExtID)
	return t
}

func (c context) network() Template {
	t := Template{
		RoleName: c.prefix + "NetworkRead",
		Title:    "Shares owned by a network account",
		Account:  fmt.Sprintf("Each account that owns shared networking (%s). RAM lists only the caller's own shares, so the transit gateways, subnets, Resolver rules and prefix lists shared from a network account are invisible from the management account. It trusts %s.", strings.Join(c.networks, ", "), c.orgRole()),
		Purpose:  "Lists the resource shares the network account owns, with their principals, resources and the retain-on-leave setting.",
		Statements: []Statement{
			{Sid: "OwnResourceSharesRead", Actions: actions(collector.RoleNetwork, "ram"), Resource: []string{"*"},
				Justification: "GetResourceShares with resourceOwner SELF takes no resource and lists only the shares this account owns; ListPrincipals and ListResources accept resource share ARNs, which are only known once GetResourceShares has answered. Nothing here can create, modify or accept a share."},
		},
		DelegatedAdministrator: "Not applicable: RAM has no organization-wide view of shares owned by other accounts, so each owning account needs its own role (or a profile with equivalent read access, named under network in the configuration).",
		References:             []string{refSARRAM, refRAMSharing},
	}
	t.TrustPolicy = c.collectorTrust("")
	return t
}

// policy is the IAM JSON shape.
type policy struct {
	Version   string            `json:"Version"`
	Statement []policyStatement `json:"Statement"`
}

type policyStatement struct {
	Sid       string         `json:"Sid,omitempty"`
	Effect    string         `json:"Effect"`
	Principal map[string]any `json:"Principal,omitempty"`
	Action    any            `json:"Action"`
	Resource  any            `json:"Resource,omitempty"`
	Condition map[string]any `json:"Condition,omitempty"`
}

// operatorTrust trusts the operator principals that run orgshift.
func (c context) operatorTrust() json.RawMessage {
	st := policyStatement{Sid: "OrgshiftOperator", Effect: "Allow", Principal: map[string]any{"AWS": c.operators}, Action: "sts:AssumeRole"}
	if c.externalID != "" {
		st.Condition = map[string]any{"StringEquals": map[string]any{"sts:ExternalId": c.externalID}}
	}
	return mustJSON(policy{Version: "2012-10-17", Statement: []policyStatement{st}})
}

// collectorTrust trusts the org-management role.
func (c context) collectorTrust(externalID string) json.RawMessage {
	st := policyStatement{Sid: "OrgshiftCollector", Effect: "Allow", Principal: map[string]any{"AWS": c.orgRole()}, Action: "sts:AssumeRole"}
	if externalID != "" {
		st.Condition = map[string]any{"StringEquals": map[string]any{"sts:ExternalId": externalID}}
	}
	return mustJSON(policy{Version: "2012-10-17", Statement: []policyStatement{st}})
}

// render fills the permissions policy and the commands.
func (c context) render(t *Template) error {
	if len(t.Statements) > 0 {
		p := policy{Version: "2012-10-17"}
		for _, s := range t.Statements {
			var res any = s.Resource
			if len(s.Resource) == 1 {
				res = s.Resource[0]
			}
			p.Statement = append(p.Statement, policyStatement{Sid: s.Sid, Effect: "Allow", Action: s.Actions, Resource: res, Condition: s.Condition})
		}
		t.PermissionsPolicy = mustJSON(p)
	}
	id := string(t.ID)
	t.Commands = []string{fmt.Sprintf("aws iam create-role --role-name %s --assume-role-policy-document file://%s-trust.json --description \"orgshift read-only collector: %s\" --max-session-duration 3600", t.RoleName, id, t.Title)}
	if t.PermissionsPolicy != nil {
		t.Commands = append(t.Commands, fmt.Sprintf("aws iam put-role-policy --role-name %s --policy-name %s --policy-document file://%s-permissions.json", t.RoleName, t.RoleName, id))
	}
	return nil
}

// checkJustifications refuses a statement with Resource "*" and no reason.
func checkJustifications(t Template) error {
	for _, s := range t.Statements {
		for _, r := range s.Resource {
			if r == "*" && strings.TrimSpace(s.Justification) == "" {
				return fmt.Errorf("%s/%s grants Resource \"*\" without a justification", t.RoleName, s.Sid)
			}
		}
		if len(s.Actions) == 0 {
			return fmt.Errorf("%s/%s has no actions", t.RoleName, s.Sid)
		}
	}
	return nil
}

func mustJSON(v any) json.RawMessage {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		panic(err)
	}
	return b.Bytes()
}

// Files renders the templates as files: a README and, per template, the
// trust policy, the permissions policy (when there is one) and the
// delegation policy example. The map is keyed by file name.
func Files(ts []Template, in Input) map[string][]byte {
	out := map[string][]byte{"README.md": []byte(Markdown(ts, in))}
	for _, t := range ts {
		id := string(t.ID)
		out[id+"-trust.json"] = t.TrustPolicy
		if t.PermissionsPolicy != nil {
			out[id+"-permissions.json"] = t.PermissionsPolicy
		}
		if t.DelegationPolicy != nil {
			out[id+"-delegation-policy.json"] = t.DelegationPolicy
		}
	}
	return out
}

// Write writes Files into dir and returns the paths written, sorted.
func Write(dir string, ts []Template, in Input) ([]string, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	files := Files(ts, in)
	var paths []string
	for name, data := range files {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, data, 0o644); err != nil {
			return nil, err
		}
		paths = append(paths, p)
	}
	sort.Strings(paths)
	return paths, nil
}

// Markdown renders the templates as one document.
func Markdown(ts []Template, in Input) string {
	c, _ := in.context()
	var b strings.Builder
	b.WriteString("# IAM templates for the orgshift collector\n\n")
	if c.placeholder {
		b.WriteString("Generated by `orgshift iam-templates` without a configuration: account IDs and the operator principal are placeholders in angle brackets. Run `orgshift iam-templates --config orgshift.yaml --out docs/iam` to fill them in from your configuration.\n\n")
	} else {
		fmt.Fprintf(&b, "Generated by `orgshift iam-templates` for the %s organization (%s, management account %s).\n\n", c.sideName, c.orgName, c.mgmt)
	}
	b.WriteString("One role per collector responsibility. Every role is read-only: its actions come from the operation catalog in `internal/collector/operations.go`, where each is classified by what it does (read, read that AWS bills, session), and a test refuses any write and any billable read without an opt-in. Every statement whose Resource is `*` says why it cannot be narrower. The operator who runs orgshift assumes the management-account roles; the org-management role assumes the member and network roles.\n\n")
	b.WriteString("Order of work: create the roles, run `orgshift preflight --config orgshift.yaml` to see which calls are available, denied or unknown per domain, grant what is missing, then `orgshift collect`.\n\n")
	b.WriteString("| Responsibility | Role | Account | Permissions file |\n|---|---|---|---|\n")
	for _, t := range ts {
		perm := "none needed in this build"
		if t.PermissionsPolicy != nil {
			perm = fmt.Sprintf("`%s-permissions.json`", t.ID)
		}
		fmt.Fprintf(&b, "| `%s` | `%s` | %s | %s |\n", t.ID, t.RoleName, firstSentence(t.Account), perm)
	}
	b.WriteString("\n")
	for _, t := range ts {
		fmt.Fprintf(&b, "## %s: %s\n\n", t.ID, t.Title)
		fmt.Fprintf(&b, "**Role name:** `%s`\n\n**Where it goes:** %s\n\n**What it reads:** %s\n\n", t.RoleName, t.Account, t.Purpose)
		fmt.Fprintf(&b, "**Trust policy** (`%s-trust.json`):\n\n```json\n%s```\n\n", t.ID, t.TrustPolicy)
		if t.PermissionsPolicy != nil {
			fmt.Fprintf(&b, "**Permissions policy** (`%s-permissions.json`):\n\n```json\n%s```\n\n", t.ID, t.PermissionsPolicy)
			b.WriteString("**Why each statement is scoped the way it is:**\n\n")
			for _, s := range t.Statements {
				fmt.Fprintf(&b, "- `%s` (%s): %s\n", s.Sid, strings.Join(s.Resource, ", "), s.Justification)
			}
			b.WriteString("\n")
		} else {
			b.WriteString("**Permissions policy:** none in this build. The role only has to exist and trust the collector; `sts:GetCallerIdentity` needs no permission.\n\n")
		}
		fmt.Fprintf(&b, "**Delegated administrator alternative:** %s\n\n", t.DelegatedAdministrator)
		if t.DelegationPolicy != nil {
			fmt.Fprintf(&b, "Example delegation policy (`%s-delegation-policy.json`), attached from the management account with `aws organizations put-resource-policy --content file://%s-delegation-policy.json`:\n\n```json\n%s```\n\n", t.ID, t.ID, t.DelegationPolicy)
		}
		if len(t.Planned) > 0 {
			b.WriteString("**Planned for later milestones** (not in the permissions policy; listed so the role's eventual scope is known):\n\n| Action | Kind | Fills | Opt-in | Purpose |\n|---|---|---|---|---|\n")
			for _, o := range t.Planned {
				optIn := ""
				if o.OptIn != "" {
					optIn = "`" + o.OptIn + "`"
				}
				fmt.Fprintf(&b, "| `%s` | %s | `%s` | %s | %s |\n", o.Action(), o.Kind, o.Domain, optIn, o.Purpose)
			}
			b.WriteString("\n")
		}
		if len(t.Notes) > 0 {
			b.WriteString("**Notes:**\n\n")
			for _, n := range t.Notes {
				fmt.Fprintf(&b, "- %s\n", n)
			}
			b.WriteString("\n")
		}
		b.WriteString("**Create it:**\n\n```sh\n")
		for _, cmd := range t.Commands {
			b.WriteString(cmd + "\n")
		}
		b.WriteString("```\n\n")
		b.WriteString("**References:** " + strings.Join(t.References, ", ") + "\n\n")
	}
	return b.String()
}

func firstSentence(s string) string {
	if i := strings.Index(s, ". "); i >= 0 {
		return s[:i+1]
	}
	return s
}
