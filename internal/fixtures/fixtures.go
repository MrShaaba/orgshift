// Package fixtures generates two fictional AWS organizations, Larkspur
// Holdings and Fernhill Group, with realistic problems planted in them so the
// evaluator and the UI can be exercised without touching a real account.
//
// Everything here is invented. Account IDs use the 111111111111 and
// 222222222222 ranges, organization and OU identifiers are made up, and
// resource identifiers come from a seeded random source so the output is
// stable from run to run.
package fixtures

import (
	"encoding/json"
	"fmt"
	"math/rand"

	"github.com/MrShaaba/orgshift/internal/snapshot"
)

// Seed is the fixed seed for the identifier generator.
const Seed = 20260101

// Names of the fixture organizations as used by the CLI and the UI.
// LarkspurPartialName is the same organization as Larkspur, collected with
// credentials that could not read everything: it shows how incomplete
// coverage turns into REVIEW findings instead of a quiet GO.
const (
	LarkspurName        = "Larkspur Holdings"
	FernhillName        = "Fernhill Group"
	LarkspurPartialName = "Larkspur Holdings (partial collection)"
)

// fixtureCollectedAt is the timestamp written into every fixture record.
const fixtureCollectedAt = "2026-01-01T00:00:00Z"

// fixtureJoinedAt is when the fixture accounts joined their organizations:
// long enough ago that the four-day rule for created accounts is satisfied.
const fixtureJoinedAt = "2023-03-15T09:00:00Z"

// Identifiers of the account most of the planted problems are about, of the
// OUs used by the whole-OU move scenario, and of the Control Tower scenario
// inside Fernhill (an enrolled, Account Factory vended account leaving its
// registered OU for an unregistered one).
const (
	LarkspurPaymentsProd    = "111111111115"
	FernhillPaymentsOU      = "ou-fern-pay1"
	LarkspurWorkloadsOU     = "ou-lark-work"
	FernhillBusinessUnitsOU = "ou-fern-bu"
	FernhillRetailProd      = "222222222225"
	FernhillRetailOU        = "ou-fern-ret"
	FernhillSandboxOU       = "ou-fern-sand"
	FernhillAuditAccount    = "222222222223"
)

// Identifiers of the Identity Center scenario: the Larkspur instance whose
// assignments on the payments account disappear in a cross-organization
// move, and the permission set that has no counterpart in Fernhill.
const (
	LarkspurIdentityCenterInstance = "arn:aws:sso:::instance/ssoins-larkspur00000001"
	LarkspurPaymentsEngineerSet    = "PaymentsEngineer"
	FernhillIdentityCenterInstance = "arn:aws:sso:::instance/ssoins-fernhill00000001"
)

type gen struct {
	r *rand.Rand
}

func newGen() *gen { return &gen{r: rand.New(rand.NewSource(Seed))} }

func (g *gen) hex(n int) string {
	const digits = "0123456789abcdef"
	b := make([]byte, n)
	for i := range b {
		b[i] = digits[g.r.Intn(len(digits))]
	}
	return string(b)
}

func (g *gen) id(prefix string) string { return prefix + "-0" + g.hex(16) }

// uuid draws an identity store style identifier.
func (g *gen) uuid() string {
	return g.hex(8) + "-" + g.hex(4) + "-" + g.hex(4) + "-" + g.hex(4) + "-" + g.hex(12)
}

func doc(s string) json.RawMessage {
	var buf json.RawMessage
	if err := json.Unmarshal([]byte(s), &buf); err != nil {
		panic(fmt.Sprintf("fixture policy is not valid JSON: %v\n%s", err, s))
	}
	return buf
}

func orgArn(mgmt, org string) string {
	return "arn:aws:organizations::" + mgmt + ":organization/" + org
}
func ouArn(mgmt, org, ou string) string {
	return "arn:aws:organizations::" + mgmt + ":ou/" + org + "/" + ou
}

const fullAccess = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`
const rcpFullAccess = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"*","Resource":"*"}]}`

// All returns the fixture organizations keyed by their friendly name.
func All() map[string]*snapshot.Snapshot {
	return map[string]*snapshot.Snapshot{LarkspurName: Larkspur(), FernhillName: Fernhill(), LarkspurPartialName: LarkspurPartial()}
}

// LarkspurPartial is Larkspur Holdings as a collector with narrower
// permissions would have recorded it: the RAM calls were denied, the
// Control Tower lookup ran in the wrong region, the Identity Center step was
// skipped, and the organization trail, Config aggregator and StackSet
// domains were not collected. The lists are empty where the collector
// could not look, and the coverage block says so.
func LarkspurPartial() *snapshot.Snapshot {
	s := Larkspur()
	s.Organization.Name = LarkspurPartialName
	s.ResourceShares = []snapshot.ResourceShare{}
	s.OrganizationTrails = []snapshot.OrganizationTrail{}
	s.ConfigAggregators = []snapshot.ConfigAggregator{}
	s.StackSets = []snapshot.StackSet{}
	s.IdentityCenter = nil
	s.Coverage = completeCoverage(s, "us-east-1")
	replace := func(domain string, rec snapshot.DomainCoverage) {
		var kept []snapshot.DomainCoverage
		for _, d := range s.Coverage.Domains {
			if d.Domain != domain {
				kept = append(kept, d)
			}
		}
		rec.Domain, rec.CollectedAt = domain, fixtureCollectedAt
		s.Coverage.Domains = append(kept, rec)
	}
	replace(snapshot.DomainResourceShares, snapshot.DomainCoverage{Status: snapshot.CoverageAccessDenied, AccountID: "111111111111", Region: "us-east-1",
		Operations: []string{"ram:GetResourceShares"}, Error: "AccessDeniedException: User: arn:aws:sts::111111111111:assumed-role/OrgshiftReadOnly/collect is not authorized to perform: ram:GetResourceShares"})
	replace(snapshot.DomainControlTower, snapshot.DomainCoverage{Status: snapshot.CoverageError, Region: "us-east-1",
		Operations: []string{"controltower:ListLandingZones"}, Error: "no landing zone answered in us-east-1 although trusted access for controltower.amazonaws.com is enabled; the landing zone APIs answer only in the home region, re-run with --region <home region>"})
	replace(snapshot.DomainEnrolledAccounts, snapshot.DomainCoverage{Status: snapshot.CoverageError, Region: "us-east-1",
		Operations: []string{"controltower:ListEnabledBaselines"}, Error: "not read: the landing zone was not found in us-east-1"})
	replace(snapshot.DomainIdentityCenter, snapshot.DomainCoverage{Status: snapshot.CoverageSkipped, Region: "us-east-1", Reason: "--skip-identity-center"})
	for _, d := range []string{snapshot.DomainOrgTrails, snapshot.DomainConfigAggregator, snapshot.DomainStackSets} {
		replace(d, snapshot.DomainCoverage{Status: snapshot.CoverageUnsupported, Reason: "not collected by this collector version; add by hand (docs/snapshot.md)"})
	}
	// Trusted access shows Control Tower is in use, which is what makes the
	// empty landing zone lookup suspicious.
	s.TrustedAccessServices = append(s.TrustedAccessServices, "controltower.amazonaws.com")
	return s
}

// completeCoverage records every domain as observed or empty, as a
// collector with full permissions in the right region would.
func completeCoverage(s *snapshot.Snapshot, region string) *snapshot.Coverage {
	at := fixtureCollectedAt
	rec := func(domain string, items int, ops ...string) snapshot.DomainCoverage {
		d := snapshot.DomainCoverage{Domain: domain, Status: snapshot.CoverageObserved, Items: items, Pages: 1, CollectedAt: at, Operations: ops}
		if items == 0 {
			d.Status = snapshot.CoverageEmpty
		}
		return d
	}
	cov := &snapshot.Coverage{CollectorVersion: "fixture"}
	cov.Domains = append(cov.Domains,
		rec(snapshot.DomainOrganization, 1, "organizations:DescribeOrganization"),
		rec(snapshot.DomainTree, len(s.OUs)+len(s.Accounts)+1, "organizations:ListRoots", "organizations:ListOrganizationalUnitsForParent", "organizations:ListAccountsForParent"),
		rec(snapshot.DomainAccountTags, len(s.Accounts), "organizations:ListTagsForResource"),
		rec(snapshot.DomainEnabledRegions, len(s.Accounts), "account:ListRegions"),
	)
	for _, t := range snapshot.AllPolicyTypes {
		if !s.PolicyTypeEnabled(t) {
			cov.Domains = append(cov.Domains, snapshot.DomainCoverage{Domain: snapshot.PolicyDomain(t), Status: snapshot.CoverageEmpty, CollectedAt: at, Reason: "policy type not enabled at the root"})
			continue
		}
		n := 0
		for _, p := range s.Policies {
			if p.Type == t {
				n++
			}
		}
		cov.Domains = append(cov.Domains, rec(snapshot.PolicyDomain(t), n, "organizations:ListPolicies", "organizations:DescribePolicy", "organizations:ListTargetsForPolicy"))
	}
	cov.Domains = append(cov.Domains,
		rec(snapshot.DomainDelegatedAdmins, len(s.DelegatedAdministrators), "organizations:ListDelegatedAdministrators", "organizations:ListDelegatedServicesForAccount"),
		rec(snapshot.DomainTrustedAccess, len(s.TrustedAccessServices), "organizations:ListAWSServiceAccessForOrganization"),
	)
	owners := map[string]int{}
	var ownerOrder []string
	for _, sh := range s.ResourceShares {
		if _, ok := owners[sh.OwnerAccountID]; !ok {
			ownerOrder = append(ownerOrder, sh.OwnerAccountID)
		}
		owners[sh.OwnerAccountID]++
	}
	if len(ownerOrder) == 0 {
		ownerOrder = append(ownerOrder, s.Organization.ManagementAccountID)
	}
	for _, o := range ownerOrder {
		d := rec(snapshot.DomainResourceShares, owners[o], "ram:GetResourceShares", "ram:ListPrincipals", "ram:ListResources")
		d.AccountID, d.Region = o, region
		cov.Domains = append(cov.Domains, d)
	}
	cov.Domains = append(cov.Domains,
		rec(snapshot.DomainOrgTrails, len(s.OrganizationTrails), "cloudtrail:DescribeTrails"),
		rec(snapshot.DomainConfigAggregator, len(s.ConfigAggregators), "config:DescribeConfigurationAggregators"),
		rec(snapshot.DomainStackSets, len(s.StackSets), "cloudformation:ListStackSets", "cloudformation:DescribeStackSet"),
	)
	ct := snapshot.DomainCoverage{Domain: snapshot.DomainControlTower, Status: snapshot.CoverageEmpty, Region: region, CollectedAt: at, Operations: []string{"controltower:ListLandingZones"}, Reason: "no landing zone in " + region}
	enrolled := snapshot.DomainCoverage{Domain: snapshot.DomainEnrolledAccounts, Status: snapshot.CoverageEmpty, Region: region, CollectedAt: at, Reason: "no landing zone"}
	if s.ControlTower != nil {
		ct = rec(snapshot.DomainControlTower, 1+len(s.ControlTower.RegisteredOUs)+len(s.ControlTower.EnabledControls), "controltower:ListLandingZones", "controltower:GetLandingZone", "controltower:ListEnabledBaselines", "controltower:ListEnabledControls", "controlcatalog:GetControl")
		ct.Region = region
		enrolled = rec(snapshot.DomainEnrolledAccounts, len(s.ControlTower.EnrolledAccounts), "controltower:ListEnabledBaselines")
		enrolled.Region = region
	}
	ic := snapshot.DomainCoverage{Domain: snapshot.DomainIdentityCenter, Status: snapshot.CoverageEmpty, Region: region, CollectedAt: at, Operations: []string{"sso:ListInstances"}, Reason: "no instance in " + region}
	if s.IdentityCenter != nil {
		ic = rec(snapshot.DomainIdentityCenter, 1+len(s.IdentityCenter.PermissionSets)+len(s.IdentityCenter.Assignments), "sso:ListInstances", "sso:ListPermissionSets", "sso:DescribePermissionSet", "sso:ListAccountAssignments")
		ic.Region = region
	}
	cov.Domains = append(cov.Domains, ct, enrolled, ic)
	return cov
}

// Larkspur builds the legacy organization that the payments account is
// moving out of.
func Larkspur() *snapshot.Snapshot {
	g := newGen()
	const (
		org  = "o-larkspur0001"
		mgmt = "111111111111"
		root = "r-lark"
	)
	tgw := "tgw-" + g.hex(17)
	subnetA := "subnet-" + g.hex(17)
	subnetB := "subnet-" + g.hex(17)
	rslv := "rslvr-rr-" + g.hex(17)
	ipam := "ipam-pool-" + g.hex(17)
	pl := "pl-" + g.hex(17)

	allSCPTargets := []string{root, "ou-lark-infra", "ou-lark-sec", "ou-lark-work", "ou-lark-prod", "ou-lark-dev", "ou-lark-sand",
		"111111111111", "111111111112", "111111111113", "111111111114", "111111111115", "111111111116", "111111111117", "111111111118"}

	s := &snapshot.Snapshot{
		SchemaVersion: snapshot.SchemaVersion,
		GeneratedAt:   "2026-01-01T00:00:00Z",
		Source:        "fixture",
		Organization: snapshot.Organization{
			ID: org, ARN: orgArn(mgmt, org), ManagementAccountID: mgmt, FeatureSet: "ALL", Name: LarkspurName,
		},
		Root: snapshot.Root{
			ID: root, ARN: "arn:aws:organizations::" + mgmt + ":root/" + org + "/" + root, Name: "Root",
			EnabledPolicyTypes: []snapshot.PolicyType{snapshot.PolicyTypeSCP, snapshot.PolicyTypeRCP, snapshot.PolicyTypeTag, snapshot.PolicyTypeBackup},
		},
		OUs: []snapshot.OU{
			{ID: "ou-lark-infra", Name: "Infrastructure", ParentID: root},
			{ID: "ou-lark-sec", Name: "Security", ParentID: root},
			{ID: "ou-lark-work", Name: "Workloads", ParentID: root},
			{ID: "ou-lark-prod", Name: "Production", ParentID: "ou-lark-work"},
			{ID: "ou-lark-dev", Name: "Development", ParentID: "ou-lark-work"},
			{ID: "ou-lark-sand", Name: "Sandbox", ParentID: root},
		},
		Accounts: []snapshot.Account{
			acct("111111111111", "larkspur-management", root, "platform", []string{"us-east-1", "eu-west-1", "ap-southeast-1"}),
			acct("111111111112", "larkspur-network", "ou-lark-infra", "platform", []string{"us-east-1", "eu-west-1", "ap-southeast-1"}),
			acct("111111111113", "larkspur-security", "ou-lark-sec", "security", []string{"us-east-1", "eu-west-1", "ap-southeast-1"}),
			acct("111111111114", "larkspur-logging", "ou-lark-sec", "security", []string{"us-east-1", "eu-west-1", "ap-southeast-1"}),
			acct(LarkspurPaymentsProd, "larkspur-payments-prod", "ou-lark-prod", "payments", []string{"us-east-1", "eu-west-1", "ap-southeast-1"}),
			acct("111111111116", "larkspur-payments-dev", "ou-lark-dev", "payments", []string{"us-east-1", "eu-west-1"}),
			acct("111111111117", "larkspur-sandbox-1", "ou-lark-sand", "sandbox", []string{"us-east-1"}),
			acct("111111111118", "larkspur-data-prod", "ou-lark-prod", "data", []string{"us-east-1", "eu-west-1"}),
		},
		Policies: []snapshot.Policy{
			{ID: "p-FullAWSAccess", Name: "FullAWSAccess", Type: snapshot.PolicyTypeSCP, AWSManaged: true,
				Description: "Allows access to every operation", Document: doc(fullAccess), Targets: allSCPTargets},
			{ID: "p-lark0001", Name: "Larkspur-Baseline-Guardrails", Type: snapshot.PolicyTypeSCP,
				Description: "Protects organization-wide logging and membership",
				Document: doc(`{"Version":"2012-10-17","Statement":[
					{"Sid":"DenyLeaveOrganization","Effect":"Deny","Action":["organizations:LeaveOrganization"],"Resource":"*"},
					{"Sid":"ProtectOrgTrail","Effect":"Deny","Action":["cloudtrail:StopLogging","cloudtrail:DeleteTrail","cloudtrail:UpdateTrail"],"Resource":"arn:aws:cloudtrail:*:*:trail/larkspur-org-trail"},
					{"Sid":"DenyRootUser","Effect":"Deny","Action":"*","Resource":"*","Condition":{"StringLike":{"aws:PrincipalArn":"arn:aws:iam::*:root"}}}
				]}`), Targets: []string{root}},
			{ID: "p-lark0002", Name: "Larkspur-Allowed-Regions", Type: snapshot.PolicyTypeSCP,
				Description: "Keeps workloads in the three regions Larkspur operates in",
				Document: doc(`{"Version":"2012-10-17","Statement":[
					{"Sid":"DenyOutsideApprovedRegions","Effect":"Deny",
					 "NotAction":["iam:*","sts:*","organizations:*","support:*","budgets:*","cloudfront:*","route53:*","waf:*","health:*","account:*"],
					 "Resource":"*",
					 "Condition":{"StringNotEquals":{"aws:RequestedRegion":["us-east-1","eu-west-1","ap-southeast-1"]}}}
				]}`), Targets: []string{"ou-lark-work"}},
			{ID: "p-lark0003", Name: "Larkspur-Sandbox-Limits", Type: snapshot.PolicyTypeSCP,
				Description: "Stops sandboxes from running expensive or networked services",
				Document: doc(`{"Version":"2012-10-17","Statement":[
					{"Sid":"NoExpensiveServices","Effect":"Deny","Action":["redshift:*","sagemaker:CreateNotebookInstance","ec2:CreateTransitGateway*","directconnect:*"],"Resource":"*"},
					{"Sid":"NoLargeInstances","Effect":"Deny","Action":"ec2:RunInstances","Resource":"arn:aws:ec2:*:*:instance/*",
					 "Condition":{"StringNotLike":{"ec2:InstanceType":["t3.*","t4g.*"]}}}
				]}`), Targets: []string{"ou-lark-sand"}},
			{ID: "p-lark0006", Name: "Larkspur-Dev-Guardrails", Type: snapshot.PolicyTypeSCP,
				Description: "Development accounts cannot commit to reservations or savings plans",
				Document: doc(`{"Version":"2012-10-17","Statement":[
					{"Sid":"NoCommitments","Effect":"Deny","Action":["ec2:PurchaseReservedInstancesOffering","ec2:ModifyReservedInstances","savingsplans:CreateSavingsPlan","rds:PurchaseReservedDBInstancesOffering"],"Resource":"*"}
				]}`), Targets: []string{"ou-lark-dev"}},
			{ID: "p-RCPFullAWSAccess", Name: "RCPFullAWSAccess", Type: snapshot.PolicyTypeRCP, AWSManaged: true,
				Description: "Allows access to every operation", Document: doc(rcpFullAccess), Targets: allSCPTargets},
			{ID: "p-lark0004", Name: "Larkspur-Tagging-Standard", Type: snapshot.PolicyTypeTag,
				Description: "Owner tag, reporting only",
				Document:    doc(`{"tags":{"owner":{"tag_key":{"@@assign":"owner"}}}}`), Targets: []string{root}},
			{ID: "p-lark0005", Name: "Larkspur-Daily-Backups", Type: snapshot.PolicyTypeBackup,
				Description: "Daily backups for production",
				Document:    doc(`{"plans":{"larkspur-daily":{"regions":{"@@assign":["us-east-1","eu-west-1"]},"rules":{"daily":{"schedule_expression":{"@@assign":"cron(0 3 ? * * *)"},"target_backup_vault_name":{"@@assign":"Default"},"lifecycle":{"delete_after_days":{"@@assign":"35"}}}},"selections":{"tags":{"prod":{"iam_role_arn":{"@@assign":"arn:aws:iam::$account:role/LarkspurBackupRole"},"tag_key":{"@@assign":"environment"},"tag_value":{"@@assign":["production"]}}}}}}}`),
				Targets:     []string{"ou-lark-prod"}},
		},
		ResourceShares: []snapshot.ResourceShare{
			{ARN: "arn:aws:ram:us-east-1:111111111112:resource-share/" + g.id("share")[6:], Name: "larkspur-core-network",
				OwnerAccountID: "111111111112", Status: "ACTIVE", Principals: []string{orgArn(mgmt, org)},
				Resources: []snapshot.SharedResource{
					{ARN: "arn:aws:ec2:us-east-1:111111111112:transit-gateway/" + tgw, Type: "ec2:TransitGateway"},
					{ARN: "arn:aws:ec2:us-east-1:111111111112:subnet/" + subnetA, Type: "ec2:Subnet"},
					{ARN: "arn:aws:ec2:us-east-1:111111111112:subnet/" + subnetB, Type: "ec2:Subnet"},
					{ARN: "arn:aws:route53resolver:us-east-1:111111111112:resolver-rule/" + rslv, Type: "route53resolver:ResolverRule"},
				}},
			{ARN: "arn:aws:ram:us-east-1:111111111112:resource-share/" + g.id("share")[6:], Name: "larkspur-ipam",
				OwnerAccountID: "111111111112", Status: "ACTIVE", Principals: []string{orgArn(mgmt, org)},
				Resources: []snapshot.SharedResource{
					{ARN: "arn:aws:ec2::111111111112:ipam-pool/" + ipam, Type: "ec2:IpamPool"},
				}},
			{ARN: "arn:aws:ram:us-east-1:111111111112:resource-share/" + g.id("share")[6:], Name: "larkspur-workload-prefix-lists",
				OwnerAccountID: "111111111112", Status: "ACTIVE", Principals: []string{ouArn(mgmt, org, "ou-lark-work")},
				Resources: []snapshot.SharedResource{
					{ARN: "arn:aws:ec2:us-east-1:111111111112:prefix-list/" + pl, Type: "ec2:PrefixList"},
				}},
			{ARN: "arn:aws:ram:us-east-1:111111111113:resource-share/" + g.id("share")[6:], Name: "larkspur-license-config",
				OwnerAccountID: "111111111113", Status: "ACTIVE", Principals: []string{LarkspurPaymentsProd, "111111111118"},
				Resources: []snapshot.SharedResource{
					{ARN: "arn:aws:license-manager:us-east-1:111111111113:license-configuration:lic-" + g.hex(16), Type: "license-manager:LicenseConfiguration"},
				}},
		},
		DelegatedAdministrators: []snapshot.DelegatedAdministrator{
			{AccountID: "111111111113", ServicePrincipal: "guardduty.amazonaws.com", DelegationDate: "2024-03-02T10:00:00Z"},
			{AccountID: "111111111113", ServicePrincipal: "securityhub.amazonaws.com", DelegationDate: "2024-03-02T10:05:00Z"},
			{AccountID: "111111111113", ServicePrincipal: "config.amazonaws.com", DelegationDate: "2024-03-02T10:10:00Z"},
			{AccountID: "111111111114", ServicePrincipal: "cloudtrail.amazonaws.com", DelegationDate: "2024-03-02T10:15:00Z"},
		},
		TrustedAccessServices: []string{
			"cloudtrail.amazonaws.com", "config.amazonaws.com", "guardduty.amazonaws.com", "securityhub.amazonaws.com",
			"ram.amazonaws.com", "sso.amazonaws.com", "member.org.stacksets.cloudformation.amazonaws.com",
			"tagpolicies.tag.amazonaws.com", "backup.amazonaws.com", "account.amazonaws.com",
		},
		OrganizationTrails: []snapshot.OrganizationTrail{
			{Name: "larkspur-org-trail", ARN: "arn:aws:cloudtrail:us-east-1:111111111114:trail/larkspur-org-trail",
				OwnerAccountID: "111111111114", HomeRegion: "us-east-1", S3BucketName: "larkspur-cloudtrail-archive"},
		},
		ConfigAggregators: []snapshot.ConfigAggregator{
			{Name: "larkspur-org-aggregator", AccountID: "111111111113", Region: "us-east-1", OrganizationSource: true},
		},
		StackSets: []snapshot.StackSet{
			{Name: "larkspur-baseline-roles", AdministrationAccountID: mgmt, PermissionModel: "SERVICE_MANAGED",
				AutoDeployment: true, RetainStacksOnAccountRemoval: false, TargetOUs: []string{"ou-lark-work"},
				Regions: []string{"us-east-1"}, Description: "Audit and break-glass IAM roles for workload accounts"},
			{Name: "larkspur-config-recorder", AdministrationAccountID: mgmt, PermissionModel: "SERVICE_MANAGED",
				AutoDeployment: true, RetainStacksOnAccountRemoval: true, TargetOUs: []string{root},
				Regions: []string{"us-east-1", "eu-west-1", "ap-southeast-1"}, Description: "AWS Config recorder and delivery channel"},
		},
		Usage: map[string]*snapshot.AccountUsage{
			LarkspurPaymentsProd: paymentsUsage(g),
			"111111111117": {
				Actions: []snapshot.ActionInUse{
					{Action: "ec2:RunInstances", Source: "manual", Note: "developer experiments"},
					{Action: "s3:*", Source: "iam-last-accessed"},
					{Action: "redshift:CreateCluster", Source: "manual", Note: "denied today by Larkspur-Sandbox-Limits"},
				},
			},
			"111111111116": {
				Actions: []snapshot.ActionInUse{
					{Action: "ec2:RunInstances", Source: "manual"},
					{Action: "ec2:CreateVpc", Source: "manual", Note: "ephemeral test VPCs"},
					{Action: "lambda:*", Source: "iam-last-accessed"},
				},
			},
			"111111111118": {
				Actions: []snapshot.ActionInUse{
					{Action: "glue:StartJobRun", Source: "iam-last-accessed", LastUsed: "2025-12-31T23:30:00Z"},
					{Action: "athena:StartQueryExecution", Source: "iam-last-accessed", LastUsed: "2025-12-31T23:35:00Z"},
					{Action: "s3:GetObject", Resource: "arn:aws:s3:::larkspur-payments-settlement-files/*", Source: "manual", Note: "reads the ledger export from the payments account"},
					{Action: "s3:PutObject", Resource: "arn:aws:s3:::larkspur-data-lake/*", Source: "iam-last-accessed", LastUsed: "2025-12-31T23:36:00Z"},
					{Action: "kms:Decrypt", Source: "iam-last-accessed", LastUsed: "2025-12-31T23:36:00Z"},
					{Action: "sts:AssumeRole", Source: "iam-last-accessed", LastUsed: "2025-12-31T23:36:00Z"},
					{Action: "ec2:RunInstances", Regions: []string{"us-east-1"}, Source: "manual", Note: "spot fleet for nightly model training"},
					{Action: "ec2:CreateTransitGatewayVpcAttachment", Source: "manual", Note: "data lake VPC hangs off the shared transit gateway"},
				},
				InboundAccess: []snapshot.InboundAccess{
					{Principal: "arn:aws:iam::111111111115:role/SettlementExporter", Actions: []string{"s3:PutObject"},
						Resource: "arn:aws:s3:::larkspur-data-lake/ledger/*", Note: "payments account pushes the nightly ledger export"},
				},
			},
		},
	}
	// Drawn after the usage block so the identifiers above keep their values.
	s.IdentityCenter = larkspurIdentityCenter(g)
	s.Coverage = completeCoverage(s, "us-east-1")
	return s
}

func paymentsUsage(g *gen) *snapshot.AccountUsage {
	instances := func(n int, tags map[string]string) []snapshot.TaggedResource {
		var out []snapshot.TaggedResource
		for i := 0; i < n; i++ {
			out = append(out, snapshot.TaggedResource{
				ARN: "arn:aws:ec2:us-east-1:111111111115:instance/i-" + g.hex(17), Type: "ec2:instance", Region: "us-east-1", Tags: tags,
			})
		}
		return out
	}
	var resources []snapshot.TaggedResource
	resources = append(resources, instances(3, map[string]string{"Name": "pay-api", "Cost-Center": "CC-1001", "environment": "production", "owner": "payments-team"})...)
	resources = append(resources, instances(2, map[string]string{"Name": "pay-worker", "environment": "production", "owner": "payments-team"})...)
	resources = append(resources,
		snapshot.TaggedResource{ARN: "arn:aws:rds:us-east-1:111111111115:db:payments-ledger", Type: "rds:db", Region: "us-east-1",
			Tags: map[string]string{"cost-center": "PAY-01", "environment": "production", "owner": "payments-team"}},
		snapshot.TaggedResource{ARN: "arn:aws:s3:::larkspur-payments-settlement-files", Type: "s3:bucket",
			Tags: map[string]string{"cost-center": "CC-3001", "environment": "production", "owner": "payments-team"}},
		snapshot.TaggedResource{ARN: "arn:aws:lambda:us-east-1:111111111115:function:settlement-notifier", Type: "lambda:function", Region: "us-east-1",
			Tags: map[string]string{"environment": "production"}},
	)
	return &snapshot.AccountUsage{
		Actions: []snapshot.ActionInUse{
			{Action: "ec2:RunInstances", Source: "iam-last-accessed", LastUsed: "2025-12-30T08:12:00Z"},
			{Action: "ec2:DescribeInstances", Source: "iam-last-accessed", LastUsed: "2025-12-31T23:40:00Z"},
			{Action: "ec2:TerminateInstances", Source: "iam-last-accessed", LastUsed: "2025-12-29T15:03:00Z", Note: "autoscaling cleanup role"},
			{Action: "ec2:CreateVpc", Source: "manual", Note: "disaster recovery runbook creates a fresh VPC in the standby region"},
			{Action: "ec2:CreateTransitGatewayVpcAttachment", Source: "manual", Note: "attaches new VPCs to the shared transit gateway"},
			{Action: "iam:CreateUser", Source: "iam-last-accessed", LastUsed: "2025-12-15T09:00:00Z", Note: "legacy CI pipeline rotates an IAM user for the SFTP gateway"},
			{Action: "iam:CreateRole", Source: "iam-last-accessed", LastUsed: "2025-12-28T11:30:00Z"},
			{Action: "iam:PassRole", Source: "iam-last-accessed", LastUsed: "2025-12-30T08:12:00Z"},
			{Action: "sts:AssumeRole", Source: "iam-last-accessed", LastUsed: "2025-12-31T23:59:00Z"},
			{Action: "s3:GetObject", Resource: "arn:aws:s3:::larkspur-payments-settlement-files/*", Source: "iam-last-accessed", LastUsed: "2025-12-31T23:58:00Z"},
			{Action: "s3:PutObject", Resource: "arn:aws:s3:::larkspur-payments-settlement-files/*", Source: "iam-last-accessed", LastUsed: "2025-12-31T23:58:00Z"},
			{Action: "kms:Decrypt", Source: "iam-last-accessed", LastUsed: "2025-12-31T23:58:00Z"},
			{Action: "rds:CreateDBInstance", Regions: []string{"us-east-1"}, Source: "manual", Note: "ledger database, only ever in us-east-1"},
			{Action: "rds:DescribeDBInstances", Source: "iam-last-accessed", LastUsed: "2025-12-31T22:00:00Z"},
			{Action: "dynamodb:*", Source: "iam-last-accessed", LastUsed: "2025-12-31T23:50:00Z", Note: "service used, tracked actions not available"},
			{Action: "lambda:InvokeFunction", Source: "iam-last-accessed", LastUsed: "2025-12-31T23:59:00Z"},
			{Action: "logs:CreateLogGroup", Source: "iam-last-accessed", LastUsed: "2025-12-31T23:59:00Z"},
			{Action: "cloudwatch:PutMetricData", Source: "iam-last-accessed", LastUsed: "2025-12-31T23:59:00Z"},
			{Action: "secretsmanager:GetSecretValue", Source: "iam-last-accessed", LastUsed: "2025-12-31T23:59:00Z"},
			{Action: "organizations:DescribeOrganization", Source: "iam-last-accessed", LastUsed: "2025-12-20T10:00:00Z"},
		},
		InboundAccess: []snapshot.InboundAccess{
			{Principal: "999999999999", PrincipalOrgID: "o-acquirer0001", Actions: []string{"s3:GetObject", "s3:ListBucket"},
				Resource: "arn:aws:s3:::larkspur-payments-settlement-files/*", Note: "card acquirer pulls settlement files nightly"},
			{Principal: "arn:aws:iam::111111111118:role/DataPlatformIngest", Actions: []string{"sts:AssumeRole"},
				Resource: "arn:aws:iam::111111111115:role/DataExportReader", Note: "data platform reads the ledger export"},
			{Principal: "arn:aws:iam::111111111118:role/DataPlatformIngest", Actions: []string{"kms:Decrypt"},
				Resource: "arn:aws:kms:us-east-1:111111111115:key/" + g.id("key")[4:], Note: "decrypts the ledger export"},
			{Principal: "888888888888", Actions: []string{"sqs:SendMessage"},
				Resource: "arn:aws:sqs:us-east-1:111111111115:fraud-events", Note: "fraud vendor, organization unknown"},
			{Principal: "cloudtrail.amazonaws.com", Actions: []string{"s3:PutObject"},
				Resource: "arn:aws:s3:::larkspur-payments-settlement-files/audit/*"},
		},
		TaggedResources: resources,
	}
}

// Fernhill builds the target organization.
func Fernhill() *snapshot.Snapshot {
	g := newGen()
	// Burn the same number of draws Larkspur uses for its network identifiers
	// so the two organizations do not share resource IDs.
	for i := 0; i < 6; i++ {
		g.hex(17)
	}
	const (
		org  = "o-fernhill0001"
		mgmt = "222222222221"
		root = "r-fern"
	)
	tgw := "tgw-" + g.hex(17)
	rslv := "rslvr-rr-" + g.hex(17)

	allTargets := []string{root, "ou-fern-core", "ou-fern-bu", FernhillPaymentsOU, "ou-fern-ret", "ou-fern-sand", "ou-fern-susp",
		"222222222221", "222222222222", "222222222223", "222222222224", "222222222225", "222222222226", "222222222227"}

	euRegions := []string{"eu-west-1", "eu-central-1"}
	s := &snapshot.Snapshot{
		SchemaVersion: snapshot.SchemaVersion,
		GeneratedAt:   "2026-01-01T00:00:00Z",
		Source:        "fixture",
		Organization: snapshot.Organization{
			ID: org, ARN: orgArn(mgmt, org), ManagementAccountID: mgmt, FeatureSet: "ALL", Name: FernhillName,
		},
		Root: snapshot.Root{
			ID: root, ARN: "arn:aws:organizations::" + mgmt + ":root/" + org + "/" + root, Name: "Root",
			EnabledPolicyTypes: []snapshot.PolicyType{snapshot.PolicyTypeSCP, snapshot.PolicyTypeRCP, snapshot.PolicyTypeTag, snapshot.PolicyTypeBackup},
		},
		OUs: []snapshot.OU{
			{ID: "ou-fern-core", Name: "Core", ParentID: root},
			{ID: "ou-fern-bu", Name: "Business Units", ParentID: root},
			{ID: FernhillPaymentsOU, Name: "Payments", ParentID: "ou-fern-bu"},
			{ID: "ou-fern-ret", Name: "Retail", ParentID: "ou-fern-bu"},
			{ID: "ou-fern-sand", Name: "Sandbox", ParentID: root},
			{ID: "ou-fern-susp", Name: "Suspended", ParentID: root},
		},
		Accounts: []snapshot.Account{
			acct("222222222221", "fernhill-management", root, "platform", euRegions),
			acct("222222222222", "fernhill-network", "ou-fern-core", "platform", euRegions),
			acct("222222222223", "fernhill-security", "ou-fern-core", "security", euRegions),
			acct("222222222224", "fernhill-log-archive", "ou-fern-core", "security", euRegions),
			acct("222222222225", "fernhill-retail-prod", "ou-fern-ret", "retail", euRegions),
			acct("222222222226", "fernhill-payments-core", FernhillPaymentsOU, "payments", euRegions),
			acct("222222222227", "fernhill-sandbox", "ou-fern-sand", "sandbox", []string{"eu-west-1"}),
		},
		Policies: []snapshot.Policy{
			{ID: "p-FullAWSAccess", Name: "FullAWSAccess", Type: snapshot.PolicyTypeSCP, AWSManaged: true,
				Description: "Allows access to every operation", Document: doc(fullAccess), Targets: allTargets},
			{ID: "p-fern0001", Name: "Fernhill-Root-Guardrails", Type: snapshot.PolicyTypeSCP,
				Description: "Organization-wide guardrails: no leaving, no IAM users, protected logging",
				Document: doc(`{"Version":"2012-10-17","Statement":[
					{"Sid":"DenyLeaveOrganization","Effect":"Deny","Action":["organizations:LeaveOrganization"],"Resource":"*"},
					{"Sid":"NoIAMUsers","Effect":"Deny","Action":["iam:CreateUser","iam:CreateAccessKey","iam:CreateLoginProfile"],"Resource":"*"},
					{"Sid":"ProtectLogging","Effect":"Deny","Action":["cloudtrail:StopLogging","cloudtrail:DeleteTrail","config:DeleteConfigurationRecorder","config:StopConfigurationRecorder","guardduty:DeleteDetector"],"Resource":"*"},
					{"Sid":"DenyRootUser","Effect":"Deny","Action":"*","Resource":"*","Condition":{"StringLike":{"aws:PrincipalArn":"arn:aws:iam::*:root"}}}
				]}`), Targets: []string{root}},
			{ID: "p-fern0002", Name: "Fernhill-EU-Only-Regions", Type: snapshot.PolicyTypeSCP,
				Description: "Business unit workloads stay inside the EU",
				Document: doc(`{"Version":"2012-10-17","Statement":[
					{"Sid":"DenyOutsideEU","Effect":"Deny",
					 "NotAction":["iam:*","sts:*","organizations:*","support:*","budgets:*","cloudfront:*","route53:*","waf:*","health:*","account:*","access-analyzer:*","trustedadvisor:*"],
					 "Resource":"*",
					 "Condition":{"StringNotEquals":{"aws:RequestedRegion":["eu-west-1","eu-central-1"]}}}
				]}`), Targets: []string{"ou-fern-bu"}},
			{ID: "p-fern0003", Name: "Fernhill-Payments-Controls", Type: snapshot.PolicyTypeSCP,
				Description: "Networking is managed centrally; destructive compute actions need the platform tag",
				Document: doc(`{"Version":"2012-10-17","Statement":[
					{"Sid":"CentralNetworkingOnly","Effect":"Deny","Action":["ec2:CreateVpc","ec2:DeleteVpc","ec2:CreateInternetGateway","ec2:AttachInternetGateway","ec2:CreateVpcPeeringConnection","ec2:CreateTransitGatewayVpcAttachment"],"Resource":"*"},
					{"Sid":"TerminateNeedsPlatformTag","Effect":"Deny","Action":["ec2:TerminateInstances","rds:DeleteDBInstance"],"Resource":"*",
					 "Condition":{"StringNotEquals":{"aws:PrincipalTag/team":"platform"}}},
					{"Sid":"NoPublicBuckets","Effect":"Deny","Action":["s3:PutBucketPublicAccessBlock","s3:DeletePublicAccessBlock"],"Resource":"*"}
				]}`), Targets: []string{FernhillPaymentsOU}},
			{ID: "p-fern0004", Name: "Fernhill-Sandbox-Limits", Type: snapshot.PolicyTypeSCP,
				Document: doc(`{"Version":"2012-10-17","Statement":[
					{"Sid":"NoExpensiveServices","Effect":"Deny","Action":["redshift:*","emr:*","directconnect:*"],"Resource":"*"}
				]}`), Targets: []string{"ou-fern-sand"}},
			{ID: "p-fern0005", Name: "Fernhill-Suspended", Type: snapshot.PolicyTypeSCP,
				Document: doc(`{"Version":"2012-10-17","Statement":[{"Sid":"DenyAll","Effect":"Deny","Action":"*","Resource":"*"}]}`),
				Targets:  []string{"ou-fern-susp"}},
			// Control Tower attaches one guardrail SCP per registered OU. The
			// statements are the mandatory preventive controls; the names follow
			// the aws-guardrails-<random> convention Control Tower uses.
			{ID: "p-fern0010", Name: "aws-guardrails-kjwqpf", Type: snapshot.PolicyTypeSCP,
				Description: "This policy is managed by AWS Control Tower. Do not edit or detach it.",
				Document: doc(`{"Version":"2012-10-17","Statement":[
					{"Sid":"GRCLOUDTRAILENABLED","Effect":"Deny","Action":["cloudtrail:DeleteTrail","cloudtrail:PutEventSelectors","cloudtrail:StopLogging","cloudtrail:UpdateTrail"],"Resource":"arn:aws:cloudtrail:*:*:trail/aws-controltower-*",
					 "Condition":{"ArnNotLike":{"aws:PrincipalArn":"arn:aws:iam::*:role/AWSControlTowerExecution"}}},
					{"Sid":"GRCONFIGENABLED","Effect":"Deny","Action":["config:DeleteConfigurationRecorder","config:DeleteDeliveryChannel","config:PutConfigurationRecorder","config:PutDeliveryChannel","config:StopConfigurationRecorder"],"Resource":"*",
					 "Condition":{"ArnNotLike":{"aws:PrincipalArn":"arn:aws:iam::*:role/AWSControlTowerExecution"}}},
					{"Sid":"GRRESTRICTROOTUSERACCESSKEYS","Effect":"Deny","Action":"iam:CreateAccessKey","Resource":"*",
					 "Condition":{"StringLike":{"aws:PrincipalArn":"arn:aws:iam::*:root"}}}
				]}`), Targets: []string{"ou-fern-bu"}},
			{ID: "p-fern0011", Name: "aws-guardrails-ztmvqe", Type: snapshot.PolicyTypeSCP,
				Description: "This policy is managed by AWS Control Tower. Do not edit or detach it.",
				Document: doc(`{"Version":"2012-10-17","Statement":[
					{"Sid":"GRAUDITBUCKETPOLICYCHANGESPROHIBITED","Effect":"Deny","Action":["s3:DeleteBucketPolicy","s3:PutBucketPolicy"],"Resource":"arn:aws:s3:::aws-controltower-*",
					 "Condition":{"ArnNotLike":{"aws:PrincipalArn":"arn:aws:iam::*:role/AWSControlTowerExecution"}}}
				]}`), Targets: []string{"ou-fern-core"}},
			{ID: "p-RCPFullAWSAccess", Name: "RCPFullAWSAccess", Type: snapshot.PolicyTypeRCP, AWSManaged: true,
				Description: "Allows access to every operation", Document: doc(rcpFullAccess), Targets: allTargets},
			{ID: "p-fern0006", Name: "Fernhill-Block-External-Principals", Type: snapshot.PolicyTypeRCP,
				Description: "Resources in business unit accounts can only be used from inside the organization",
				Document: doc(`{"Version":"2012-10-17","Statement":[
					{"Sid":"EnforceOrgIdentities","Effect":"Deny","Principal":"*",
					 "Action":["s3:*","sts:AssumeRole","sts:SetContext","kms:*","sqs:*","secretsmanager:*"],
					 "Resource":"*",
					 "Condition":{"StringNotEqualsIfExists":{"aws:PrincipalOrgID":"o-fernhill0001"},"BoolIfExists":{"aws:PrincipalIsAWSService":"false"}}}
				]}`), Targets: []string{"ou-fern-bu"}},
			{ID: "p-fern0007", Name: "Fernhill-Cost-Allocation", Type: snapshot.PolicyTypeTag,
				Description: "Every billable resource carries a cost-center code",
				Document:    doc(`{"tags":{"cost-center":{"tag_key":{"@@assign":"cost-center"},"tag_value":{"@@assign":["CC-1001","CC-1002","CC-2001","CC-2002"]},"enforced_for":{"@@assign":["ec2:instance","ec2:volume","rds:db","s3:bucket","lambda:function"]}},"environment":{"tag_key":{"@@assign":"environment"},"tag_value":{"@@assign":["production","staging","development"]}}}}`),
				Targets:     []string{root}},
			{ID: "p-fern0008", Name: "Fernhill-Payments-Cost-Centers", Type: snapshot.PolicyTypeTag,
				Description: "Adds the payments cost centers",
				Document:    doc(`{"tags":{"cost-center":{"tag_value":{"@@append":["CC-3001","CC-3002"]}}}}`),
				Targets:     []string{FernhillPaymentsOU}},
			{ID: "p-fern0009", Name: "Fernhill-Core-Backups", Type: snapshot.PolicyTypeBackup,
				Document: doc(`{"plans":{"fernhill-hourly":{"regions":{"@@assign":["eu-west-1","eu-central-1"]},"rules":{"hourly":{"schedule_expression":{"@@assign":"cron(0 * ? * * *)"},"target_backup_vault_name":{"@@assign":"FernhillVault"},"lifecycle":{"delete_after_days":{"@@assign":"14"}}}},"selections":{"tags":{"all":{"iam_role_arn":{"@@assign":"arn:aws:iam::$account:role/FernhillBackupRole"},"tag_key":{"@@assign":"backup"},"tag_value":{"@@assign":["true"]}}}}}}}`),
				Targets:  []string{"ou-fern-bu"}},
		},
		ResourceShares: []snapshot.ResourceShare{
			{ARN: "arn:aws:ram:eu-west-1:222222222222:resource-share/" + g.id("share")[6:], Name: "fernhill-core-network",
				OwnerAccountID: "222222222222", Status: "ACTIVE", Principals: []string{orgArn(mgmt, org)},
				Resources: []snapshot.SharedResource{
					{ARN: "arn:aws:ec2:eu-west-1:222222222222:transit-gateway/" + tgw, Type: "ec2:TransitGateway"},
					{ARN: "arn:aws:route53resolver:eu-west-1:222222222222:resolver-rule/" + rslv, Type: "route53resolver:ResolverRule"},
				}},
		},
		DelegatedAdministrators: []snapshot.DelegatedAdministrator{
			{AccountID: "222222222223", ServicePrincipal: "guardduty.amazonaws.com", DelegationDate: "2025-01-10T09:00:00Z"},
			{AccountID: "222222222223", ServicePrincipal: "securityhub.amazonaws.com", DelegationDate: "2025-01-10T09:05:00Z"},
			{AccountID: "222222222223", ServicePrincipal: "access-analyzer.amazonaws.com", DelegationDate: "2025-01-10T09:10:00Z"},
		},
		TrustedAccessServices: []string{
			"cloudtrail.amazonaws.com", "config.amazonaws.com", "guardduty.amazonaws.com", "securityhub.amazonaws.com",
			"ram.amazonaws.com", "sso.amazonaws.com", "member.org.stacksets.cloudformation.amazonaws.com",
			"tagpolicies.tag.amazonaws.com", "backup.amazonaws.com", "access-analyzer.amazonaws.com", "controltower.amazonaws.com",
		},
		OrganizationTrails: []snapshot.OrganizationTrail{
			{Name: "fernhill-org-trail", ARN: "arn:aws:cloudtrail:eu-west-1:222222222224:trail/fernhill-org-trail",
				OwnerAccountID: "222222222224", HomeRegion: "eu-west-1", S3BucketName: "fernhill-log-archive"},
		},
		ConfigAggregators: []snapshot.ConfigAggregator{
			{Name: "fernhill-org-aggregator", AccountID: "222222222223", Region: "eu-west-1", OrganizationSource: true},
		},
		StackSets: []snapshot.StackSet{
			{Name: "fernhill-baseline", AdministrationAccountID: mgmt, PermissionModel: "SERVICE_MANAGED",
				AutoDeployment: true, RetainStacksOnAccountRemoval: false, TargetOUs: []string{"ou-fern-bu"},
				Regions: []string{"eu-west-1"}, Description: "Baseline IAM roles and GuardDuty membership"},
		},
		ControlTower:   fernhillControlTower(),
		IdentityCenter: fernhillIdentityCenter(g),
		Usage: map[string]*snapshot.AccountUsage{
			FernhillRetailProd: {
				Actions: []snapshot.ActionInUse{
					{Action: "ec2:RunInstances", Source: "iam-last-accessed", LastUsed: "2025-12-31T20:00:00Z"},
					{Action: "ec2:CreateVolume", Source: "iam-last-accessed", LastUsed: "2025-12-31T20:00:00Z"},
					{Action: "s3:GetObject", Resource: "arn:aws:s3:::fernhill-retail-assets/*", Source: "iam-last-accessed", LastUsed: "2025-12-31T23:59:00Z"},
					{Action: "s3:PutObject", Resource: "arn:aws:s3:::fernhill-retail-assets/*", Source: "iam-last-accessed", LastUsed: "2025-12-31T23:59:00Z"},
					{Action: "rds:CreateDBInstance", Regions: []string{"eu-west-1"}, Source: "manual", Note: "catalogue database"},
					{Action: "lambda:InvokeFunction", Source: "iam-last-accessed", LastUsed: "2025-12-31T23:59:00Z"},
					{Action: "cloudwatch:PutMetricData", Source: "iam-last-accessed", LastUsed: "2025-12-31T23:59:00Z"},
				},
			},
		},
	}
	s.Coverage = completeCoverage(s, "eu-west-1")
	return s
}

// fernhillControlTower is the landing zone that governs Fernhill: the Core
// and Business Units trees are registered, the Sandbox and Suspended OUs are
// not, and two accounts were vended by Account Factory.
func fernhillControlTower() *snapshot.ControlTower {
	control := func(id, name, behavior, ou, impl string) snapshot.EnabledControl {
		identifier := "arn:aws:controltower:eu-west-1::control/" + id
		if behavior == snapshot.ControlProactive {
			identifier = "arn:aws:controlcatalog:::control/" + id
		}
		return snapshot.EnabledControl{ControlIdentifier: identifier, Name: name, Behavior: behavior, TargetOUID: ou,
			Status: "SUCCEEDED", DriftStatus: "IN_SYNC", Implementation: impl}
	}
	const (
		scp  = "AWS::Organizations::Policy"
		rule = "AWS::Config::ConfigRule"
		hook = "AWS::CloudFormation::Hook"
	)
	registered := func(ou string) snapshot.RegisteredOU {
		return snapshot.RegisteredOU{OUID: ou, BaselineVersion: "4.0", Status: "SUCCEEDED", DriftStatus: "IN_SYNC"}
	}
	return &snapshot.ControlTower{
		LandingZoneARN: "arn:aws:controltower:eu-west-1:222222222221:landingzone/FERNHILLLZ000001",
		Version:        "3.3", LatestAvailableVersion: "3.3", Status: "ACTIVE", DriftStatus: "IN_SYNC",
		// Fernhill has not opted into auto-enrollment, so moves made with
		// Organizations leave inheritance drift.
		AutoEnrollment: snapshot.AutoEnrollmentDisabled,
		HomeRegion:     "eu-west-1", GovernedRegions: []string{"eu-west-1", "eu-central-1"},
		AuditAccountID: FernhillAuditAccount, LogArchiveAccountID: "222222222224",
		RegisteredOUs: []snapshot.RegisteredOU{registered("ou-fern-core"), registered("ou-fern-bu"), registered(FernhillPaymentsOU), registered(FernhillRetailOU)},
		EnrolledAccounts: []snapshot.EnrolledAccount{
			{AccountID: "222222222222", Status: "ENROLLED"},
			{AccountID: FernhillAuditAccount, Status: "ENROLLED"},
			{AccountID: "222222222224", Status: "ENROLLED"},
			{AccountID: FernhillRetailProd, VendedByAccountFactory: true, ProvisionedProduct: "fernhill-retail-prod", Status: "ENROLLED"},
			{AccountID: "222222222226", VendedByAccountFactory: true, ProvisionedProduct: "fernhill-payments-core", Status: "ENROLLED"},
		},
		EnabledControls: []snapshot.EnabledControl{
			control("AWS-GR_AUDIT_BUCKET_POLICY_CHANGES_PROHIBITED", "Disallow changes to bucket policy for Amazon S3 buckets created by AWS Control Tower", snapshot.ControlPreventive, "ou-fern-core", scp),
			control("AWS-GR_AUDIT_BUCKET_PUBLIC_READ_PROHIBITED", "Detect whether public read access to Amazon S3 buckets created by AWS Control Tower is allowed", snapshot.ControlDetective, "ou-fern-core", rule),
			control("AWS-GR_CLOUDTRAIL_ENABLED", "Disallow changes to CloudTrail set up by AWS Control Tower", snapshot.ControlPreventive, "ou-fern-bu", scp),
			control("AWS-GR_CONFIG_ENABLED", "Disallow changes to AWS Config set up by AWS Control Tower", snapshot.ControlPreventive, "ou-fern-bu", scp),
			control("AWS-GR_RESTRICT_ROOT_USER_ACCESS_KEYS", "Disallow creation of access keys for the root user", snapshot.ControlPreventive, "ou-fern-bu", scp),
			control("AWS-GR_ENCRYPTED_VOLUMES", "Detect whether encryption is enabled for Amazon EBS volumes attached to Amazon EC2 instances", snapshot.ControlDetective, "ou-fern-bu", rule),
			control("AWS-GR_RESTRICTED_SSH", "Detect whether unrestricted incoming SSH traffic is allowed", snapshot.ControlDetective, "ou-fern-bu", rule),
			control("AWS-GR_RDS_STORAGE_ENCRYPTED", "Detect whether storage encryption is enabled for Amazon RDS database instances", snapshot.ControlDetective, "ou-fern-bu", rule),
			control("AWS-GR_S3_BUCKET_PUBLIC_READ_PROHIBITED", "Detect whether public read access to Amazon S3 buckets is allowed", snapshot.ControlDetective, FernhillPaymentsOU, rule),
			control("7f3kq9x2m1pz8r4v6t0nb5cy", "CT.S3.PR.1: Require that an Amazon S3 bucket has block public access settings configured", snapshot.ControlProactive, FernhillPaymentsOU, hook),
			control("AWS-GR_RESTRICTED_COMMON_PORTS", "Detect whether unrestricted incoming TCP traffic is allowed on common ports", snapshot.ControlDetective, FernhillRetailOU, rule),
		},
	}
}

// larkspurIdentityCenter is the Identity Center instance of Larkspur. The
// payments account carries four assignments across three permission sets,
// and the DataPlatformOperator role is still provisioned there although its
// assignment was removed (a stale AWSReservedSSO_* role).
func larkspurIdentityCenter(g *gen) *snapshot.IdentityCenter {
	const (
		instance = LarkspurIdentityCenterInstance
		admin    = "arn:aws:sso:::permissionSet/ssoins-larkspur00000001/ps-lark00000001"
		payments = "arn:aws:sso:::permissionSet/ssoins-larkspur00000001/ps-lark00000002"
		readOnly = "arn:aws:sso:::permissionSet/ssoins-larkspur00000001/ps-lark00000003"
		data     = "arn:aws:sso:::permissionSet/ssoins-larkspur00000001/ps-lark00000004"
		sandbox  = "arn:aws:sso:::permissionSet/ssoins-larkspur00000001/ps-lark00000005"
	)
	all := []string{"111111111111", "111111111112", "111111111113", "111111111114", LarkspurPaymentsProd, "111111111116", "111111111117", "111111111118"}
	platformAdmins, paymentsEngineers, securityAuditors, dataPlatform, developers := g.uuid(), g.uuid(), g.uuid(), g.uuid(), g.uuid()
	oncall := g.uuid()
	assign := func(account, ps, kind, id, name string) snapshot.AccountAssignment {
		return snapshot.AccountAssignment{AccountID: account, PermissionSetARN: ps, PrincipalType: kind, PrincipalID: id, PrincipalName: name}
	}
	var assignments []snapshot.AccountAssignment
	for _, a := range all {
		assignments = append(assignments, assign(a, admin, snapshot.PrincipalGroup, platformAdmins, "Platform-Admins"))
	}
	assignments = append(assignments,
		assign(LarkspurPaymentsProd, payments, snapshot.PrincipalGroup, paymentsEngineers, "Payments-Engineers"),
		assign(LarkspurPaymentsProd, payments, snapshot.PrincipalUser, oncall, "oncall.payments"),
		assign(LarkspurPaymentsProd, readOnly, snapshot.PrincipalGroup, securityAuditors, "Security-Auditors"),
		assign("111111111116", payments, snapshot.PrincipalGroup, paymentsEngineers, "Payments-Engineers"),
		assign("111111111113", readOnly, snapshot.PrincipalGroup, securityAuditors, "Security-Auditors"),
		assign("111111111114", readOnly, snapshot.PrincipalGroup, securityAuditors, "Security-Auditors"),
		assign("111111111118", readOnly, snapshot.PrincipalGroup, securityAuditors, "Security-Auditors"),
		assign("111111111118", data, snapshot.PrincipalGroup, dataPlatform, "Data-Platform"),
		assign("111111111117", sandbox, snapshot.PrincipalGroup, developers, "Developers"),
	)
	return &snapshot.IdentityCenter{
		InstanceARN: instance, IdentityStoreID: "d-lark0000001", Region: "us-east-1", OwnerAccountID: "111111111111", Name: "Larkspur SSO",
		PermissionSets: []snapshot.PermissionSet{
			{ARN: admin, Name: "AdministratorAccess", Description: "Full access for the platform team", SessionDuration: "PT1H",
				ManagedPolicies: []string{"arn:aws:iam::aws:policy/AdministratorAccess"}, ProvisionedAccounts: all},
			{ARN: payments, Name: LarkspurPaymentsEngineerSet, Description: "Day-to-day operations in the payments accounts", SessionDuration: "PT8H",
				CustomerManagedPolicies: []string{"/larkspur/LarkspurPaymentsEngineer"},
				InlinePolicy:            doc(`{"Version":"2012-10-17","Statement":[{"Sid":"NoIAMChanges","Effect":"Deny","Action":["iam:Create*","iam:Delete*","iam:Put*","iam:Attach*","iam:Detach*"],"Resource":"*"}]}`),
				ProvisionedAccounts:     []string{LarkspurPaymentsProd, "111111111116"}},
			{ARN: readOnly, Name: "ReadOnlyAccess", Description: "Audit access", SessionDuration: "PT8H",
				ManagedPolicies:     []string{"arn:aws:iam::aws:policy/ReadOnlyAccess"},
				ProvisionedAccounts: []string{"111111111111", "111111111112", "111111111113", "111111111114", LarkspurPaymentsProd, "111111111116", "111111111118"}},
			{ARN: data, Name: "DataPlatformOperator", Description: "Glue and Athena operations", SessionDuration: "PT4H",
				ManagedPolicies:     []string{"arn:aws:iam::aws:policy/AmazonAthenaFullAccess", "arn:aws:iam::aws:policy/AWSGlueConsoleFullAccess"},
				PermissionsBoundary: "arn:aws:iam::aws:policy/PowerUserAccess",
				// Still provisioned in the payments account from the ledger export project; the assignment is gone.
				ProvisionedAccounts: []string{"111111111118", LarkspurPaymentsProd}},
			{ARN: sandbox, Name: "SandboxDeveloper", SessionDuration: "PT12H",
				ManagedPolicies: []string{"arn:aws:iam::aws:policy/PowerUserAccess"}, ProvisionedAccounts: []string{"111111111117"}},
		},
		Assignments: assignments,
	}
}

// fernhillIdentityCenter is the Identity Center instance of Fernhill. It has
// permission sets named like two of Larkspur's (with different settings) and
// nothing resembling PaymentsEngineer.
func fernhillIdentityCenter(g *gen) *snapshot.IdentityCenter {
	const (
		admin    = "arn:aws:sso:::permissionSet/ssoins-fernhill00000001/ps-fern00000001"
		readOnly = "arn:aws:sso:::permissionSet/ssoins-fernhill00000001/ps-fern00000002"
		dev      = "arn:aws:sso:::permissionSet/ssoins-fernhill00000001/ps-fern00000003"
	)
	all := []string{"222222222221", "222222222222", "222222222223", "222222222224", FernhillRetailProd, "222222222226", "222222222227"}
	platform, auditors, retailDevs, paymentsDevs := g.uuid(), g.uuid(), g.uuid(), g.uuid()
	assign := func(account, ps, id, name string) snapshot.AccountAssignment {
		return snapshot.AccountAssignment{AccountID: account, PermissionSetARN: ps, PrincipalType: snapshot.PrincipalGroup, PrincipalID: id, PrincipalName: name}
	}
	var assignments []snapshot.AccountAssignment
	for _, a := range all {
		assignments = append(assignments, assign(a, admin, platform, "Fernhill-Platform"))
		if a != "222222222227" {
			assignments = append(assignments, assign(a, readOnly, auditors, "Fernhill-Auditors"))
		}
	}
	assignments = append(assignments,
		assign(FernhillRetailProd, dev, retailDevs, "Retail-Developers"),
		assign("222222222226", dev, paymentsDevs, "Payments-Developers"),
	)
	return &snapshot.IdentityCenter{
		InstanceARN: FernhillIdentityCenterInstance, IdentityStoreID: "d-fern0000001", Region: "eu-west-1", OwnerAccountID: "222222222221", Name: "Fernhill Identity Center",
		PermissionSets: []snapshot.PermissionSet{
			{ARN: admin, Name: "AdministratorAccess", Description: "Platform team break-glass", SessionDuration: "PT2H",
				ManagedPolicies: []string{"arn:aws:iam::aws:policy/AdministratorAccess"}, ProvisionedAccounts: all},
			{ARN: readOnly, Name: "ReadOnlyAccess", Description: "Audit and security review", SessionDuration: "PT12H",
				ManagedPolicies:     []string{"arn:aws:iam::aws:policy/ReadOnlyAccess", "arn:aws:iam::aws:policy/job-function/ViewOnlyAccess"},
				ProvisionedAccounts: []string{"222222222221", "222222222222", "222222222223", "222222222224", FernhillRetailProd, "222222222226"}},
			{ARN: dev, Name: "BusinessUnitDeveloper", Description: "Developers in business unit accounts", SessionDuration: "PT8H",
				ManagedPolicies: []string{"arn:aws:iam::aws:policy/PowerUserAccess"}, PermissionsBoundary: "/fernhill/FernhillDeveloperBoundary",
				ProvisionedAccounts: []string{FernhillRetailProd, "222222222226"}},
		},
		Assignments: assignments,
	}
}

func acct(id, name, parent, team string, regions []string) snapshot.Account {
	return snapshot.Account{
		ID: id, ARN: "arn:aws:organizations::" + id + ":account/" + id,
		Name: name, Email: "aws+" + name + "@example.com", Status: "ACTIVE", JoinedMethod: "CREATED", JoinedAt: fixtureJoinedAt,
		ParentID: parent, Tags: map[string]string{"team": team, "managed-by": "orgshift-fixture"}, EnabledRegions: regions,
	}
}
