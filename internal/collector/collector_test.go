package collector

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/account"
	accounttypes "github.com/aws/aws-sdk-go-v2/service/account/types"
	"github.com/aws/aws-sdk-go-v2/service/controlcatalog"
	cctypes "github.com/aws/aws-sdk-go-v2/service/controlcatalog/types"
	"github.com/aws/aws-sdk-go-v2/service/controltower"
	"github.com/aws/aws-sdk-go-v2/service/controltower/document"
	cttypes "github.com/aws/aws-sdk-go-v2/service/controltower/types"
	"github.com/aws/aws-sdk-go-v2/service/identitystore"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	orgtypes "github.com/aws/aws-sdk-go-v2/service/organizations/types"
	"github.com/aws/aws-sdk-go-v2/service/ram"
	ramtypes "github.com/aws/aws-sdk-go-v2/service/ram/types"
	"github.com/aws/aws-sdk-go-v2/service/ssoadmin"
	ssotypes "github.com/aws/aws-sdk-go-v2/service/ssoadmin/types"

	"github.com/MrShaaba/orgshift/internal/snapshot"
)

type fakeOrgs struct{}

func (fakeOrgs) DescribeOrganization(context.Context, *organizations.DescribeOrganizationInput, ...func(*organizations.Options)) (*organizations.DescribeOrganizationOutput, error) {
	return &organizations.DescribeOrganizationOutput{Organization: &orgtypes.Organization{Id: aws.String("o-fake00000001"), Arn: aws.String("arn:aws:organizations::111111111111:organization/o-fake00000001"), MasterAccountId: aws.String("111111111111"), FeatureSet: orgtypes.OrganizationFeatureSetAll}}, nil
}
func (fakeOrgs) ListRoots(context.Context, *organizations.ListRootsInput, ...func(*organizations.Options)) (*organizations.ListRootsOutput, error) {
	return &organizations.ListRootsOutput{Roots: []orgtypes.Root{{Id: aws.String("r-fake"), Name: aws.String("Root"), PolicyTypes: []orgtypes.PolicyTypeSummary{
		{Type: orgtypes.PolicyTypeServiceControlPolicy, Status: orgtypes.PolicyTypeStatusEnabled},
		{Type: orgtypes.PolicyTypeTagPolicy, Status: orgtypes.PolicyTypeStatusPendingDisable},
	}}}}, nil
}
func (fakeOrgs) ListOrganizationalUnitsForParent(_ context.Context, in *organizations.ListOrganizationalUnitsForParentInput, _ ...func(*organizations.Options)) (*organizations.ListOrganizationalUnitsForParentOutput, error) {
	if aws.ToString(in.ParentId) == "r-fake" {
		return &organizations.ListOrganizationalUnitsForParentOutput{OrganizationalUnits: []orgtypes.OrganizationalUnit{{Id: aws.String("ou-fake-work"), Name: aws.String("Workloads"), Arn: aws.String(fakeOUARN)}}}, nil
	}
	return &organizations.ListOrganizationalUnitsForParentOutput{}, nil
}
func (fakeOrgs) ListAccountsForParent(_ context.Context, in *organizations.ListAccountsForParentInput, _ ...func(*organizations.Options)) (*organizations.ListAccountsForParentOutput, error) {
	switch aws.ToString(in.ParentId) {
	case "r-fake":
		return &organizations.ListAccountsForParentOutput{Accounts: []orgtypes.Account{{Id: aws.String("111111111111"), Name: aws.String("management"), Status: orgtypes.AccountStatusActive}}}, nil
	case "ou-fake-work":
		return &organizations.ListAccountsForParentOutput{Accounts: []orgtypes.Account{{Id: aws.String("111111111112"), Name: aws.String("app"), Status: orgtypes.AccountStatusActive}}}, nil
	}
	return &organizations.ListAccountsForParentOutput{}, nil
}
func (fakeOrgs) ListPolicies(_ context.Context, in *organizations.ListPoliciesInput, _ ...func(*organizations.Options)) (*organizations.ListPoliciesOutput, error) {
	if in.Filter != orgtypes.PolicyTypeServiceControlPolicy {
		return nil, context.DeadlineExceeded // must not be called for disabled types
	}
	return &organizations.ListPoliciesOutput{Policies: []orgtypes.PolicySummary{{Id: aws.String("p-FullAWSAccess"), Name: aws.String("FullAWSAccess"), AwsManaged: true, Type: orgtypes.PolicyTypeServiceControlPolicy}}}, nil
}
func (fakeOrgs) DescribePolicy(context.Context, *organizations.DescribePolicyInput, ...func(*organizations.Options)) (*organizations.DescribePolicyOutput, error) {
	return &organizations.DescribePolicyOutput{Policy: &orgtypes.Policy{Content: aws.String(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`)}}, nil
}
func (fakeOrgs) ListTargetsForPolicy(context.Context, *organizations.ListTargetsForPolicyInput, ...func(*organizations.Options)) (*organizations.ListTargetsForPolicyOutput, error) {
	return &organizations.ListTargetsForPolicyOutput{Targets: []orgtypes.PolicyTargetSummary{{TargetId: aws.String("r-fake")}, {TargetId: aws.String("ou-fake-work")}, {TargetId: aws.String("111111111112")}, {TargetId: aws.String("111111111111")}}}, nil
}
func (fakeOrgs) ListTagsForResource(context.Context, *organizations.ListTagsForResourceInput, ...func(*organizations.Options)) (*organizations.ListTagsForResourceOutput, error) {
	return &organizations.ListTagsForResourceOutput{Tags: []orgtypes.Tag{{Key: aws.String("team"), Value: aws.String("platform")}}}, nil
}
func (fakeOrgs) ListDelegatedAdministrators(context.Context, *organizations.ListDelegatedAdministratorsInput, ...func(*organizations.Options)) (*organizations.ListDelegatedAdministratorsOutput, error) {
	return &organizations.ListDelegatedAdministratorsOutput{DelegatedAdministrators: []orgtypes.DelegatedAdministrator{{Id: aws.String("111111111112")}}}, nil
}
func (fakeOrgs) ListDelegatedServicesForAccount(context.Context, *organizations.ListDelegatedServicesForAccountInput, ...func(*organizations.Options)) (*organizations.ListDelegatedServicesForAccountOutput, error) {
	ts := time.Date(2025, 1, 2, 3, 4, 5, 0, time.UTC)
	return &organizations.ListDelegatedServicesForAccountOutput{DelegatedServices: []orgtypes.DelegatedService{{ServicePrincipal: aws.String("guardduty.amazonaws.com"), DelegationEnabledDate: &ts}}}, nil
}
func (fakeOrgs) ListAWSServiceAccessForOrganization(context.Context, *organizations.ListAWSServiceAccessForOrganizationInput, ...func(*organizations.Options)) (*organizations.ListAWSServiceAccessForOrganizationOutput, error) {
	return &organizations.ListAWSServiceAccessForOrganizationOutput{EnabledServicePrincipals: []orgtypes.EnabledServicePrincipal{{ServicePrincipal: aws.String("ram.amazonaws.com")}, {ServicePrincipal: aws.String("cloudtrail.amazonaws.com")}}}, nil
}

type fakeRAM struct{}

func (fakeRAM) GetResourceShares(context.Context, *ram.GetResourceSharesInput, ...func(*ram.Options)) (*ram.GetResourceSharesOutput, error) {
	return &ram.GetResourceSharesOutput{ResourceShares: []ramtypes.ResourceShare{
		{ResourceShareArn: aws.String("arn:aws:ram:us-east-1:111111111111:resource-share/abc"), Name: aws.String("net"), OwningAccountId: aws.String("111111111111"), Status: ramtypes.ResourceShareStatusActive,
			AllowExternalPrincipals: aws.Bool(true), ResourceShareConfiguration: &ramtypes.ResourceShareConfiguration{RetainSharingOnAccountLeaveOrganization: aws.Bool(true)}},
		{ResourceShareArn: aws.String("arn:aws:ram:us-east-1:111111111111:resource-share/old"), Name: aws.String("old"), OwningAccountId: aws.String("111111111111"), Status: ramtypes.ResourceShareStatusDeleted},
	}}, nil
}
func (fakeRAM) ListPrincipals(context.Context, *ram.ListPrincipalsInput, ...func(*ram.Options)) (*ram.ListPrincipalsOutput, error) {
	return &ram.ListPrincipalsOutput{Principals: []ramtypes.Principal{{Id: aws.String("arn:aws:organizations::111111111111:organization/o-fake00000001")}}}, nil
}
func (fakeRAM) ListResources(context.Context, *ram.ListResourcesInput, ...func(*ram.Options)) (*ram.ListResourcesOutput, error) {
	return &ram.ListResourcesOutput{Resources: []ramtypes.Resource{{Arn: aws.String("arn:aws:ec2:us-east-1:111111111111:transit-gateway/tgw-1"), Type: aws.String("ec2:TransitGateway")}}}, nil
}

const fakeOUARN = "arn:aws:organizations::111111111111:ou/o-fake00000001/ou-fake-work"

type fakeControlTower struct{ fail bool }

func (f fakeControlTower) ListLandingZones(context.Context, *controltower.ListLandingZonesInput, ...func(*controltower.Options)) (*controltower.ListLandingZonesOutput, error) {
	if f.fail {
		return nil, context.DeadlineExceeded
	}
	return &controltower.ListLandingZonesOutput{LandingZones: []cttypes.LandingZoneSummary{{Arn: aws.String("arn:aws:controltower:us-east-1:111111111111:landingzone/FAKELZ0000000001")}}}, nil
}
func (fakeControlTower) GetLandingZone(context.Context, *controltower.GetLandingZoneInput, ...func(*controltower.Options)) (*controltower.GetLandingZoneOutput, error) {
	manifest := map[string]any{
		"governedRegions":    []any{"us-east-1", "eu-west-1"},
		"centralizedLogging": map[string]any{"accountId": "111111111112", "enabled": true},
		"securityRoles":      map[string]any{"accountId": "111111111111"},
	}
	return &controltower.GetLandingZoneOutput{LandingZone: &cttypes.LandingZoneDetail{
		Version: aws.String("3.3"), Status: cttypes.LandingZoneStatusActive,
		DriftStatus: &cttypes.LandingZoneDriftStatusSummary{Status: cttypes.LandingZoneDriftStatusInSync},
		Manifest:    document.NewLazyDocument(manifest),
	}}, nil
}
func (fakeControlTower) ListEnabledBaselines(context.Context, *controltower.ListEnabledBaselinesInput, ...func(*controltower.Options)) (*controltower.ListEnabledBaselinesOutput, error) {
	status := &cttypes.EnablementStatusSummary{Status: cttypes.EnablementStatusSucceeded}
	return &controltower.ListEnabledBaselinesOutput{EnabledBaselines: []cttypes.EnabledBaselineSummary{
		{Arn: aws.String("arn:aws:controltower:us-east-1:111111111111:enabledbaseline/A"), BaselineIdentifier: aws.String("arn:aws:controltower:us-east-1::baseline/17BSJV3IGJ2QSGA2"),
			TargetIdentifier: aws.String(fakeOUARN), BaselineVersion: aws.String("4.0"), StatusSummary: status,
			DriftStatusSummary: &cttypes.EnabledBaselineDriftStatusSummary{Types: &cttypes.EnabledBaselineDriftTypes{Inheritance: &cttypes.EnabledBaselineInheritanceDrift{Status: cttypes.EnabledBaselineDriftStatusInSync}}}},
		// A child baseline on the same OU must not register it twice.
		{Arn: aws.String("arn:aws:controltower:us-east-1:111111111111:enabledbaseline/B"), BaselineIdentifier: aws.String("arn:aws:controltower:us-east-1::baseline/LN25R72TTG6IGPTQ"),
			TargetIdentifier: aws.String(fakeOUARN), ParentIdentifier: aws.String("arn:aws:controltower:us-east-1:111111111111:enabledbaseline/A"), StatusSummary: status},
		// Baselines on accounts are not OU registrations.
		{Arn: aws.String("arn:aws:controltower:us-east-1:111111111111:enabledbaseline/C"), BaselineIdentifier: aws.String("arn:aws:controltower:us-east-1::baseline/J8VYYMGXZ4GQZ7SM"),
			TargetIdentifier: aws.String("111111111112"), StatusSummary: status},
	}}, nil
}
func (fakeControlTower) ListEnabledControls(_ context.Context, in *controltower.ListEnabledControlsInput, _ ...func(*controltower.Options)) (*controltower.ListEnabledControlsOutput, error) {
	if aws.ToString(in.TargetIdentifier) != fakeOUARN {
		return nil, context.DeadlineExceeded
	}
	return &controltower.ListEnabledControlsOutput{EnabledControls: []cttypes.EnabledControlSummary{
		{ControlIdentifier: aws.String("arn:aws:controltower:us-east-1::control/AWS-GR_ENCRYPTED_VOLUMES"), TargetIdentifier: aws.String(fakeOUARN),
			StatusSummary: &cttypes.EnablementStatusSummary{Status: cttypes.EnablementStatusSucceeded}, DriftStatusSummary: &cttypes.DriftStatusSummary{DriftStatus: cttypes.DriftStatusInSync}},
		{ControlIdentifier: aws.String("arn:aws:controltower:us-east-1::control/AWS-GR_CONFIG_ENABLED"), TargetIdentifier: aws.String(fakeOUARN),
			ParentIdentifier: aws.String("arn:aws:controltower:us-east-1:111111111111:enabledcontrol/parent")},
	}}, nil
}

type fakeCatalog struct{}

func (fakeCatalog) GetControl(context.Context, *controlcatalog.GetControlInput, ...func(*controlcatalog.Options)) (*controlcatalog.GetControlOutput, error) {
	return &controlcatalog.GetControlOutput{Name: aws.String("Detect whether encryption is enabled for Amazon EBS volumes"), Behavior: cctypes.ControlBehaviorDetective,
		Implementation: &cctypes.ImplementationDetails{Type: aws.String("AWS::Config::ConfigRule")}}, nil
}

const (
	fakeInstance = "arn:aws:sso:::instance/ssoins-fake000000000001"
	fakePSAdmin  = "arn:aws:sso:::permissionSet/ssoins-fake000000000001/ps-admin"
	fakePSEmpty  = "arn:aws:sso:::permissionSet/ssoins-fake000000000001/ps-empty"
)

type fakeSSOAdmin struct{ fail bool }

func (f fakeSSOAdmin) ListInstances(context.Context, *ssoadmin.ListInstancesInput, ...func(*ssoadmin.Options)) (*ssoadmin.ListInstancesOutput, error) {
	if f.fail {
		return nil, context.DeadlineExceeded
	}
	return &ssoadmin.ListInstancesOutput{Instances: []ssotypes.InstanceMetadata{{InstanceArn: aws.String(fakeInstance), IdentityStoreId: aws.String("d-fake000001"), Name: aws.String("Fake SSO"), OwnerAccountId: aws.String("111111111111")}}}, nil
}
func (fakeSSOAdmin) ListPermissionSets(context.Context, *ssoadmin.ListPermissionSetsInput, ...func(*ssoadmin.Options)) (*ssoadmin.ListPermissionSetsOutput, error) {
	return &ssoadmin.ListPermissionSetsOutput{PermissionSets: []string{fakePSAdmin, fakePSEmpty}}, nil
}
func (fakeSSOAdmin) DescribePermissionSet(_ context.Context, in *ssoadmin.DescribePermissionSetInput, _ ...func(*ssoadmin.Options)) (*ssoadmin.DescribePermissionSetOutput, error) {
	name := "Empty"
	if aws.ToString(in.PermissionSetArn) == fakePSAdmin {
		name = "AdministratorAccess"
	}
	return &ssoadmin.DescribePermissionSetOutput{PermissionSet: &ssotypes.PermissionSet{Name: aws.String(name), Description: aws.String("desc"), SessionDuration: aws.String("PT1H"), PermissionSetArn: in.PermissionSetArn}}, nil
}
func (fakeSSOAdmin) ListManagedPoliciesInPermissionSet(_ context.Context, in *ssoadmin.ListManagedPoliciesInPermissionSetInput, _ ...func(*ssoadmin.Options)) (*ssoadmin.ListManagedPoliciesInPermissionSetOutput, error) {
	if aws.ToString(in.PermissionSetArn) != fakePSAdmin {
		return &ssoadmin.ListManagedPoliciesInPermissionSetOutput{}, nil
	}
	return &ssoadmin.ListManagedPoliciesInPermissionSetOutput{AttachedManagedPolicies: []ssotypes.AttachedManagedPolicy{{Arn: aws.String("arn:aws:iam::aws:policy/AdministratorAccess"), Name: aws.String("AdministratorAccess")}}}, nil
}
func (fakeSSOAdmin) ListCustomerManagedPolicyReferencesInPermissionSet(_ context.Context, in *ssoadmin.ListCustomerManagedPolicyReferencesInPermissionSetInput, _ ...func(*ssoadmin.Options)) (*ssoadmin.ListCustomerManagedPolicyReferencesInPermissionSetOutput, error) {
	if aws.ToString(in.PermissionSetArn) != fakePSAdmin {
		return &ssoadmin.ListCustomerManagedPolicyReferencesInPermissionSetOutput{}, nil
	}
	return &ssoadmin.ListCustomerManagedPolicyReferencesInPermissionSetOutput{CustomerManagedPolicyReferences: []ssotypes.CustomerManagedPolicyReference{{Name: aws.String("Guardrail")}, {Name: aws.String("Ops"), Path: aws.String("/team/")}}}, nil
}
func (fakeSSOAdmin) GetInlinePolicyForPermissionSet(_ context.Context, in *ssoadmin.GetInlinePolicyForPermissionSetInput, _ ...func(*ssoadmin.Options)) (*ssoadmin.GetInlinePolicyForPermissionSetOutput, error) {
	if aws.ToString(in.PermissionSetArn) != fakePSAdmin {
		return &ssoadmin.GetInlinePolicyForPermissionSetOutput{InlinePolicy: aws.String("")}, nil
	}
	return &ssoadmin.GetInlinePolicyForPermissionSetOutput{InlinePolicy: aws.String(`{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"iam:*","Resource":"*"}]}`)}, nil
}
func (fakeSSOAdmin) GetPermissionsBoundaryForPermissionSet(_ context.Context, in *ssoadmin.GetPermissionsBoundaryForPermissionSetInput, _ ...func(*ssoadmin.Options)) (*ssoadmin.GetPermissionsBoundaryForPermissionSetOutput, error) {
	if aws.ToString(in.PermissionSetArn) != fakePSAdmin {
		return nil, &ssotypes.ResourceNotFoundException{Message: aws.String("no boundary")}
	}
	return &ssoadmin.GetPermissionsBoundaryForPermissionSetOutput{PermissionsBoundary: &ssotypes.PermissionsBoundary{CustomerManagedPolicyReference: &ssotypes.CustomerManagedPolicyReference{Name: aws.String("Boundary"), Path: aws.String("/")}}}, nil
}
func (fakeSSOAdmin) ListAccountsForProvisionedPermissionSet(_ context.Context, in *ssoadmin.ListAccountsForProvisionedPermissionSetInput, _ ...func(*ssoadmin.Options)) (*ssoadmin.ListAccountsForProvisionedPermissionSetOutput, error) {
	if aws.ToString(in.PermissionSetArn) != fakePSAdmin {
		return &ssoadmin.ListAccountsForProvisionedPermissionSetOutput{}, nil
	}
	// 999999999999 is not in the tree and must be skipped.
	return &ssoadmin.ListAccountsForProvisionedPermissionSetOutput{AccountIds: []string{"111111111112", "999999999999", "111111111111"}}, nil
}
func (fakeSSOAdmin) ListAccountAssignments(_ context.Context, in *ssoadmin.ListAccountAssignmentsInput, _ ...func(*ssoadmin.Options)) (*ssoadmin.ListAccountAssignmentsOutput, error) {
	if aws.ToString(in.PermissionSetArn) != fakePSAdmin || aws.ToString(in.AccountId) == "999999999999" {
		return nil, context.DeadlineExceeded
	}
	if aws.ToString(in.AccountId) == "111111111111" {
		return &ssoadmin.ListAccountAssignmentsOutput{}, nil
	}
	return &ssoadmin.ListAccountAssignmentsOutput{AccountAssignments: []ssotypes.AccountAssignment{
		{AccountId: in.AccountId, PermissionSetArn: in.PermissionSetArn, PrincipalType: ssotypes.PrincipalTypeGroup, PrincipalId: aws.String("g-1")},
		{AccountId: in.AccountId, PermissionSetArn: in.PermissionSetArn, PrincipalType: ssotypes.PrincipalTypeUser, PrincipalId: aws.String("u-1")},
	}}, nil
}

type fakeIdentityStore struct{}

func (fakeIdentityStore) DescribeUser(_ context.Context, in *identitystore.DescribeUserInput, _ ...func(*identitystore.Options)) (*identitystore.DescribeUserOutput, error) {
	if aws.ToString(in.IdentityStoreId) != "d-fake000001" {
		return nil, context.DeadlineExceeded
	}
	return &identitystore.DescribeUserOutput{UserName: aws.String("alice"), DisplayName: aws.String("Alice")}, nil
}
func (fakeIdentityStore) DescribeGroup(context.Context, *identitystore.DescribeGroupInput, ...func(*identitystore.Options)) (*identitystore.DescribeGroupOutput, error) {
	return &identitystore.DescribeGroupOutput{DisplayName: aws.String("Admins")}, nil
}

type fakeAccount struct{}

func (fakeAccount) ListRegions(context.Context, *account.ListRegionsInput, ...func(*account.Options)) (*account.ListRegionsOutput, error) {
	return &account.ListRegionsOutput{Regions: []accounttypes.Region{{RegionName: aws.String("us-east-1")}, {RegionName: aws.String("eu-west-1")}}}, nil
}

func TestCollectBuildsAValidSnapshot(t *testing.T) {
	snap, err := Collect(context.Background(), Options{
		Name: "Fake Org", Organizations: fakeOrgs{}, RAM: []RAMAPI{fakeRAM{}}, Account: fakeAccount{},
		ControlTower: fakeControlTower{}, ControlCatalog: fakeCatalog{}, SSOAdmin: fakeSSOAdmin{}, IdentityStore: fakeIdentityStore{}, Region: "us-east-1",
		Now: func() time.Time { return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC) },
	})
	if err != nil {
		t.Fatal(err)
	}
	ic := snap.IdentityCenter
	if ic == nil || ic.InstanceARN != fakeInstance || ic.IdentityStoreID != "d-fake000001" || ic.Region != "us-east-1" || ic.OwnerAccountID != "111111111111" || ic.Name != "Fake SSO" {
		t.Fatalf("identity center instance wrong: %+v", ic)
	}
	if len(ic.PermissionSets) != 2 {
		t.Fatalf("expected two permission sets: %+v", ic.PermissionSets)
	}
	admin, empty := ic.PermissionSets[0], ic.PermissionSets[1]
	if admin.Name != "AdministratorAccess" || admin.SessionDuration != "PT1H" || len(admin.ManagedPolicies) != 1 || strings.Join(admin.CustomerManagedPolicies, ",") != "/Guardrail,/team/Ops" ||
		len(admin.InlinePolicy) == 0 || admin.PermissionsBoundary != "/Boundary" || strings.Join(admin.ProvisionedAccounts, ",") != "111111111111,111111111112" {
		t.Errorf("admin permission set wrong (unknown provisioned account skipped, lists sorted): %+v", admin)
	}
	if empty.Name != "Empty" || len(empty.InlinePolicy) != 0 || empty.PermissionsBoundary != "" || len(empty.ProvisionedAccounts) != 0 || len(empty.ManagedPolicies) != 0 {
		t.Errorf("a permission set without policies, boundary or provisioning must stay empty: %+v", empty)
	}
	if len(ic.Assignments) != 2 || ic.Assignments[0].PrincipalName != "Admins" || ic.Assignments[0].PrincipalType != snapshot.PrincipalGroup ||
		ic.Assignments[1].PrincipalName != "alice" || ic.Assignments[1].AccountID != "111111111112" || ic.Assignments[1].PermissionSetARN != fakePSAdmin {
		t.Errorf("assignments wrong (names resolved through the identity store): %+v", ic.Assignments)
	}
	ct := snap.ControlTower
	if ct == nil || ct.Version != "3.3" || ct.Status != "ACTIVE" || ct.DriftStatus != "IN_SYNC" || ct.HomeRegion != "us-east-1" {
		t.Fatalf("landing zone wrong: %+v", ct)
	}
	if len(ct.GovernedRegions) != 2 || ct.LogArchiveAccountID != "111111111112" || ct.AuditAccountID != "111111111111" {
		t.Errorf("manifest fields wrong: %+v", ct)
	}
	if len(ct.RegisteredOUs) != 1 || ct.RegisteredOUs[0].OUID != "ou-fake-work" || ct.RegisteredOUs[0].BaselineVersion != "4.0" || ct.RegisteredOUs[0].DriftStatus != "IN_SYNC" {
		t.Errorf("registered OUs wrong (one OU, deduplicated, accounts skipped): %+v", ct.RegisteredOUs)
	}
	if len(ct.EnabledControls) != 1 || ct.EnabledControls[0].Behavior != snapshot.ControlDetective || ct.EnabledControls[0].Implementation != "AWS::Config::ConfigRule" || ct.EnabledControls[0].TargetOUID != "ou-fake-work" {
		t.Errorf("enabled controls wrong (inherited child skipped, catalog applied): %+v", ct.EnabledControls)
	}
	// Baseline C targets account 111111111112: that is an enrolment record,
	// read from the API rather than assumed from the OU.
	if len(ct.EnrolledAccounts) != 1 || ct.EnrolledAccounts[0].AccountID != "111111111112" || ct.EnrolledAccounts[0].Source != snapshot.EnrolledFromBaseline || ct.EnrolledAccounts[0].VendedByAccountFactory {
		t.Errorf("enrolled accounts should come from the child enabled baselines: %+v", ct.EnrolledAccounts)
	}
	if ct.AutoEnrollment != snapshot.AutoEnrollmentDisabled {
		t.Errorf("a landing zone without remediation types has auto-enrollment off, got %q", ct.AutoEnrollment)
	}
	if snap.Coverage == nil || len(snap.Coverage.Domains) == 0 || len(snap.CoverageGaps()) != 3 {
		t.Errorf("coverage should be recorded, with only the three unsupported domains as gaps: %+v", snap.CoverageGaps())
	}
	if snap.Organization.ID != "o-fake00000001" || snap.Organization.Name != "Fake Org" || snap.GeneratedAt != "2026-01-01T00:00:00Z" {
		t.Errorf("organization block wrong: %+v", snap.Organization)
	}
	if len(snap.OUs) != 1 || len(snap.Accounts) != 2 || snap.Accounts[1].ParentID != "ou-fake-work" {
		t.Errorf("tree wrong: %+v %+v", snap.OUs, snap.Accounts)
	}
	if len(snap.Root.EnabledPolicyTypes) != 1 || snap.Root.EnabledPolicyTypes[0] != snapshot.PolicyTypeSCP {
		t.Errorf("only enabled policy types should be recorded: %v", snap.Root.EnabledPolicyTypes)
	}
	if len(snap.Policies) != 1 || len(snap.Policies[0].Targets) != 4 || !snap.Policies[0].AWSManaged {
		t.Errorf("policies wrong: %+v", snap.Policies)
	}
	if len(snap.ResourceShares) != 1 || snap.ResourceShares[0].Resources[0].Type != "ec2:TransitGateway" {
		t.Errorf("deleted shares must be skipped and resources listed: %+v", snap.ResourceShares)
	}
	if sh := snap.ResourceShares[0]; !sh.RetainSharingOnAccountLeave || !sh.AllowExternalPrincipals {
		t.Errorf("RetainSharingOnAccountLeaveOrganization is read from the share configuration: %+v", sh)
	}
	if len(snap.DelegatedAdministrators) != 1 || snap.DelegatedAdministrators[0].DelegationDate != "2025-01-02T03:04:05Z" {
		t.Errorf("delegated admins wrong: %+v", snap.DelegatedAdministrators)
	}
	if snap.TrustedAccessServices[0] != "cloudtrail.amazonaws.com" {
		t.Errorf("trusted access should be sorted: %v", snap.TrustedAccessServices)
	}
	if len(snap.Accounts[0].EnabledRegions) != 2 || snap.Accounts[0].Tags["team"] != "platform" {
		t.Errorf("regions and tags wrong: %+v", snap.Accounts[0])
	}
	data, err := snapshot.Marshal(snap)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := snapshot.Parse(data); err != nil {
		t.Fatalf("collected snapshot does not round-trip: %v", err)
	}
}

func TestControlTowerIsOptional(t *testing.T) {
	snap, err := Collect(context.Background(), Options{Organizations: fakeOrgs{}, ControlTower: fakeControlTower{fail: true}})
	if err != nil {
		t.Fatalf("a failing Control Tower call must not fail the collection: %v", err)
	}
	if snap.ControlTower != nil {
		t.Error("no landing zone should be recorded when the API cannot be read")
	}
	snap, err = Collect(context.Background(), Options{Organizations: fakeOrgs{}, ControlTower: fakeControlTower{}})
	if err != nil {
		t.Fatal(err)
	}
	if c := snap.ControlTower.EnabledControls[0]; c.Behavior != "" || c.Name != "" || c.ControlIdentifier == "" {
		t.Errorf("without a catalog client controls are recorded by identifier only: %+v", c)
	}
}

func TestIdentityCenterIsOptional(t *testing.T) {
	snap, err := Collect(context.Background(), Options{Organizations: fakeOrgs{}, SSOAdmin: fakeSSOAdmin{fail: true}})
	if err != nil {
		t.Fatalf("a failing Identity Center call must not fail the collection: %v", err)
	}
	if snap.IdentityCenter != nil {
		t.Error("no instance should be recorded when the API cannot be read")
	}
	snap, err = Collect(context.Background(), Options{Organizations: fakeOrgs{}, SSOAdmin: fakeSSOAdmin{}})
	if err != nil {
		t.Fatal(err)
	}
	if a := snap.IdentityCenter.Assignments; len(a) != 2 || a[0].PrincipalName != "" || a[0].PrincipalID != "g-1" {
		t.Errorf("without an identity store client principals are recorded by id only: %+v", a)
	}
	if !strings.Contains(Summary(snap), "Identity Center with 2 permission sets and 2 account assignments") {
		t.Errorf("summary should mention Identity Center: %s", Summary(snap))
	}
}

func TestCollectRequiresClient(t *testing.T) {
	if _, err := Collect(context.Background(), Options{}); err == nil {
		t.Fatal("expected an error without an Organizations client")
	}
}
