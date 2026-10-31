package collector

import (
	"context"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/account"
	accounttypes "github.com/aws/aws-sdk-go-v2/service/account/types"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	orgtypes "github.com/aws/aws-sdk-go-v2/service/organizations/types"
	"github.com/aws/aws-sdk-go-v2/service/ram"
	ramtypes "github.com/aws/aws-sdk-go-v2/service/ram/types"

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
		return &organizations.ListOrganizationalUnitsForParentOutput{OrganizationalUnits: []orgtypes.OrganizationalUnit{{Id: aws.String("ou-fake-work"), Name: aws.String("Workloads")}}}, nil
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
		{ResourceShareArn: aws.String("arn:aws:ram:us-east-1:111111111111:resource-share/abc"), Name: aws.String("net"), OwningAccountId: aws.String("111111111111"), Status: ramtypes.ResourceShareStatusActive},
		{ResourceShareArn: aws.String("arn:aws:ram:us-east-1:111111111111:resource-share/old"), Name: aws.String("old"), OwningAccountId: aws.String("111111111111"), Status: ramtypes.ResourceShareStatusDeleted},
	}}, nil
}
func (fakeRAM) ListPrincipals(context.Context, *ram.ListPrincipalsInput, ...func(*ram.Options)) (*ram.ListPrincipalsOutput, error) {
	return &ram.ListPrincipalsOutput{Principals: []ramtypes.Principal{{Id: aws.String("arn:aws:organizations::111111111111:organization/o-fake00000001")}}}, nil
}
func (fakeRAM) ListResources(context.Context, *ram.ListResourcesInput, ...func(*ram.Options)) (*ram.ListResourcesOutput, error) {
	return &ram.ListResourcesOutput{Resources: []ramtypes.Resource{{Arn: aws.String("arn:aws:ec2:us-east-1:111111111111:transit-gateway/tgw-1"), Type: aws.String("ec2:TransitGateway")}}}, nil
}

type fakeAccount struct{}

func (fakeAccount) ListRegions(context.Context, *account.ListRegionsInput, ...func(*account.Options)) (*account.ListRegionsOutput, error) {
	return &account.ListRegionsOutput{Regions: []accounttypes.Region{{RegionName: aws.String("us-east-1")}, {RegionName: aws.String("eu-west-1")}}}, nil
}

func TestCollectBuildsAValidSnapshot(t *testing.T) {
	snap, err := Collect(context.Background(), Options{
		Name: "Fake Org", Organizations: fakeOrgs{}, RAM: []RAMAPI{fakeRAM{}}, Account: fakeAccount{},
		Now: func() time.Time { return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC) },
	})
	if err != nil {
		t.Fatal(err)
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

func TestCollectRequiresClient(t *testing.T) {
	if _, err := Collect(context.Background(), Options{}); err == nil {
		t.Fatal("expected an error without an Organizations client")
	}
}
