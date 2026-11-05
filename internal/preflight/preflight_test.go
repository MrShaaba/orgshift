package preflight

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/account"
	accounttypes "github.com/aws/aws-sdk-go-v2/service/account/types"
	"github.com/aws/aws-sdk-go-v2/service/cloudformation"
	cfntypes "github.com/aws/aws-sdk-go-v2/service/cloudformation/types"
	"github.com/aws/aws-sdk-go-v2/service/controlcatalog"
	cctypes "github.com/aws/aws-sdk-go-v2/service/controlcatalog/types"
	"github.com/aws/aws-sdk-go-v2/service/controltower"
	cttypes "github.com/aws/aws-sdk-go-v2/service/controltower/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/identitystore"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	orgtypes "github.com/aws/aws-sdk-go-v2/service/organizations/types"
	"github.com/aws/aws-sdk-go-v2/service/ram"
	ramtypes "github.com/aws/aws-sdk-go-v2/service/ram/types"
	"github.com/aws/aws-sdk-go-v2/service/resourceexplorer2"
	retypes "github.com/aws/aws-sdk-go-v2/service/resourceexplorer2/types"
	"github.com/aws/aws-sdk-go-v2/service/resourcegroupstaggingapi"
	tagtypes "github.com/aws/aws-sdk-go-v2/service/resourcegroupstaggingapi/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/aws-sdk-go-v2/service/ssoadmin"
	ssotypes "github.com/aws/aws-sdk-go-v2/service/ssoadmin/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	ststypes "github.com/aws/aws-sdk-go-v2/service/sts/types"
	"github.com/aws/smithy-go"

	"github.com/MrShaaba/orgshift/internal/collector"
	"github.com/MrShaaba/orgshift/internal/evaluator"
	"github.com/MrShaaba/orgshift/internal/snapshot"
)

// fake answers every API the preflight probes with a small organization.
// deny maps an operation name to the error it returns; assumeFail maps an
// account ID to the error AssumeRole returns for it.
type fake struct {
	account, arn  string
	deny          map[string]error
	assumeFail    map[string]error
	noLandingZone bool
	noInstance    bool
	trusted       []string
	throttleOnce  map[string]bool
	// aggregator is the Region of the member accounts' Resource Explorer
	// aggregator index; empty means none.
	aggregator string

	mu    sync.Mutex
	calls map[string]int
}

func newFake(account string) *fake {
	return &fake{account: account, arn: "arn:aws:sts::" + account + ":assumed-role/OrgshiftOrgRead/preflight", deny: map[string]error{}, assumeFail: map[string]error{}, calls: map[string]int{}, throttleOnce: map[string]bool{}}
}

func denied(op string) error {
	return &smithy.GenericAPIError{Code: "AccessDeniedException", Message: "not authorized to perform: " + op}
}

func (f *fake) call(op string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls[op]++
	if f.throttleOnce[op] {
		delete(f.throttleOnce, op)
		return &smithy.GenericAPIError{Code: "ThrottlingException", Message: "Rate exceeded"}
	}
	return f.deny[op]
}

func (f *fake) count(op string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls[op]
}

const (
	root   = "r-fake"
	ou     = "ou-fake-work"
	ouARN  = "arn:aws:organizations::111111111111:ou/o-fake/ou-fake-work"
	member = "111111111112"
)

func (f *fake) GetCallerIdentity(context.Context, *sts.GetCallerIdentityInput, ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error) {
	if err := f.call("GetCallerIdentity"); err != nil {
		return nil, err
	}
	return &sts.GetCallerIdentityOutput{Account: aws.String(f.account), Arn: aws.String(f.arn), UserId: aws.String("AROA:preflight")}, nil
}

func (f *fake) AssumeRole(_ context.Context, in *sts.AssumeRoleInput, _ ...func(*sts.Options)) (*sts.AssumeRoleOutput, error) {
	if err := f.call("AssumeRole"); err != nil {
		return nil, err
	}
	arn := aws.ToString(in.RoleArn)
	acct := strings.Split(arn, ":")[4]
	if err := f.assumeFail[acct]; err != nil {
		return nil, err
	}
	return &sts.AssumeRoleOutput{AssumedRoleUser: &ststypes.AssumedRoleUser{Arn: aws.String("arn:aws:sts::" + acct + ":assumed-role/OrgshiftMemberRead/orgshift-preflight")}}, nil
}

func (f *fake) DescribeOrganization(context.Context, *organizations.DescribeOrganizationInput, ...func(*organizations.Options)) (*organizations.DescribeOrganizationOutput, error) {
	if err := f.call("DescribeOrganization"); err != nil {
		return nil, err
	}
	return &organizations.DescribeOrganizationOutput{Organization: &orgtypes.Organization{Id: aws.String("o-fake"), MasterAccountId: aws.String("111111111111")}}, nil
}

func (f *fake) ListRoots(context.Context, *organizations.ListRootsInput, ...func(*organizations.Options)) (*organizations.ListRootsOutput, error) {
	if err := f.call("ListRoots"); err != nil {
		return nil, err
	}
	return &organizations.ListRootsOutput{Roots: []orgtypes.Root{{Id: aws.String(root), PolicyTypes: []orgtypes.PolicyTypeSummary{{Type: orgtypes.PolicyTypeServiceControlPolicy, Status: orgtypes.PolicyTypeStatusEnabled}}}}}, nil
}

func (f *fake) ListOrganizationalUnitsForParent(_ context.Context, in *organizations.ListOrganizationalUnitsForParentInput, _ ...func(*organizations.Options)) (*organizations.ListOrganizationalUnitsForParentOutput, error) {
	if err := f.call("ListOrganizationalUnitsForParent"); err != nil {
		return nil, err
	}
	if aws.ToString(in.ParentId) == root {
		return &organizations.ListOrganizationalUnitsForParentOutput{OrganizationalUnits: []orgtypes.OrganizationalUnit{{Id: aws.String(ou), Arn: aws.String(ouARN)}}}, nil
	}
	return &organizations.ListOrganizationalUnitsForParentOutput{}, nil
}

func (f *fake) ListAccountsForParent(_ context.Context, in *organizations.ListAccountsForParentInput, _ ...func(*organizations.Options)) (*organizations.ListAccountsForParentOutput, error) {
	if err := f.call("ListAccountsForParent"); err != nil {
		return nil, err
	}
	switch aws.ToString(in.ParentId) {
	case root:
		return &organizations.ListAccountsForParentOutput{Accounts: []orgtypes.Account{{Id: aws.String("111111111111"), Status: orgtypes.AccountStatusActive}}}, nil
	case ou:
		return &organizations.ListAccountsForParentOutput{Accounts: []orgtypes.Account{{Id: aws.String(member), Status: orgtypes.AccountStatusActive}, {Id: aws.String("111111111113"), Status: orgtypes.AccountStatusActive}, {Id: aws.String("111111111114"), Status: orgtypes.AccountStatusSuspended}}}, nil
	}
	return &organizations.ListAccountsForParentOutput{}, nil
}

func (f *fake) ListPolicies(_ context.Context, in *organizations.ListPoliciesInput, _ ...func(*organizations.Options)) (*organizations.ListPoliciesOutput, error) {
	if err := f.call("ListPolicies"); err != nil {
		return nil, err
	}
	if in.Filter != orgtypes.PolicyTypeServiceControlPolicy {
		return nil, &smithy.GenericAPIError{Code: "PolicyTypeNotEnabledException", Message: "not enabled"}
	}
	return &organizations.ListPoliciesOutput{Policies: []orgtypes.PolicySummary{{Id: aws.String("p-FullAWSAccess")}}}, nil
}

func (f *fake) DescribePolicy(context.Context, *organizations.DescribePolicyInput, ...func(*organizations.Options)) (*organizations.DescribePolicyOutput, error) {
	if err := f.call("DescribePolicy"); err != nil {
		return nil, err
	}
	return &organizations.DescribePolicyOutput{Policy: &orgtypes.Policy{Content: aws.String(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`)}}, nil
}

func (f *fake) ListTargetsForPolicy(context.Context, *organizations.ListTargetsForPolicyInput, ...func(*organizations.Options)) (*organizations.ListTargetsForPolicyOutput, error) {
	if err := f.call("ListTargetsForPolicy"); err != nil {
		return nil, err
	}
	return &organizations.ListTargetsForPolicyOutput{Targets: []orgtypes.PolicyTargetSummary{{TargetId: aws.String(root)}}}, nil
}

func (f *fake) ListTagsForResource(context.Context, *organizations.ListTagsForResourceInput, ...func(*organizations.Options)) (*organizations.ListTagsForResourceOutput, error) {
	if err := f.call("ListTagsForResource"); err != nil {
		return nil, err
	}
	return &organizations.ListTagsForResourceOutput{}, nil
}

func (f *fake) ListDelegatedAdministrators(context.Context, *organizations.ListDelegatedAdministratorsInput, ...func(*organizations.Options)) (*organizations.ListDelegatedAdministratorsOutput, error) {
	if err := f.call("ListDelegatedAdministrators"); err != nil {
		return nil, err
	}
	return &organizations.ListDelegatedAdministratorsOutput{DelegatedAdministrators: []orgtypes.DelegatedAdministrator{{Id: aws.String("111111111113")}}}, nil
}

func (f *fake) ListDelegatedServicesForAccount(context.Context, *organizations.ListDelegatedServicesForAccountInput, ...func(*organizations.Options)) (*organizations.ListDelegatedServicesForAccountOutput, error) {
	if err := f.call("ListDelegatedServicesForAccount"); err != nil {
		return nil, err
	}
	return &organizations.ListDelegatedServicesForAccountOutput{DelegatedServices: []orgtypes.DelegatedService{{ServicePrincipal: aws.String("guardduty.amazonaws.com")}}}, nil
}

func (f *fake) ListAWSServiceAccessForOrganization(context.Context, *organizations.ListAWSServiceAccessForOrganizationInput, ...func(*organizations.Options)) (*organizations.ListAWSServiceAccessForOrganizationOutput, error) {
	if err := f.call("ListAWSServiceAccessForOrganization"); err != nil {
		return nil, err
	}
	out := &organizations.ListAWSServiceAccessForOrganizationOutput{}
	for _, s := range f.trusted {
		out.EnabledServicePrincipals = append(out.EnabledServicePrincipals, orgtypes.EnabledServicePrincipal{ServicePrincipal: aws.String(s)})
	}
	return out, nil
}

func (f *fake) ListRegions(_ context.Context, in *account.ListRegionsInput, _ ...func(*account.Options)) (*account.ListRegionsOutput, error) {
	if err := f.call("ListRegions"); err != nil {
		return nil, err
	}
	return &account.ListRegionsOutput{Regions: []accounttypes.Region{{RegionName: aws.String("us-east-1")}}}, nil
}

func (f *fake) GetResourceShares(context.Context, *ram.GetResourceSharesInput, ...func(*ram.Options)) (*ram.GetResourceSharesOutput, error) {
	if err := f.call("GetResourceShares"); err != nil {
		return nil, err
	}
	return &ram.GetResourceSharesOutput{ResourceShares: []ramtypes.ResourceShare{{ResourceShareArn: aws.String("arn:aws:ram:us-east-1:" + f.account + ":resource-share/abc"), ResourceShareConfiguration: &ramtypes.ResourceShareConfiguration{RetainSharingOnAccountLeaveOrganization: aws.Bool(true)}}}}, nil
}

func (f *fake) ListPrincipals(context.Context, *ram.ListPrincipalsInput, ...func(*ram.Options)) (*ram.ListPrincipalsOutput, error) {
	if err := f.call("ListPrincipals"); err != nil {
		return nil, err
	}
	return &ram.ListPrincipalsOutput{Principals: []ramtypes.Principal{{Id: aws.String(member)}}}, nil
}

func (f *fake) ListResources(context.Context, *ram.ListResourcesInput, ...func(*ram.Options)) (*ram.ListResourcesOutput, error) {
	if err := f.call("ListResources"); err != nil {
		return nil, err
	}
	return &ram.ListResourcesOutput{Resources: []ramtypes.Resource{{Arn: aws.String("arn:aws:ec2:us-east-1:111111111111:transit-gateway/tgw-1"), Type: aws.String("ec2:TransitGateway")}}}, nil
}

func (f *fake) ListLandingZones(context.Context, *controltower.ListLandingZonesInput, ...func(*controltower.Options)) (*controltower.ListLandingZonesOutput, error) {
	if err := f.call("ListLandingZones"); err != nil {
		return nil, err
	}
	if f.noLandingZone {
		return &controltower.ListLandingZonesOutput{}, nil
	}
	return &controltower.ListLandingZonesOutput{LandingZones: []cttypes.LandingZoneSummary{{Arn: aws.String("arn:aws:controltower:us-east-1:111111111111:landingzone/LZ")}}}, nil
}

func (f *fake) GetLandingZone(context.Context, *controltower.GetLandingZoneInput, ...func(*controltower.Options)) (*controltower.GetLandingZoneOutput, error) {
	if err := f.call("GetLandingZone"); err != nil {
		return nil, err
	}
	return &controltower.GetLandingZoneOutput{LandingZone: &cttypes.LandingZoneDetail{Version: aws.String("3.3"), Status: cttypes.LandingZoneStatusActive}}, nil
}

func (f *fake) ListEnabledBaselines(context.Context, *controltower.ListEnabledBaselinesInput, ...func(*controltower.Options)) (*controltower.ListEnabledBaselinesOutput, error) {
	if err := f.call("ListEnabledBaselines"); err != nil {
		return nil, err
	}
	return &controltower.ListEnabledBaselinesOutput{EnabledBaselines: []cttypes.EnabledBaselineSummary{
		{Arn: aws.String("arn:aws:controltower:us-east-1:111111111111:enabledbaseline/A"), TargetIdentifier: aws.String(ouARN)},
		{Arn: aws.String("arn:aws:controltower:us-east-1:111111111111:enabledbaseline/B"), TargetIdentifier: aws.String("arn:aws:organizations::111111111111:account/o-fake/" + member)},
	}}, nil
}

func (f *fake) ListEnabledControls(context.Context, *controltower.ListEnabledControlsInput, ...func(*controltower.Options)) (*controltower.ListEnabledControlsOutput, error) {
	if err := f.call("ListEnabledControls"); err != nil {
		return nil, err
	}
	return &controltower.ListEnabledControlsOutput{EnabledControls: []cttypes.EnabledControlSummary{{ControlIdentifier: aws.String("arn:aws:controlcatalog:::control/abc")}}}, nil
}

func (f *fake) GetControl(context.Context, *controlcatalog.GetControlInput, ...func(*controlcatalog.Options)) (*controlcatalog.GetControlOutput, error) {
	if err := f.call("GetControl"); err != nil {
		return nil, err
	}
	return &controlcatalog.GetControlOutput{Name: aws.String("Disallow public buckets"), Behavior: cctypes.ControlBehaviorPreventive}, nil
}

func (f *fake) ListInstances(context.Context, *ssoadmin.ListInstancesInput, ...func(*ssoadmin.Options)) (*ssoadmin.ListInstancesOutput, error) {
	if err := f.call("ListInstances"); err != nil {
		return nil, err
	}
	if f.noInstance {
		return &ssoadmin.ListInstancesOutput{}, nil
	}
	return &ssoadmin.ListInstancesOutput{Instances: []ssotypes.InstanceMetadata{{InstanceArn: aws.String("arn:aws:sso:::instance/ssoins-1"), IdentityStoreId: aws.String("d-1")}}}, nil
}

func (f *fake) ListPermissionSets(context.Context, *ssoadmin.ListPermissionSetsInput, ...func(*ssoadmin.Options)) (*ssoadmin.ListPermissionSetsOutput, error) {
	if err := f.call("ListPermissionSets"); err != nil {
		return nil, err
	}
	return &ssoadmin.ListPermissionSetsOutput{PermissionSets: []string{"arn:aws:sso:::permissionSet/ssoins-1/ps-1"}}, nil
}

func (f *fake) DescribePermissionSet(context.Context, *ssoadmin.DescribePermissionSetInput, ...func(*ssoadmin.Options)) (*ssoadmin.DescribePermissionSetOutput, error) {
	if err := f.call("DescribePermissionSet"); err != nil {
		return nil, err
	}
	return &ssoadmin.DescribePermissionSetOutput{PermissionSet: &ssotypes.PermissionSet{Name: aws.String("Admin")}}, nil
}

func (f *fake) ListManagedPoliciesInPermissionSet(context.Context, *ssoadmin.ListManagedPoliciesInPermissionSetInput, ...func(*ssoadmin.Options)) (*ssoadmin.ListManagedPoliciesInPermissionSetOutput, error) {
	if err := f.call("ListManagedPoliciesInPermissionSet"); err != nil {
		return nil, err
	}
	return &ssoadmin.ListManagedPoliciesInPermissionSetOutput{}, nil
}

func (f *fake) ListCustomerManagedPolicyReferencesInPermissionSet(context.Context, *ssoadmin.ListCustomerManagedPolicyReferencesInPermissionSetInput, ...func(*ssoadmin.Options)) (*ssoadmin.ListCustomerManagedPolicyReferencesInPermissionSetOutput, error) {
	if err := f.call("ListCustomerManagedPolicyReferencesInPermissionSet"); err != nil {
		return nil, err
	}
	return &ssoadmin.ListCustomerManagedPolicyReferencesInPermissionSetOutput{}, nil
}

func (f *fake) GetInlinePolicyForPermissionSet(context.Context, *ssoadmin.GetInlinePolicyForPermissionSetInput, ...func(*ssoadmin.Options)) (*ssoadmin.GetInlinePolicyForPermissionSetOutput, error) {
	if err := f.call("GetInlinePolicyForPermissionSet"); err != nil {
		return nil, err
	}
	return &ssoadmin.GetInlinePolicyForPermissionSetOutput{}, nil
}

func (f *fake) GetPermissionsBoundaryForPermissionSet(context.Context, *ssoadmin.GetPermissionsBoundaryForPermissionSetInput, ...func(*ssoadmin.Options)) (*ssoadmin.GetPermissionsBoundaryForPermissionSetOutput, error) {
	if err := f.call("GetPermissionsBoundaryForPermissionSet"); err != nil {
		return nil, err
	}
	return nil, &ssotypes.ResourceNotFoundException{Message: aws.String("no boundary")}
}

func (f *fake) ListAccountsForProvisionedPermissionSet(context.Context, *ssoadmin.ListAccountsForProvisionedPermissionSetInput, ...func(*ssoadmin.Options)) (*ssoadmin.ListAccountsForProvisionedPermissionSetOutput, error) {
	if err := f.call("ListAccountsForProvisionedPermissionSet"); err != nil {
		return nil, err
	}
	return &ssoadmin.ListAccountsForProvisionedPermissionSetOutput{AccountIds: []string{member}}, nil
}

func (f *fake) ListAccountAssignments(context.Context, *ssoadmin.ListAccountAssignmentsInput, ...func(*ssoadmin.Options)) (*ssoadmin.ListAccountAssignmentsOutput, error) {
	if err := f.call("ListAccountAssignments"); err != nil {
		return nil, err
	}
	return &ssoadmin.ListAccountAssignmentsOutput{AccountAssignments: []ssotypes.AccountAssignment{{PrincipalType: ssotypes.PrincipalTypeGroup, PrincipalId: aws.String("g-1")}}}, nil
}

func (f *fake) DescribeUser(context.Context, *identitystore.DescribeUserInput, ...func(*identitystore.Options)) (*identitystore.DescribeUserOutput, error) {
	if err := f.call("DescribeUser"); err != nil {
		return nil, err
	}
	return &identitystore.DescribeUserOutput{UserName: aws.String("alice")}, nil
}

func (f *fake) DescribeGroup(context.Context, *identitystore.DescribeGroupInput, ...func(*identitystore.Options)) (*identitystore.DescribeGroupOutput, error) {
	if err := f.call("DescribeGroup"); err != nil {
		return nil, err
	}
	return &identitystore.DescribeGroupOutput{DisplayName: aws.String("Admins")}, nil
}

// The StackSet reads of the management account and the workload reads of
// a member account, answered by the same fake.

func (f *fake) ListStackSets(context.Context, *cloudformation.ListStackSetsInput, ...func(*cloudformation.Options)) (*cloudformation.ListStackSetsOutput, error) {
	if err := f.call("ListStackSets"); err != nil {
		return nil, err
	}
	return &cloudformation.ListStackSetsOutput{Summaries: []cfntypes.StackSetSummary{{StackSetName: aws.String("baseline-roles")}}}, nil
}

func (f *fake) DescribeStackSet(context.Context, *cloudformation.DescribeStackSetInput, ...func(*cloudformation.Options)) (*cloudformation.DescribeStackSetOutput, error) {
	if err := f.call("DescribeStackSet"); err != nil {
		return nil, err
	}
	return &cloudformation.DescribeStackSetOutput{StackSet: &cfntypes.StackSet{StackSetName: aws.String("baseline-roles"), PermissionModel: cfntypes.PermissionModelsServiceManaged}}, nil
}

func (f *fake) ListStackInstances(context.Context, *cloudformation.ListStackInstancesInput, ...func(*cloudformation.Options)) (*cloudformation.ListStackInstancesOutput, error) {
	if err := f.call("ListStackInstances"); err != nil {
		return nil, err
	}
	return &cloudformation.ListStackInstancesOutput{Summaries: []cfntypes.StackInstanceSummary{{Account: aws.String(member)}}}, nil
}

func (f *fake) DescribeStacks(context.Context, *cloudformation.DescribeStacksInput, ...func(*cloudformation.Options)) (*cloudformation.DescribeStacksOutput, error) {
	if err := f.call("DescribeStacks"); err != nil {
		return nil, err
	}
	return &cloudformation.DescribeStacksOutput{Stacks: []cfntypes.Stack{{StackName: aws.String("payments-api")}}}, nil
}

func (f *fake) ListStackResources(context.Context, *cloudformation.ListStackResourcesInput, ...func(*cloudformation.Options)) (*cloudformation.ListStackResourcesOutput, error) {
	if err := f.call("ListStackResources"); err != nil {
		return nil, err
	}
	return &cloudformation.ListStackResourcesOutput{StackResourceSummaries: []cfntypes.StackResourceSummary{{ResourceType: aws.String("AWS::IAM::Role")}}}, nil
}

func (f *fake) ListExports(context.Context, *cloudformation.ListExportsInput, ...func(*cloudformation.Options)) (*cloudformation.ListExportsOutput, error) {
	if err := f.call("ListExports"); err != nil {
		return nil, err
	}
	return &cloudformation.ListExportsOutput{}, nil
}

func (f *fake) ListImports(context.Context, *cloudformation.ListImportsInput, ...func(*cloudformation.Options)) (*cloudformation.ListImportsOutput, error) {
	if err := f.call("ListImports"); err != nil {
		return nil, err
	}
	return &cloudformation.ListImportsOutput{}, nil
}

func (f *fake) GetTemplate(context.Context, *cloudformation.GetTemplateInput, ...func(*cloudformation.Options)) (*cloudformation.GetTemplateOutput, error) {
	if err := f.call("GetTemplate"); err != nil {
		return nil, err
	}
	return &cloudformation.GetTemplateOutput{TemplateBody: aws.String(`{"Resources": {}}`)}, nil
}

func (f *fake) GetResources(context.Context, *resourcegroupstaggingapi.GetResourcesInput, ...func(*resourcegroupstaggingapi.Options)) (*resourcegroupstaggingapi.GetResourcesOutput, error) {
	if err := f.call("GetResources"); err != nil {
		return nil, err
	}
	return &resourcegroupstaggingapi.GetResourcesOutput{ResourceTagMappingList: []tagtypes.ResourceTagMapping{{ResourceARN: aws.String("arn:aws:sqs:us-east-1:" + member + ":events")}}}, nil
}

func (f *fake) ListIndexes(context.Context, *resourceexplorer2.ListIndexesInput, ...func(*resourceexplorer2.Options)) (*resourceexplorer2.ListIndexesOutput, error) {
	if err := f.call("ListIndexes"); err != nil {
		return nil, err
	}
	out := &resourceexplorer2.ListIndexesOutput{}
	if f.aggregator != "" {
		out.Indexes = []retypes.Index{{Region: aws.String(f.aggregator), Type: retypes.IndexTypeAggregator}}
	}
	return out, nil
}

func (f *fake) Search(context.Context, *resourceexplorer2.SearchInput, ...func(*resourceexplorer2.Options)) (*resourceexplorer2.SearchOutput, error) {
	if err := f.call("Search"); err != nil {
		return nil, err
	}
	return &resourceexplorer2.SearchOutput{Resources: []retypes.Resource{{Arn: aws.String("arn:aws:sqs:us-east-1:" + member + ":events")}}}, nil
}

func (f *fake) ListRoles(context.Context, *iam.ListRolesInput, ...func(*iam.Options)) (*iam.ListRolesOutput, error) {
	if err := f.call("ListRoles"); err != nil {
		return nil, err
	}
	return &iam.ListRolesOutput{Roles: []iamtypes.Role{{RoleName: aws.String("AppInstance")}}}, nil
}

func (f *fake) ListBuckets(context.Context, *s3.ListBucketsInput, ...func(*s3.Options)) (*s3.ListBucketsOutput, error) {
	if err := f.call("ListBuckets"); err != nil {
		return nil, err
	}
	return &s3.ListBucketsOutput{Buckets: []s3types.Bucket{{Name: aws.String("settlement")}}}, nil
}

func (f *fake) GetBucketPolicy(context.Context, *s3.GetBucketPolicyInput, ...func(*s3.Options)) (*s3.GetBucketPolicyOutput, error) {
	if err := f.call("GetBucketPolicy"); err != nil {
		return nil, err
	}
	return nil, &smithy.GenericAPIError{Code: "NoSuchBucketPolicy", Message: "The bucket policy does not exist"}
}

// memberFactory hands the fake out as the clients of any member account;
// the S3 client exists only with the opt-in, as in the CLI.
func memberFactory(f *fake, bucketPolicies bool) collector.MemberClientFactory {
	return func(context.Context, string, string) (*collector.MemberClients, error) {
		mc := &collector.MemberClients{Stacks: f, Tagging: f, ResourceExplorer: f, Roles: f}
		if bucketPolicies {
			mc.Buckets = f
		}
		return mc, nil
	}
}

// clientsFor wires one fake into every client slot.
func clientsFor(f *fake, label, expected string) *Clients {
	return &Clients{Label: label, ExpectedAccount: expected, Via: "profile test", Region: "us-east-1", STS: f, Organizations: f, Account: f, RAM: f, ControlTower: f, ControlTowerRegion: "us-east-1", ControlCatalog: f, SSOAdmin: f, IdentityCenterRegion: "us-east-1", IdentityStore: f, StackSets: f}
}

func side(name string, f *fake, expected string) SideInput {
	return SideInput{Name: name, Management: clientsFor(f, "management", expected),
		Member: &Member{RoleName: "OrgshiftMemberRead", Accounts: []string{member}, Sample: 2, STS: f, Clients: memberFactory(f, false), Regions: []string{"us-east-1"}}, Skip: map[string]string{}}
}

func domain(t *testing.T, s SideResult, name string) DomainResult {
	t.Helper()
	for _, d := range s.Domains {
		if d.Domain == name {
			return d
		}
	}
	t.Fatalf("no domain %s in %+v", name, s.Domains)
	return DomainResult{}
}

func fixedClock() func() time.Time {
	t := time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)
	return func() time.Time { t = t.Add(time.Millisecond); return t }
}

func TestEverythingAvailableIsReady(t *testing.T) {
	src, dst := newFake("111111111111"), newFake("222222222222")
	src.trusted = []string{"account.amazonaws.com", "controltower.amazonaws.com", "sso.amazonaws.com"}
	res := Run(context.Background(), Input{Sides: []SideInput{side("source", src, "111111111111"), side("destination", dst, "222222222222")}, Version: "test", Now: fixedClock()})
	if !res.Ready || len(res.Blocking) != 0 || !strings.HasPrefix(res.GeneratedAt, "2026-11-02T12:00:00") {
		t.Fatalf("expected ready: %+v (generated %s)", res.Blocking, res.GeneratedAt)
	}
	if len(res.Matrix.Rows) != len(evaluator.DescribeDomains())+1 || res.Matrix.SingleSide {
		t.Fatalf("matrix rows: %d", len(res.Matrix.Rows))
	}
	s := res.Sides[0]
	for _, d := range s.Domains {
		switch d.Domain {
		case snapshot.DomainOrgTrails, snapshot.DomainConfigAggregator:
			if d.Status != Unknown || d.Required || !strings.Contains(d.Detail, "not collected by this build") {
				t.Errorf("%s should be unknown and not required: %+v", d.Domain, d)
			}
		default:
			if d.Status != Available || !d.Required {
				t.Errorf("%s should be available and required: %+v", d.Domain, d)
			}
		}
	}
	ops := map[string]bool{}
	for _, p := range s.Probes {
		ops[p.Operation] = true
		if p.Status == Available && p.Millis < 0 {
			t.Errorf("probe timing: %+v", p)
		}
	}
	for _, want := range []string{"organizations:DescribeOrganization", "organizations:ListTargetsForPolicy", "account:ListRegions", "ram:ListResources", "controltower:ListEnabledControls", "controlcatalog:GetControl", "sso:ListAccountAssignments", "identitystore:DescribeGroup", "sts:AssumeRole", "organizations:ListDelegatedServicesForAccount",
		"cloudformation:ListStackSets", "cloudformation:DescribeStackSet", "cloudformation:ListStackInstances", "cloudformation:DescribeStacks", "cloudformation:ListStackResources", "cloudformation:ListExports", "cloudformation:GetTemplate",
		"tag:GetResources", "resource-explorer-2:ListIndexes", "iam:ListRoles"} {
		if !ops[want] {
			t.Errorf("%s was not probed; probed: %v", want, ops)
		}
	}
	// The configured account plus a sample of two more: only one other
	// active member exists (the management account and the suspended
	// account are skipped), so two roles are assumed.
	if n := src.count("AssumeRole"); n != 2 {
		t.Errorf("member role should be tried in the configured account plus the one other active member, got %d", n)
	}
	if d := domain(t, s, MemberInspectionDomain); d.Status != Available || !strings.Contains(d.Detail, "2 call(s)") {
		t.Errorf("member inspection: %+v", d)
	}
	if d := domain(t, s, snapshot.DomainPoliciesRCP); d.Status != Available {
		t.Errorf("a disabled policy type is still a permitted call: %+v", d)
	}
	if len(s.Identities) != 1 || s.Identities[0].Status != Available || s.Identities[0].Actual.ARN != src.arn || s.Identities[0].Via != "profile test" {
		t.Errorf("identities: %+v", s.Identities)
	}
	for _, row := range res.Matrix.Rows {
		if row.Domain == snapshot.DomainTree && (row.Why == "" || row.Check != "coverage" || row.Source.Status != Available || row.Target.Status != Available) {
			t.Errorf("tree row: %+v", row)
		}
		if row.Domain == MemberInspectionDomain && row.Why == "" {
			t.Errorf("member row needs a description: %+v", row)
		}
	}
	if !strings.Contains(res.Line(), "ready") {
		t.Errorf("line: %s", res.Line())
	}
}

func TestDeniedCallsBlockAndNameTheGrant(t *testing.T) {
	src := newFake("111111111111")
	src.deny["GetResourceShares"] = denied("ram:GetResourceShares")
	src.deny["ListEnabledControls"] = denied("controltower:ListEnabledControls")
	net := newFake("111111111120")
	net.deny["ListPrincipals"] = denied("ram:ListPrincipals")
	in := side("source", src, "111111111111")
	in.Network = []*Clients{clientsFor(net, "network account", "111111111120")}
	res := Run(context.Background(), Input{Sides: []SideInput{in}, Now: fixedClock()})
	if res.Ready || len(res.Blocking) != 3 {
		t.Fatalf("expected three blocking items: %+v", res.Blocking)
	}
	joined := strings.Join(res.Blocking, "\n")
	for _, want := range []string{"source: ram:GetResourceShares denied for management", "grant it to arn:aws:sts::111111111111:assumed-role/OrgshiftOrgRead/preflight", "ram:ListPrincipals denied for network account", "controltower:ListEnabledControls denied"} {
		if !strings.Contains(joined, want) {
			t.Errorf("blocking should contain %q:\n%s", want, joined)
		}
	}
	s := res.Sides[0]
	if d := domain(t, s, snapshot.DomainResourceShares); d.Status != Denied || !strings.Contains(d.Detail, "ram:GetResourceShares denied") || !strings.Contains(d.Detail, "network account ram:ListPrincipals denied") {
		t.Errorf("shares domain: %+v", d)
	}
	if d := domain(t, s, snapshot.DomainControlTower); d.Status != Denied {
		t.Errorf("control tower domain: %+v", d)
	}
	if d := domain(t, s, snapshot.DomainEnrolledAccounts); d.Status != Available {
		t.Errorf("enrolled accounts come from ListEnabledBaselines, which succeeded: %+v", d)
	}
	if d := domain(t, s, snapshot.DomainTree); d.Status != Available {
		t.Errorf("unrelated domains stay available: %+v", d)
	}
	if res.Matrix.Rows[0].Target.Status != Unknown || !res.Matrix.SingleSide {
		t.Errorf("single side: %+v", res.Matrix.Rows[0].Target)
	}
	if len(res.Notes) < 2 || !strings.Contains(res.Notes[1], "docs/iam") {
		t.Errorf("notes: %v", res.Notes)
	}
}

func TestIdentityMismatchStopsTheSide(t *testing.T) {
	wrong := newFake("999999999999")
	res := Run(context.Background(), Input{Sides: []SideInput{side("source", wrong, "111111111111")}, Now: fixedClock()})
	if res.Ready {
		t.Fatal("a mismatch is not ready")
	}
	s := res.Sides[0]
	if len(s.Identities) != 1 || s.Identities[0].Status != Mismatch || !strings.Contains(s.Identities[0].Detail, "999999999999") {
		t.Errorf("identity: %+v", s.Identities)
	}
	if !strings.Contains(strings.Join(res.Blocking, "\n"), "identity mismatch") {
		t.Errorf("blocking: %v", res.Blocking)
	}
	if wrong.count("DescribeOrganization")+wrong.count("ListInstances")+wrong.count("AssumeRole") != 0 {
		t.Error("nothing must be probed with credentials for the wrong account")
	}
	for _, d := range []string{snapshot.DomainOrganization, snapshot.DomainIdentityCenter, MemberInspectionDomain, snapshot.DomainResourceShares} {
		if r := domain(t, s, d); r.Status != Unknown || !strings.Contains(r.Detail, "identity check failed") {
			t.Errorf("%s: %+v", d, r)
		}
	}
	// A credential that cannot be resolved at all is an error, not a mismatch.
	broken := newFake("111111111111")
	broken.deny["GetCallerIdentity"] = errors.New("ExpiredToken: The security token included in the request is expired")
	res = Run(context.Background(), Input{Sides: []SideInput{side("source", broken, "111111111111")}})
	if res.Ready || res.Sides[0].Identities[0].Status != Failed || !strings.Contains(res.Blocking[0], "ExpiredToken") {
		t.Errorf("broken credentials: %+v %v", res.Sides[0].Identities, res.Blocking)
	}
}

func TestControlTowerAndIdentityCenterAbsenceIsReadWithTrustedAccess(t *testing.T) {
	f := newFake("111111111111")
	f.noLandingZone, f.noInstance = true, true
	f.trusted = []string{"controltower.amazonaws.com", "sso.amazonaws.com"}
	res := Run(context.Background(), Input{Sides: []SideInput{side("source", f, "111111111111")}})
	s := res.Sides[0]
	if d := domain(t, s, snapshot.DomainControlTower); d.Status != Failed || !strings.Contains(d.Detail, "control_tower.home_region") {
		t.Errorf("wrong region should be an error with the hint: %+v", d)
	}
	if d := domain(t, s, snapshot.DomainEnrolledAccounts); d.Status != Unknown || !strings.Contains(d.Detail, "landing zone lookup failed") {
		t.Errorf("enrolled accounts follow: %+v", d)
	}
	if d := domain(t, s, snapshot.DomainIdentityCenter); d.Status != Failed || !strings.Contains(d.Detail, "identity_center.region") {
		t.Errorf("identity center wrong region: %+v", d)
	}
	// Without trusted access the empty answers are confirmed absences.
	f = newFake("111111111111")
	f.noLandingZone, f.noInstance = true, true
	res = Run(context.Background(), Input{Sides: []SideInput{side("source", f, "111111111111")}})
	s = res.Sides[0]
	if d := domain(t, s, snapshot.DomainControlTower); d.Status != Available {
		t.Errorf("no landing zone and no trusted access is fine: %+v", d)
	}
	if d := domain(t, s, snapshot.DomainIdentityCenter); d.Status != Available {
		t.Errorf("no instance and no trusted access is fine: %+v", d)
	}
	if !res.Ready {
		t.Errorf("should be ready: %v", res.Blocking)
	}
}

func TestMemberRoleDeniedInOneAccount(t *testing.T) {
	f := newFake("111111111111")
	f.assumeFail["111111111113"] = denied("sts:AssumeRole")
	in := side("source", f, "111111111111")
	in.Member.Accounts = []string{member, "111111111113"}
	in.Member.Sample = 0
	res := Run(context.Background(), Input{Sides: []SideInput{in}})
	d := domain(t, res.Sides[0], MemberInspectionDomain)
	if d.Status != Denied || !strings.Contains(d.Detail, "member 111111111113 sts:AssumeRole denied") || strings.Contains(d.Detail, member+" sts:AssumeRole denied") {
		t.Errorf("member domain: %+v", d)
	}
	if res.Ready || !strings.Contains(strings.Join(res.Blocking, "\n"), "sts:AssumeRole denied for member 111111111113") {
		t.Errorf("blocking: %v", res.Blocking)
	}
	if f.count("AssumeRole") != 2 {
		t.Errorf("sample 0 means only the configured accounts: %d", f.count("AssumeRole"))
	}
	// Without a member configuration there is no row to fill in.
	in.Member = nil
	res = Run(context.Background(), Input{Sides: []SideInput{in}})
	if d := domain(t, res.Sides[0], MemberInspectionDomain); d.Status != Unknown {
		t.Errorf("no member role configured: %+v", d)
	}
}

func TestSkippedDomainsAreNotRequired(t *testing.T) {
	f := newFake("111111111111")
	in := side("source", f, "111111111111")
	in.Skip = map[string]string{snapshot.DomainResourceShares: "configuration: skip", snapshot.DomainControlTower: "configuration: skip", snapshot.DomainIdentityCenter: "configuration: skip"}
	res := Run(context.Background(), Input{Sides: []SideInput{in}})
	for _, d := range []string{snapshot.DomainResourceShares, snapshot.DomainControlTower, snapshot.DomainEnrolledAccounts, snapshot.DomainIdentityCenter} {
		if r := domain(t, res.Sides[0], d); r.Status != Skipped || r.Required {
			t.Errorf("%s: %+v", d, r)
		}
	}
	if f.count("GetResourceShares")+f.count("ListLandingZones")+f.count("ListInstances") != 0 {
		t.Error("skipped domains must not be called")
	}
	if !res.Ready {
		t.Errorf("skipped is not blocking: %v", res.Blocking)
	}
}

func TestThrottlingIsRetried(t *testing.T) {
	f := newFake("111111111111")
	f.throttleOnce["DescribeOrganization"] = true
	var slept []time.Duration
	sleep := func(ctx context.Context, d time.Duration) error { slept = append(slept, d); return nil }
	res := Run(context.Background(), Input{Sides: []SideInput{side("source", f, "111111111111")}, Sleep: sleep, Retry: collector.RetryOptions{Attempts: 3, Base: time.Millisecond, Cap: time.Millisecond}})
	if d := domain(t, res.Sides[0], snapshot.DomainOrganization); d.Status != Available {
		t.Errorf("a throttled probe is retried: %+v", d)
	}
	if f.count("DescribeOrganization") != 2 || len(slept) != 1 {
		t.Errorf("calls=%d slept=%v", f.count("DescribeOrganization"), slept)
	}
}

func TestSeparateIdentityCenterAccessIsVerified(t *testing.T) {
	f := newFake("111111111111")
	delegated := newFake("111111111130")
	in := side("source", f, "111111111111")
	in.IdentityCenter = clientsFor(delegated, "identity center", "111111111130")
	res := Run(context.Background(), Input{Sides: []SideInput{in}})
	s := res.Sides[0]
	if len(s.Identities) != 2 || s.Identities[1].Access != "identity center" || s.Identities[1].Status != Available {
		t.Errorf("identities: %+v", s.Identities)
	}
	if delegated.count("ListInstances") != 1 || f.count("ListInstances") != 0 {
		t.Error("identity center reads go through the delegated credentials")
	}
	if d := domain(t, s, snapshot.DomainIdentityCenter); d.Status != Available {
		t.Errorf("identity center: %+v", d)
	}
}

// The workload reads are probed inside the accounts named for inspection:
// one page of each, never the billed S3 reads unless they are opted in.
func TestWorkloadProbes(t *testing.T) {
	f := newFake("111111111111")
	res := Run(context.Background(), Input{Sides: []SideInput{side("source", f, "111111111111")}})
	s := res.Sides[0]
	if !res.Ready {
		t.Fatalf("everything is available: %v", res.Blocking)
	}
	for _, d := range snapshot.WorkloadDomains {
		if r := domain(t, s, d); r.Status != Available || !r.Required {
			t.Errorf("%s: %+v", d, r)
		}
	}
	if d := domain(t, s, snapshot.DomainStackSets); d.Status != Available || !strings.Contains(d.Detail, "3 call(s)") {
		t.Errorf("stack sets: %+v", d)
	}
	if f.count("ListBuckets")+f.count("GetBucketPolicy") != 0 {
		t.Errorf("the billed S3 reads are not probed without the opt-in: %d", f.count("ListBuckets")+f.count("GetBucketPolicy"))
	}
	if f.count("ListImports") != 0 {
		t.Error("ListImports has nothing safe to probe and is left to the collector")
	}
	var bucketNote, explorerNote string
	for _, p := range s.Probes {
		if p.Operation == "s3:GetBucketPolicy" {
			bucketNote = string(p.Status) + ": " + p.Detail
		}
		if p.Operation == "resource-explorer-2:ListIndexes" {
			explorerNote = string(p.Status) + ": " + p.Detail
		}
		if snapshot.IsWorkloadDomain(p.Domain) && p.Access != "member "+member {
			t.Errorf("workload probes run inside the member account: %+v", p)
		}
	}
	if !strings.Contains(bucketNote, "unknown: not tried: bucket policies are a billed read") || !strings.Contains(bucketNote, "partially evaluated") {
		t.Errorf("the S3 probe says why it was not tried: %s", bucketNote)
	}
	if !strings.Contains(explorerNote, "available: no aggregator index: the collector uses the Resource Groups Tagging API") {
		t.Errorf("resource explorer without an aggregator: %s", explorerNote)
	}

	// With the opt-in the S3 reads are probed: one bucket, billed.
	f = newFake("111111111111")
	in := side("source", f, "111111111111")
	in.Member.Clients, in.Member.BucketPolicies = memberFactory(f, true), true
	res = Run(context.Background(), Input{Sides: []SideInput{in}})
	if f.count("ListBuckets") != 1 || f.count("GetBucketPolicy") != 1 || !res.Ready {
		t.Errorf("opted in: %d ListBuckets, %d GetBucketPolicy, ready %t", f.count("ListBuckets"), f.count("GetBucketPolicy"), res.Ready)
	}
	// An aggregator index is searched; a denied search does not block when
	// the source is auto, because the Tagging API is the fallback.
	f = newFake("111111111111")
	f.aggregator = "us-east-1"
	f.deny["Search"] = denied("resource-explorer-2:Search")
	res = Run(context.Background(), Input{Sides: []SideInput{side("source", f, "111111111111")}})
	if d := domain(t, res.Sides[0], snapshot.DomainWorkloadResources); !res.Ready || d.Status != Available || f.count("Search") != 1 {
		t.Errorf("a failed search with the Tagging API available: %+v ready %t", d, res.Ready)
	}
	// Asked for explicitly, the same denial blocks.
	f = newFake("111111111111")
	f.aggregator = "us-east-1"
	f.deny["Search"] = denied("resource-explorer-2:Search")
	in = side("source", f, "111111111111")
	in.Member.ResourceSource = snapshot.ResourceSourceResourceExplorer
	res = Run(context.Background(), Input{Sides: []SideInput{in}})
	if d := domain(t, res.Sides[0], snapshot.DomainWorkloadResources); res.Ready || d.Status != Denied || f.count("GetResources") != 0 {
		t.Errorf("explicit resource-explorer with a denied search: %+v", d)
	}
	// A denied read inside the member account blocks and names the call.
	f = newFake("111111111111")
	f.deny["DescribeStacks"] = denied("cloudformation:DescribeStacks")
	res = Run(context.Background(), Input{Sides: []SideInput{side("source", f, "111111111111")}})
	if d := domain(t, res.Sides[0], snapshot.DomainWorkloadStacks); res.Ready || d.Status != Denied || !strings.Contains(strings.Join(res.Blocking, "\n"), "cloudformation:DescribeStacks denied for member "+member) {
		t.Errorf("denied stacks: %+v %v", d, res.Blocking)
	}
	if f.count("GetTemplate") != 0 {
		t.Error("nothing more is tried in a domain whose first call was denied")
	}
	// No account named: nothing to try, and that is said rather than
	// shown as available.
	f = newFake("111111111111")
	in = side("source", f, "111111111111")
	in.Member.Accounts = nil
	res = Run(context.Background(), Input{Sides: []SideInput{in}})
	for _, d := range snapshot.WorkloadDomains {
		if r := domain(t, res.Sides[0], d); r.Status != Unknown || r.Required || !strings.Contains(r.Detail, "no account named under member_inspection.accounts") {
			t.Errorf("%s without accounts: %+v", d, r)
		}
	}
	if !res.Ready || f.count("DescribeStacks") != 0 {
		t.Errorf("nothing to inspect is not blocking: %v", res.Blocking)
	}
	// Skipped by configuration.
	f = newFake("111111111111")
	in = side("source", f, "111111111111")
	in.Skip = map[string]string{snapshot.DomainStackSets: "configuration: skip stack_sets"}
	for _, d := range snapshot.WorkloadDomains {
		in.Skip[d] = "configuration: skip workloads"
	}
	res = Run(context.Background(), Input{Sides: []SideInput{in}})
	for _, d := range append([]string{snapshot.DomainStackSets}, snapshot.WorkloadDomains...) {
		if r := domain(t, res.Sides[0], d); r.Status != Skipped || r.Required {
			t.Errorf("%s skipped: %+v", d, r)
		}
	}
	if f.count("ListStackSets")+f.count("DescribeStacks")+f.count("GetResources")+f.count("ListRoles") != 0 {
		t.Error("skipped domains must not be called")
	}
}
