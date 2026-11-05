package collector

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudformation"
	cfntypes "github.com/aws/aws-sdk-go-v2/service/cloudformation/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/resourceexplorer2"
	redoc "github.com/aws/aws-sdk-go-v2/service/resourceexplorer2/document"
	retypes "github.com/aws/aws-sdk-go-v2/service/resourceexplorer2/types"
	"github.com/aws/aws-sdk-go-v2/service/resourcegroupstaggingapi"
	tagtypes "github.com/aws/aws-sdk-go-v2/service/resourcegroupstaggingapi/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"

	"github.com/MrShaaba/orgshift/internal/snapshot"
	"github.com/MrShaaba/orgshift/internal/workload"
)

// Everything below is fake: fictional accounts, stacks and policies served
// from memory. No test in this package makes a network call.

const memberAccount = "111111111112"

// A template in YAML with the short forms, a secret-looking default that
// must never reach the snapshot, a cross-account stack output, an import,
// and two policies conditioned on the organization: one resolvable through
// a parameter, one computed at deployment.
const apiTemplate = `AWSTemplateFormatVersion: "2010-09-09"
Description: payments api
Parameters:
  AppSubnetIds:
    Type: List<AWS::EC2::Subnet::Id>
  OrgId:
    Type: String
  ApiKey:
    Type: String
    Default: SuperSecretValue-do-not-store
Resources:
  Group:
    Type: AWS::AutoScaling::AutoScalingGroup
    Properties:
      VPCZoneIdentifier: !Ref AppSubnetIds
      Tags:
        - Key: vpc
          Value: !ImportValue payments-vpc-id
  LogRole:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Version: "2012-10-17"
        Statement:
          - Sid: FromTheOrganization
            Effect: Allow
            Principal: {AWS: "*"}
            Action: sts:AssumeRole
            Condition:
              StringEquals:
                aws:PrincipalOrgID: !Ref OrgId
  Topic:
    Type: AWS::SNS::TopicPolicy
    Properties:
      PolicyDocument:
        Statement:
          Effect: Allow
          Principal: "*"
          Action: sns:Publish
          Condition:
            ForAnyValue:StringLike:
              aws:PrincipalOrgPaths:
                - !Sub "${OrgId}/r-root/ou-work/*"
  Subscription:
    Type: AWS::Logs::SubscriptionFilter
    Properties:
      DestinationArn:
        Fn::GetStackOutput:
          StackName: shared-observability
          OutputName: LogDestinationArn
          Region: us-east-1
          RoleArn: arn:aws:iam::111111111199:role/CfnOutputReader
  Attachment:
    Type: AWS::EC2::TransitGatewayAttachment
    Properties:
      TransitGatewayId: tgw-0123456789abcdef0
Outputs:
  Endpoint:
    Value: https://internal.example.test/secret-path
`

const networkTemplate = `{"Resources": {"Vpc": {"Type": "AWS::EC2::VPC"}}, "Outputs": {"VpcId": {"Value": {"Ref": "Vpc"}, "Export": {"Name": "payments-vpc-id"}}}}`

type fakeMember struct {
	mu    sync.Mutex
	calls map[string]int
	deny  map[string]bool
	// region is the Region the clients were built for.
	region     string
	aggregator string
	searchFail bool
	stacks     []cfntypes.Stack
	templates  map[string]string
	resources  map[string][]string
	exports    []cfntypes.Export
	imports    map[string][]string
	tagged     []tagtypes.ResourceTagMapping
	explored   []retypes.Resource
	roles      []iamtypes.Role
	buckets    []s3types.Bucket
	policies   map[string]string
}

func (f *fakeMember) call(op string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.calls == nil {
		f.calls = map[string]int{}
	}
	f.calls[op]++
	if f.deny[op] || f.deny["*"] {
		return &smithy.GenericAPIError{Code: "AccessDenied", Message: "User is not authorized to perform: " + op}
	}
	return nil
}

func (f *fakeMember) count(op string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls[op]
}

func (f *fakeMember) DescribeStacks(context.Context, *cloudformation.DescribeStacksInput, ...func(*cloudformation.Options)) (*cloudformation.DescribeStacksOutput, error) {
	if err := f.call("DescribeStacks"); err != nil {
		return nil, err
	}
	return &cloudformation.DescribeStacksOutput{Stacks: f.stacks}, nil
}

func (f *fakeMember) ListStackResources(_ context.Context, in *cloudformation.ListStackResourcesInput, _ ...func(*cloudformation.Options)) (*cloudformation.ListStackResourcesOutput, error) {
	if err := f.call("ListStackResources"); err != nil {
		return nil, err
	}
	out := &cloudformation.ListStackResourcesOutput{}
	for i, t := range f.resources[aws.ToString(in.StackName)] {
		out.StackResourceSummaries = append(out.StackResourceSummaries, cfntypes.StackResourceSummary{ResourceType: aws.String(t), LogicalResourceId: aws.String("R" + string(rune('a'+i)))})
	}
	return out, nil
}

func (f *fakeMember) ListExports(context.Context, *cloudformation.ListExportsInput, ...func(*cloudformation.Options)) (*cloudformation.ListExportsOutput, error) {
	if err := f.call("ListExports"); err != nil {
		return nil, err
	}
	return &cloudformation.ListExportsOutput{Exports: f.exports}, nil
}

func (f *fakeMember) ListImports(_ context.Context, in *cloudformation.ListImportsInput, _ ...func(*cloudformation.Options)) (*cloudformation.ListImportsOutput, error) {
	if err := f.call("ListImports"); err != nil {
		return nil, err
	}
	importers, ok := f.imports[aws.ToString(in.ExportName)]
	if !ok {
		return nil, &smithy.GenericAPIError{Code: "ValidationError", Message: "Export '" + aws.ToString(in.ExportName) + "' is not imported by any stack."}
	}
	return &cloudformation.ListImportsOutput{Imports: importers}, nil
}

func (f *fakeMember) GetTemplate(_ context.Context, in *cloudformation.GetTemplateInput, _ ...func(*cloudformation.Options)) (*cloudformation.GetTemplateOutput, error) {
	if err := f.call("GetTemplate"); err != nil {
		return nil, err
	}
	return &cloudformation.GetTemplateOutput{TemplateBody: aws.String(f.templates[aws.ToString(in.StackName)])}, nil
}

func (f *fakeMember) GetResources(context.Context, *resourcegroupstaggingapi.GetResourcesInput, ...func(*resourcegroupstaggingapi.Options)) (*resourcegroupstaggingapi.GetResourcesOutput, error) {
	if err := f.call("GetResources"); err != nil {
		return nil, err
	}
	return &resourcegroupstaggingapi.GetResourcesOutput{ResourceTagMappingList: f.tagged}, nil
}

func (f *fakeMember) ListIndexes(context.Context, *resourceexplorer2.ListIndexesInput, ...func(*resourceexplorer2.Options)) (*resourceexplorer2.ListIndexesOutput, error) {
	if err := f.call("ListIndexes"); err != nil {
		return nil, err
	}
	out := &resourceexplorer2.ListIndexesOutput{}
	if f.aggregator != "" {
		out.Indexes = []retypes.Index{{Region: aws.String(f.aggregator), Type: retypes.IndexTypeAggregator}}
	}
	return out, nil
}

func (f *fakeMember) Search(context.Context, *resourceexplorer2.SearchInput, ...func(*resourceexplorer2.Options)) (*resourceexplorer2.SearchOutput, error) {
	if err := f.call("Search"); err != nil {
		return nil, err
	}
	if f.searchFail {
		return nil, &smithy.GenericAPIError{Code: "UnauthorizedException", Message: "no default view in this Region"}
	}
	return &resourceexplorer2.SearchOutput{Resources: f.explored}, nil
}

func (f *fakeMember) ListRoles(context.Context, *iam.ListRolesInput, ...func(*iam.Options)) (*iam.ListRolesOutput, error) {
	if err := f.call("ListRoles"); err != nil {
		return nil, err
	}
	return &iam.ListRolesOutput{Roles: f.roles}, nil
}

func (f *fakeMember) ListBuckets(context.Context, *s3.ListBucketsInput, ...func(*s3.Options)) (*s3.ListBucketsOutput, error) {
	if err := f.call("ListBuckets"); err != nil {
		return nil, err
	}
	return &s3.ListBucketsOutput{Buckets: f.buckets}, nil
}

func (f *fakeMember) GetBucketPolicy(_ context.Context, in *s3.GetBucketPolicyInput, _ ...func(*s3.Options)) (*s3.GetBucketPolicyOutput, error) {
	if err := f.call("GetBucketPolicy"); err != nil {
		return nil, err
	}
	doc, ok := f.policies[aws.ToString(in.Bucket)]
	if !ok {
		return nil, &smithy.GenericAPIError{Code: "NoSuchBucketPolicy", Message: "The bucket policy does not exist"}
	}
	return &s3.GetBucketPolicyOutput{Policy: aws.String(doc)}, nil
}

const orgTrust = `{"Version":"2012-10-17","Statement":[{"Sid":"DataPlatform","Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole","Condition":{"StringEquals":{"aws:PrincipalOrgID":"o-example00001"}}}]}`
const plainTrust = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}`
const perimeterPolicy = `{"Version":"2012-10-17","Statement":[{"Sid":"Perimeter","Effect":"Deny","Principal":"*","Action":"s3:*","Resource":"arn:aws:s3:::settlement/*","Condition":{"StringNotEqualsIfExists":{"aws:PrincipalOrgID":"o-example00001"}}}]}`

// newMember is a member account with three stacks, three tagged resources,
// two roles and three buckets.
func newMember() *fakeMember {
	stackID := func(name string) *string {
		return aws.String("arn:aws:cloudformation:us-east-1:" + memberAccount + ":stack/" + name + "/11111111-2222-3333-4444-555555555555")
	}
	return &fakeMember{
		region: "us-east-1", deny: map[string]bool{},
		stacks: []cfntypes.Stack{
			{StackName: aws.String("StackSet-baseline-roles-0f0f0f0f-aaaa-bbbb-cccc-121212121212"), StackId: stackID("StackSet-baseline-roles-0f0f0f0f-aaaa-bbbb-cccc-121212121212"), StackStatus: cfntypes.StackStatusCreateComplete},
			{StackName: aws.String("payments-network"), StackId: stackID("payments-network"), StackStatus: cfntypes.StackStatusUpdateComplete, EnableTerminationProtection: aws.Bool(true),
				Outputs: []cfntypes.Output{{OutputKey: aws.String("VpcId"), OutputValue: aws.String("vpc-0aaaaaaaaaaaaaaaa"), ExportName: aws.String("payments-vpc-id")}},
				Tags:    []cfntypes.Tag{{Key: aws.String("team"), Value: aws.String("payments")}}},
			{StackName: aws.String("payments-api"), StackId: stackID("payments-api"), StackStatus: cfntypes.StackStatusUpdateComplete, Description: aws.String("payments api"),
				Parameters: []cfntypes.Parameter{
					{ParameterKey: aws.String("AppSubnetIds"), ParameterValue: aws.String("subnet-0aaaaaaaaaaaaaaaa,subnet-0bbbbbbbbbbbbbbbb")},
					{ParameterKey: aws.String("OrgId"), ParameterValue: aws.String("o-example00001")},
					{ParameterKey: aws.String("ApiKey"), ParameterValue: aws.String("****")}},
				Outputs: []cfntypes.Output{{OutputKey: aws.String("Endpoint"), OutputValue: aws.String("https://internal.example.test/secret-path")}}},
		},
		templates: map[string]string{"payments-api": apiTemplate, "payments-network": networkTemplate,
			"StackSet-baseline-roles-0f0f0f0f-aaaa-bbbb-cccc-121212121212": `{"Resources": {"Audit": {"Type": "AWS::IAM::Role"}}}`},
		resources: map[string][]string{
			"payments-api":     {"AWS::AutoScaling::AutoScalingGroup", "AWS::IAM::Role", "AWS::SNS::TopicPolicy", "AWS::Logs::SubscriptionFilter", "AWS::EC2::TransitGatewayAttachment"},
			"payments-network": {"AWS::EC2::VPC", "AWS::EC2::Subnet", "AWS::EC2::Subnet"},
			"StackSet-baseline-roles-0f0f0f0f-aaaa-bbbb-cccc-121212121212": {"AWS::IAM::Role", "AWS::IAM::Role"},
		},
		exports: []cfntypes.Export{{Name: aws.String("payments-vpc-id"), ExportingStackId: stackID("payments-network")}, {Name: aws.String("unused-export"), ExportingStackId: stackID("payments-network")}},
		imports: map[string][]string{"payments-vpc-id": {"payments-api"}},
		tagged: []tagtypes.ResourceTagMapping{
			{ResourceARN: aws.String("arn:aws:ec2:us-east-1:" + memberAccount + ":instance/i-0aaaaaaaaaaaaaaaa"), Tags: []tagtypes.Tag{{Key: aws.String("aws:cloudformation:stack-name"), Value: aws.String("payments-api")}, {Key: aws.String("cost-center"), Value: aws.String("PAY-01")}}},
			{ResourceARN: aws.String("arn:aws:dynamodb:us-east-1:" + memberAccount + ":table/scores"), Tags: []tagtypes.Tag{{Key: aws.String("Terraform"), Value: aws.String("true")}}},
			{ResourceARN: aws.String("arn:aws:sqs:us-east-1:" + memberAccount + ":events")},
		},
		roles: []iamtypes.Role{
			{Arn: aws.String("arn:aws:iam::" + memberAccount + ":role/DataExportReader"), RoleName: aws.String("DataExportReader"), AssumeRolePolicyDocument: aws.String(url.PathEscape(orgTrust))},
			{Arn: aws.String("arn:aws:iam::" + memberAccount + ":role/AppInstance"), RoleName: aws.String("AppInstance"), AssumeRolePolicyDocument: aws.String(plainTrust)},
		},
		buckets: []s3types.Bucket{
			{Name: aws.String("settlement"), BucketRegion: aws.String("us-east-1")},
			{Name: aws.String("logs-without-policy"), BucketRegion: aws.String("us-east-1")},
			{Name: aws.String("elsewhere"), BucketRegion: aws.String("ap-southeast-2")},
		},
		policies: map[string]string{"settlement": perimeterPolicy, "elsewhere": perimeterPolicy},
	}
}

// clientsOf wires one fake into every client slot of the Regions given.
func clientsOf(f *fakeMember, withBuckets bool) MemberClientFactory {
	return func(_ context.Context, account, region string) (*MemberClients, error) {
		if account != memberAccount {
			return nil, errors.New("unexpected account " + account)
		}
		mc := &MemberClients{Stacks: f, Tagging: f, ResourceExplorer: f, Roles: f}
		if withBuckets {
			mc.Buckets = f
		}
		return mc, nil
	}
}

func collectWorkloads(t *testing.T, w *WorkloadOptions) *snapshot.Snapshot {
	t.Helper()
	snap, err := Collect(context.Background(), Options{Organizations: fakeOrgs{}, Region: "us-east-1", Workloads: w, Sleep: func(context.Context, time.Duration) error { return nil }})
	if err != nil {
		t.Fatal(err)
	}
	if err := snap.Validate(); err != nil {
		t.Fatal(err)
	}
	return snap
}

func recordsOf(s *snapshot.Snapshot, domain, account string) []snapshot.DomainCoverage {
	var out []snapshot.DomainCoverage
	for _, d := range s.Coverage.Domains {
		if d.Domain == domain && d.AccountID == account {
			out = append(out, d)
		}
	}
	return out
}

func stackNamed(t *testing.T, w *snapshot.AccountWorkloads, name string) snapshot.Stack {
	t.Helper()
	for _, st := range w.Stacks {
		if st.Name == name {
			return st
		}
	}
	t.Fatalf("no stack %s", name)
	return snapshot.Stack{}
}

func TestWorkloadInventoryIsCollected(t *testing.T) {
	f := newMember()
	snap := collectWorkloads(t, &WorkloadOptions{Accounts: []string{memberAccount}, Regions: []string{"us-east-1"}, Clients: clientsOf(f, true)})
	w := snap.Workloads[memberAccount]
	if w == nil || len(w.Stacks) != 3 || len(w.Regions) != 1 || w.CollectedAt == "" {
		t.Fatalf("inventory: %+v", w)
	}
	// Stacks: status, tags, resource types and counts, outputs and exports,
	// termination protection.
	net := stackNamed(t, w, "payments-network")
	if net.Status != "UPDATE_COMPLETE" || !net.TerminationProtection || net.Tags["team"] != "payments" || net.ResourceTypes["AWS::EC2::Subnet"] != 2 || net.ResourceCount() != 3 ||
		len(net.Outputs) != 1 || net.Outputs[0].Key != "VpcId" || net.Outputs[0].ExportName != "payments-vpc-id" || net.Region != "us-east-1" || !strings.HasPrefix(net.ID, "arn:aws:cloudformation:") {
		t.Errorf("network stack: %+v", net)
	}
	api := stackNamed(t, w, "payments-api")
	if len(api.Imports) != 1 || api.Imports[0].ExportName != "payments-vpc-id" || api.Imports[0].ExportingStack != "payments-network" {
		t.Errorf("imports come from ListExports and ListImports: %+v", api.Imports)
	}
	if len(api.ExternalOutputs) != 1 || api.ExternalOutputs[0].StackName != "shared-observability" || api.ExternalOutputs[0].OutputName != "LogDestinationArn" ||
		api.ExternalOutputs[0].RoleARN != "arn:aws:iam::111111111199:role/CfnOutputReader" || api.ExternalOutputs[0].AccountID != "111111111199" {
		t.Errorf("Fn::GetStackOutput: %+v", api.ExternalOutputs)
	}
	refs := map[string]string{}
	for _, r := range api.References {
		refs[r.ID] = r.Kind + " via " + r.Via
	}
	if refs["subnet-0aaaaaaaaaaaaaaaa"] != "subnet via parameter AppSubnetIds" || refs["subnet-0bbbbbbbbbbbbbbbb"] != "subnet via parameter AppSubnetIds" || refs["tgw-0123456789abcdef0"] != "transit-gateway via template" {
		t.Errorf("references: %v", refs)
	}
	base := stackNamed(t, w, "StackSet-baseline-roles-0f0f0f0f-aaaa-bbbb-cccc-121212121212")
	if base.StackSet == nil || base.StackSet.Evidence != snapshot.StackSetEvidenceName || !strings.HasPrefix(base.StackSet.Name, "baseline-roles") {
		t.Errorf("a StackSet-named stack records the name as evidence: %+v", base.StackSet)
	}
	// The resource sample, with the source that was used.
	if w.ResourceSource != snapshot.ResourceSourceTaggingAPI || len(w.Resources) != 3 || w.ResourcesTruncated {
		t.Fatalf("resources: %s %+v", w.ResourceSource, w.Resources)
	}
	if r := w.Resources[0]; r.Type != "ec2:instance" || r.Stack != "payments-api" || r.Tags["cost-center"] != "PAY-01" || r.Region != "us-east-1" {
		t.Errorf("tagged instance: %+v", r)
	}
	if r := w.Resources[2]; r.Type != "sqs:queue" || len(r.Tags) != 0 {
		t.Errorf("a resource whose tags were removed has an empty tag set: %+v", r)
	}
	// Policies: the role trust on the organization (URL-encoded by IAM), and
	// the two policies declared in the template. Bucket policies are off.
	if w.PoliciesInspected != 4 || len(w.ResourcePolicies) != 3 {
		t.Fatalf("policies: %d inspected, %+v", w.PoliciesInspected, w.ResourcePolicies)
	}
	trust := w.ResourcePolicies[0]
	if trust.Kind != snapshot.PolicyKindRoleTrust || !strings.HasSuffix(trust.ResourceARN, "role/DataExportReader") || trust.Source != "iam:ListRoles" || !json.Valid(trust.Document) ||
		len(trust.Conditions) != 1 || trust.Conditions[0].Key != "aws:PrincipalOrgID" || trust.Conditions[0].Values[0] != "o-example00001" {
		t.Errorf("trust policy: %+v", trust)
	}
	byResource := map[string]snapshot.ResourcePolicy{}
	for _, p := range w.ResourcePolicies[1:] {
		byResource[p.Resource] = p
	}
	role := byResource["LogRole"]
	if role.Kind != snapshot.PolicyKindTemplate || role.Stack != "payments-api" || len(role.Document) != 0 || len(role.Conditions) != 1 || role.Conditions[0].Dynamic ||
		role.Conditions[0].Values[0] != "o-example00001" || role.Conditions[0].Sid != "FromTheOrganization" || role.Conditions[0].Effect != "Allow" {
		t.Errorf("a Ref to a parameter resolves to its value: %+v", role)
	}
	topic := byResource["Topic"]
	if len(topic.Conditions) != 1 || !topic.Conditions[0].Dynamic || topic.Conditions[0].Key != "aws:PrincipalOrgPaths" || topic.Conditions[0].Operator != "ForAnyValue:StringLike" || !strings.Contains(topic.Conditions[0].Values[0], "Fn::Sub") {
		t.Errorf("a value computed at deployment is marked dynamic: %+v", topic)
	}

	// Coverage: one record per domain for the account, and the reason bucket
	// policies were not read.
	if recs := recordsOf(snap, snapshot.DomainWorkloadStacks, memberAccount); len(recs) != 1 || recs[0].Status != snapshot.CoverageObserved || recs[0].Items != 3 || !strings.Contains(recs[0].Reason, "regions us-east-1") ||
		!containsString(recs[0].Operations, "cloudformation:GetTemplate") {
		t.Errorf("stacks coverage: %+v", recs)
	}
	if recs := recordsOf(snap, snapshot.DomainWorkloadResources, memberAccount); len(recs) != 1 || recs[0].Status != snapshot.CoverageObserved || !strings.Contains(recs[0].Reason, "Resource Groups Tagging API") ||
		!strings.Contains(recs[0].Reason, "never untagged ones") || !strings.Contains(recs[0].Reason, "the account has no aggregator index") {
		t.Errorf("resources coverage: %+v", recs)
	}
	recs := recordsOf(snap, snapshot.DomainWorkloadPolicies, memberAccount)
	if len(recs) != 2 || recs[0].Status != snapshot.CoverageObserved || !strings.Contains(recs[0].Reason, "4 policies read, 3 reference organization identity") ||
		recs[1].Status != snapshot.CoverageSkipped || recs[1].Reason != BucketPoliciesSkipped {
		t.Errorf("policies coverage: %+v", recs)
	}
	if got := snap.DomainStatus(snapshot.DomainWorkloadPolicies, memberAccount); got != snapshot.CoverageSkipped {
		t.Errorf("without bucket policies the domain is not complete, got %s", got)
	}
	// So the layer is partially evaluated, and says so.
	if inv := workload.Build(snap, memberAccount); inv.Evaluation() != workload.PartiallyEvaluated || !inv.Collected {
		t.Errorf("layer: %s", inv.Evaluation())
	}

	// Nothing the template, the outputs or the parameters carry is stored.
	data, err := json.Marshal(snap)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"SuperSecretValue", "secret-path", "internal.example.test", "****", "AWSTemplateFormatVersion", "vpc-0aaaaaaaaaaaaaaaa"} {
		if strings.Contains(string(data), secret) {
			t.Errorf("the snapshot must not carry %q from a template, an output value or a parameter value", secret)
		}
	}
	// An export nobody imports is answered with a ValidationError, which is
	// not a failure.
	if f.count("ListImports") != 2 {
		t.Errorf("every export is asked for its importers, got %d calls", f.count("ListImports"))
	}
}

// The S3 reads are billed, so they are made only with the opt-in: not even
// a client that could make them is used without it.
func TestBucketPoliciesAreReadOnlyWithTheOptIn(t *testing.T) {
	f := newMember()
	snap := collectWorkloads(t, &WorkloadOptions{Accounts: []string{memberAccount}, Regions: []string{"us-east-1"}, Clients: clientsOf(f, true)})
	if f.count("ListBuckets") != 0 || f.count("GetBucketPolicy") != 0 {
		t.Fatalf("no S3 call without the opt-in: %d ListBuckets, %d GetBucketPolicy", f.count("ListBuckets"), f.count("GetBucketPolicy"))
	}
	for _, p := range snap.Workloads[memberAccount].ResourcePolicies {
		if p.Kind == snapshot.PolicyKindBucket {
			t.Errorf("no bucket policy without the opt-in: %+v", p)
		}
	}
	for _, d := range snap.Coverage.Domains {
		for _, op := range d.Operations {
			if strings.HasPrefix(op, "s3:") {
				t.Errorf("coverage must not claim an S3 call: %+v", d)
			}
		}
	}

	f = newMember()
	snap = collectWorkloads(t, &WorkloadOptions{Accounts: []string{memberAccount}, Regions: []string{"us-east-1"}, Clients: clientsOf(f, true), BucketPolicies: true})
	if f.count("ListBuckets") != 1 || f.count("GetBucketPolicy") != 2 {
		t.Fatalf("with the opt-in: one ListBuckets and one GetBucketPolicy per bucket in the workload Regions, got %d and %d", f.count("ListBuckets"), f.count("GetBucketPolicy"))
	}
	w := snap.Workloads[memberAccount]
	var bucket *snapshot.ResourcePolicy
	for i := range w.ResourcePolicies {
		if w.ResourcePolicies[i].Kind == snapshot.PolicyKindBucket {
			bucket = &w.ResourcePolicies[i]
		}
	}
	if bucket == nil || bucket.ResourceARN != "arn:aws:s3:::settlement" || bucket.Source != "s3:GetBucketPolicy" || bucket.Conditions[0].Operator != "StringNotEqualsIfExists" || bucket.Conditions[0].Effect != "Deny" {
		t.Fatalf("bucket policy: %+v", w.ResourcePolicies)
	}
	if w.PoliciesInspected != 5 {
		t.Errorf("one bucket policy was read on top of the four others, got %d", w.PoliciesInspected)
	}
	recs := recordsOf(snap, snapshot.DomainWorkloadPolicies, memberAccount)
	if len(recs) != 1 || recs[0].Status != snapshot.CoverageObserved || !containsString(recs[0].Operations, "s3:GetBucketPolicy") {
		t.Errorf("with the opt-in the domain is complete: %+v", recs)
	}
	if inv := workload.Build(snap, memberAccount); inv.Evaluation() != workload.Evaluated {
		t.Errorf("layer with bucket policies: %s", inv.Evaluation())
	}
	// Opted in without an S3 client is an error of the domain, not silence.
	f = newMember()
	snap = collectWorkloads(t, &WorkloadOptions{Accounts: []string{memberAccount}, Regions: []string{"us-east-1"}, Clients: clientsOf(f, false), BucketPolicies: true})
	if recs := recordsOf(snap, snapshot.DomainWorkloadPolicies, memberAccount); len(recs) != 1 || recs[0].Status != snapshot.CoveragePartial || !strings.Contains(recs[0].Error, "no S3 client") {
		t.Errorf("opted in without a client: %+v", recs)
	}
	// A denied GetBucketPolicy leaves the domain partial.
	f = newMember()
	f.deny["GetBucketPolicy"] = true
	snap = collectWorkloads(t, &WorkloadOptions{Accounts: []string{memberAccount}, Regions: []string{"us-east-1"}, Clients: clientsOf(f, true), BucketPolicies: true})
	if recs := recordsOf(snap, snapshot.DomainWorkloadPolicies, memberAccount); len(recs) != 1 || recs[0].Status != snapshot.CoveragePartial || !strings.Contains(recs[0].Error, "AccessDenied") {
		t.Errorf("denied bucket policy: %+v", recs)
	}
}

func TestResourceExplorerIsUsedWhenAnAggregatorExists(t *testing.T) {
	tags := redoc.NewLazyDocument([]map[string]any{{"Key": "cost-center", "Value": "PAY-01"}, {"Key": "aws:cloudformation:stack-name", "Value": "payments-api"}})
	explored := []retypes.Resource{
		{Arn: aws.String("arn:aws:ec2:us-east-1:" + memberAccount + ":instance/i-0cccccccccccccccc"), Region: aws.String("us-east-1"), ResourceType: aws.String("ec2:instance"),
			Properties: []retypes.ResourceProperty{{Name: aws.String("tags"), Data: tags}}},
		{Arn: aws.String("arn:aws:lambda:us-east-1:" + memberAccount + ":function:untagged"), Region: aws.String("us-east-1"), ResourceType: aws.String("lambda:function")},
		{Arn: aws.String("arn:aws:iam::" + memberAccount + ":role/global-role"), Region: aws.String("global"), ResourceType: aws.String("iam:role")},
		{Arn: aws.String("arn:aws:ec2:ap-southeast-2:" + memberAccount + ":instance/i-0dddddddddddddddd"), Region: aws.String("ap-southeast-2"), ResourceType: aws.String("ec2:instance")},
	}
	f := newMember()
	f.aggregator, f.explored = "eu-west-1", explored
	asked := map[string]int{}
	factory := func(ctx context.Context, account, region string) (*MemberClients, error) {
		asked[region]++
		return clientsOf(f, false)(ctx, account, region)
	}
	snap := collectWorkloads(t, &WorkloadOptions{Accounts: []string{memberAccount}, Regions: []string{"us-east-1"}, Clients: factory})
	w := snap.Workloads[memberAccount]
	if w.ResourceSource != snapshot.ResourceSourceResourceExplorer || len(w.Resources) != 3 || f.count("GetResources") != 0 || asked["eu-west-1"] != 1 {
		t.Fatalf("resource explorer sample: %s, %d resources, %d tagging calls, aggregator clients %d", w.ResourceSource, len(w.Resources), f.count("GetResources"), asked["eu-west-1"])
	}
	if r := w.Resources[0]; r.Tags["cost-center"] != "PAY-01" || r.Stack != "payments-api" || r.Type != "ec2:instance" {
		t.Errorf("tags come from the tags property: %+v", r)
	}
	if r := w.Resources[1]; len(r.Tags) != 0 || r.Type != "lambda:function" {
		t.Errorf("Resource Explorer returns untagged resources too: %+v", r)
	}
	recs := recordsOf(snap, snapshot.DomainWorkloadResources, memberAccount)
	if len(recs) != 1 || recs[0].Status != snapshot.CoverageObserved || !strings.Contains(recs[0].Reason, "aggregator index in eu-west-1") || !containsString(recs[0].Operations, "resource-explorer-2:Search") {
		t.Errorf("coverage: %+v", recs)
	}

	// A search that fails (no default view) falls back to the Tagging API
	// when the source is auto, and the record says why.
	f = newMember()
	f.aggregator, f.searchFail = "us-east-1", true
	snap = collectWorkloads(t, &WorkloadOptions{Accounts: []string{memberAccount}, Regions: []string{"us-east-1"}, Clients: clientsOf(f, false)})
	w = snap.Workloads[memberAccount]
	recs = recordsOf(snap, snapshot.DomainWorkloadResources, memberAccount)
	if w.ResourceSource != snapshot.ResourceSourceTaggingAPI || len(w.Resources) != 3 || !strings.Contains(recs[0].Reason, "Resource Explorer was not used: its search in us-east-1 failed (UnauthorizedException") {
		t.Errorf("fallback: %s %+v", w.ResourceSource, recs)
	}
	// Asked for explicitly, a missing index is a failure of the domain.
	f = newMember()
	snap = collectWorkloads(t, &WorkloadOptions{Accounts: []string{memberAccount}, Regions: []string{"us-east-1"}, Clients: clientsOf(f, false), ResourceSource: snapshot.ResourceSourceResourceExplorer})
	recs = recordsOf(snap, snapshot.DomainWorkloadResources, memberAccount)
	if len(recs) != 1 || recs[0].Status.Complete() || !strings.Contains(recs[0].Error, "no Resource Explorer aggregator index") || f.count("GetResources") != 0 {
		t.Errorf("explicit resource-explorer without an index: %+v", recs)
	}
	// The Tagging API alone never asks Resource Explorer.
	f = newMember()
	f.aggregator = "us-east-1"
	collectWorkloads(t, &WorkloadOptions{Accounts: []string{memberAccount}, Regions: []string{"us-east-1"}, Clients: clientsOf(f, false), ResourceSource: snapshot.ResourceSourceTaggingAPI})
	if f.count("ListIndexes") != 0 || f.count("Search") != 0 || f.count("GetResources") != 1 {
		t.Errorf("tagging-api source: %d ListIndexes, %d Search, %d GetResources", f.count("ListIndexes"), f.count("Search"), f.count("GetResources"))
	}
	// A search that returns 1,000 results is truncated by the service.
	f = newMember()
	f.aggregator = "us-east-1"
	for i := 0; i < 1000; i++ {
		f.explored = append(f.explored, explored[1])
	}
	snap = collectWorkloads(t, &WorkloadOptions{Accounts: []string{memberAccount}, Regions: []string{"us-east-1"}, Clients: clientsOf(f, false), MaxResources: 5000})
	if w = snap.Workloads[memberAccount]; !w.ResourcesTruncated || !strings.Contains(recordsOf(snap, snapshot.DomainWorkloadResources, memberAccount)[0].Reason, "only the first 1,000 results") {
		t.Errorf("1,000 results mean the search was cut: truncated=%t", w.ResourcesTruncated)
	}
}

func TestDeniedMemberReadsAreRecordedPerDomain(t *testing.T) {
	// Everything denied: no inventory, three records with the error.
	f := newMember()
	f.deny["*"] = true
	snap := collectWorkloads(t, &WorkloadOptions{Accounts: []string{memberAccount}, Regions: []string{"us-east-1"}, Clients: clientsOf(f, false)})
	if snap.Workloads[memberAccount] != nil {
		t.Errorf("nothing could be read, so there is no inventory: %+v", snap.Workloads[memberAccount])
	}
	for _, d := range snapshot.WorkloadDomains {
		if got := snap.DomainStatus(d, memberAccount); got != snapshot.CoverageAccessDenied {
			t.Errorf("%s: %s", d, got)
		}
	}
	if inv := workload.Build(snap, memberAccount); inv.Evaluation() != workload.NotEvaluated || inv.Collected {
		t.Errorf("denied inventory: %s", inv.Evaluation())
	}
	// One read denied: the others are still collected.
	f = newMember()
	f.deny["ListRoles"] = true
	snap = collectWorkloads(t, &WorkloadOptions{Accounts: []string{memberAccount}, Regions: []string{"us-east-1"}, Clients: clientsOf(f, false)})
	w := snap.Workloads[memberAccount]
	if w == nil || len(w.Stacks) != 3 || len(w.Resources) != 3 {
		t.Fatalf("a denied policy read must not lose the stacks: %+v", w)
	}
	if got := snap.DomainStatus(snapshot.DomainWorkloadStacks, memberAccount); got != snapshot.CoverageObserved {
		t.Errorf("stacks: %s", got)
	}
	recs := recordsOf(snap, snapshot.DomainWorkloadPolicies, memberAccount)
	if recs[0].Status != snapshot.CoveragePartial || !strings.Contains(recs[0].Error, "AccessDenied") || len(w.ResourcePolicies) != 2 {
		t.Errorf("the template policies were read before the role list was denied: %+v, %d policies", recs[0], len(w.ResourcePolicies))
	}
	// A template that cannot be read leaves the stack in the inventory and
	// the domain partial.
	f = newMember()
	f.deny["GetTemplate"] = true
	snap = collectWorkloads(t, &WorkloadOptions{Accounts: []string{memberAccount}, Regions: []string{"us-east-1"}, Clients: clientsOf(f, false)})
	if recs := recordsOf(snap, snapshot.DomainWorkloadStacks, memberAccount); recs[0].Status != snapshot.CoveragePartial || recs[0].Items != 3 || !strings.Contains(recs[0].Error, "template of stack") {
		t.Errorf("denied templates: %+v", recs)
	}
	// An account the organization does not have is that account's error,
	// not the collection's.
	f = newMember()
	snap = collectWorkloads(t, &WorkloadOptions{Accounts: []string{"999999999999", memberAccount}, Regions: []string{"us-east-1"}, Clients: clientsOf(f, false)})
	if recs := recordsOf(snap, snapshot.DomainWorkloadStacks, "999999999999"); len(recs) != 1 || recs[0].Status != snapshot.CoverageError || !strings.Contains(recs[0].Error, "is not an account of organization") {
		t.Errorf("unknown account: %+v", recs)
	}
	if snap.Workloads["999999999999"] != nil || snap.Workloads[memberAccount] == nil {
		t.Errorf("the known account is still inspected: %+v", snap.Workloads)
	}
	// The member role cannot be assumed at all (the factory fails).
	broken := func(context.Context, string, string) (*MemberClients, error) {
		return nil, &smithy.GenericAPIError{Code: "AccessDenied", Message: "not authorized to perform: sts:AssumeRole"}
	}
	snap = collectWorkloads(t, &WorkloadOptions{Accounts: []string{memberAccount}, Regions: []string{"us-east-1"}, Clients: broken})
	for _, d := range snapshot.WorkloadDomains {
		recs := recordsOf(snap, d, memberAccount)
		if len(recs) != 1 || recs[0].Status != snapshot.CoverageAccessDenied || !strings.Contains(recs[0].Error, "sts:AssumeRole") {
			t.Errorf("%s: %+v", d, recs)
		}
	}
	if snap.Workloads != nil {
		t.Error("no inventory when the role cannot be assumed")
	}
}

func TestWorkloadCapsMakeTheDomainPartial(t *testing.T) {
	f := newMember()
	snap := collectWorkloads(t, &WorkloadOptions{Accounts: []string{memberAccount}, Regions: []string{"us-east-1"}, Clients: clientsOf(f, false), MaxStacks: 2, MaxResources: 2, MaxRoles: 1})
	w := snap.Workloads[memberAccount]
	if len(w.Stacks) != 2 || len(w.Resources) != 2 || !w.ResourcesTruncated {
		t.Fatalf("caps: %d stacks, %d resources, truncated %t", len(w.Stacks), len(w.Resources), w.ResourcesTruncated)
	}
	if rec := recordsOf(snap, snapshot.DomainWorkloadStacks, memberAccount)[0]; rec.Status != snapshot.CoveragePartial || !strings.Contains(rec.Error, "capped") || !strings.Contains(rec.Error, "workloads.max_stacks") {
		t.Errorf("capped stacks: %+v", rec)
	}
	// A capped sample is still a sample: observed, with the cap in the reason.
	if rec := recordsOf(snap, snapshot.DomainWorkloadResources, memberAccount)[0]; rec.Status != snapshot.CoverageObserved || !strings.Contains(rec.Reason, "capped at 2 resources") {
		t.Errorf("capped resources: %+v", rec)
	}
	if rec := recordsOf(snap, snapshot.DomainWorkloadPolicies, memberAccount)[0]; rec.Status != snapshot.CoveragePartial || !strings.Contains(rec.Error, "workloads.max_roles") {
		t.Errorf("capped roles: %+v", rec)
	}
}

// fakeStackSets serves two StackSets from the management account.
type fakeStackSets struct {
	denyDescribe string
}

func (fakeStackSets) ListStackSets(context.Context, *cloudformation.ListStackSetsInput, ...func(*cloudformation.Options)) (*cloudformation.ListStackSetsOutput, error) {
	return &cloudformation.ListStackSetsOutput{Summaries: []cfntypes.StackSetSummary{{StackSetName: aws.String("baseline-roles")}, {StackSetName: aws.String("tooling")}}}, nil
}

func (f fakeStackSets) DescribeStackSet(_ context.Context, in *cloudformation.DescribeStackSetInput, _ ...func(*cloudformation.Options)) (*cloudformation.DescribeStackSetOutput, error) {
	name := aws.ToString(in.StackSetName)
	if name == f.denyDescribe {
		return nil, &smithy.GenericAPIError{Code: "AccessDenied", Message: "not authorized to perform: cloudformation:DescribeStackSet"}
	}
	if name == "baseline-roles" {
		return &cloudformation.DescribeStackSetOutput{StackSet: &cfntypes.StackSet{StackSetName: in.StackSetName, StackSetId: aws.String("baseline-roles:1111"), PermissionModel: cfntypes.PermissionModelsServiceManaged,
			StackSetARN:    aws.String("arn:aws:cloudformation:us-east-1:111111111111:stackset/baseline-roles:1111"),
			AutoDeployment: &cfntypes.AutoDeployment{Enabled: aws.Bool(true), RetainStacksOnAccountRemoval: aws.Bool(false)}, OrganizationalUnitIds: []string{"ou-example-work"}, Regions: []string{"us-east-1"},
			Description: aws.String("Audit roles")}}, nil
	}
	return &cloudformation.DescribeStackSetOutput{StackSet: &cfntypes.StackSet{StackSetName: in.StackSetName, StackSetId: aws.String("tooling:2222"), PermissionModel: cfntypes.PermissionModelsSelfManaged,
		AdministrationRoleARN: aws.String("arn:aws:iam::111111111115:role/AWSCloudFormationStackSetAdministrationRole"), Regions: []string{"eu-west-1", "us-east-1"}}}, nil
}

func (fakeStackSets) ListStackInstances(_ context.Context, in *cloudformation.ListStackInstancesInput, _ ...func(*cloudformation.Options)) (*cloudformation.ListStackInstancesOutput, error) {
	if aws.ToString(in.StackSetName) == "baseline-roles" {
		return &cloudformation.ListStackInstancesOutput{Summaries: []cfntypes.StackInstanceSummary{
			{Account: aws.String(memberAccount), Region: aws.String("us-east-1"), StackId: aws.String("arn:aws:cloudformation:us-east-1:" + memberAccount + ":stack/StackSet-baseline-roles-0f0f0f0f-aaaa-bbbb-cccc-121212121212/11111111-2222-3333-4444-555555555555"),
				Status: cfntypes.StackInstanceStatusCurrent, OrganizationalUnitId: aws.String("ou-example-work")}}}, nil
	}
	return &cloudformation.ListStackInstancesOutput{Summaries: []cfntypes.StackInstanceSummary{
		{Account: aws.String("111111111114"), Region: aws.String("us-east-1"), StackId: aws.String("arn:aws:cloudformation:us-east-1:111111111114:stack/StackSet-tooling-1/x"), Status: cfntypes.StackInstanceStatusCurrent},
		{Account: aws.String("111111111114"), Region: aws.String("eu-west-1"), StackId: aws.String("arn:aws:cloudformation:eu-west-1:111111111114:stack/StackSet-tooling-2/y"), Status: cfntypes.StackInstanceStatusOutdated}}}, nil
}

func TestStackSetsAreCollectedWithTheirInstances(t *testing.T) {
	f := newMember()
	snap, err := Collect(context.Background(), Options{Organizations: fakeOrgs{}, Region: "us-east-1", StackSets: fakeStackSets{},
		Workloads: &WorkloadOptions{Accounts: []string{memberAccount}, Regions: []string{"us-east-1"}, Clients: clientsOf(f, false)}})
	if err != nil {
		t.Fatal(err)
	}
	if len(snap.StackSets) != 2 {
		t.Fatalf("stack sets: %+v", snap.StackSets)
	}
	base := snap.StackSetByName("baseline-roles")
	if base == nil || base.PermissionModel != "SERVICE_MANAGED" || !base.AutoDeployment || base.RetainStacksOnAccountRemoval || base.TargetOUs[0] != "ou-example-work" || base.AdministrationAccountID != "111111111111" ||
		base.ID != "baseline-roles:1111" || len(base.Instances) != 1 || base.Instances[0].AccountID != memberAccount || base.Instances[0].OrganizationalUnitID != "ou-example-work" || len(base.TargetAccounts) != 0 {
		t.Errorf("service-managed StackSet: %+v", base)
	}
	tooling := snap.StackSetByName("tooling")
	if tooling.PermissionModel != "SELF_MANAGED" || tooling.AdministrationAccountID != "111111111115" || len(tooling.Instances) != 2 || strings.Join(tooling.TargetAccounts, ",") != "111111111114" {
		t.Errorf("self-managed StackSet: %+v", tooling)
	}
	rec := record(t, snap, snapshot.DomainStackSets)
	if rec.Status != snapshot.CoverageObserved || rec.Items != 2 || !containsString(rec.Operations, "cloudformation:ListStackInstances") || !strings.Contains(rec.Reason, "delegated administrator") {
		t.Errorf("coverage: %+v", rec)
	}
	// The instance record ties the stack in the member account to its
	// StackSet: provenance by fact, not by name.
	inv := workload.Build(snap, memberAccount)
	var view *workload.StackView
	for i := range inv.Stacks {
		if strings.HasPrefix(inv.Stacks[i].Name, "StackSet-baseline-roles") {
			view = &inv.Stacks[i]
		}
	}
	if view == nil || view.Provenance.Kind != workload.KindStackSetServiceManaged || view.Provenance.Confidence != workload.ConfidenceHigh || view.StackSetSettings == nil || !view.StackSetSettings.MatchedByInstance {
		t.Errorf("collected instance and collected stack should match by stack ID: %+v", view)
	}
	if sum := Summary(snap); !strings.Contains(sum, "2 StackSets with 3 stack instances") || !strings.Contains(sum, "workload inventory of 1 account(s): 3 stacks, 3 sampled resources, 3 policies tied to organization identity") {
		t.Errorf("summary: %s", sum)
	}
	// One StackSet that cannot be described leaves the domain partial.
	snap, err = Collect(context.Background(), Options{Organizations: fakeOrgs{}, Region: "us-east-1", StackSets: fakeStackSets{denyDescribe: "tooling"}})
	if err != nil {
		t.Fatal(err)
	}
	if rec := record(t, snap, snapshot.DomainStackSets); rec.Status != snapshot.CoveragePartial || len(snap.StackSets) != 1 || !strings.Contains(rec.Error, "StackSet tooling") {
		t.Errorf("partial StackSets: %+v", rec)
	}
}

func TestTemplateParsing(t *testing.T) {
	tmpl, err := parseTemplate(apiTemplate)
	if err != nil {
		t.Fatal(err)
	}
	res := tmpl["Resources"].(map[string]any)
	group := res["Group"].(map[string]any)["Properties"].(map[string]any)
	if ref, ok := group["VPCZoneIdentifier"].(map[string]any); !ok || ref["Ref"] != "AppSubnetIds" {
		t.Errorf("!Ref becomes Ref: %+v", group["VPCZoneIdentifier"])
	}
	tag := group["Tags"].([]any)[0].(map[string]any)["Value"].(map[string]any)
	if tag["Fn::ImportValue"] != "payments-vpc-id" {
		t.Errorf("!ImportValue becomes Fn::ImportValue: %+v", tag)
	}
	// JSON is YAML too.
	if j, err := parseTemplate(networkTemplate); err != nil || j["Resources"] == nil {
		t.Errorf("JSON template: %v", err)
	}
	for _, bad := range []string{"", "- a\n- b\n", "{unclosed", "just a string"} {
		if _, err := parseTemplate(bad); err == nil {
			t.Errorf("%q should not parse as a template", bad)
		}
	}
	// Without the stack's parameters a Ref stays unresolved and is dynamic.
	facts := factsOfTemplate(tmpl, "payments-api", nil)
	for _, p := range facts.policies {
		if p.Resource == "LogRole" && (!p.Conditions[0].Dynamic || !strings.Contains(p.Conditions[0].Values[0], `"Ref":"OrgId"`)) {
			t.Errorf("an unresolved Ref is dynamic and names the parameter: %+v", p.Conditions[0])
		}
	}
	if len(facts.externalOutputs) != 1 || len(facts.policies) != 2 || len(facts.references) != 1 {
		t.Errorf("facts: %+v", facts)
	}
	// A role ARN that is computed leaves the account unknown.
	dyn, err := parseTemplate(`{"Resources": {"X": {"Type": "AWS::SSM::Parameter", "Properties": {"Value": {"Fn::GetStackOutput": {"StackName": "other", "OutputName": "Out", "RoleArn": {"Fn::Sub": "arn:aws:iam::${Acct}:role/R"}}}}}}}`)
	if err != nil {
		t.Fatal(err)
	}
	if got := factsOfTemplate(dyn, "s", nil).externalOutputs; len(got) != 1 || got[0].RoleARN != "" || got[0].AccountID != "" || got[0].StackName != "other" {
		t.Errorf("computed role ARN: %+v", got)
	}
	if decodePolicy(url.PathEscape(orgTrust)) != orgTrust || decodePolicy(orgTrust) != orgTrust {
		t.Error("IAM returns trust policies URL-encoded; both forms decode to the JSON")
	}
	if stackNameFromID("arn:aws:cloudformation:us-east-1:111111111112:stack/payments-network/1111") != "payments-network" || stackNameFromID("plain") != "plain" {
		t.Error("stack name from a stack ID")
	}
}

// A collected snapshot evaluates like a fixture: the planted problems of
// the fake account come out of the workloads check.
func TestCollectedInventoryFeedsTheSameViews(t *testing.T) {
	f := newMember()
	snap, err := Collect(context.Background(), Options{Organizations: fakeOrgs{}, Region: "us-east-1", StackSets: fakeStackSets{},
		Workloads: &WorkloadOptions{Accounts: []string{memberAccount}, Regions: []string{"us-east-1"}, Clients: clientsOf(f, true), BucketPolicies: true}})
	if err != nil {
		t.Fatal(err)
	}
	inv := workload.Build(snap, memberAccount)
	plan := inv.Redeploy()
	if inv.Evaluation() != workload.Evaluated || len(plan.Groups) != 3 {
		t.Fatalf("collected inventory: %s", inv.Evaluation())
	}
	deps := strings.Join(plan.Dependencies, "\n")
	for _, want := range []string{"Order: payments-network exports values that payments-api import(s)", "Cross-account reference: payments-api reads output LogDestinationArn of stack shared-observability in account 111111111199",
		"payments-api takes subnet subnet-0aaaaaaaaaaaaaaaa, subnet-0bbbbbbbbbbbbbbbb", "Organization identity: 4 policy(ies)"} {
		if !strings.Contains(deps, want) {
			t.Errorf("redeployment dependencies should contain %q:\n%s", want, deps)
		}
	}
	// The snapshot survives a save and a load.
	data, err := json.Marshal(snap)
	if err != nil {
		t.Fatal(err)
	}
	back, err := snapshot.Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(back.Workloads[memberAccount].Stacks) != 3 || back.SchemaVersion != snapshot.SchemaVersion {
		t.Errorf("round trip: %+v", back.Workloads[memberAccount])
	}
}
