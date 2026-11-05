package fixtures

import (
	"fmt"
	"sort"
	"strings"

	"github.com/MrShaaba/orgshift/internal/snapshot"
)

// Workload fixtures: what a collector with the member inspection role would
// have read inside the accounts the scenarios move. Problems are planted on
// purpose:
//
//   - larkspur-payments-prod carries an instance of the service-managed
//     StackSet larkspur-baseline-roles, which is deleted when the account
//     leaves its target OU (auto-deployment on, retain off);
//   - its payments-api stack imports an export of payments-network (a
//     cross-stack export) and reads an output of a stack in the security
//     account with Fn::GetStackOutput (a cross-account reference);
//   - payments-api and payments-ledger-db sit on subnets shared through RAM
//     and payments-network attaches to the shared transit gateway;
//   - the settlement bucket's policy keeps everyone outside the Larkspur
//     organization out, so the account's own roles lose the bucket the
//     moment the account changes organization;
//   - two worker instances, a Lambda function, a queue and a volume carry
//     no cost-center tag, and the workers are tagged the Terraform way.
//
// Fernhill's retail account carries the Control Tower baseline stacks and
// its sandbox a StackSet instance nobody in the organization administers.

// Names of the planted workload objects, for tests.
const (
	LarkspurBaselineStackSet  = "larkspur-baseline-roles"
	LarkspurRecorderStackSet  = "larkspur-config-recorder"
	LarkspurSettlementBucket  = "arn:aws:s3:::larkspur-payments-settlement-files"
	LarkspurAPIStack          = "payments-api"
	LarkspurNetworkStack      = "payments-network"
	LarkspurStorageStack      = "payments-settlement-storage"
	LarkspurLedgerStack       = "payments-ledger-db"
	LarkspurObservabilityRole = "arn:aws:iam::111111111113:role/CfnOutputReader"
	FernhillBaselineStackSet  = "fernhill-baseline"
)

const workloadCollectedAt = fixtureCollectedAt

func stackID(region, account, name, id string) string {
	return fmt.Sprintf("arn:aws:cloudformation:%s:%s:stack/%s/%s", region, account, name, id)
}

// instance records a StackSet instance and returns the name and ID of the
// stack it creates in the account.
func instance(g *gen, ss *snapshot.StackSet, account, region, ou string) (name, id string) {
	name = "StackSet-" + ss.Name + "-" + g.uuid()
	id = stackID(region, account, name, g.uuid())
	ss.Instances = append(ss.Instances, snapshot.StackInstance{AccountID: account, Region: region, StackID: id, Status: "CURRENT", OrganizationalUnitID: ou})
	return name, id
}

func kept(kind, arn, resource, stack, source string, document string) snapshot.ResourcePolicy {
	p := snapshot.ResourcePolicy{Kind: kind, ResourceARN: arn, Resource: resource, Stack: stack, Source: source}
	p.Document = doc(document)
	conds, err := snapshot.ExtractOrgConditions(p.Document)
	if err != nil || len(conds) == 0 {
		panic(fmt.Sprintf("fixture policy for %s%s carries no organization condition: %v", arn, resource, err))
	}
	p.Conditions = conds
	return p
}

func withTags(base map[string]string, extra ...string) map[string]string {
	out := map[string]string{}
	for k, v := range base {
		out[k] = v
	}
	for i := 0; i+1 < len(extra); i += 2 {
		out[extra[i]] = extra[i+1]
	}
	return out
}

// larkspurWorkloads adds the workload inventories of the payments, payments
// development and data accounts and the instances of the two StackSets.
func larkspurWorkloads(g *gen, s *snapshot.Snapshot, tgw, subnetA, subnetB string) {
	baseline, recorder := s.StackSetByName(LarkspurBaselineStackSet), s.StackSetByName(LarkspurRecorderStackSet)
	baseline.ID = LarkspurBaselineStackSet + ":" + g.uuid()
	recorder.ID = LarkspurRecorderStackSet + ":" + g.uuid()
	type ref struct{ name, id string }
	baselineOf, recorderOf := map[string]ref{}, map[string]ref{}
	ix := s.Index()
	// The baseline targets the Workloads OU in us-east-1; the recorder the
	// root in three Regions. StackSets never deploys to the management
	// account.
	accounts := make([]string, 0, len(s.Accounts))
	for _, a := range s.Accounts {
		accounts = append(accounts, a.ID)
	}
	sort.Strings(accounts)
	for _, id := range accounts {
		if id == s.Organization.ManagementAccountID {
			continue
		}
		if ix.IsUnder(id, LarkspurWorkloadsOU) {
			n, sid := instance(g, baseline, id, "us-east-1", LarkspurWorkloadsOU)
			baselineOf[id] = ref{n, sid}
		}
		for _, region := range recorder.Regions {
			n, sid := instance(g, recorder, id, region, s.Root.ID)
			recorderOf[id+"/"+region] = ref{n, sid}
		}
	}
	created, updated := "2024-05-06T08:00:00Z", "2025-11-18T14:30:00Z"
	baselineStack := func(account string) snapshot.Stack {
		r := baselineOf[account]
		return snapshot.Stack{Name: r.name, ID: r.id, Region: "us-east-1", Status: "UPDATE_COMPLETE", Description: "Audit and break-glass IAM roles for workload accounts",
			Tags: map[string]string{"managed-by": "platform"}, CreatedAt: created, UpdatedAt: updated,
			ResourceTypes: map[string]int{"AWS::IAM::Role": 3, "AWS::IAM::ManagedPolicy": 1},
			StackSet:      &snapshot.StackSetRef{Name: baseline.Name, ID: baseline.ID, Evidence: snapshot.StackSetEvidenceInstance}}
	}
	recorderStack := func(account, region string) snapshot.Stack {
		r := recorderOf[account+"/"+region]
		return snapshot.Stack{Name: r.name, ID: r.id, Region: region, Status: "CREATE_COMPLETE", Description: "AWS Config recorder and delivery channel",
			Tags: map[string]string{"managed-by": "platform"}, CreatedAt: created,
			ResourceTypes: map[string]int{"AWS::Config::ConfigurationRecorder": 1, "AWS::Config::DeliveryChannel": 1, "AWS::IAM::Role": 1},
			StackSet:      &snapshot.StackSetRef{Name: recorder.Name, ID: recorder.ID, Evidence: snapshot.StackSetEvidenceInstance}}
	}
	plain := func(account, region, name, description string, tags map[string]string, types map[string]int) snapshot.Stack {
		return snapshot.Stack{Name: name, ID: stackID(region, account, name, g.uuid()), Region: region, Status: "UPDATE_COMPLETE", Description: description,
			Tags: tags, CreatedAt: created, UpdatedAt: updated, ResourceTypes: types}
	}
	shared := func(via string) []snapshot.ResourceReference {
		return []snapshot.ResourceReference{{Kind: snapshot.RefSubnet, ID: subnetA, Via: via}, {Kind: snapshot.RefSubnet, ID: subnetB, Via: via}}
	}

	// --- larkspur-payments-prod ---
	const pay = LarkspurPaymentsProd
	payTags := map[string]string{"cost-center": "CC-1001", "environment": "production", "owner": "payments-team"}
	network := plain(pay, "us-east-1", LarkspurNetworkStack, "VPC, security groups and the attachment to the shared transit gateway", payTags,
		map[string]int{"AWS::EC2::VPC": 1, "AWS::EC2::TransitGatewayAttachment": 1, "AWS::EC2::Route": 4, "AWS::EC2::SecurityGroup": 3})
	network.TerminationProtection = true
	network.Outputs = []snapshot.StackOutput{{Key: "VpcId", ExportName: "payments-vpc-id"}, {Key: "AppSecurityGroupId", ExportName: "payments-app-sg"}, {Key: "AttachmentId"}}
	network.References = []snapshot.ResourceReference{{Kind: snapshot.RefTransitGateway, ID: tgw, AccountID: "111111111112", Via: "parameter TransitGatewayId"}}

	api := plain(pay, "us-east-1", LarkspurAPIStack, "Payments API: load balancer, launch template and autoscaling group", payTags,
		map[string]int{"AWS::AutoScaling::AutoScalingGroup": 1, "AWS::EC2::LaunchTemplate": 1, "AWS::ElasticLoadBalancingV2::LoadBalancer": 1,
			"AWS::ElasticLoadBalancingV2::TargetGroup": 1, "AWS::IAM::Role": 2, "AWS::Logs::LogGroup": 1})
	api.Imports = []snapshot.StackImport{{ExportName: "payments-app-sg", ExportingStack: LarkspurNetworkStack}, {ExportName: "payments-vpc-id", ExportingStack: LarkspurNetworkStack}}
	api.ExternalOutputs = []snapshot.ExternalOutput{{StackName: "shared-observability", OutputName: "LogDestinationArn", Region: "us-east-1", RoleARN: LarkspurObservabilityRole, AccountID: "111111111113"}}
	api.References = shared("parameter AppSubnetIds")

	storage := plain(pay, "us-east-1", LarkspurStorageStack, "Settlement file bucket, its policy and its key", payTags,
		map[string]int{"AWS::S3::Bucket": 1, "AWS::S3::BucketPolicy": 1, "AWS::KMS::Key": 1, "AWS::KMS::Alias": 1})
	storage.TerminationProtection = true
	storage.Outputs = []snapshot.StackOutput{{Key: "BucketName"}}

	ledger := plain(pay, "us-east-1", LarkspurLedgerStack, "Ledger database", payTags,
		map[string]int{"AWS::RDS::DBInstance": 1, "AWS::RDS::DBSubnetGroup": 1, "AWS::SecretsManager::Secret": 1})
	ledger.TerminationProtection = true
	ledger.References = shared("parameter DatabaseSubnetIds")

	standby := plain(pay, "eu-west-1", "payments-dr-standby", "Standby VPC for the disaster recovery runbook", payTags,
		map[string]int{"AWS::EC2::VPC": 1, "AWS::EC2::Subnet": 2, "AWS::EC2::RouteTable": 1})

	// The resource sample: the tagged resources the usage block already
	// lists, now with the tags that say who deployed them, plus a few the
	// Tagging API would also return.
	var payResources []snapshot.WorkloadResource
	for _, r := range s.UsageFor(pay).TaggedResources {
		w := snapshot.WorkloadResource{ARN: r.ARN, Type: r.Type, Region: r.Region, Tags: withTags(r.Tags)}
		switch {
		case r.Tags["Name"] == "pay-api":
			w.Tags["aws:cloudformation:stack-name"] = LarkspurAPIStack
			w.Tags["aws:cloudformation:logical-id"] = "AppAutoScalingGroup"
		case r.Tags["Name"] == "pay-worker":
			w.Tags["managed-by"] = "terraform"
			w.Tags["tf-workspace"] = "payments-workers"
		case r.Type == "rds:db":
			w.Tags["aws:cloudformation:stack-name"] = LarkspurLedgerStack
		case r.Type == "s3:bucket":
			w.Tags["aws:cloudformation:stack-name"] = LarkspurStorageStack
		}
		payResources = append(payResources, w)
	}
	payResources = append(payResources,
		snapshot.WorkloadResource{ARN: "arn:aws:iam::" + pay + ":role/larkspur-audit", Type: "iam:role",
			Tags: map[string]string{"aws:cloudformation:stack-name": baselineOf[pay].name, "managed-by": "platform"}},
		snapshot.WorkloadResource{ARN: "arn:aws:iam::" + pay + ":role/larkspur-break-glass", Type: "iam:role",
			Tags: map[string]string{"aws:cloudformation:stack-name": baselineOf[pay].name, "managed-by": "platform"}},
		snapshot.WorkloadResource{ARN: "arn:aws:ec2:us-east-1:" + pay + ":transit-gateway-attachment/tgw-attach-" + g.hex(17), Type: "ec2:transit-gateway-attachment", Region: "us-east-1",
			Tags: withTags(payTags, "aws:cloudformation:stack-name", LarkspurNetworkStack)},
		snapshot.WorkloadResource{ARN: "arn:aws:dynamodb:us-east-1:" + pay + ":table/fraud-scores", Type: "dynamodb:table", Region: "us-east-1",
			Tags: map[string]string{"Terraform": "true", "environment": "production", "cost-center": "CC-1001"}},
		snapshot.WorkloadResource{ARN: "arn:aws:sqs:us-east-1:" + pay + ":fraud-events", Type: "sqs:queue", Region: "us-east-1",
			Tags: map[string]string{"owner": "fraud-team"}},
		snapshot.WorkloadResource{ARN: "arn:aws:ec2:us-east-1:" + pay + ":volume/vol-" + g.hex(17), Type: "ec2:volume", Region: "us-east-1", Tags: map[string]string{}},
	)
	payPolicies := []snapshot.ResourcePolicy{
		kept(snapshot.PolicyKindBucket, LarkspurSettlementBucket, "", "", "s3:GetBucketPolicy", `{"Version":"2012-10-17","Statement":[
			{"Sid":"ReadFromTheOrganization","Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::larkspur-payments-settlement-files/*",
			 "Condition":{"StringEquals":{"aws:PrincipalOrgID":"o-larkspur0001"}}},
			{"Sid":"AcquirerPull","Effect":"Allow","Principal":{"AWS":"arn:aws:iam::999999999999:root"},"Action":["s3:GetObject","s3:ListBucket"],
			 "Resource":["arn:aws:s3:::larkspur-payments-settlement-files","arn:aws:s3:::larkspur-payments-settlement-files/*"]},
			{"Sid":"DataPerimeter","Effect":"Deny","Principal":"*","Action":"s3:*",
			 "Resource":["arn:aws:s3:::larkspur-payments-settlement-files","arn:aws:s3:::larkspur-payments-settlement-files/*"],
			 "Condition":{"StringNotEqualsIfExists":{"aws:PrincipalOrgID":["o-larkspur0001","o-acquirer0001"]},"BoolIfExists":{"aws:PrincipalIsAWSService":"false"}}}
		]}`),
		kept(snapshot.PolicyKindRoleTrust, "arn:aws:iam::"+pay+":role/DataExportReader", "", "", "iam:ListRoles", `{"Version":"2012-10-17","Statement":[
			{"Sid":"DataPlatformFromTheOrganization","Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole",
			 "Condition":{"StringEquals":{"aws:PrincipalOrgID":"o-larkspur0001"},"ArnLike":{"aws:PrincipalArn":"arn:aws:iam::*:role/DataPlatformIngest"}}}
		]}`),
		{Kind: snapshot.PolicyKindTemplate, Resource: "AppLogSubscriptionRole", Stack: LarkspurAPIStack, Source: "cloudformation:GetTemplate",
			Conditions: []snapshot.OrgCondition{{Effect: "Allow", Operator: "ForAnyValue:StringLike", Key: "aws:PrincipalOrgPaths", Values: []string{"o-larkspur0001/r-lark/ou-lark-sec/*"}}}},
	}
	s.Workloads = map[string]*snapshot.AccountWorkloads{
		pay: {
			Regions: []string{"us-east-1", "eu-west-1"}, CollectedAt: workloadCollectedAt,
			Stacks: []snapshot.Stack{baselineStack(pay), recorderStack(pay, "us-east-1"), network, api, storage, ledger,
				recorderStack(pay, "eu-west-1"), standby},
			Resources: payResources, ResourceSource: snapshot.ResourceSourceTaggingAPI,
			ResourcePolicies: payPolicies, PoliciesInspected: 17,
		},
	}

	// --- larkspur-payments-dev: nothing planted, a clean inventory ---
	const dev = "111111111116"
	devTags := map[string]string{"cost-center": "CC-1002", "environment": "development", "owner": "payments-team"}
	apiDev := plain(dev, "us-east-1", "payments-api-dev", "Payments API, development", devTags,
		map[string]int{"AWS::AutoScaling::AutoScalingGroup": 1, "AWS::EC2::LaunchTemplate": 1, "AWS::EC2::VPC": 1, "AWS::EC2::Subnet": 2, "AWS::IAM::Role": 1})
	s.Workloads[dev] = &snapshot.AccountWorkloads{
		Regions: []string{"us-east-1"}, CollectedAt: workloadCollectedAt,
		Stacks: []snapshot.Stack{baselineStack(dev), recorderStack(dev, "us-east-1"), apiDev},
		Resources: []snapshot.WorkloadResource{
			{ARN: "arn:aws:ec2:us-east-1:" + dev + ":instance/i-" + g.hex(17), Type: "ec2:instance", Region: "us-east-1", Tags: withTags(devTags, "aws:cloudformation:stack-name", "payments-api-dev")},
			{ARN: "arn:aws:ec2:us-east-1:" + dev + ":instance/i-" + g.hex(17), Type: "ec2:instance", Region: "us-east-1", Tags: withTags(devTags, "aws:cloudformation:stack-name", "payments-api-dev")},
		},
		ResourceSource: snapshot.ResourceSourceTaggingAPI, ResourcePolicies: []snapshot.ResourcePolicy{}, PoliciesInspected: 6,
	}

	// --- larkspur-data-prod: a bucket open to the Workloads OU path ---
	const data = "111111111118"
	dataTags := map[string]string{"cost-center": "CC-2001", "environment": "production", "owner": "data-platform"}
	lake := plain(data, "us-east-1", "data-lake-core", "Data lake buckets and the Glue catalogue", dataTags,
		map[string]int{"AWS::S3::Bucket": 2, "AWS::S3::BucketPolicy": 1, "AWS::Glue::Database": 1})
	lake.Outputs = []snapshot.StackOutput{{Key: "LakeBucketName", ExportName: "data-lake-bucket"}}
	ingest := plain(data, "us-east-1", "data-lake-ingest", "Nightly ingest jobs", dataTags,
		map[string]int{"AWS::Glue::Job": 3, "AWS::IAM::Role": 1, "AWS::EC2::TransitGatewayAttachment": 1})
	ingest.Imports = []snapshot.StackImport{{ExportName: "data-lake-bucket", ExportingStack: "data-lake-core"}}
	ingest.References = []snapshot.ResourceReference{{Kind: snapshot.RefTransitGateway, ID: tgw, AccountID: "111111111112", Via: "parameter TransitGatewayId"}}
	s.Workloads[data] = &snapshot.AccountWorkloads{
		Regions: []string{"us-east-1"}, CollectedAt: workloadCollectedAt,
		Stacks: []snapshot.Stack{baselineStack(data), recorderStack(data, "us-east-1"), lake, ingest},
		Resources: []snapshot.WorkloadResource{
			{ARN: "arn:aws:s3:::larkspur-data-lake", Type: "s3:bucket", Tags: withTags(dataTags, "aws:cloudformation:stack-name", "data-lake-core")},
			{ARN: "arn:aws:glue:us-east-1:" + data + ":job/ledger-ingest", Type: "glue:job", Region: "us-east-1", Tags: withTags(dataTags, "aws:cloudformation:stack-name", "data-lake-ingest")},
			{ARN: "arn:aws:lambda:us-east-1:" + data + ":function:model-trainer", Type: "lambda:function", Region: "us-east-1", Tags: map[string]string{"owner": "data-science"}},
		},
		ResourceSource: snapshot.ResourceSourceTaggingAPI,
		ResourcePolicies: []snapshot.ResourcePolicy{
			kept(snapshot.PolicyKindBucket, "arn:aws:s3:::larkspur-data-lake", "", "", "s3:GetBucketPolicy", `{"Version":"2012-10-17","Statement":[
				{"Sid":"WorkloadAccountsWrite","Effect":"Allow","Principal":"*","Action":"s3:PutObject","Resource":"arn:aws:s3:::larkspur-data-lake/*",
				 "Condition":{"ForAnyValue:StringLike":{"aws:PrincipalOrgPaths":"o-larkspur0001/r-lark/ou-lark-work/*"}}}
			]}`),
		},
		PoliciesInspected: 9,
	}
}

// fernhillWorkloads adds the inventories of the retail and sandbox accounts.
func fernhillWorkloads(g *gen, s *snapshot.Snapshot) {
	baseline := s.StackSetByName(FernhillBaselineStackSet)
	baseline.ID = FernhillBaselineStackSet + ":" + g.uuid()
	created := "2025-02-01T09:00:00Z"
	names := map[string]string{}
	ids := map[string]string{}
	ix := s.Index()
	accounts := make([]string, 0, len(s.Accounts))
	for _, a := range s.Accounts {
		accounts = append(accounts, a.ID)
	}
	sort.Strings(accounts)
	for _, id := range accounts {
		if id != s.Organization.ManagementAccountID && ix.IsUnder(id, FernhillBusinessUnitsOU) {
			names[id], ids[id] = instance(g, baseline, id, "eu-west-1", FernhillBusinessUnitsOU)
		}
	}
	plain := func(account, name, description string, tags map[string]string, types map[string]int) snapshot.Stack {
		return snapshot.Stack{Name: name, ID: stackID("eu-west-1", account, name, g.uuid()), Region: "eu-west-1", Status: "UPDATE_COMPLETE", Description: description,
			Tags: tags, CreatedAt: created, ResourceTypes: types}
	}
	controlTower := func(account, baselineName string, types map[string]int) snapshot.Stack {
		name := "StackSet-AWSControlTowerBP-BASELINE-" + baselineName + "-" + g.uuid()
		return snapshot.Stack{Name: name, ID: stackID("eu-west-1", account, name, g.uuid()), Region: "eu-west-1", Status: "CREATE_COMPLETE",
			Description: "AWS Control Tower baseline", CreatedAt: created, ResourceTypes: types,
			StackSet: &snapshot.StackSetRef{Name: "AWSControlTowerBP-BASELINE-" + baselineName, Evidence: snapshot.StackSetEvidenceName}}
	}

	const retail = FernhillRetailProd
	retailTags := map[string]string{"cost-center": "CC-2001", "environment": "production"}
	catalogue := plain(retail, "retail-catalogue", "Catalogue service and its database", retailTags,
		map[string]int{"AWS::ECS::Service": 1, "AWS::ECS::TaskDefinition": 1, "AWS::RDS::DBInstance": 1, "AWS::S3::Bucket": 1, "AWS::S3::BucketPolicy": 1})
	catalogue.TerminationProtection = true
	s.Workloads = map[string]*snapshot.AccountWorkloads{
		retail: {
			Regions: []string{"eu-west-1"}, CollectedAt: workloadCollectedAt,
			Stacks: []snapshot.Stack{
				controlTower(retail, "CLOUDTRAIL", map[string]int{"AWS::CloudTrail::Trail": 1, "AWS::IAM::Role": 1}),
				controlTower(retail, "CONFIG", map[string]int{"AWS::Config::ConfigurationRecorder": 1, "AWS::Config::DeliveryChannel": 1, "AWS::IAM::Role": 1}),
				controlTower(retail, "ROLES", map[string]int{"AWS::IAM::Role": 2}),
				{Name: names[retail], ID: ids[retail], Region: "eu-west-1", Status: "CREATE_COMPLETE", Description: "Baseline IAM roles and GuardDuty membership", CreatedAt: created,
					ResourceTypes: map[string]int{"AWS::IAM::Role": 2, "AWS::GuardDuty::Member": 1},
					StackSet:      &snapshot.StackSetRef{Name: baseline.Name, ID: baseline.ID, Evidence: snapshot.StackSetEvidenceInstance}},
				catalogue,
			},
			Resources: []snapshot.WorkloadResource{
				{ARN: "arn:aws:iam::" + retail + ":role/aws-controltower-ConfigRecorderRole", Type: "iam:role", Tags: map[string]string{}},
				{ARN: "arn:aws:s3:::fernhill-retail-assets", Type: "s3:bucket", Tags: withTags(retailTags, "aws:cloudformation:stack-name", "retail-catalogue")},
				{ARN: "arn:aws:rds:eu-west-1:" + retail + ":db:catalogue", Type: "rds:db", Region: "eu-west-1", Tags: withTags(retailTags, "aws:cloudformation:stack-name", "retail-catalogue")},
				{ARN: "arn:aws:s3:::fernhill-retail-exports", Type: "s3:bucket", Tags: map[string]string{"managed-by": "terraform", "cost-center": "CC-2001"}},
			},
			ResourceSource: snapshot.ResourceSourceResourceExplorer,
			ResourcePolicies: []snapshot.ResourcePolicy{
				kept(snapshot.PolicyKindBucket, "arn:aws:s3:::fernhill-retail-assets", "", "", "s3:GetBucketPolicy", `{"Version":"2012-10-17","Statement":[
					{"Sid":"OrganizationRead","Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::fernhill-retail-assets/*",
					 "Condition":{"StringEquals":{"aws:PrincipalOrgID":"o-fernhill0001"}}}
				]}`),
			},
			PoliciesInspected: 8,
		},
	}

	const sandbox = "222222222227"
	tooling := "StackSet-team-tooling-" + g.uuid()
	s.Workloads[sandbox] = &snapshot.AccountWorkloads{
		Regions: []string{"eu-west-1"}, CollectedAt: workloadCollectedAt,
		Stacks: []snapshot.Stack{
			plain(sandbox, "sandbox-experiments", "Developer experiments", map[string]string{"owner": "developers"}, map[string]int{"AWS::EC2::Instance": 2, "AWS::S3::Bucket": 1}),
			{Name: tooling, ID: stackID("eu-west-1", sandbox, tooling, g.uuid()), Region: "eu-west-1", Status: "CREATE_COMPLETE", Description: "Team tooling", CreatedAt: created,
				ResourceTypes: map[string]int{"AWS::IAM::Role": 1, "AWS::Lambda::Function": 1},
				StackSet:      &snapshot.StackSetRef{Name: "team-tooling", Evidence: snapshot.StackSetEvidenceName}},
		},
		Resources: []snapshot.WorkloadResource{
			{ARN: "arn:aws:ec2:eu-west-1:" + sandbox + ":instance/i-" + g.hex(17), Type: "ec2:instance", Region: "eu-west-1", Tags: map[string]string{"aws:cloudformation:stack-name": "sandbox-experiments", "owner": "developers"}},
			{ARN: "arn:aws:s3:::fernhill-sandbox-scratch", Type: "s3:bucket", Tags: map[string]string{"provisioner": "terraform"}},
			{ARN: "arn:aws:lambda:eu-west-1:" + sandbox + ":function:demo", Type: "lambda:function", Region: "eu-west-1", Tags: map[string]string{}},
		},
		ResourceSource: snapshot.ResourceSourceResourceExplorer, ResourcePolicies: []snapshot.ResourcePolicy{}, PoliciesInspected: 3,
	}
}

// workloadCoverage adds one record per workload domain for every account
// that has an inventory.
func workloadCoverage(s *snapshot.Snapshot) []snapshot.DomainCoverage {
	var out []snapshot.DomainCoverage
	ids := make([]string, 0, len(s.Workloads))
	for id := range s.Workloads {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	rec := func(domain, account string, items int, reason string, ops ...string) snapshot.DomainCoverage {
		d := snapshot.DomainCoverage{Domain: domain, Status: snapshot.CoverageObserved, AccountID: account, Items: items, Pages: 1, CollectedAt: fixtureCollectedAt, Operations: ops, Reason: reason}
		if items == 0 {
			d.Status = snapshot.CoverageEmpty
		}
		return d
	}
	for _, id := range ids {
		w := s.Workloads[id]
		resourceOps := []string{"tag:GetResources"}
		if w.ResourceSource == snapshot.ResourceSourceResourceExplorer {
			resourceOps = []string{"resource-explorer-2:ListIndexes", "resource-explorer-2:Search"}
		}
		out = append(out,
			rec(snapshot.DomainWorkloadStacks, id, len(w.Stacks), "regions "+join(w.Regions), "cloudformation:DescribeStacks", "cloudformation:ListStackResources", "cloudformation:ListExports", "cloudformation:ListImports", "cloudformation:GetTemplate"),
			rec(snapshot.DomainWorkloadResources, id, len(w.Resources), "a sample from "+w.ResourceSource, resourceOps...),
			rec(snapshot.DomainWorkloadPolicies, id, len(w.ResourcePolicies), fmt.Sprintf("%d policies read, %d reference organization identity", w.PoliciesInspected, len(w.ResourcePolicies)), "s3:GetBucketPolicy", "iam:ListRoles"),
		)
	}
	return out
}

func join(list []string) string { return strings.Join(list, ", ") }
