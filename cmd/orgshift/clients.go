package main

import (
	"context"
	"fmt"
	"log"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/account"
	"github.com/aws/aws-sdk-go-v2/service/cloudformation"
	"github.com/aws/aws-sdk-go-v2/service/controlcatalog"
	"github.com/aws/aws-sdk-go-v2/service/controltower"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/identitystore"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	"github.com/aws/aws-sdk-go-v2/service/ram"
	"github.com/aws/aws-sdk-go-v2/service/resourceexplorer2"
	"github.com/aws/aws-sdk-go-v2/service/resourcegroupstaggingapi"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/ssoadmin"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"github.com/MrShaaba/orgshift/internal/awsaccess"
	"github.com/MrShaaba/orgshift/internal/collector"
	"github.com/MrShaaba/orgshift/internal/config"
	"github.com/MrShaaba/orgshift/internal/preflight"
	"github.com/MrShaaba/orgshift/internal/snapshot"
)

// sideClients holds the SDK clients of one configured side, wired both for
// the preflight and for the collector.
type sideClients struct {
	name      string
	side      *config.Side
	preflight preflight.SideInput
	collect   collector.Options
	// identities lists the verified identities, for the CLI to print.
	identities []string
}

// buildSide builds the credentials of one side from the configuration.
// With verify set, every credential is checked with sts:GetCallerIdentity
// against its configured account and a mismatch is an error (collect);
// without it the preflight does the checking and reports it.
func buildSide(ctx context.Context, cfg *config.Config, name string, verify bool, version string, logger *log.Logger) (*sideClients, error) {
	side, err := cfg.Side(name)
	if err != nil {
		return nil, err
	}
	bo := awsaccess.BuildOptions{RetryAttempts: cfg.Collection.RetryAttempts}
	sc := &sideClients{name: name, side: side}
	mgmtCfg, err := awsaccess.Build(ctx, side.Management, nil, bo)
	if err != nil {
		return nil, fmt.Errorf("%s management: %w", name, err)
	}
	check := func(label string, a config.Access, c aws.Config) error {
		if !verify {
			return nil
		}
		id, err := awsaccess.Verify(ctx, sts.NewFromConfig(c), name+" "+label, a.AccountID)
		if err != nil {
			return err
		}
		sc.identities = append(sc.identities, fmt.Sprintf("%s %s: %s", name, label, id.ARN))
		return nil
	}
	if err := check(side.Management.Label, side.Management, mgmtCfg); err != nil {
		return nil, err
	}
	skip := map[string]string{}
	for _, d := range side.Skip {
		skip[d] = "configuration: skip " + d
	}
	if reason, off := skip["workloads"]; off {
		delete(skip, "workloads")
		for _, d := range snapshot.WorkloadDomains {
			skip[d] = reason
		}
	}
	if !side.ControlTowerEnabled() {
		skip[snapshot.DomainControlTower] = "configuration: control_tower disabled"
		skip[snapshot.DomainEnrolledAccounts] = skip[snapshot.DomainControlTower]
	}
	if !side.IdentityCenterEnabled() {
		skip[snapshot.DomainIdentityCenter] = "configuration: identity_center disabled"
	}
	mgmt := &preflight.Clients{Label: side.Management.Label, ExpectedAccount: side.Management.AccountID, Via: side.Management.Describe(), Region: mgmtCfg.Region,
		STS: sts.NewFromConfig(mgmtCfg), Organizations: organizations.NewFromConfig(mgmtCfg)}
	opts := collector.Options{
		Name: side.Name, Region: mgmtCfg.Region, ControlTowerRegion: side.ControlTowerRegion(), IdentityCenterRegion: side.IdentityCenterRegion(),
		Version: "orgshift " + version, Organizations: mgmt.Organizations, Logger: logger, SkipReasons: skip, Concurrency: cfg.Collection.Concurrency,
	}
	if _, off := skip[snapshot.DomainEnabledRegions]; !off {
		mgmt.Account = account.NewFromConfig(mgmtCfg)
		opts.Account = mgmt.Account
	}
	if _, off := skip[snapshot.DomainResourceShares]; !off {
		mgmt.RAM = ram.NewFromConfig(mgmtCfg)
		opts.RAM = append(opts.RAM, mgmt.RAM)
		opts.RAMLabels = append(opts.RAMLabels, side.Management.Label)
	}
	if _, off := skip[snapshot.DomainControlTower]; !off {
		ctCfg := mgmtCfg.Copy()
		ctCfg.Region = side.ControlTowerRegion()
		mgmt.ControlTower, mgmt.ControlCatalog, mgmt.ControlTowerRegion = controltower.NewFromConfig(ctCfg), controlcatalog.NewFromConfig(ctCfg), ctCfg.Region
		opts.ControlTower, opts.ControlCatalog = mgmt.ControlTower, mgmt.ControlCatalog
	}
	if _, off := skip[snapshot.DomainStackSets]; !off {
		mgmt.StackSets = cloudformation.NewFromConfig(mgmtCfg)
		opts.StackSets = mgmt.StackSets
	}
	in := preflight.SideInput{Name: name, Management: mgmt, Skip: skip}
	if _, off := skip[snapshot.DomainIdentityCenter]; !off {
		icAccess := side.IdentityCenterAccess()
		icCfg := mgmtCfg.Copy()
		icCfg.Region = side.IdentityCenterRegion()
		target := mgmt
		if side.IdentityCenter != nil && side.IdentityCenter.Access != nil {
			icCfg, err = awsaccess.Build(ctx, icAccess, &mgmtCfg, bo)
			if err != nil {
				return nil, fmt.Errorf("%s identity center: %w", name, err)
			}
			if err := check(icAccess.Label, icAccess, icCfg); err != nil {
				return nil, err
			}
			target = &preflight.Clients{Label: icAccess.Label, ExpectedAccount: icAccess.AccountID, Via: icAccess.Describe(), Region: icCfg.Region, STS: sts.NewFromConfig(icCfg)}
			in.IdentityCenter = target
		}
		target.SSOAdmin, target.IdentityStore, target.IdentityCenterRegion = ssoadmin.NewFromConfig(icCfg), identitystore.NewFromConfig(icCfg), icCfg.Region
		opts.SSOAdmin, opts.IdentityStore = target.SSOAdmin, target.IdentityStore
	}
	for _, n := range side.Network {
		c, err := awsaccess.Build(ctx, n, &mgmtCfg, bo)
		if err != nil {
			return nil, fmt.Errorf("%s %s: %w", name, n.Label, err)
		}
		if err := check(n.Label, n, c); err != nil {
			return nil, err
		}
		client := &preflight.Clients{Label: n.Label, ExpectedAccount: n.AccountID, Via: n.Describe(), Region: c.Region, STS: sts.NewFromConfig(c), RAM: ram.NewFromConfig(c)}
		in.Network = append(in.Network, client)
		if _, off := skip[snapshot.DomainResourceShares]; !off {
			opts.RAM = append(opts.RAM, client.RAM)
			opts.RAMLabels = append(opts.RAMLabels, n.Label)
		}
	}
	for _, s := range side.Security {
		c, err := awsaccess.Build(ctx, s, &mgmtCfg, bo)
		if err != nil {
			return nil, fmt.Errorf("%s %s: %w", name, s.Label, err)
		}
		if err := check(s.Label, s, c); err != nil {
			return nil, err
		}
		in.Security = append(in.Security, &preflight.Clients{Label: s.Label, ExpectedAccount: s.AccountID, Via: s.Describe(), Region: c.Region, STS: sts.NewFromConfig(c)})
	}
	if m := side.MemberInspection; m != nil {
		in.Member = &preflight.Member{RoleName: m.RoleName, ExternalID: m.ExternalID, Accounts: m.Accounts, Sample: m.MemberSample(), STS: sts.NewFromConfig(mgmtCfg)}
		if _, off := skip[snapshot.DomainWorkloadStacks]; !off {
			regions := side.WorkloadRegions
			if len(regions) == 0 {
				regions = []string{mgmtCfg.Region}
			}
			factory := memberClients(mgmtCfg, m, bo, cfg.Billable.BucketPolicies)
			w := &collector.WorkloadOptions{Accounts: m.Accounts, Regions: regions, Clients: factory, BucketPolicies: cfg.Billable.BucketPolicies}
			if sw := side.Workloads; sw != nil {
				w.ResourceSource, w.MaxStacks, w.MaxResources, w.MaxBuckets, w.MaxRoles = sw.ResourceSource, sw.MaxStacks, sw.MaxResources, sw.MaxBuckets, sw.MaxRoles
			}
			opts.Workloads = w
			in.Member.Clients, in.Member.Regions, in.Member.ResourceSource, in.Member.BucketPolicies = factory, regions, w.ResourceSource, cfg.Billable.BucketPolicies
		}
	}
	sc.preflight = in
	sc.collect = opts
	return sc, nil
}

// memberClients returns the factory that builds the clients of a member
// account in a Region by assuming the member inspection role from the
// management credentials. Building is offline: the role is assumed by the
// first call made with the clients. The S3 client exists only when the
// bucket-policies opt-in is on, so nothing can call it otherwise.
func memberClients(mgmtCfg aws.Config, m *config.MemberInspection, bo awsaccess.BuildOptions, bucketPolicies bool) collector.MemberClientFactory {
	var mu sync.Mutex
	cache := map[string]*collector.MemberClients{}
	return func(ctx context.Context, accountID, region string) (*collector.MemberClients, error) {
		mu.Lock()
		defer mu.Unlock()
		key := accountID + "/" + region
		if c, ok := cache[key]; ok {
			return c, nil
		}
		access := config.Access{Label: "member " + accountID, AccountID: accountID, Region: region, From: "management",
			AssumeRole: []config.RoleHop{{RoleARN: fmt.Sprintf("arn:aws:iam::%s:role/%s", accountID, m.RoleName), ExternalID: m.ExternalID, SessionName: "orgshift-workloads"}}}
		c, err := awsaccess.Build(ctx, access, &mgmtCfg, bo)
		if err != nil {
			return nil, err
		}
		mc := &collector.MemberClients{Stacks: cloudformation.NewFromConfig(c), Tagging: resourcegroupstaggingapi.NewFromConfig(c),
			ResourceExplorer: resourceexplorer2.NewFromConfig(c), Roles: iam.NewFromConfig(c)}
		if bucketPolicies {
			mc.Buckets = s3.NewFromConfig(c)
		}
		cache[key] = mc
		return mc, nil
	}
}
