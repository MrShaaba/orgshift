package collector

import (
	"context"
	"fmt"
	"log"
	"sort"
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

// OrganizationsAPI is the subset of the Organizations client the collector
// uses. Every method is a read-only operation from Allowlist.
type OrganizationsAPI interface {
	DescribeOrganization(context.Context, *organizations.DescribeOrganizationInput, ...func(*organizations.Options)) (*organizations.DescribeOrganizationOutput, error)
	ListRoots(context.Context, *organizations.ListRootsInput, ...func(*organizations.Options)) (*organizations.ListRootsOutput, error)
	ListOrganizationalUnitsForParent(context.Context, *organizations.ListOrganizationalUnitsForParentInput, ...func(*organizations.Options)) (*organizations.ListOrganizationalUnitsForParentOutput, error)
	ListAccountsForParent(context.Context, *organizations.ListAccountsForParentInput, ...func(*organizations.Options)) (*organizations.ListAccountsForParentOutput, error)
	ListPolicies(context.Context, *organizations.ListPoliciesInput, ...func(*organizations.Options)) (*organizations.ListPoliciesOutput, error)
	DescribePolicy(context.Context, *organizations.DescribePolicyInput, ...func(*organizations.Options)) (*organizations.DescribePolicyOutput, error)
	ListTargetsForPolicy(context.Context, *organizations.ListTargetsForPolicyInput, ...func(*organizations.Options)) (*organizations.ListTargetsForPolicyOutput, error)
	ListTagsForResource(context.Context, *organizations.ListTagsForResourceInput, ...func(*organizations.Options)) (*organizations.ListTagsForResourceOutput, error)
	ListDelegatedAdministrators(context.Context, *organizations.ListDelegatedAdministratorsInput, ...func(*organizations.Options)) (*organizations.ListDelegatedAdministratorsOutput, error)
	ListDelegatedServicesForAccount(context.Context, *organizations.ListDelegatedServicesForAccountInput, ...func(*organizations.Options)) (*organizations.ListDelegatedServicesForAccountOutput, error)
	ListAWSServiceAccessForOrganization(context.Context, *organizations.ListAWSServiceAccessForOrganizationInput, ...func(*organizations.Options)) (*organizations.ListAWSServiceAccessForOrganizationOutput, error)
}

// RAMAPI is the subset of the RAM client the collector uses.
type RAMAPI interface {
	GetResourceShares(context.Context, *ram.GetResourceSharesInput, ...func(*ram.Options)) (*ram.GetResourceSharesOutput, error)
	ListPrincipals(context.Context, *ram.ListPrincipalsInput, ...func(*ram.Options)) (*ram.ListPrincipalsOutput, error)
	ListResources(context.Context, *ram.ListResourcesInput, ...func(*ram.Options)) (*ram.ListResourcesOutput, error)
}

// AccountAPI is the subset of the Account client the collector uses.
type AccountAPI interface {
	ListRegions(context.Context, *account.ListRegionsInput, ...func(*account.Options)) (*account.ListRegionsOutput, error)
}

// Options configure a collection run.
type Options struct {
	// Name is the friendly organization name stored in the snapshot.
	Name string
	// Organizations is the client for the management or delegated-admin
	// account. Required.
	Organizations OrganizationsAPI
	// RAM lists resource shares owned by each client's account. Shares owned
	// by other accounts (a network account, say) need their own client.
	RAM []RAMAPI
	// Account lists enabled regions per account. Optional.
	Account AccountAPI
	// Logger receives progress and warnings. Optional.
	Logger *log.Logger
	// Now overrides the timestamp, for tests.
	Now func() time.Time
}

// Collect reads the organization and returns a validated snapshot.
func Collect(ctx context.Context, opts Options) (*snapshot.Snapshot, error) {
	if opts.Organizations == nil {
		return nil, fmt.Errorf("an Organizations client is required")
	}
	if opts.Logger == nil {
		opts.Logger = log.New(logDiscard{}, "", 0)
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	c := &run{opts: opts, ctx: ctx, snap: &snapshot.Snapshot{SchemaVersion: snapshot.SchemaVersion, Source: "collector"}}
	c.snap.GeneratedAt = opts.Now().UTC().Format(time.RFC3339)
	c.snap.Organization.Name = opts.Name
	steps := []struct {
		name string
		fn   func() error
	}{
		{"organization", c.organization},
		{"roots and tree", c.tree},
		{"policies", c.policies},
		{"delegated administrators", c.delegated},
		{"trusted access", c.trustedAccess},
		{"resource shares", c.shares},
		{"enabled regions", c.regions},
	}
	for _, s := range steps {
		opts.Logger.Printf("collecting %s", s.name)
		if err := s.fn(); err != nil {
			return nil, fmt.Errorf("%s: %w", s.name, err)
		}
	}
	c.snap.Usage = map[string]*snapshot.AccountUsage{}
	if err := c.snap.Validate(); err != nil {
		return nil, fmt.Errorf("collected snapshot failed validation: %w", err)
	}
	return c.snap, nil
}

type logDiscard struct{}

func (logDiscard) Write(p []byte) (int, error) { return len(p), nil }

type run struct {
	opts Options
	ctx  context.Context
	snap *snapshot.Snapshot
}

func (r *run) organization() error {
	out, err := r.opts.Organizations.DescribeOrganization(r.ctx, &organizations.DescribeOrganizationInput{})
	if err != nil {
		return err
	}
	o := out.Organization
	r.snap.Organization.ID = aws.ToString(o.Id)
	r.snap.Organization.ARN = aws.ToString(o.Arn)
	r.snap.Organization.ManagementAccountID = aws.ToString(o.MasterAccountId)
	r.snap.Organization.FeatureSet = string(o.FeatureSet)
	return nil
}

func (r *run) tree() error {
	roots, err := r.opts.Organizations.ListRoots(r.ctx, &organizations.ListRootsInput{})
	if err != nil {
		return err
	}
	if len(roots.Roots) == 0 {
		return fmt.Errorf("the organization has no root")
	}
	root := roots.Roots[0]
	r.snap.Root = snapshot.Root{ID: aws.ToString(root.Id), ARN: aws.ToString(root.Arn), Name: aws.ToString(root.Name)}
	for _, pt := range root.PolicyTypes {
		if pt.Status == orgtypes.PolicyTypeStatusEnabled {
			r.snap.Root.EnabledPolicyTypes = append(r.snap.Root.EnabledPolicyTypes, snapshot.PolicyType(pt.Type))
		}
	}
	return r.walk(r.snap.Root.ID)
}

func (r *run) walk(parentID string) error {
	ouPager := organizations.NewListOrganizationalUnitsForParentPaginator(r.opts.Organizations, &organizations.ListOrganizationalUnitsForParentInput{ParentId: aws.String(parentID)})
	var children []string
	for ouPager.HasMorePages() {
		page, err := ouPager.NextPage(r.ctx)
		if err != nil {
			return err
		}
		for _, ou := range page.OrganizationalUnits {
			r.snap.OUs = append(r.snap.OUs, snapshot.OU{ID: aws.ToString(ou.Id), ARN: aws.ToString(ou.Arn), Name: aws.ToString(ou.Name), ParentID: parentID})
			children = append(children, aws.ToString(ou.Id))
		}
	}
	acctPager := organizations.NewListAccountsForParentPaginator(r.opts.Organizations, &organizations.ListAccountsForParentInput{ParentId: aws.String(parentID)})
	for acctPager.HasMorePages() {
		page, err := acctPager.NextPage(r.ctx)
		if err != nil {
			return err
		}
		for _, a := range page.Accounts {
			acct := snapshot.Account{
				ID: aws.ToString(a.Id), ARN: aws.ToString(a.Arn), Name: aws.ToString(a.Name), Email: aws.ToString(a.Email),
				Status: string(a.Status), JoinedMethod: string(a.JoinedMethod), ParentID: parentID,
			}
			tags, err := r.tags(acct.ID)
			if err != nil {
				r.opts.Logger.Printf("warning: tags for account %s: %v", acct.ID, err)
			}
			acct.Tags = tags
			r.snap.Accounts = append(r.snap.Accounts, acct)
		}
	}
	for _, id := range children {
		if err := r.walk(id); err != nil {
			return err
		}
	}
	return nil
}

func (r *run) tags(resourceID string) (map[string]string, error) {
	pager := organizations.NewListTagsForResourcePaginator(r.opts.Organizations, &organizations.ListTagsForResourceInput{ResourceId: aws.String(resourceID)})
	tags := map[string]string{}
	for pager.HasMorePages() {
		page, err := pager.NextPage(r.ctx)
		if err != nil {
			return nil, err
		}
		for _, t := range page.Tags {
			tags[aws.ToString(t.Key)] = aws.ToString(t.Value)
		}
	}
	if len(tags) == 0 {
		return nil, nil
	}
	return tags, nil
}

func (r *run) policies() error {
	for _, t := range r.snap.Root.EnabledPolicyTypes {
		pager := organizations.NewListPoliciesPaginator(r.opts.Organizations, &organizations.ListPoliciesInput{Filter: orgtypes.PolicyType(t)})
		for pager.HasMorePages() {
			page, err := pager.NextPage(r.ctx)
			if err != nil {
				return err
			}
			for _, summary := range page.Policies {
				id := aws.ToString(summary.Id)
				desc, err := r.opts.Organizations.DescribePolicy(r.ctx, &organizations.DescribePolicyInput{PolicyId: aws.String(id)})
				if err != nil {
					return fmt.Errorf("describe %s: %w", id, err)
				}
				p := snapshot.Policy{
					ID: id, ARN: aws.ToString(summary.Arn), Name: aws.ToString(summary.Name), Description: aws.ToString(summary.Description),
					Type: t, AWSManaged: summary.AwsManaged, Document: []byte(aws.ToString(desc.Policy.Content)),
				}
				targets := organizations.NewListTargetsForPolicyPaginator(r.opts.Organizations, &organizations.ListTargetsForPolicyInput{PolicyId: aws.String(id)})
				for targets.HasMorePages() {
					tp, err := targets.NextPage(r.ctx)
					if err != nil {
						return fmt.Errorf("targets of %s: %w", id, err)
					}
					for _, tgt := range tp.Targets {
						p.Targets = append(p.Targets, aws.ToString(tgt.TargetId))
					}
				}
				sort.Strings(p.Targets)
				if p.Targets == nil {
					p.Targets = []string{}
				}
				r.snap.Policies = append(r.snap.Policies, p)
			}
		}
	}
	return nil
}

func (r *run) delegated() error {
	pager := organizations.NewListDelegatedAdministratorsPaginator(r.opts.Organizations, &organizations.ListDelegatedAdministratorsInput{})
	for pager.HasMorePages() {
		page, err := pager.NextPage(r.ctx)
		if err != nil {
			return err
		}
		for _, admin := range page.DelegatedAdministrators {
			id := aws.ToString(admin.Id)
			svcPager := organizations.NewListDelegatedServicesForAccountPaginator(r.opts.Organizations, &organizations.ListDelegatedServicesForAccountInput{AccountId: aws.String(id)})
			for svcPager.HasMorePages() {
				sp, err := svcPager.NextPage(r.ctx)
				if err != nil {
					return err
				}
				for _, svc := range sp.DelegatedServices {
					d := snapshot.DelegatedAdministrator{AccountID: id, ServicePrincipal: aws.ToString(svc.ServicePrincipal)}
					if svc.DelegationEnabledDate != nil {
						d.DelegationDate = svc.DelegationEnabledDate.UTC().Format(time.RFC3339)
					}
					r.snap.DelegatedAdministrators = append(r.snap.DelegatedAdministrators, d)
				}
			}
		}
	}
	return nil
}

func (r *run) trustedAccess() error {
	pager := organizations.NewListAWSServiceAccessForOrganizationPaginator(r.opts.Organizations, &organizations.ListAWSServiceAccessForOrganizationInput{})
	for pager.HasMorePages() {
		page, err := pager.NextPage(r.ctx)
		if err != nil {
			return err
		}
		for _, s := range page.EnabledServicePrincipals {
			r.snap.TrustedAccessServices = append(r.snap.TrustedAccessServices, aws.ToString(s.ServicePrincipal))
		}
	}
	sort.Strings(r.snap.TrustedAccessServices)
	return nil
}

func (r *run) shares() error {
	for _, client := range r.opts.RAM {
		pager := ram.NewGetResourceSharesPaginator(client, &ram.GetResourceSharesInput{ResourceOwner: ramtypes.ResourceOwnerSelf})
		for pager.HasMorePages() {
			page, err := pager.NextPage(r.ctx)
			if err != nil {
				return err
			}
			for _, sh := range page.ResourceShares {
				if sh.Status == ramtypes.ResourceShareStatusDeleted || sh.Status == ramtypes.ResourceShareStatusDeleting {
					continue
				}
				arn := aws.ToString(sh.ResourceShareArn)
				s := snapshot.ResourceShare{
					ARN: arn, Name: aws.ToString(sh.Name), OwnerAccountID: aws.ToString(sh.OwningAccountId), Status: string(sh.Status),
					AllowExternalPrincipals: aws.ToBool(sh.AllowExternalPrincipals), Principals: []string{}, Resources: []snapshot.SharedResource{},
				}
				pp := ram.NewListPrincipalsPaginator(client, &ram.ListPrincipalsInput{ResourceOwner: ramtypes.ResourceOwnerSelf, ResourceShareArns: []string{arn}})
				for pp.HasMorePages() {
					page, err := pp.NextPage(r.ctx)
					if err != nil {
						return fmt.Errorf("principals of %s: %w", arn, err)
					}
					for _, p := range page.Principals {
						s.Principals = append(s.Principals, aws.ToString(p.Id))
					}
				}
				rp := ram.NewListResourcesPaginator(client, &ram.ListResourcesInput{ResourceOwner: ramtypes.ResourceOwnerSelf, ResourceShareArns: []string{arn}})
				for rp.HasMorePages() {
					page, err := rp.NextPage(r.ctx)
					if err != nil {
						return fmt.Errorf("resources of %s: %w", arn, err)
					}
					for _, res := range page.Resources {
						s.Resources = append(s.Resources, snapshot.SharedResource{ARN: aws.ToString(res.Arn), Type: aws.ToString(res.Type)})
					}
				}
				r.snap.ResourceShares = append(r.snap.ResourceShares, s)
			}
		}
	}
	return nil
}

func (r *run) regions() error {
	if r.opts.Account == nil {
		return nil
	}
	for i := range r.snap.Accounts {
		a := &r.snap.Accounts[i]
		pager := account.NewListRegionsPaginator(r.opts.Account, &account.ListRegionsInput{
			AccountId: aws.String(a.ID),
			RegionOptStatusContains: []accounttypes.RegionOptStatus{
				accounttypes.RegionOptStatusEnabled, accounttypes.RegionOptStatusEnabledByDefault, accounttypes.RegionOptStatusEnabling,
			},
		})
		var regions []string
		failed := false
		for pager.HasMorePages() {
			page, err := pager.NextPage(r.ctx)
			if err != nil {
				r.opts.Logger.Printf("warning: enabled regions for %s: %v (needs account:ListRegions and trusted access for account.amazonaws.com)", a.ID, err)
				failed = true
				break
			}
			for _, reg := range page.Regions {
				regions = append(regions, aws.ToString(reg.RegionName))
			}
		}
		if !failed {
			sort.Strings(regions)
			a.EnabledRegions = regions
		}
	}
	return nil
}

// Summary describes what a snapshot contains, for the CLI.
func Summary(s *snapshot.Snapshot) string {
	return fmt.Sprintf("organization %s: %d OUs, %d accounts, %d policies, %d resource shares, %d delegated administrators, %d trusted services",
		s.Organization.ID, len(s.OUs), len(s.Accounts), len(s.Policies), len(s.ResourceShares), len(s.DelegatedAdministrators), len(s.TrustedAccessServices))
}
