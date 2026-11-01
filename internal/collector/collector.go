package collector

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"sort"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/account"
	accounttypes "github.com/aws/aws-sdk-go-v2/service/account/types"
	"github.com/aws/aws-sdk-go-v2/service/controlcatalog"
	"github.com/aws/aws-sdk-go-v2/service/controltower"
	"github.com/aws/aws-sdk-go-v2/service/identitystore"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	orgtypes "github.com/aws/aws-sdk-go-v2/service/organizations/types"
	"github.com/aws/aws-sdk-go-v2/service/ram"
	ramtypes "github.com/aws/aws-sdk-go-v2/service/ram/types"
	"github.com/aws/aws-sdk-go-v2/service/ssoadmin"
	ssotypes "github.com/aws/aws-sdk-go-v2/service/ssoadmin/types"

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

// ControlTowerAPI is the subset of the Control Tower client the collector
// uses. The landing zone APIs only answer in the landing zone's home region.
type ControlTowerAPI interface {
	ListLandingZones(context.Context, *controltower.ListLandingZonesInput, ...func(*controltower.Options)) (*controltower.ListLandingZonesOutput, error)
	GetLandingZone(context.Context, *controltower.GetLandingZoneInput, ...func(*controltower.Options)) (*controltower.GetLandingZoneOutput, error)
	ListEnabledBaselines(context.Context, *controltower.ListEnabledBaselinesInput, ...func(*controltower.Options)) (*controltower.ListEnabledBaselinesOutput, error)
	ListEnabledControls(context.Context, *controltower.ListEnabledControlsInput, ...func(*controltower.Options)) (*controltower.ListEnabledControlsOutput, error)
}

// ControlCatalogAPI describes controls (name, behavior, implementation).
type ControlCatalogAPI interface {
	GetControl(context.Context, *controlcatalog.GetControlInput, ...func(*controlcatalog.Options)) (*controlcatalog.GetControlOutput, error)
}

// SSOAdminAPI is the subset of the IAM Identity Center admin client the
// collector uses. The instance APIs answer only in the instance's region.
type SSOAdminAPI interface {
	ListInstances(context.Context, *ssoadmin.ListInstancesInput, ...func(*ssoadmin.Options)) (*ssoadmin.ListInstancesOutput, error)
	ListPermissionSets(context.Context, *ssoadmin.ListPermissionSetsInput, ...func(*ssoadmin.Options)) (*ssoadmin.ListPermissionSetsOutput, error)
	DescribePermissionSet(context.Context, *ssoadmin.DescribePermissionSetInput, ...func(*ssoadmin.Options)) (*ssoadmin.DescribePermissionSetOutput, error)
	ListManagedPoliciesInPermissionSet(context.Context, *ssoadmin.ListManagedPoliciesInPermissionSetInput, ...func(*ssoadmin.Options)) (*ssoadmin.ListManagedPoliciesInPermissionSetOutput, error)
	ListCustomerManagedPolicyReferencesInPermissionSet(context.Context, *ssoadmin.ListCustomerManagedPolicyReferencesInPermissionSetInput, ...func(*ssoadmin.Options)) (*ssoadmin.ListCustomerManagedPolicyReferencesInPermissionSetOutput, error)
	GetInlinePolicyForPermissionSet(context.Context, *ssoadmin.GetInlinePolicyForPermissionSetInput, ...func(*ssoadmin.Options)) (*ssoadmin.GetInlinePolicyForPermissionSetOutput, error)
	GetPermissionsBoundaryForPermissionSet(context.Context, *ssoadmin.GetPermissionsBoundaryForPermissionSetInput, ...func(*ssoadmin.Options)) (*ssoadmin.GetPermissionsBoundaryForPermissionSetOutput, error)
	ListAccountsForProvisionedPermissionSet(context.Context, *ssoadmin.ListAccountsForProvisionedPermissionSetInput, ...func(*ssoadmin.Options)) (*ssoadmin.ListAccountsForProvisionedPermissionSetOutput, error)
	ListAccountAssignments(context.Context, *ssoadmin.ListAccountAssignmentsInput, ...func(*ssoadmin.Options)) (*ssoadmin.ListAccountAssignmentsOutput, error)
}

// IdentityStoreAPI resolves user and group IDs to names.
type IdentityStoreAPI interface {
	DescribeUser(context.Context, *identitystore.DescribeUserInput, ...func(*identitystore.Options)) (*identitystore.DescribeUserOutput, error)
	DescribeGroup(context.Context, *identitystore.DescribeGroupInput, ...func(*identitystore.Options)) (*identitystore.DescribeGroupOutput, error)
}

// Options configure a collection run.
type Options struct {
	// Name is the friendly organization name stored in the snapshot.
	Name string
	// Region is the region the clients call. It is recorded as the Identity
	// Center region, which the AWSReservedSSO_* role path carries.
	Region string
	// Organizations is the client for the management or delegated-admin
	// account. Required.
	Organizations OrganizationsAPI
	// RAM lists resource shares owned by each client's account. Shares owned
	// by other accounts (a network account, say) need their own client.
	RAM []RAMAPI
	// Account lists enabled regions per account. Optional.
	Account AccountAPI
	// ControlTower reads the landing zone, registered OUs and enabled
	// controls. Optional; a failing ListLandingZones call is logged and the
	// snapshot is written without a control_tower block.
	ControlTower ControlTowerAPI
	// ControlCatalog names each enabled control and tells its behavior.
	// Optional; without it controls are recorded by identifier only.
	ControlCatalog ControlCatalogAPI
	// SSOAdmin reads the IAM Identity Center instance, its permission sets
	// and account assignments. Optional; a failing ListInstances call is
	// logged and the snapshot is written without an identity_center block.
	SSOAdmin SSOAdminAPI
	// IdentityStore resolves assignment principals to user and group names.
	// Optional; without it principals are recorded by ID only.
	IdentityStore IdentityStoreAPI
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
		{"control tower", c.controlTower},
		{"identity center", c.identityCenter},
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
	opts     Options
	ctx      context.Context
	snap     *snapshot.Snapshot
	controls map[string]*controlcatalog.GetControlOutput
	// principals caches identity store lookups by "TYPE:id".
	principals map[string]string
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

// controlTower reads the landing zone, the registered OUs (OUs with an
// enabled baseline) and the controls enabled on each of them. Enrolled
// accounts are not collected: there is no List/Describe/Get call for them.
func (r *run) controlTower() error {
	client := r.opts.ControlTower
	if client == nil {
		return nil
	}
	zones, err := client.ListLandingZones(r.ctx, &controltower.ListLandingZonesInput{})
	if err != nil {
		r.opts.Logger.Printf("warning: Control Tower: %v (the landing zone APIs answer only in the home region; pass --region accordingly or --skip-control-tower)", err)
		return nil
	}
	if len(zones.LandingZones) == 0 {
		r.opts.Logger.Printf("no Control Tower landing zone in this region")
		return nil
	}
	arn := aws.ToString(zones.LandingZones[0].Arn)
	ct := &snapshot.ControlTower{LandingZoneARN: arn, HomeRegion: arnRegion(arn), RegisteredOUs: []snapshot.RegisteredOU{}, EnabledControls: []snapshot.EnabledControl{}}
	lz, err := client.GetLandingZone(r.ctx, &controltower.GetLandingZoneInput{LandingZoneIdentifier: aws.String(arn)})
	if err != nil {
		return fmt.Errorf("get landing zone: %w", err)
	}
	if d := lz.LandingZone; d != nil {
		ct.Version = aws.ToString(d.Version)
		ct.Status = string(d.Status)
		if d.DriftStatus != nil {
			ct.DriftStatus = string(d.DriftStatus.Status)
		}
		if d.Manifest != nil {
			// The manifest is a free-form document; go through its JSON form.
			var m struct {
				GovernedRegions    []string `json:"governedRegions"`
				CentralizedLogging struct {
					AccountID string `json:"accountId"`
				} `json:"centralizedLogging"`
				SecurityRoles struct {
					AccountID string `json:"accountId"`
				} `json:"securityRoles"`
			}
			raw, err := d.Manifest.MarshalSmithyDocument()
			if err == nil {
				err = json.Unmarshal(raw, &m)
			}
			if err != nil {
				r.opts.Logger.Printf("warning: landing zone manifest could not be decoded: %v", err)
			} else {
				ct.GovernedRegions = m.GovernedRegions
				ct.LogArchiveAccountID = m.CentralizedLogging.AccountID
				ct.AuditAccountID = m.SecurityRoles.AccountID
			}
		}
	}

	ouByARN, arnByOU := map[string]string{}, map[string]string{}
	for _, ou := range r.snap.OUs {
		ouByARN[ou.ARN] = ou.ID
		arnByOU[ou.ID] = ou.ARN
	}
	seen := map[string]bool{}
	baselines := controltower.NewListEnabledBaselinesPaginator(client, &controltower.ListEnabledBaselinesInput{IncludeChildren: true})
	for baselines.HasMorePages() {
		page, err := baselines.NextPage(r.ctx)
		if err != nil {
			return fmt.Errorf("enabled baselines: %w", err)
		}
		for _, b := range page.EnabledBaselines {
			target := aws.ToString(b.TargetIdentifier)
			id := ouByARN[target]
			if id == "" {
				if !strings.Contains(target, ":ou/") {
					continue // baselines on accounts or the root
				}
				id = target[strings.LastIndex(target, "/")+1:]
			}
			if seen[id] {
				continue
			}
			seen[id] = true
			ro := snapshot.RegisteredOU{OUID: id, BaselineVersion: aws.ToString(b.BaselineVersion)}
			if b.StatusSummary != nil {
				ro.Status = string(b.StatusSummary.Status)
			}
			if b.DriftStatusSummary != nil && b.DriftStatusSummary.Types != nil && b.DriftStatusSummary.Types.Inheritance != nil {
				ro.DriftStatus = string(b.DriftStatusSummary.Types.Inheritance.Status)
			}
			ct.RegisteredOUs = append(ct.RegisteredOUs, ro)
		}
	}

	for _, ro := range ct.RegisteredOUs {
		ouARN := arnByOU[ro.OUID]
		if ouARN == "" {
			r.opts.Logger.Printf("warning: registered OU %s is not in the organization tree; its controls were not listed", ro.OUID)
			continue
		}
		controls := controltower.NewListEnabledControlsPaginator(client, &controltower.ListEnabledControlsInput{TargetIdentifier: aws.String(ouARN)})
		for controls.HasMorePages() {
			page, err := controls.NextPage(r.ctx)
			if err != nil {
				return fmt.Errorf("enabled controls on %s: %w", ro.OUID, err)
			}
			for _, c := range page.EnabledControls {
				if c.ParentIdentifier != nil {
					continue // inherited from a parent OU; recorded there
				}
				ec := snapshot.EnabledControl{ControlIdentifier: aws.ToString(c.ControlIdentifier), TargetOUID: ro.OUID}
				if c.StatusSummary != nil {
					ec.Status = string(c.StatusSummary.Status)
				}
				if c.DriftStatusSummary != nil {
					ec.DriftStatus = string(c.DriftStatusSummary.DriftStatus)
				}
				r.describeControl(&ec)
				ct.EnabledControls = append(ct.EnabledControls, ec)
			}
		}
	}
	r.snap.ControlTower = ct
	return nil
}

// describeControl fills the name, behavior and implementation of a control
// from the Control Catalog, caching per identifier.
func (r *run) describeControl(ec *snapshot.EnabledControl) {
	if r.opts.ControlCatalog == nil {
		return
	}
	if r.controls == nil {
		r.controls = map[string]*controlcatalog.GetControlOutput{}
	}
	out, cached := r.controls[ec.ControlIdentifier]
	if !cached {
		var err error
		out, err = r.opts.ControlCatalog.GetControl(r.ctx, &controlcatalog.GetControlInput{ControlArn: aws.String(ec.ControlIdentifier)})
		if err != nil {
			r.opts.Logger.Printf("warning: control %s: %v (needs controlcatalog:GetControl)", ec.ControlIdentifier, err)
			out = nil
		}
		r.controls[ec.ControlIdentifier] = out
	}
	if out == nil {
		return
	}
	ec.Name = aws.ToString(out.Name)
	ec.Behavior = string(out.Behavior)
	if out.Implementation != nil {
		ec.Implementation = aws.ToString(out.Implementation.Type)
	}
}

// identityCenter reads the Identity Center instance, every permission set
// with its policies, the accounts each one is provisioned in and the
// assignments on those accounts.
func (r *run) identityCenter() error {
	client := r.opts.SSOAdmin
	if client == nil {
		return nil
	}
	instances, err := client.ListInstances(r.ctx, &ssoadmin.ListInstancesInput{})
	if err != nil {
		r.opts.Logger.Printf("warning: Identity Center: %v (the instance APIs answer only in the instance's region; pass --region accordingly or --skip-identity-center)", err)
		return nil
	}
	if len(instances.Instances) == 0 {
		r.opts.Logger.Printf("no Identity Center instance in this region")
		return nil
	}
	inst := instances.Instances[0]
	ic := &snapshot.IdentityCenter{
		InstanceARN: aws.ToString(inst.InstanceArn), IdentityStoreID: aws.ToString(inst.IdentityStoreId), Region: r.opts.Region,
		OwnerAccountID: aws.ToString(inst.OwnerAccountId), Name: aws.ToString(inst.Name),
		PermissionSets: []snapshot.PermissionSet{}, Assignments: []snapshot.AccountAssignment{},
	}
	known := map[string]bool{}
	for _, a := range r.snap.Accounts {
		known[a.ID] = true
	}
	instanceARN := aws.String(ic.InstanceARN)
	sets := ssoadmin.NewListPermissionSetsPaginator(client, &ssoadmin.ListPermissionSetsInput{InstanceArn: instanceARN})
	for sets.HasMorePages() {
		page, err := sets.NextPage(r.ctx)
		if err != nil {
			return fmt.Errorf("permission sets: %w", err)
		}
		for _, arn := range page.PermissionSets {
			ps, err := r.permissionSet(instanceARN, arn)
			if err != nil {
				return err
			}
			accounts := ssoadmin.NewListAccountsForProvisionedPermissionSetPaginator(client, &ssoadmin.ListAccountsForProvisionedPermissionSetInput{InstanceArn: instanceARN, PermissionSetArn: aws.String(arn)})
			for accounts.HasMorePages() {
				ap, err := accounts.NextPage(r.ctx)
				if err != nil {
					return fmt.Errorf("accounts provisioned with %s: %w", ps.Name, err)
				}
				for _, acct := range ap.AccountIds {
					if !known[acct] {
						r.opts.Logger.Printf("warning: permission set %s is provisioned in %s, which is not in the organization tree; skipped", ps.Name, acct)
						continue
					}
					ps.ProvisionedAccounts = append(ps.ProvisionedAccounts, acct)
					assignments := ssoadmin.NewListAccountAssignmentsPaginator(client, &ssoadmin.ListAccountAssignmentsInput{InstanceArn: instanceARN, AccountId: aws.String(acct), PermissionSetArn: aws.String(arn)})
					for assignments.HasMorePages() {
						asp, err := assignments.NextPage(r.ctx)
						if err != nil {
							return fmt.Errorf("assignments of %s in %s: %w", ps.Name, acct, err)
						}
						for _, a := range asp.AccountAssignments {
							kind := string(a.PrincipalType)
							id := aws.ToString(a.PrincipalId)
							ic.Assignments = append(ic.Assignments, snapshot.AccountAssignment{
								AccountID: acct, PermissionSetARN: arn, PrincipalType: kind, PrincipalID: id,
								PrincipalName: r.principalName(ic.IdentityStoreID, kind, id),
							})
						}
					}
				}
			}
			sort.Strings(ps.ProvisionedAccounts)
			ic.PermissionSets = append(ic.PermissionSets, ps)
		}
	}
	r.snap.IdentityCenter = ic
	return nil
}

// permissionSet describes one permission set: name, session, policies and
// boundary.
func (r *run) permissionSet(instanceARN *string, arn string) (snapshot.PermissionSet, error) {
	client := r.opts.SSOAdmin
	i, p := instanceARN, aws.String(arn)
	desc, err := client.DescribePermissionSet(r.ctx, &ssoadmin.DescribePermissionSetInput{InstanceArn: i, PermissionSetArn: p})
	if err != nil {
		return snapshot.PermissionSet{}, fmt.Errorf("describe permission set %s: %w", arn, err)
	}
	ps := snapshot.PermissionSet{ARN: arn}
	if d := desc.PermissionSet; d != nil {
		ps.Name, ps.Description, ps.SessionDuration = aws.ToString(d.Name), aws.ToString(d.Description), aws.ToString(d.SessionDuration)
	}
	managed := ssoadmin.NewListManagedPoliciesInPermissionSetPaginator(client, &ssoadmin.ListManagedPoliciesInPermissionSetInput{InstanceArn: i, PermissionSetArn: p})
	for managed.HasMorePages() {
		page, err := managed.NextPage(r.ctx)
		if err != nil {
			return ps, fmt.Errorf("managed policies of %s: %w", ps.Name, err)
		}
		for _, m := range page.AttachedManagedPolicies {
			ps.ManagedPolicies = append(ps.ManagedPolicies, aws.ToString(m.Arn))
		}
	}
	customer := ssoadmin.NewListCustomerManagedPolicyReferencesInPermissionSetPaginator(client, &ssoadmin.ListCustomerManagedPolicyReferencesInPermissionSetInput{InstanceArn: i, PermissionSetArn: p})
	for customer.HasMorePages() {
		page, err := customer.NextPage(r.ctx)
		if err != nil {
			return ps, fmt.Errorf("customer managed policies of %s: %w", ps.Name, err)
		}
		for _, c := range page.CustomerManagedPolicyReferences {
			ps.CustomerManagedPolicies = append(ps.CustomerManagedPolicies, policyPath(c))
		}
	}
	inline, err := client.GetInlinePolicyForPermissionSet(r.ctx, &ssoadmin.GetInlinePolicyForPermissionSetInput{InstanceArn: i, PermissionSetArn: p})
	if err != nil {
		return ps, fmt.Errorf("inline policy of %s: %w", ps.Name, err)
	}
	if doc := aws.ToString(inline.InlinePolicy); doc != "" {
		ps.InlinePolicy = json.RawMessage(doc)
	}
	boundary, err := client.GetPermissionsBoundaryForPermissionSet(r.ctx, &ssoadmin.GetPermissionsBoundaryForPermissionSetInput{InstanceArn: i, PermissionSetArn: p})
	var notFound *ssotypes.ResourceNotFoundException
	switch {
	case errors.As(err, &notFound):
		// No boundary set.
	case err != nil:
		return ps, fmt.Errorf("permissions boundary of %s: %w", ps.Name, err)
	case boundary.PermissionsBoundary != nil && boundary.PermissionsBoundary.ManagedPolicyArn != nil:
		ps.PermissionsBoundary = aws.ToString(boundary.PermissionsBoundary.ManagedPolicyArn)
	case boundary.PermissionsBoundary != nil && boundary.PermissionsBoundary.CustomerManagedPolicyReference != nil:
		ps.PermissionsBoundary = policyPath(*boundary.PermissionsBoundary.CustomerManagedPolicyReference)
	}
	return ps, nil
}

// policyPath renders a customer managed policy reference as path + name.
func policyPath(ref ssotypes.CustomerManagedPolicyReference) string {
	path := aws.ToString(ref.Path)
	if path == "" {
		path = "/"
	}
	return path + aws.ToString(ref.Name)
}

// principalName resolves a user or group ID to its name through the
// identity store, caching per principal. It returns "" when there is no
// identity store client or the lookup fails.
func (r *run) principalName(storeID, kind, id string) string {
	if r.opts.IdentityStore == nil || storeID == "" || id == "" {
		return ""
	}
	if r.principals == nil {
		r.principals = map[string]string{}
	}
	key := kind + ":" + id
	if name, cached := r.principals[key]; cached {
		return name
	}
	name := ""
	var err error
	switch kind {
	case snapshot.PrincipalUser:
		var out *identitystore.DescribeUserOutput
		out, err = r.opts.IdentityStore.DescribeUser(r.ctx, &identitystore.DescribeUserInput{IdentityStoreId: aws.String(storeID), UserId: aws.String(id)})
		if err == nil {
			name = aws.ToString(out.UserName)
			if name == "" {
				name = aws.ToString(out.DisplayName)
			}
		}
	case snapshot.PrincipalGroup:
		var out *identitystore.DescribeGroupOutput
		out, err = r.opts.IdentityStore.DescribeGroup(r.ctx, &identitystore.DescribeGroupInput{IdentityStoreId: aws.String(storeID), GroupId: aws.String(id)})
		if err == nil {
			name = aws.ToString(out.DisplayName)
		}
	}
	if err != nil {
		r.opts.Logger.Printf("warning: %s %s could not be resolved: %v (needs identitystore:DescribeUser and DescribeGroup)", strings.ToLower(kind), id, err)
	}
	r.principals[key] = name
	return name
}

func arnRegion(arn string) string {
	parts := strings.SplitN(arn, ":", 6)
	if len(parts) == 6 {
		return parts[3]
	}
	return ""
}

// Summary describes what a snapshot contains, for the CLI.
func Summary(s *snapshot.Snapshot) string {
	out := fmt.Sprintf("organization %s: %d OUs, %d accounts, %d policies, %d resource shares, %d delegated administrators, %d trusted services",
		s.Organization.ID, len(s.OUs), len(s.Accounts), len(s.Policies), len(s.ResourceShares), len(s.DelegatedAdministrators), len(s.TrustedAccessServices))
	if ct := s.ControlTower; ct != nil {
		out += fmt.Sprintf("; Control Tower %s with %d registered OUs and %d enabled controls", ct.Version, len(ct.RegisteredOUs), len(ct.EnabledControls))
	}
	if ic := s.IdentityCenter; ic != nil {
		out += fmt.Sprintf("; Identity Center with %d permission sets and %d account assignments", len(ic.PermissionSets), len(ic.Assignments))
	}
	return out
}
