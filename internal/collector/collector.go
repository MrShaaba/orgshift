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
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/aws-sdk-go-v2/service/account"
	accounttypes "github.com/aws/aws-sdk-go-v2/service/account/types"
	"github.com/aws/aws-sdk-go-v2/service/controlcatalog"
	"github.com/aws/aws-sdk-go-v2/service/controltower"
	cttypes "github.com/aws/aws-sdk-go-v2/service/controltower/types"
	"github.com/aws/aws-sdk-go-v2/service/identitystore"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	orgtypes "github.com/aws/aws-sdk-go-v2/service/organizations/types"
	"github.com/aws/aws-sdk-go-v2/service/ram"
	ramtypes "github.com/aws/aws-sdk-go-v2/service/ram/types"
	"github.com/aws/aws-sdk-go-v2/service/ssoadmin"
	ssotypes "github.com/aws/aws-sdk-go-v2/service/ssoadmin/types"
	"github.com/aws/smithy-go"

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
	// Region is the region the clients call. It is recorded on the regional
	// coverage records and as the Identity Center region, which the
	// AWSReservedSSO_* role path carries.
	Region string
	// Version is the collector build, recorded in the coverage block.
	Version string
	// Organizations is the client for the management or delegated-admin
	// account. Required.
	Organizations OrganizationsAPI
	// RAM lists resource shares owned by each client's account. Shares owned
	// by other accounts (a network account, say) need their own client.
	RAM []RAMAPI
	// RAMLabels names each RAM client (a profile name, say) for the coverage
	// records, in the same order as RAM. Optional.
	RAMLabels []string
	// Account lists enabled regions per account. Optional.
	Account AccountAPI
	// ControlTower reads the landing zone, registered OUs, enrolled accounts
	// and enabled controls. Optional; a failing call is recorded in the
	// coverage block and the snapshot is written without a control_tower
	// block.
	ControlTower ControlTowerAPI
	// ControlCatalog names each enabled control and tells its behavior.
	// Optional; without it controls are recorded by identifier only.
	ControlCatalog ControlCatalogAPI
	// SSOAdmin reads the IAM Identity Center instance, its permission sets
	// and account assignments. Optional; a failing call is recorded in the
	// coverage block and the snapshot is written without an identity_center
	// block.
	SSOAdmin SSOAdminAPI
	// IdentityStore resolves assignment principals to user and group names.
	// Optional; without it principals are recorded by ID only.
	IdentityStore IdentityStoreAPI
	// SkipReasons says why an optional client is nil, keyed by coverage
	// domain ("--skip-ram", say). Domains without a reason are recorded as
	// skipped with a generic note.
	SkipReasons map[string]string
	// Logger receives progress and warnings. Optional.
	Logger *log.Logger
	// Now overrides the timestamp, for tests.
	Now func() time.Time
}

// Collect reads the organization and returns a validated snapshot. The
// organization and its tree are required: a failure there is returned as an
// error. Every other domain is isolated: a failure is recorded in the
// snapshot's coverage block (access denied, partial, error, skipped,
// unsupported) and collection carries on, so the snapshot says exactly what
// it could not see instead of presenting an empty list as fact.
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
	c.snap.ResourceShares = []snapshot.ResourceShare{}
	c.snap.DelegatedAdministrators = []snapshot.DelegatedAdministrator{}
	c.snap.TrustedAccessServices = []string{}
	c.snap.OrganizationTrails = []snapshot.OrganizationTrail{}
	c.snap.ConfigAggregators = []snapshot.ConfigAggregator{}
	c.snap.StackSets = []snapshot.StackSet{}
	for _, s := range []struct {
		name string
		fn   func() error
	}{{"organization", c.organization}, {"roots and tree", c.tree}} {
		opts.Logger.Printf("collecting %s", s.name)
		if err := s.fn(); err != nil {
			return nil, fmt.Errorf("%s: %w", s.name, err)
		}
	}
	for _, s := range []struct {
		name string
		fn   func()
	}{
		{"account tags", c.accountTags},
		{"policies", c.policies},
		{"delegated administrators", c.delegated},
		{"trusted access", c.trustedAccess},
		{"resource shares", c.shares},
		{"enabled regions", c.regions},
		{"control tower", c.controlTower},
		{"identity center", c.identityCenter},
		{"organization trails, Config aggregators and StackSets", c.notCollected},
	} {
		opts.Logger.Printf("collecting %s", s.name)
		s.fn()
	}
	c.snap.Usage = map[string]*snapshot.AccountUsage{}
	c.snap.Coverage = &snapshot.Coverage{CollectorVersion: opts.Version, Domains: c.cov}
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
	cov      []snapshot.DomainCoverage
	controls map[string]*controlcatalog.GetControlOutput
	// principals caches identity store lookups by "TYPE:id".
	principals map[string]string
}

// record appends a coverage record, stamping it with the collection time.
func (r *run) record(d snapshot.DomainCoverage) {
	if d.CollectedAt == "" {
		d.CollectedAt = r.snap.GeneratedAt
	}
	if d.Status != snapshot.CoverageObserved && d.Status != snapshot.CoverageEmpty {
		r.opts.Logger.Printf("coverage: %s", d.Label())
	}
	r.cov = append(r.cov, d)
}

// observed records a successful domain: observed when items were found,
// empty otherwise.
func (r *run) observed(domain string, items, pages int, ops ...string) snapshot.DomainCoverage {
	d := snapshot.DomainCoverage{Domain: domain, Status: snapshot.CoverageObserved, Items: items, Pages: pages, Operations: ops}
	if items == 0 {
		d.Status = snapshot.CoverageEmpty
	}
	return d
}

// failed records a failed domain, classifying the error. When pages were
// read before the failure the domain is partial.
func (r *run) failed(domain string, err error, pages, items int, ops ...string) snapshot.DomainCoverage {
	status, msg := classify(err)
	if pages > 0 || items > 0 {
		status = snapshot.CoveragePartial
	}
	return snapshot.DomainCoverage{Domain: domain, Status: status, Error: msg, Pages: pages, Items: items, Operations: ops}
}

// skipped records a domain the operator turned off.
func (r *run) skipped(domain string) snapshot.DomainCoverage {
	reason := r.opts.SkipReasons[domain]
	if reason == "" {
		reason = "no client configured for this domain"
	}
	return snapshot.DomainCoverage{Domain: domain, Status: snapshot.CoverageSkipped, Reason: reason}
}

// classify maps an API error to a coverage status and a message that keeps
// the error code.
func classify(err error) (snapshot.CoverageStatus, string) {
	if err == nil {
		return snapshot.CoverageObserved, ""
	}
	msg := err.Error()
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		code := apiErr.ErrorCode()
		msg = code + ": " + apiErr.ErrorMessage()
		switch code {
		case "AccessDeniedException", "AccessDenied", "UnauthorizedOperation", "AuthorizationError", "UnauthorizedException", "NotAuthorized", "Forbidden":
			return snapshot.CoverageAccessDenied, msg
		case "AWSOrganizationsNotInUseException", "UnsupportedOperation", "UnsupportedAPIEndpointException", "UnknownOperationException", "InvalidAction", "UnsupportedOperationException":
			return snapshot.CoverageUnsupported, msg
		}
	}
	var re *awshttp.ResponseError
	if errors.As(err, &re) && re.HTTPStatusCode() == 403 {
		return snapshot.CoverageAccessDenied, msg
	}
	return snapshot.CoverageError, msg
}

// paginate drives a paginator through closures and reports how many pages
// were read before an error.
func paginate(hasMore func() bool, next func() error) (pages int, err error) {
	for hasMore() {
		if err := next(); err != nil {
			return pages, err
		}
		pages++
	}
	return pages, nil
}

func (r *run) organization() error {
	out, err := r.opts.Organizations.DescribeOrganization(r.ctx, &organizations.DescribeOrganizationInput{})
	if err != nil {
		r.record(r.failed(snapshot.DomainOrganization, err, 0, 0, "organizations:DescribeOrganization"))
		return err
	}
	o := out.Organization
	r.snap.Organization.ID = aws.ToString(o.Id)
	r.snap.Organization.ARN = aws.ToString(o.Arn)
	r.snap.Organization.ManagementAccountID = aws.ToString(o.MasterAccountId)
	r.snap.Organization.FeatureSet = string(o.FeatureSet)
	r.record(r.observed(snapshot.DomainOrganization, 1, 1, "organizations:DescribeOrganization"))
	return nil
}

const treeOps = "organizations:ListRoots, organizations:ListOrganizationalUnitsForParent, organizations:ListAccountsForParent"

func (r *run) tree() error {
	ops := strings.Split(treeOps, ", ")
	roots, err := r.opts.Organizations.ListRoots(r.ctx, &organizations.ListRootsInput{})
	if err != nil {
		r.record(r.failed(snapshot.DomainTree, err, 0, 0, ops...))
		return err
	}
	if len(roots.Roots) == 0 {
		err := fmt.Errorf("the organization has no root")
		r.record(r.failed(snapshot.DomainTree, err, 1, 0, ops...))
		return err
	}
	root := roots.Roots[0]
	r.snap.Root = snapshot.Root{ID: aws.ToString(root.Id), ARN: aws.ToString(root.Arn), Name: aws.ToString(root.Name)}
	for _, pt := range root.PolicyTypes {
		if pt.Status == orgtypes.PolicyTypeStatusEnabled {
			r.snap.Root.EnabledPolicyTypes = append(r.snap.Root.EnabledPolicyTypes, snapshot.PolicyType(pt.Type))
		}
	}
	pages := 1
	if err := r.walk(r.snap.Root.ID, &pages); err != nil {
		r.record(r.failed(snapshot.DomainTree, err, pages, len(r.snap.OUs)+len(r.snap.Accounts), ops...))
		return err
	}
	r.record(r.observed(snapshot.DomainTree, 1+len(r.snap.OUs)+len(r.snap.Accounts), pages, ops...))
	return nil
}

func (r *run) walk(parentID string, pages *int) error {
	ouPager := organizations.NewListOrganizationalUnitsForParentPaginator(r.opts.Organizations, &organizations.ListOrganizationalUnitsForParentInput{ParentId: aws.String(parentID)})
	var children []string
	n, err := paginate(ouPager.HasMorePages, func() error {
		page, err := ouPager.NextPage(r.ctx)
		if err != nil {
			return err
		}
		for _, ou := range page.OrganizationalUnits {
			r.snap.OUs = append(r.snap.OUs, snapshot.OU{ID: aws.ToString(ou.Id), ARN: aws.ToString(ou.Arn), Name: aws.ToString(ou.Name), ParentID: parentID})
			children = append(children, aws.ToString(ou.Id))
		}
		return nil
	})
	*pages += n
	if err != nil {
		return err
	}
	acctPager := organizations.NewListAccountsForParentPaginator(r.opts.Organizations, &organizations.ListAccountsForParentInput{ParentId: aws.String(parentID)})
	n, err = paginate(acctPager.HasMorePages, func() error {
		page, err := acctPager.NextPage(r.ctx)
		if err != nil {
			return err
		}
		for _, a := range page.Accounts {
			acct := snapshot.Account{
				ID: aws.ToString(a.Id), ARN: aws.ToString(a.Arn), Name: aws.ToString(a.Name), Email: aws.ToString(a.Email),
				Status: string(a.Status), JoinedMethod: string(a.JoinedMethod), ParentID: parentID,
			}
			if a.JoinedTimestamp != nil {
				acct.JoinedAt = a.JoinedTimestamp.UTC().Format(time.RFC3339)
			}
			r.snap.Accounts = append(r.snap.Accounts, acct)
		}
		return nil
	})
	*pages += n
	if err != nil {
		return err
	}
	for _, id := range children {
		if err := r.walk(id, pages); err != nil {
			return err
		}
	}
	return nil
}

// accountTags reads the tags of every account. One failing account makes
// the domain partial; the others keep their tags.
func (r *run) accountTags() {
	const op = "organizations:ListTagsForResource"
	var failures []string
	var firstErr error
	pages := 0
	for i := range r.snap.Accounts {
		a := &r.snap.Accounts[i]
		pager := organizations.NewListTagsForResourcePaginator(r.opts.Organizations, &organizations.ListTagsForResourceInput{ResourceId: aws.String(a.ID)})
		tags := map[string]string{}
		n, err := paginate(pager.HasMorePages, func() error {
			page, err := pager.NextPage(r.ctx)
			if err != nil {
				return err
			}
			for _, t := range page.Tags {
				tags[aws.ToString(t.Key)] = aws.ToString(t.Value)
			}
			return nil
		})
		pages += n
		if err != nil {
			failures = append(failures, a.ID)
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		if len(tags) > 0 {
			a.Tags = tags
		}
	}
	if firstErr != nil {
		d := r.failed(snapshot.DomainAccountTags, firstErr, pages, len(r.snap.Accounts)-len(failures), op)
		d.Error = fmt.Sprintf("%d of %d accounts failed (%s): %s", len(failures), len(r.snap.Accounts), strings.Join(firstN(failures, 5), ", "), d.Error)
		if len(failures) == len(r.snap.Accounts) {
			d.Status, _ = classify(firstErr)
		}
		r.record(d)
		return
	}
	r.record(r.observed(snapshot.DomainAccountTags, len(r.snap.Accounts), pages, op))
}

func (r *run) policies() {
	ops := []string{"organizations:ListPolicies", "organizations:DescribePolicy", "organizations:ListTargetsForPolicy"}
	for _, t := range snapshot.AllPolicyTypes {
		domain := snapshot.PolicyDomain(t)
		if !r.snap.PolicyTypeEnabled(t) {
			r.record(snapshot.DomainCoverage{Domain: domain, Status: snapshot.CoverageEmpty, Reason: "policy type not enabled at the root"})
			continue
		}
		items, pages := 0, 0
		pager := organizations.NewListPoliciesPaginator(r.opts.Organizations, &organizations.ListPoliciesInput{Filter: orgtypes.PolicyType(t)})
		n, err := paginate(pager.HasMorePages, func() error {
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
				tn, err := paginate(targets.HasMorePages, func() error {
					tp, err := targets.NextPage(r.ctx)
					if err != nil {
						return err
					}
					for _, tgt := range tp.Targets {
						p.Targets = append(p.Targets, aws.ToString(tgt.TargetId))
					}
					return nil
				})
				pages += tn
				if err != nil {
					return fmt.Errorf("targets of %s: %w", id, err)
				}
				sort.Strings(p.Targets)
				if p.Targets == nil {
					p.Targets = []string{}
				}
				r.snap.Policies = append(r.snap.Policies, p)
				items++
			}
			return nil
		})
		pages += n
		if err != nil {
			// Drop the half-read type so an incomplete attachment list does
			// not pass for the whole picture; the record says what happened.
			var kept []snapshot.Policy
			for _, p := range r.snap.Policies {
				if p.Type != t {
					kept = append(kept, p)
				}
			}
			r.snap.Policies = kept
			d := r.failed(domain, err, pages, items, ops...)
			d.Items = 0
			if items > 0 {
				d.Error = fmt.Sprintf("%d policies read before the failure were dropped: %s", items, d.Error)
			}
			r.record(d)
			continue
		}
		r.record(r.observed(domain, items, pages, ops...))
	}
}

func (r *run) delegated() {
	ops := []string{"organizations:ListDelegatedAdministrators", "organizations:ListDelegatedServicesForAccount"}
	items, pages := 0, 0
	pager := organizations.NewListDelegatedAdministratorsPaginator(r.opts.Organizations, &organizations.ListDelegatedAdministratorsInput{})
	n, err := paginate(pager.HasMorePages, func() error {
		page, err := pager.NextPage(r.ctx)
		if err != nil {
			return err
		}
		for _, admin := range page.DelegatedAdministrators {
			id := aws.ToString(admin.Id)
			svcPager := organizations.NewListDelegatedServicesForAccountPaginator(r.opts.Organizations, &organizations.ListDelegatedServicesForAccountInput{AccountId: aws.String(id)})
			sn, err := paginate(svcPager.HasMorePages, func() error {
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
					items++
				}
				return nil
			})
			pages += sn
			if err != nil {
				return fmt.Errorf("services of %s: %w", id, err)
			}
		}
		return nil
	})
	pages += n
	if err != nil {
		r.record(r.failed(snapshot.DomainDelegatedAdmins, err, pages, items, ops...))
		return
	}
	r.record(r.observed(snapshot.DomainDelegatedAdmins, items, pages, ops...))
}

func (r *run) trustedAccess() {
	const op = "organizations:ListAWSServiceAccessForOrganization"
	pager := organizations.NewListAWSServiceAccessForOrganizationPaginator(r.opts.Organizations, &organizations.ListAWSServiceAccessForOrganizationInput{})
	pages, err := paginate(pager.HasMorePages, func() error {
		page, err := pager.NextPage(r.ctx)
		if err != nil {
			return err
		}
		for _, s := range page.EnabledServicePrincipals {
			r.snap.TrustedAccessServices = append(r.snap.TrustedAccessServices, aws.ToString(s.ServicePrincipal))
		}
		return nil
	})
	sort.Strings(r.snap.TrustedAccessServices)
	if err != nil {
		r.record(r.failed(snapshot.DomainTrustedAccess, err, pages, len(r.snap.TrustedAccessServices), op))
		return
	}
	r.record(r.observed(snapshot.DomainTrustedAccess, len(r.snap.TrustedAccessServices), pages, op))
}

func (r *run) trusted(servicePrincipal string) bool {
	for _, s := range r.snap.TrustedAccessServices {
		if s == servicePrincipal {
			return true
		}
	}
	return false
}

// shares lists the resource shares owned by each RAM client's account. RAM
// only shows shares owned by the caller, so each client is one record.
func (r *run) shares() {
	ops := []string{"ram:GetResourceShares", "ram:ListPrincipals", "ram:ListResources"}
	if len(r.opts.RAM) == 0 {
		d := r.skipped(snapshot.DomainResourceShares)
		d.Region = r.opts.Region
		r.record(d)
		return
	}
	for i, client := range r.opts.RAM {
		label := ""
		if i < len(r.opts.RAMLabels) {
			label = r.opts.RAMLabels[i]
		}
		items, pages := 0, 0
		owner := ""
		pager := ram.NewGetResourceSharesPaginator(client, &ram.GetResourceSharesInput{ResourceOwner: ramtypes.ResourceOwnerSelf})
		n, err := paginate(pager.HasMorePages, func() error {
			page, err := pager.NextPage(r.ctx)
			if err != nil {
				return err
			}
			for _, sh := range page.ResourceShares {
				if owner == "" {
					owner = aws.ToString(sh.OwningAccountId)
				}
				if sh.Status == ramtypes.ResourceShareStatusDeleted || sh.Status == ramtypes.ResourceShareStatusDeleting {
					continue
				}
				arn := aws.ToString(sh.ResourceShareArn)
				// RetainSharingOnAccountLeaveOrganization is not exposed on
				// ResourceShare by the RAM SDK module this build can use (the
				// one that has it requires Go 1.24), so the field stays false
				// unless entered by hand; false is the documented default.
				s := snapshot.ResourceShare{
					ARN: arn, Name: aws.ToString(sh.Name), OwnerAccountID: aws.ToString(sh.OwningAccountId), Status: string(sh.Status),
					AllowExternalPrincipals: aws.ToBool(sh.AllowExternalPrincipals),
					Principals:              []string{}, Resources: []snapshot.SharedResource{},
				}
				pp := ram.NewListPrincipalsPaginator(client, &ram.ListPrincipalsInput{ResourceOwner: ramtypes.ResourceOwnerSelf, ResourceShareArns: []string{arn}})
				pn, err := paginate(pp.HasMorePages, func() error {
					page, err := pp.NextPage(r.ctx)
					if err != nil {
						return err
					}
					for _, p := range page.Principals {
						s.Principals = append(s.Principals, aws.ToString(p.Id))
					}
					return nil
				})
				pages += pn
				if err != nil {
					return fmt.Errorf("principals of %s: %w", arn, err)
				}
				rp := ram.NewListResourcesPaginator(client, &ram.ListResourcesInput{ResourceOwner: ramtypes.ResourceOwnerSelf, ResourceShareArns: []string{arn}})
				rn, err := paginate(rp.HasMorePages, func() error {
					page, err := rp.NextPage(r.ctx)
					if err != nil {
						return err
					}
					for _, res := range page.Resources {
						s.Resources = append(s.Resources, snapshot.SharedResource{ARN: aws.ToString(res.Arn), Type: aws.ToString(res.Type)})
					}
					return nil
				})
				pages += rn
				if err != nil {
					return fmt.Errorf("resources of %s: %w", arn, err)
				}
				r.snap.ResourceShares = append(r.snap.ResourceShares, s)
				items++
			}
			return nil
		})
		pages += n
		var d snapshot.DomainCoverage
		if err != nil {
			d = r.failed(snapshot.DomainResourceShares, err, pages, items, ops...)
		} else {
			d = r.observed(snapshot.DomainResourceShares, items, pages, ops...)
		}
		d.Region = r.opts.Region
		if owner != "" && accountIDLike(owner) {
			d.AccountID = owner
		}
		if label != "" {
			d.Reason = strings.TrimSpace(d.Reason + " client " + label)
		}
		r.record(d)
	}
}

func (r *run) regions() {
	const op = "account:ListRegions"
	if r.opts.Account == nil {
		r.record(r.skipped(snapshot.DomainEnabledRegions))
		return
	}
	var failures []string
	var firstErr error
	pages := 0
	for i := range r.snap.Accounts {
		a := &r.snap.Accounts[i]
		pager := account.NewListRegionsPaginator(r.opts.Account, &account.ListRegionsInput{
			AccountId: aws.String(a.ID),
			RegionOptStatusContains: []accounttypes.RegionOptStatus{
				accounttypes.RegionOptStatusEnabled, accounttypes.RegionOptStatusEnabledByDefault, accounttypes.RegionOptStatusEnabling,
			},
		})
		var regions []string
		n, err := paginate(pager.HasMorePages, func() error {
			page, err := pager.NextPage(r.ctx)
			if err != nil {
				return err
			}
			for _, reg := range page.Regions {
				regions = append(regions, aws.ToString(reg.RegionName))
			}
			return nil
		})
		pages += n
		if err != nil {
			failures = append(failures, a.ID)
			if firstErr == nil {
				firstErr = err
			}
			// A per-account record so the evaluator knows this account's
			// region list is unknown rather than empty.
			d := r.failed(snapshot.DomainEnabledRegions, err, 0, 0, op)
			d.AccountID = a.ID
			r.record(d)
			continue
		}
		sort.Strings(regions)
		a.EnabledRegions = regions
	}
	if firstErr != nil {
		r.opts.Logger.Printf("warning: enabled regions failed for %d account(s) (needs account:ListRegions and trusted access for account.amazonaws.com): %v", len(failures), firstErr)
		if len(failures) == len(r.snap.Accounts) {
			return
		}
	}
	d := r.observed(snapshot.DomainEnabledRegions, len(r.snap.Accounts)-len(failures), pages, op)
	if len(failures) > 0 {
		d.Reason = fmt.Sprintf("%d account(s) failed and have their own records", len(failures))
	}
	r.record(d)
}

// notCollected records the domains this collector version does not read.
func (r *run) notCollected() {
	for _, d := range []string{snapshot.DomainOrgTrails, snapshot.DomainConfigAggregator, snapshot.DomainStackSets} {
		r.record(snapshot.DomainCoverage{Domain: d, Status: snapshot.CoverageUnsupported, Reason: "not collected by this collector version; add the entries by hand (docs/snapshot.md) or wait for the collector that reads them (ROADMAP.md)"})
	}
}

// controlTower reads the landing zone, the registered OUs (OUs with an
// enabled baseline), the enrolled accounts (child enabled baselines whose
// target is an account) and the controls enabled on each registered OU.
func (r *run) controlTower() {
	client := r.opts.ControlTower
	ops := []string{"controltower:ListLandingZones", "controltower:GetLandingZone", "controltower:ListEnabledBaselines", "controltower:ListEnabledControls", "controlcatalog:GetControl"}
	regional := func(d snapshot.DomainCoverage) snapshot.DomainCoverage { d.Region = r.opts.Region; return d }
	if client == nil {
		r.record(regional(r.skipped(snapshot.DomainControlTower)))
		r.record(regional(r.skipped(snapshot.DomainEnrolledAccounts)))
		return
	}
	zones, err := client.ListLandingZones(r.ctx, &controltower.ListLandingZonesInput{})
	if err != nil {
		d := r.failed(snapshot.DomainControlTower, err, 0, 0, ops[0])
		d.Error += "; the landing zone APIs answer only in the home region, pass --region accordingly"
		r.record(regional(d))
		r.record(regional(snapshot.DomainCoverage{Domain: snapshot.DomainEnrolledAccounts, Status: snapshot.CoverageError, Error: "not read: the landing zone lookup failed"}))
		return
	}
	if len(zones.LandingZones) == 0 {
		if r.trusted("controltower.amazonaws.com") {
			// An empty answer in the wrong region looks like "no Control
			// Tower"; trusted access says it is in use, so do not believe it.
			msg := fmt.Sprintf("no landing zone answered in %s although trusted access for controltower.amazonaws.com is enabled; the landing zone APIs answer only in the home region, re-run with --region <home region>", r.opts.Region)
			r.record(regional(snapshot.DomainCoverage{Domain: snapshot.DomainControlTower, Status: snapshot.CoverageError, Error: msg, Operations: ops[:1]}))
			r.record(regional(snapshot.DomainCoverage{Domain: snapshot.DomainEnrolledAccounts, Status: snapshot.CoverageError, Error: "not read: the landing zone was not found in " + r.opts.Region}))
			return
		}
		r.record(regional(snapshot.DomainCoverage{Domain: snapshot.DomainControlTower, Status: snapshot.CoverageEmpty, Operations: ops[:1], Reason: "no landing zone in " + r.opts.Region + " and no trusted access for controltower.amazonaws.com"}))
		r.record(regional(snapshot.DomainCoverage{Domain: snapshot.DomainEnrolledAccounts, Status: snapshot.CoverageEmpty, Reason: "no landing zone"}))
		return
	}
	arn := aws.ToString(zones.LandingZones[0].Arn)
	ct := &snapshot.ControlTower{LandingZoneARN: arn, HomeRegion: arnRegion(arn), RegisteredOUs: []snapshot.RegisteredOU{}, EnabledControls: []snapshot.EnabledControl{}}
	lz, err := client.GetLandingZone(r.ctx, &controltower.GetLandingZoneInput{LandingZoneIdentifier: aws.String(arn)})
	if err != nil {
		d := r.failed(snapshot.DomainControlTower, err, 1, 0, ops[:2]...)
		r.record(regional(d))
		r.record(regional(snapshot.DomainCoverage{Domain: snapshot.DomainEnrolledAccounts, Status: snapshot.CoverageError, Error: "not read: the landing zone could not be described"}))
		return
	}
	if d := lz.LandingZone; d != nil {
		ct.Version = aws.ToString(d.Version)
		ct.LatestAvailableVersion = aws.ToString(d.LatestAvailableVersion)
		ct.Status = string(d.Status)
		if d.DriftStatus != nil {
			ct.DriftStatus = string(d.DriftStatus.Status)
		}
		ct.AutoEnrollment = snapshot.AutoEnrollmentDisabled
		for _, t := range d.RemediationTypes {
			if t == cttypes.RemediationTypeInheritanceDrift {
				ct.AutoEnrollment = snapshot.AutoEnrollmentEnabled
			}
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
	known := map[string]bool{}
	for _, a := range r.snap.Accounts {
		known[a.ID] = true
	}
	seen := map[string]bool{}
	ouOfBaseline := map[string]string{} // enabled baseline ARN -> OU ID
	var childBaselines []cttypes.EnabledBaselineSummary
	pages := 2
	baselines := controltower.NewListEnabledBaselinesPaginator(client, &controltower.ListEnabledBaselinesInput{IncludeChildren: true})
	n, err := paginate(baselines.HasMorePages, func() error {
		page, err := baselines.NextPage(r.ctx)
		if err != nil {
			return err
		}
		for _, b := range page.EnabledBaselines {
			target := aws.ToString(b.TargetIdentifier)
			if acct := accountOfTarget(target); acct != "" {
				childBaselines = append(childBaselines, b)
				continue
			}
			id := ouByARN[target]
			if id == "" {
				if !strings.Contains(target, ":ou/") {
					continue // baselines on the root or other targets
				}
				id = target[strings.LastIndex(target, "/")+1:]
			}
			ouOfBaseline[aws.ToString(b.Arn)] = id
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
		return nil
	})
	pages += n
	if err != nil {
		r.snap.ControlTower = ct
		d := r.failed(snapshot.DomainControlTower, err, pages, 1+len(ct.RegisteredOUs), ops[:3]...)
		d.Error = "enabled baselines: " + d.Error
		r.record(regional(d))
		r.record(regional(snapshot.DomainCoverage{Domain: snapshot.DomainEnrolledAccounts, Status: snapshot.CoveragePartial, Error: "ListEnabledBaselines failed before every page was read: " + err.Error()}))
		return
	}
	// Enrolled accounts: one record per account with a child enabled
	// baseline, whatever the baseline.
	enrolled := map[string]*snapshot.EnrolledAccount{}
	var order []string
	for _, b := range childBaselines {
		acct := accountOfTarget(aws.ToString(b.TargetIdentifier))
		if !known[acct] {
			r.opts.Logger.Printf("warning: enabled baseline on account %s, which is not in the organization tree; skipped", acct)
			continue
		}
		e, ok := enrolled[acct]
		if !ok {
			e = &snapshot.EnrolledAccount{AccountID: acct, Source: snapshot.EnrolledFromBaseline}
			enrolled[acct] = e
			order = append(order, acct)
		}
		if b.StatusSummary != nil && (e.Status == "" || string(b.StatusSummary.Status) != string(cttypes.EnablementStatusSucceeded)) {
			e.Status = string(b.StatusSummary.Status)
		}
		if b.DriftStatusSummary != nil && b.DriftStatusSummary.Types != nil && b.DriftStatusSummary.Types.Inheritance != nil && e.DriftStatus == "" {
			e.DriftStatus = string(b.DriftStatusSummary.Types.Inheritance.Status)
		}
		if parent := ouOfBaseline[aws.ToString(b.ParentIdentifier)]; parent != "" && e.ParentOUID == "" {
			e.ParentOUID = parent
		}
	}
	sort.Strings(order)
	for _, acct := range order {
		ct.EnrolledAccounts = append(ct.EnrolledAccounts, *enrolled[acct])
	}
	r.record(regional(r.observed(snapshot.DomainEnrolledAccounts, len(ct.EnrolledAccounts), n, ops[2])))

	controlPages, controlErr := 0, error(nil)
	for _, ro := range ct.RegisteredOUs {
		ouARN := arnByOU[ro.OUID]
		if ouARN == "" {
			r.opts.Logger.Printf("warning: registered OU %s is not in the organization tree; its controls were not listed", ro.OUID)
			continue
		}
		controls := controltower.NewListEnabledControlsPaginator(client, &controltower.ListEnabledControlsInput{TargetIdentifier: aws.String(ouARN)})
		cn, err := paginate(controls.HasMorePages, func() error {
			page, err := controls.NextPage(r.ctx)
			if err != nil {
				return err
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
			return nil
		})
		controlPages += cn
		if err != nil {
			controlErr = fmt.Errorf("enabled controls on %s: %w", ro.OUID, err)
			break
		}
	}
	pages += controlPages
	r.snap.ControlTower = ct
	if controlErr != nil {
		d := r.failed(snapshot.DomainControlTower, controlErr, pages, 1+len(ct.RegisteredOUs)+len(ct.EnabledControls), ops...)
		r.record(regional(d))
		return
	}
	r.record(regional(r.observed(snapshot.DomainControlTower, 1+len(ct.RegisteredOUs)+len(ct.EnabledControls), pages, ops...)))
}

// accountOfTarget returns the account ID of a baseline target that is an
// account (an account ARN or a bare ID), or "".
func accountOfTarget(target string) string {
	if i := strings.Index(target, ":account/"); i >= 0 {
		return target[strings.LastIndex(target, "/")+1:]
	}
	if accountIDLike(target) {
		return target
	}
	return ""
}

func accountIDLike(s string) bool {
	return len(s) == 12 && strings.Trim(s, "0123456789") == ""
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
func (r *run) identityCenter() {
	client := r.opts.SSOAdmin
	ops := []string{"sso:ListInstances", "sso:ListPermissionSets", "sso:DescribePermissionSet", "sso:ListManagedPoliciesInPermissionSet", "sso:ListCustomerManagedPolicyReferencesInPermissionSet",
		"sso:GetInlinePolicyForPermissionSet", "sso:GetPermissionsBoundaryForPermissionSet", "sso:ListAccountsForProvisionedPermissionSet", "sso:ListAccountAssignments", "identitystore:DescribeUser", "identitystore:DescribeGroup"}
	regional := func(d snapshot.DomainCoverage) snapshot.DomainCoverage { d.Region = r.opts.Region; return d }
	if client == nil {
		r.record(regional(r.skipped(snapshot.DomainIdentityCenter)))
		return
	}
	instances, err := client.ListInstances(r.ctx, &ssoadmin.ListInstancesInput{})
	if err != nil {
		d := r.failed(snapshot.DomainIdentityCenter, err, 0, 0, ops[0])
		d.Error += "; the instance APIs answer only in the instance's region, pass --region accordingly"
		r.record(regional(d))
		return
	}
	if len(instances.Instances) == 0 {
		if r.trusted("sso.amazonaws.com") {
			msg := fmt.Sprintf("no Identity Center instance answered in %s although trusted access for sso.amazonaws.com is enabled; the instance APIs answer only in the instance's region, re-run with --region <instance region>", r.opts.Region)
			r.record(regional(snapshot.DomainCoverage{Domain: snapshot.DomainIdentityCenter, Status: snapshot.CoverageError, Error: msg, Operations: ops[:1]}))
			return
		}
		r.record(regional(snapshot.DomainCoverage{Domain: snapshot.DomainIdentityCenter, Status: snapshot.CoverageEmpty, Operations: ops[:1], Reason: "no instance in " + r.opts.Region + " and no trusted access for sso.amazonaws.com"}))
		return
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
	pages := 1
	sets := ssoadmin.NewListPermissionSetsPaginator(client, &ssoadmin.ListPermissionSetsInput{InstanceArn: instanceARN})
	n, err := paginate(sets.HasMorePages, func() error {
		page, err := sets.NextPage(r.ctx)
		if err != nil {
			return err
		}
		for _, arn := range page.PermissionSets {
			ps, err := r.permissionSet(instanceARN, arn)
			if err != nil {
				return err
			}
			accounts := ssoadmin.NewListAccountsForProvisionedPermissionSetPaginator(client, &ssoadmin.ListAccountsForProvisionedPermissionSetInput{InstanceArn: instanceARN, PermissionSetArn: aws.String(arn)})
			an, err := paginate(accounts.HasMorePages, func() error {
				ap, err := accounts.NextPage(r.ctx)
				if err != nil {
					return err
				}
				for _, acct := range ap.AccountIds {
					if !known[acct] {
						r.opts.Logger.Printf("warning: permission set %s is provisioned in %s, which is not in the organization tree; skipped", ps.Name, acct)
						continue
					}
					ps.ProvisionedAccounts = append(ps.ProvisionedAccounts, acct)
					assignments := ssoadmin.NewListAccountAssignmentsPaginator(client, &ssoadmin.ListAccountAssignmentsInput{InstanceArn: instanceARN, AccountId: aws.String(acct), PermissionSetArn: aws.String(arn)})
					asn, err := paginate(assignments.HasMorePages, func() error {
						asp, err := assignments.NextPage(r.ctx)
						if err != nil {
							return err
						}
						for _, a := range asp.AccountAssignments {
							kind := string(a.PrincipalType)
							id := aws.ToString(a.PrincipalId)
							ic.Assignments = append(ic.Assignments, snapshot.AccountAssignment{
								AccountID: acct, PermissionSetARN: arn, PrincipalType: kind, PrincipalID: id,
								PrincipalName: r.principalName(ic.IdentityStoreID, kind, id),
							})
						}
						return nil
					})
					pages += asn
					if err != nil {
						return fmt.Errorf("assignments of %s in %s: %w", ps.Name, acct, err)
					}
				}
				return nil
			})
			pages += an
			if err != nil {
				return fmt.Errorf("accounts provisioned with %s: %w", ps.Name, err)
			}
			sort.Strings(ps.ProvisionedAccounts)
			ic.PermissionSets = append(ic.PermissionSets, ps)
		}
		return nil
	})
	pages += n
	r.snap.IdentityCenter = ic
	items := 1 + len(ic.PermissionSets) + len(ic.Assignments)
	if err != nil {
		r.record(regional(r.failed(snapshot.DomainIdentityCenter, err, pages, items, ops...)))
		return
	}
	r.record(regional(r.observed(snapshot.DomainIdentityCenter, items, pages, ops...)))
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
	if _, err := paginate(managed.HasMorePages, func() error {
		page, err := managed.NextPage(r.ctx)
		if err != nil {
			return err
		}
		for _, m := range page.AttachedManagedPolicies {
			ps.ManagedPolicies = append(ps.ManagedPolicies, aws.ToString(m.Arn))
		}
		return nil
	}); err != nil {
		return ps, fmt.Errorf("managed policies of %s: %w", ps.Name, err)
	}
	customer := ssoadmin.NewListCustomerManagedPolicyReferencesInPermissionSetPaginator(client, &ssoadmin.ListCustomerManagedPolicyReferencesInPermissionSetInput{InstanceArn: i, PermissionSetArn: p})
	if _, err := paginate(customer.HasMorePages, func() error {
		page, err := customer.NextPage(r.ctx)
		if err != nil {
			return err
		}
		for _, c := range page.CustomerManagedPolicyReferences {
			ps.CustomerManagedPolicies = append(ps.CustomerManagedPolicies, policyPath(c))
		}
		return nil
	}); err != nil {
		return ps, fmt.Errorf("customer managed policies of %s: %w", ps.Name, err)
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

func firstN(list []string, n int) []string {
	if len(list) <= n {
		return list
	}
	return list[:n]
}

// Summary describes what a snapshot contains, for the CLI.
func Summary(s *snapshot.Snapshot) string {
	out := fmt.Sprintf("organization %s: %d OUs, %d accounts, %d policies, %d resource shares, %d delegated administrators, %d trusted services",
		s.Organization.ID, len(s.OUs), len(s.Accounts), len(s.Policies), len(s.ResourceShares), len(s.DelegatedAdministrators), len(s.TrustedAccessServices))
	if ct := s.ControlTower; ct != nil {
		out += fmt.Sprintf("; Control Tower %s with %d registered OUs, %d enrolled accounts and %d enabled controls (auto-enrollment %s)", ct.Version, len(ct.RegisteredOUs), len(ct.EnrolledAccounts), len(ct.EnabledControls), orUnknown(ct.AutoEnrollment))
	}
	if ic := s.IdentityCenter; ic != nil {
		out += fmt.Sprintf("; Identity Center with %d permission sets and %d account assignments", len(ic.PermissionSets), len(ic.Assignments))
	}
	if gaps := s.CoverageGaps(); len(gaps) > 0 {
		out += fmt.Sprintf("\ncoverage gaps (%d): %s", len(gaps), strings.Join(gaps, ", "))
		for _, d := range gaps {
			for _, rec := range s.DomainRecords(d) {
				if !rec.Status.Complete() {
					out += "\n  - " + rec.Label()
				}
			}
		}
	} else {
		out += "\ncoverage: every domain was inspected"
	}
	return out
}

func orUnknown(s string) string {
	if s == "" {
		return "unknown"
	}
	return s
}
