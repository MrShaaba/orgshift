// Package preflight checks, before any collection, which collector
// capabilities the configured credentials have: per coverage domain, the
// cheapest read call is tried (one page, one item) and classified as
// available, denied, failed or unknown. Nothing is written anywhere; the
// probes are the same read operations the collector uses, listed in the
// operation catalog, plus sts:GetCallerIdentity and sts:AssumeRole for the
// identity checks. The result has the shape of the evaluation's coverage
// matrix so the two can be read side by side.
package preflight

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sort"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/account"
	"github.com/aws/aws-sdk-go-v2/service/controlcatalog"
	"github.com/aws/aws-sdk-go-v2/service/controltower"
	"github.com/aws/aws-sdk-go-v2/service/identitystore"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	orgtypes "github.com/aws/aws-sdk-go-v2/service/organizations/types"
	"github.com/aws/aws-sdk-go-v2/service/ram"
	ramtypes "github.com/aws/aws-sdk-go-v2/service/ram/types"
	"github.com/aws/aws-sdk-go-v2/service/ssoadmin"
	ssotypes "github.com/aws/aws-sdk-go-v2/service/ssoadmin/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go"

	"github.com/MrShaaba/orgshift/internal/awsaccess"
	"github.com/MrShaaba/orgshift/internal/collector"
	"github.com/MrShaaba/orgshift/internal/evaluator"
	"github.com/MrShaaba/orgshift/internal/snapshot"
)

// SchemaVersion is bumped when the exported result shape changes.
const SchemaVersion = 1

// Status is the outcome of a probe or of a domain.
type Status string

// Statuses, from good to bad.
const (
	// Available: the call succeeded.
	Available Status = "available"
	// Skipped: the domain is turned off in the configuration.
	Skipped Status = "skipped"
	// Unknown: not probed, because nothing existed to probe against, a
	// call it depends on failed, or this build does not collect the domain.
	Unknown Status = "unknown"
	// Failed: the call failed for another reason than a permission.
	Failed Status = "error"
	// Denied: the credentials lack the permission.
	Denied Status = "denied"
	// Mismatch: the credentials belong to another account than configured.
	Mismatch Status = "mismatch"
)

func (s Status) severity() int {
	switch s {
	case Available:
		return 0
	case Skipped:
		return 1
	case Unknown:
		return 2
	case Failed:
		return 3
	case Denied:
		return 4
	case Mismatch:
		return 5
	}
	return 6
}

// Blocks reports whether the status stops the preflight from being ready.
func (s Status) Blocks() bool { return s == Failed || s == Denied || s == Mismatch }

// MemberInspectionDomain is the preflight-only row for assuming the member
// inspection role; it is not a snapshot coverage domain yet.
const MemberInspectionDomain = "member_inspection"

// Probe is one call.
type Probe struct {
	Side string `json:"side"`
	// Access names the credentials: "management", a network label, "member
	// <account>".
	Access    string `json:"access"`
	Domain    string `json:"domain"`
	Operation string `json:"operation"`
	Status    Status `json:"status"`
	Detail    string `json:"detail,omitempty"`
	AccountID string `json:"account_id,omitempty"`
	Region    string `json:"region,omitempty"`
	Millis    int64  `json:"millis"`
	// Optional probes do not degrade their domain when they are unknown
	// (there was nothing to probe against).
	Optional bool `json:"optional,omitempty"`
}

// IdentityCheck is one sts:GetCallerIdentity against the configuration.
type IdentityCheck struct {
	Side     string             `json:"side"`
	Access   string             `json:"access"`
	Expected string             `json:"expected_account"`
	Actual   awsaccess.Identity `json:"actual,omitempty"`
	Status   Status             `json:"status"`
	Detail   string             `json:"detail,omitempty"`
	// Via says how the credentials were obtained.
	Via string `json:"via,omitempty"`
}

// DomainResult is the worst outcome of a domain's probes on one side.
type DomainResult struct {
	Domain     string   `json:"domain"`
	Status     Status   `json:"status"`
	Required   bool     `json:"required"`
	Operations []string `json:"operations,omitempty"`
	Detail     string   `json:"detail,omitempty"`
}

// SideResult is one organization.
type SideResult struct {
	Name       string          `json:"name"`
	Identities []IdentityCheck `json:"identities"`
	Probes     []Probe         `json:"probes"`
	Domains    []DomainResult  `json:"domains"`
	Ready      bool            `json:"ready"`
	Blocking   []string        `json:"blocking,omitempty"`
	Notes      []string        `json:"notes,omitempty"`
}

// Cell is one domain on one side of the matrix.
type Cell struct {
	Status     Status   `json:"status"`
	Required   bool     `json:"required"`
	Detail     string   `json:"detail,omitempty"`
	Operations []string `json:"operations,omitempty"`
}

// Row is one domain across both sides.
type Row struct {
	Domain string `json:"domain"`
	Why    string `json:"why,omitempty"`
	Check  string `json:"check,omitempty"`
	Source Cell   `json:"source"`
	Target Cell   `json:"target"`
}

// Matrix has the shape of the evaluation's coverage matrix.
type Matrix struct {
	// SingleSide is true when only the source was probed.
	SingleSide bool  `json:"single_side"`
	Rows       []Row `json:"rows"`
}

// Result is the whole preflight.
type Result struct {
	Tool          string       `json:"tool"`
	SchemaVersion int          `json:"schema_version"`
	GeneratedAt   string       `json:"generated_at"`
	Ready         bool         `json:"ready"`
	Sides         []SideResult `json:"sides"`
	Matrix        Matrix       `json:"matrix"`
	Blocking      []string     `json:"blocking,omitempty"`
	Notes         []string     `json:"notes,omitempty"`
}

// Assumer is the subset of STS used to test the member inspection role.
type Assumer interface {
	AssumeRole(context.Context, *sts.AssumeRoleInput, ...func(*sts.Options)) (*sts.AssumeRoleOutput, error)
}

// Clients are the API clients of one credential.
type Clients struct {
	// Label names the credential in the result ("management").
	Label string
	// ExpectedAccount is the configured account ID; Via says how the
	// credential was built, for the report.
	ExpectedAccount string
	Via             string
	Region          string
	STS             awsaccess.STSAPI
	Organizations   collector.OrganizationsAPI
	Account         collector.AccountAPI
	RAM             collector.RAMAPI
	ControlTower    collector.ControlTowerAPI
	// ControlTowerRegion is the landing zone's home region the Control
	// Tower client calls.
	ControlTowerRegion string
	ControlCatalog     collector.ControlCatalogAPI
	SSOAdmin           collector.SSOAdminAPI
	// IdentityCenterRegion is the region the Identity Center clients call.
	IdentityCenterRegion string
	IdentityStore        collector.IdentityStoreAPI
}

// Member describes the member inspection role to try.
type Member struct {
	RoleName   string
	ExternalID string
	// Accounts are always tried; Sample more are picked from the tree (0
	// for none, negative for all found within the call budget).
	Accounts []string
	Sample   int
	// STS assumes the role with the management credentials.
	STS Assumer
}

// SideInput is one organization's credentials.
type SideInput struct {
	Name       string
	Management *Clients
	// IdentityCenter overrides the management credentials for the Identity
	// Center reads (the delegated administrator); nil uses Management.
	IdentityCenter *Clients
	Network        []*Clients
	Security       []*Clients
	Member         *Member
	// Skip lists coverage domains turned off, with the reason.
	Skip map[string]string
}

// Input configures a run.
type Input struct {
	Sides   []SideInput
	Version string
	Now     func() time.Time
	Logger  *log.Logger
	Retry   collector.RetryOptions
	Sleep   collector.Sleeper
}

// unimplemented are the coverage domains this build's collector records as
// unsupported; the preflight cannot probe them.
var unimplemented = map[string]bool{snapshot.DomainOrgTrails: true, snapshot.DomainConfigAggregator: true, snapshot.DomainStackSets: true,
	snapshot.DomainWorkloadStacks: true, snapshot.DomainWorkloadResources: true, snapshot.DomainWorkloadPolicies: true}

// Run probes every side and builds the matrix.
func Run(ctx context.Context, in Input) *Result {
	if in.Now == nil {
		in.Now = time.Now
	}
	if in.Logger == nil {
		in.Logger = log.New(discard{}, "", 0)
	}
	res := &Result{Tool: "orgshift preflight " + in.Version, SchemaVersion: SchemaVersion, GeneratedAt: in.Now().UTC().Format(time.RFC3339), Ready: true}
	for _, side := range in.Sides {
		p := &prober{ctx: ctx, in: in, side: side, now: in.Now}
		sr := p.run()
		res.Sides = append(res.Sides, sr)
		if !sr.Ready {
			res.Ready = false
		}
		for _, b := range sr.Blocking {
			res.Blocking = append(res.Blocking, sr.Name+": "+b)
		}
	}
	res.Matrix = buildMatrix(res.Sides)
	res.Notes = append(res.Notes, "A probe reads one page or one item with the same operations the collector uses; nothing is written. \"unknown\" means the call was not tried: nothing existed to try it against, a call it depends on failed, or this build does not collect the domain yet.")
	if !res.Ready {
		res.Notes = append(res.Notes, "Grant what is listed under blocking (docs/iam has the templates) and run the preflight again; a denied domain is recorded as access_denied by the collector and makes the checks that depend on it REVIEW.")
	}
	return res
}

type discard struct{}

func (discard) Write(p []byte) (int, error) { return len(p), nil }

// prober holds one side's state while probing.
type prober struct {
	ctx  context.Context
	in   Input
	side SideInput
	now  func() time.Time
	res  SideResult
	// discovered state
	orgID, mgmtAccount, rootID string
	firstOU, firstMember       string
	ouARN                      map[string]string
	trusted                    []string
	accounts                   []string
}

func (p *prober) log(format string, args ...any) {
	p.in.Logger.Printf(p.side.Name+": "+format, args...)
}

// identity verifies one credential and records the check. It returns false
// when the credential cannot be used.
func (p *prober) identity(c *Clients) bool {
	chk := IdentityCheck{Side: p.side.Name, Access: c.Label, Expected: c.ExpectedAccount, Via: c.Via}
	if c.STS == nil {
		chk.Status, chk.Detail = Unknown, "no STS client"
		p.res.Identities = append(p.res.Identities, chk)
		return false
	}
	var id awsaccess.Identity
	_, err := collector.Retry(p.ctx, p.in.Retry, p.in.Sleep, func() (err error) {
		id, err = awsaccess.Verify(p.ctx, c.STS, p.side.Name+" "+c.Label, c.ExpectedAccount)
		return err
	}, nil)
	chk.Actual = id
	var mm *awsaccess.MismatchError
	switch {
	case errors.As(err, &mm):
		chk.Status = Mismatch
		chk.Detail = fmt.Sprintf("the credentials belong to account %s (%s), the configuration names %s", id.AccountID, id.ARN, c.ExpectedAccount)
		p.block("%s: identity mismatch, %s; fix the configuration or the credentials before collecting", c.Label, chk.Detail)
	case err != nil:
		chk.Status = Failed
		chk.Detail = err.Error()
		p.block("%s: the credentials could not be resolved (%s)", c.Label, err.Error())
	default:
		chk.Status = Available
		chk.Detail = "credentials belong to the configured account"
	}
	p.res.Identities = append(p.res.Identities, chk)
	p.log("%s identity: %s %s", c.Label, chk.Status, chk.Detail)
	return chk.Status == Available
}

func (p *prober) block(format string, args ...any) {
	p.res.Ready = false
	p.res.Blocking = append(p.res.Blocking, fmt.Sprintf(format, args...))
}

// probe runs one call, times it, retries throttling and records the
// outcome. fn returns a detail for the available case.
func (p *prober) probe(c *Clients, domain, op string, optional bool, fn func() (string, error)) (ok bool, detail string) {
	start := p.now()
	var d string
	_, err := collector.Retry(p.ctx, p.in.Retry, p.in.Sleep, func() (err error) {
		d, err = fn()
		return err
	}, nil)
	pr := Probe{Side: p.side.Name, Access: c.Label, Domain: domain, Operation: op, Region: c.Region, AccountID: c.ExpectedAccount, Millis: p.now().Sub(start).Milliseconds(), Optional: optional}
	switch {
	case err == nil:
		pr.Status, pr.Detail = Available, d
	default:
		status, msg := collector.ClassifyError(err)
		pr.Detail = msg
		if status == snapshot.CoverageAccessDenied {
			pr.Status = Denied
			p.block("%s denied for %s (%s): grant it to %s", op, c.Label, msg, p.identityARN(c))
		} else {
			pr.Status = Failed
			p.block("%s failed for %s: %s", op, c.Label, msg)
		}
	}
	p.res.Probes = append(p.res.Probes, pr)
	p.log("%s %s: %s %s", c.Label, op, pr.Status, pr.Detail)
	return err == nil, pr.Detail
}

// unknown records a probe that was not tried.
func (p *prober) unknown(c *Clients, domain, op, why string, optional bool) {
	p.res.Probes = append(p.res.Probes, Probe{Side: p.side.Name, Access: c.Label, Domain: domain, Operation: op, Status: Unknown, Detail: why, Region: c.Region, AccountID: c.ExpectedAccount, Optional: optional})
}

func (p *prober) skipped(c *Clients, domain, reason string) {
	p.res.Probes = append(p.res.Probes, Probe{Side: p.side.Name, Access: c.Label, Domain: domain, Status: Skipped, Detail: reason, Region: c.Region, AccountID: c.ExpectedAccount})
}

func (p *prober) identityARN(c *Clients) string {
	for _, id := range p.res.Identities {
		if id.Access == c.Label && id.Actual.ARN != "" {
			return id.Actual.ARN
		}
	}
	return c.Label
}

// run probes the side.
func (p *prober) run() SideResult {
	p.res = SideResult{Name: p.side.Name, Ready: true, Probes: []Probe{}, Identities: []IdentityCheck{}}
	m := p.side.Management
	if m == nil {
		p.block("no management credentials")
		p.res.Domains = p.aggregate()
		return p.res
	}
	if m.Label == "" {
		m.Label = "management"
	}
	mgmtOK := p.identity(m)
	if mgmtOK {
		p.organizations(m)
	} else {
		for _, d := range []string{snapshot.DomainOrganization, snapshot.DomainTree, snapshot.DomainTrustedAccess, snapshot.DomainAccountTags, snapshot.DomainEnabledRegions, snapshot.DomainPoliciesSCP, snapshot.DomainPoliciesRCP, snapshot.DomainPoliciesTag, snapshot.DomainPoliciesBackup, snapshot.DomainDelegatedAdmins, snapshot.DomainResourceShares, snapshot.DomainControlTower, snapshot.DomainEnrolledAccounts} {
			p.unknown(m, d, "", "not probed: the management identity check failed", false)
		}
	}
	for _, n := range p.side.Network {
		if n.Label == "" {
			n.Label = "network"
		}
		if p.identity(n) {
			p.shares(n)
		} else {
			p.unknown(n, snapshot.DomainResourceShares, "ram:GetResourceShares", "not probed: the identity check failed", false)
		}
	}
	for _, s := range p.side.Security {
		if s.Label == "" {
			s.Label = "security"
		}
		if p.identity(s) {
			p.res.Notes = append(p.res.Notes, fmt.Sprintf("%s: identity verified; this build's collector reads nothing from it (organization trails and Config aggregators come with a later milestone)", s.Label))
		}
	}
	p.identityCenter(mgmtOK)
	p.member(mgmtOK)
	for d := range unimplemented {
		p.unknown(m, d, "", "not collected by this build; the simulation reports the domain as unsupported until it is entered by hand or a later build collects it", true)
	}
	p.res.Domains = p.aggregate()
	return p.res
}

// organizations probes the management-account domains in dependency order.
func (p *prober) organizations(m *Clients) {
	ctx := p.ctx
	if m.Organizations == nil {
		p.unknown(m, snapshot.DomainOrganization, "organizations:DescribeOrganization", "no Organizations client", false)
		return
	}
	ok, _ := p.probe(m, snapshot.DomainOrganization, "organizations:DescribeOrganization", false, func() (string, error) {
		out, err := m.Organizations.DescribeOrganization(ctx, &organizations.DescribeOrganizationInput{})
		if err != nil {
			return "", err
		}
		p.orgID, p.mgmtAccount = aws.ToString(out.Organization.Id), aws.ToString(out.Organization.MasterAccountId)
		return fmt.Sprintf("organization %s, management account %s", p.orgID, p.mgmtAccount), nil
	})
	if !ok {
		return
	}
	if p.mgmtAccount != m.ExpectedAccount {
		p.res.Notes = append(p.res.Notes, fmt.Sprintf("%s: the credentials belong to %s, which is not the management account (%s); Organizations answers from a delegated administrator for the delegated operations only", m.Label, m.ExpectedAccount, p.mgmtAccount))
	}
	// The tree: the root, one OU, one account.
	ok, _ = p.probe(m, snapshot.DomainTree, "organizations:ListRoots", false, func() (string, error) {
		out, err := m.Organizations.ListRoots(ctx, &organizations.ListRootsInput{})
		if err != nil {
			return "", err
		}
		if len(out.Roots) == 0 {
			return "", errors.New("the organization has no root")
		}
		p.rootID = aws.ToString(out.Roots[0].Id)
		var enabled []string
		for _, pt := range out.Roots[0].PolicyTypes {
			if pt.Status == orgtypes.PolicyTypeStatusEnabled {
				enabled = append(enabled, snapshot.PolicyType(pt.Type).Short())
			}
		}
		sort.Strings(enabled)
		return fmt.Sprintf("root %s, policy types enabled: %s", p.rootID, strings.Join(enabled, ", ")), nil
	})
	if ok {
		p.ouARN = map[string]string{}
		p.probe(m, snapshot.DomainTree, "organizations:ListOrganizationalUnitsForParent", false, func() (string, error) {
			out, err := m.Organizations.ListOrganizationalUnitsForParent(ctx, &organizations.ListOrganizationalUnitsForParentInput{ParentId: aws.String(p.rootID), MaxResults: aws.Int32(1)})
			if err != nil {
				return "", err
			}
			if len(out.OrganizationalUnits) > 0 {
				p.firstOU = aws.ToString(out.OrganizationalUnits[0].Id)
				p.ouARN[p.firstOU] = aws.ToString(out.OrganizationalUnits[0].Arn)
				return "first OU " + p.firstOU, nil
			}
			return "no OUs under the root", nil
		})
		p.probe(m, snapshot.DomainTree, "organizations:ListAccountsForParent", false, func() (string, error) {
			out, err := m.Organizations.ListAccountsForParent(ctx, &organizations.ListAccountsForParentInput{ParentId: aws.String(p.rootID), MaxResults: aws.Int32(20)})
			if err != nil {
				return "", err
			}
			for _, a := range out.Accounts {
				p.accounts = append(p.accounts, aws.ToString(a.Id))
				if p.firstMember == "" && aws.ToString(a.Id) != p.mgmtAccount {
					p.firstMember = aws.ToString(a.Id)
				}
			}
			return fmt.Sprintf("%d account(s) directly under the root", len(out.Accounts)), nil
		})
	}
	// Trusted access, needed to interpret empty Control Tower and Identity
	// Center answers.
	p.probe(m, snapshot.DomainTrustedAccess, "organizations:ListAWSServiceAccessForOrganization", false, func() (string, error) {
		pager := organizations.NewListAWSServiceAccessForOrganizationPaginator(m.Organizations, &organizations.ListAWSServiceAccessForOrganizationInput{})
		p.trusted = nil
		for pager.HasMorePages() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				return "", err
			}
			for _, s := range page.EnabledServicePrincipals {
				p.trusted = append(p.trusted, aws.ToString(s.ServicePrincipal))
			}
		}
		sort.Strings(p.trusted)
		return fmt.Sprintf("%d service(s) with trusted access", len(p.trusted)), nil
	})
	// Account tags: the management account is always a taggable resource.
	p.probe(m, snapshot.DomainAccountTags, "organizations:ListTagsForResource", false, func() (string, error) {
		out, err := m.Organizations.ListTagsForResource(ctx, &organizations.ListTagsForResourceInput{ResourceId: aws.String(p.mgmtAccount)})
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("%d tag(s) on the management account", len(out.Tags)), nil
	})
	// Enabled regions: a member account when one is known, else the caller.
	if m.Account == nil {
		if reason, off := p.side.Skip[snapshot.DomainEnabledRegions]; off {
			p.skipped(m, snapshot.DomainEnabledRegions, reason)
		} else {
			p.unknown(m, snapshot.DomainEnabledRegions, "account:ListRegions", "no Account Management client", false)
		}
	} else {
		trustedAccount := p.hasTrusted("account.amazonaws.com")
		p.probe(m, snapshot.DomainEnabledRegions, "account:ListRegions", false, func() (string, error) {
			in := &account.ListRegionsInput{MaxResults: aws.Int32(1)}
			target := "the calling account"
			if p.firstMember != "" {
				in.AccountId = aws.String(p.firstMember)
				target = "member account " + p.firstMember
			}
			if _, err := m.Account.ListRegions(ctx, in); err != nil {
				return "", err
			}
			note := "trusted access for account.amazonaws.com is enabled"
			if !trustedAccount {
				note = "trusted access for account.amazonaws.com is NOT enabled, so member accounts will fail"
			}
			return fmt.Sprintf("listed for %s; %s", target, note), nil
		})
	}
	// Policies, one type at a time.
	for _, t := range snapshot.AllPolicyTypes {
		p.policies(m, t)
	}
	// Delegated administrators.
	var firstAdmin string
	ok, _ = p.probe(m, snapshot.DomainDelegatedAdmins, "organizations:ListDelegatedAdministrators", false, func() (string, error) {
		out, err := m.Organizations.ListDelegatedAdministrators(ctx, &organizations.ListDelegatedAdministratorsInput{MaxResults: aws.Int32(1)})
		if err != nil {
			return "", err
		}
		if len(out.DelegatedAdministrators) == 0 {
			return "no delegated administrators", nil
		}
		firstAdmin = aws.ToString(out.DelegatedAdministrators[0].Id)
		return "first delegated administrator " + firstAdmin, nil
	})
	switch {
	case !ok:
	case firstAdmin == "":
		p.unknown(m, snapshot.DomainDelegatedAdmins, "organizations:ListDelegatedServicesForAccount", "not tried: no delegated administrator to ask about; the call is not needed when there are none", true)
	default:
		p.probe(m, snapshot.DomainDelegatedAdmins, "organizations:ListDelegatedServicesForAccount", false, func() (string, error) {
			out, err := m.Organizations.ListDelegatedServicesForAccount(ctx, &organizations.ListDelegatedServicesForAccountInput{AccountId: aws.String(firstAdmin)})
			if err != nil {
				return "", err
			}
			return fmt.Sprintf("%d service(s) delegated to %s", len(out.DelegatedServices), firstAdmin), nil
		})
	}
	// The management account's own shares.
	if reason, off := p.side.Skip[snapshot.DomainResourceShares]; off {
		p.skipped(m, snapshot.DomainResourceShares, reason)
	} else {
		p.shares(m)
	}
	// Control Tower.
	p.controlTower(m)
}

func (p *prober) hasTrusted(sp string) bool {
	for _, s := range p.trusted {
		if s == sp {
			return true
		}
	}
	return false
}

func (p *prober) policies(m *Clients, t snapshot.PolicyType) {
	ctx := p.ctx
	domain := snapshot.PolicyDomain(t)
	var first string
	ok, _ := p.probe(m, domain, "organizations:ListPolicies", false, func() (string, error) {
		out, err := m.Organizations.ListPolicies(ctx, &organizations.ListPoliciesInput{Filter: orgtypes.PolicyType(t), MaxResults: aws.Int32(1)})
		var apiErr smithy.APIError
		if errors.As(err, &apiErr) && apiErr.ErrorCode() == "PolicyTypeNotEnabledException" {
			return "policy type not enabled in the organization; the call itself is permitted", nil
		}
		if err != nil {
			return "", err
		}
		if len(out.Policies) == 0 {
			return "no policies of this type", nil
		}
		first = aws.ToString(out.Policies[0].Id)
		return "first policy " + first, nil
	})
	if !ok {
		return
	}
	if first == "" {
		p.unknown(m, domain, "organizations:DescribePolicy", "not tried: no policy of this type to describe", true)
		p.unknown(m, domain, "organizations:ListTargetsForPolicy", "not tried: no policy of this type", true)
		return
	}
	p.probe(m, domain, "organizations:DescribePolicy", false, func() (string, error) {
		out, err := m.Organizations.DescribePolicy(ctx, &organizations.DescribePolicyInput{PolicyId: aws.String(first)})
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("%s described (%d bytes)", first, len(aws.ToString(out.Policy.Content))), nil
	})
	p.probe(m, domain, "organizations:ListTargetsForPolicy", false, func() (string, error) {
		out, err := m.Organizations.ListTargetsForPolicy(ctx, &organizations.ListTargetsForPolicyInput{PolicyId: aws.String(first), MaxResults: aws.Int32(1)})
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("%d target(s) on the first page for %s", len(out.Targets), first), nil
	})
}

// shares probes the RAM reads for one credential.
func (p *prober) shares(c *Clients) {
	ctx := p.ctx
	domain := snapshot.DomainResourceShares
	if c.RAM == nil {
		p.unknown(c, domain, "ram:GetResourceShares", "no RAM client", false)
		return
	}
	var first string
	ok, _ := p.probe(c, domain, "ram:GetResourceShares", false, func() (string, error) {
		out, err := c.RAM.GetResourceShares(ctx, &ram.GetResourceSharesInput{ResourceOwner: ramtypes.ResourceOwnerSelf, MaxResults: aws.Int32(1)})
		if err != nil {
			return "", err
		}
		if len(out.ResourceShares) == 0 {
			return "the account owns no shares", nil
		}
		first = aws.ToString(out.ResourceShares[0].ResourceShareArn)
		retain := "not reported"
		if cfg := out.ResourceShares[0].ResourceShareConfiguration; cfg != nil && cfg.RetainSharingOnAccountLeaveOrganization != nil {
			retain = fmt.Sprintf("%t", *cfg.RetainSharingOnAccountLeaveOrganization)
		}
		return fmt.Sprintf("first share %s (retain on leave: %s)", first, retain), nil
	})
	if !ok {
		return
	}
	if first == "" {
		p.unknown(c, domain, "ram:ListPrincipals", "not tried: no share to list principals of", true)
		p.unknown(c, domain, "ram:ListResources", "not tried: no share to list resources of", true)
		return
	}
	p.probe(c, domain, "ram:ListPrincipals", false, func() (string, error) {
		out, err := c.RAM.ListPrincipals(ctx, &ram.ListPrincipalsInput{ResourceOwner: ramtypes.ResourceOwnerSelf, ResourceShareArns: []string{first}, MaxResults: aws.Int32(1)})
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("%d principal(s) on the first page", len(out.Principals)), nil
	})
	p.probe(c, domain, "ram:ListResources", false, func() (string, error) {
		out, err := c.RAM.ListResources(ctx, &ram.ListResourcesInput{ResourceOwner: ramtypes.ResourceOwnerSelf, ResourceShareArns: []string{first}, MaxResults: aws.Int32(1)})
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("%d resource(s) on the first page", len(out.Resources)), nil
	})
}

// controlTower probes the landing zone chain in the home region.
func (p *prober) controlTower(m *Clients) {
	ctx := p.ctx
	domain, enrolled := snapshot.DomainControlTower, snapshot.DomainEnrolledAccounts
	if reason, off := p.side.Skip[domain]; off {
		p.skipped(m, domain, reason)
		p.skipped(m, enrolled, reason)
		return
	}
	if m.ControlTower == nil {
		p.unknown(m, domain, "controltower:ListLandingZones", "no Control Tower client", false)
		p.unknown(m, enrolled, "controltower:ListEnabledBaselines", "no Control Tower client", false)
		return
	}
	ct := *m
	if m.ControlTowerRegion != "" {
		ct.Region = m.ControlTowerRegion
	}
	c := &ct
	var lzARN string
	ok, _ := p.probe(c, domain, "controltower:ListLandingZones", false, func() (string, error) {
		out, err := c.ControlTower.ListLandingZones(ctx, &controltower.ListLandingZonesInput{MaxResults: aws.Int32(1)})
		if err != nil {
			return "", err
		}
		if len(out.LandingZones) == 0 {
			if p.hasTrusted("controltower.amazonaws.com") {
				return "", fmt.Errorf("no landing zone answered in %s although trusted access for controltower.amazonaws.com is enabled; the landing zone APIs answer only in the home region, set control_tower.home_region", c.Region)
			}
			return "no landing zone in " + c.Region + " and no trusted access for controltower.amazonaws.com", nil
		}
		lzARN = aws.ToString(out.LandingZones[0].Arn)
		return "landing zone " + lzARN, nil
	})
	if !ok {
		p.unknown(c, enrolled, "controltower:ListEnabledBaselines", "not tried: the landing zone lookup failed", false)
		return
	}
	if lzARN == "" {
		p.unknown(c, enrolled, "controltower:ListEnabledBaselines", "not tried: no landing zone", true)
		for _, op := range []string{"controltower:GetLandingZone", "controltower:ListEnabledBaselines", "controltower:ListEnabledControls", "controlcatalog:GetControl"} {
			p.unknown(c, domain, op, "not tried: no landing zone", true)
		}
		return
	}
	p.probe(c, domain, "controltower:GetLandingZone", false, func() (string, error) {
		out, err := c.ControlTower.GetLandingZone(ctx, &controltower.GetLandingZoneInput{LandingZoneIdentifier: aws.String(lzARN)})
		if err != nil {
			return "", err
		}
		if out.LandingZone != nil {
			return fmt.Sprintf("version %s, status %s", aws.ToString(out.LandingZone.Version), out.LandingZone.Status), nil
		}
		return "described", nil
	})
	var ouTarget string
	ok, detail := p.probe(c, domain, "controltower:ListEnabledBaselines", false, func() (string, error) {
		out, err := c.ControlTower.ListEnabledBaselines(ctx, &controltower.ListEnabledBaselinesInput{IncludeChildren: true, MaxResults: aws.Int32(10)})
		if err != nil {
			return "", err
		}
		ous, accounts := 0, 0
		for _, b := range out.EnabledBaselines {
			target := aws.ToString(b.TargetIdentifier)
			switch {
			case strings.Contains(target, ":account/"):
				accounts++
			case strings.Contains(target, ":ou/"):
				ous++
				if ouTarget == "" {
					ouTarget = target
				}
			}
		}
		return fmt.Sprintf("first page: %d OU baseline(s), %d account baseline(s)", ous, accounts), nil
	})
	// The same call fills the enrolled accounts.
	last := p.res.Probes[len(p.res.Probes)-1]
	last.Domain = enrolled
	last.Detail = "same call as control_tower: " + detail
	last.Millis = 0
	p.res.Probes = append(p.res.Probes, last)
	if !ok {
		return
	}
	var controlARN string
	if ouTarget == "" {
		p.unknown(c, domain, "controltower:ListEnabledControls", "not tried: no registered OU on the first page of baselines", true)
	} else {
		p.probe(c, domain, "controltower:ListEnabledControls", false, func() (string, error) {
			out, err := c.ControlTower.ListEnabledControls(ctx, &controltower.ListEnabledControlsInput{TargetIdentifier: aws.String(ouTarget), MaxResults: aws.Int32(5)})
			if err != nil {
				return "", err
			}
			if len(out.EnabledControls) > 0 {
				controlARN = aws.ToString(out.EnabledControls[0].ControlIdentifier)
			}
			return fmt.Sprintf("%d control(s) on the first page of %s", len(out.EnabledControls), ouTarget[strings.LastIndex(ouTarget, "/")+1:]), nil
		})
	}
	switch {
	case c.ControlCatalog == nil:
		p.unknown(c, domain, "controlcatalog:GetControl", "no Control Catalog client; controls are kept by identifier only", true)
	case controlARN == "":
		p.unknown(c, domain, "controlcatalog:GetControl", "not tried: no enabled control to describe", true)
	default:
		p.probe(c, domain, "controlcatalog:GetControl", false, func() (string, error) {
			out, err := c.ControlCatalog.GetControl(ctx, &controlcatalog.GetControlInput{ControlArn: aws.String(controlARN)})
			if err != nil {
				return "", err
			}
			return fmt.Sprintf("%s is %s", aws.ToString(out.Name), out.Behavior), nil
		})
	}
}

// identityCenter probes the instance chain in the instance's region.
func (p *prober) identityCenter(mgmtOK bool) {
	ctx := p.ctx
	domain := snapshot.DomainIdentityCenter
	base := p.side.IdentityCenter
	separate := base != nil
	if base == nil {
		base = p.side.Management
	}
	if base == nil {
		return
	}
	if reason, off := p.side.Skip[domain]; off {
		p.skipped(base, domain, reason)
		return
	}
	if !separate && !mgmtOK {
		p.unknown(base, domain, "sso:ListInstances", "not probed: the management identity check failed", false)
		return
	}
	if base.SSOAdmin == nil {
		p.unknown(base, domain, "sso:ListInstances", "no Identity Center client", false)
		return
	}
	if separate {
		if base.Label == "" {
			base.Label = "identity center"
		}
		if !p.identity(base) {
			p.unknown(base, domain, "sso:ListInstances", "not probed: the identity check failed", false)
			return
		}
	}
	ic := *base
	if base.IdentityCenterRegion != "" {
		ic.Region = base.IdentityCenterRegion
	}
	c := &ic
	var instanceARN, storeID string
	ok, _ := p.probe(c, domain, "sso:ListInstances", false, func() (string, error) {
		out, err := c.SSOAdmin.ListInstances(ctx, &ssoadmin.ListInstancesInput{})
		if err != nil {
			return "", err
		}
		if len(out.Instances) == 0 {
			if p.hasTrusted("sso.amazonaws.com") {
				return "", fmt.Errorf("no Identity Center instance answered in %s although trusted access for sso.amazonaws.com is enabled; the instance APIs answer only in the instance's region, set identity_center.region", c.Region)
			}
			return "no instance in " + c.Region + " and no trusted access for sso.amazonaws.com", nil
		}
		instanceARN, storeID = aws.ToString(out.Instances[0].InstanceArn), aws.ToString(out.Instances[0].IdentityStoreId)
		return "instance " + instanceARN, nil
	})
	if !ok || instanceARN == "" {
		if ok {
			p.unknown(c, domain, "sso:ListPermissionSets", "not tried: no instance", true)
		}
		return
	}
	var psARN string
	ok, _ = p.probe(c, domain, "sso:ListPermissionSets", false, func() (string, error) {
		out, err := c.SSOAdmin.ListPermissionSets(ctx, &ssoadmin.ListPermissionSetsInput{InstanceArn: aws.String(instanceARN), MaxResults: aws.Int32(1)})
		if err != nil {
			return "", err
		}
		if len(out.PermissionSets) == 0 {
			return "no permission sets", nil
		}
		psARN = out.PermissionSets[0]
		return "first permission set " + psARN, nil
	})
	if !ok {
		return
	}
	if psARN == "" {
		p.unknown(c, domain, "sso:DescribePermissionSet", "not tried: no permission set", true)
		return
	}
	i, ps := aws.String(instanceARN), aws.String(psARN)
	name := psARN
	p.probe(c, domain, "sso:DescribePermissionSet", false, func() (string, error) {
		out, err := c.SSOAdmin.DescribePermissionSet(ctx, &ssoadmin.DescribePermissionSetInput{InstanceArn: i, PermissionSetArn: ps})
		if err != nil {
			return "", err
		}
		if out.PermissionSet != nil {
			name = aws.ToString(out.PermissionSet.Name)
		}
		return "permission set " + name, nil
	})
	p.probe(c, domain, "sso:ListManagedPoliciesInPermissionSet", false, func() (string, error) {
		out, err := c.SSOAdmin.ListManagedPoliciesInPermissionSet(ctx, &ssoadmin.ListManagedPoliciesInPermissionSetInput{InstanceArn: i, PermissionSetArn: ps, MaxResults: aws.Int32(1)})
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("%d managed policy(ies) on the first page of %s", len(out.AttachedManagedPolicies), name), nil
	})
	p.probe(c, domain, "sso:ListCustomerManagedPolicyReferencesInPermissionSet", false, func() (string, error) {
		out, err := c.SSOAdmin.ListCustomerManagedPolicyReferencesInPermissionSet(ctx, &ssoadmin.ListCustomerManagedPolicyReferencesInPermissionSetInput{InstanceArn: i, PermissionSetArn: ps, MaxResults: aws.Int32(1)})
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("%d customer managed policy(ies) on the first page of %s", len(out.CustomerManagedPolicyReferences), name), nil
	})
	p.probe(c, domain, "sso:GetInlinePolicyForPermissionSet", false, func() (string, error) {
		out, err := c.SSOAdmin.GetInlinePolicyForPermissionSet(ctx, &ssoadmin.GetInlinePolicyForPermissionSetInput{InstanceArn: i, PermissionSetArn: ps})
		if err != nil {
			return "", err
		}
		if aws.ToString(out.InlinePolicy) == "" {
			return name + " has no inline policy", nil
		}
		return name + " has an inline policy", nil
	})
	p.probe(c, domain, "sso:GetPermissionsBoundaryForPermissionSet", false, func() (string, error) {
		_, err := c.SSOAdmin.GetPermissionsBoundaryForPermissionSet(ctx, &ssoadmin.GetPermissionsBoundaryForPermissionSetInput{InstanceArn: i, PermissionSetArn: ps})
		var notFound *ssotypes.ResourceNotFoundException
		if errors.As(err, &notFound) {
			return name + " has no permissions boundary", nil
		}
		if err != nil {
			return "", err
		}
		return name + " has a permissions boundary", nil
	})
	var acct string
	ok, _ = p.probe(c, domain, "sso:ListAccountsForProvisionedPermissionSet", false, func() (string, error) {
		out, err := c.SSOAdmin.ListAccountsForProvisionedPermissionSet(ctx, &ssoadmin.ListAccountsForProvisionedPermissionSetInput{InstanceArn: i, PermissionSetArn: ps, MaxResults: aws.Int32(1)})
		if err != nil {
			return "", err
		}
		if len(out.AccountIds) == 0 {
			return name + " is provisioned in no account", nil
		}
		acct = out.AccountIds[0]
		return name + " is provisioned in " + acct + " (first page)", nil
	})
	if !ok || acct == "" {
		if ok {
			p.unknown(c, domain, "sso:ListAccountAssignments", "not tried: the first permission set is provisioned nowhere", true)
		}
		return
	}
	var principalType, principalID string
	ok, _ = p.probe(c, domain, "sso:ListAccountAssignments", false, func() (string, error) {
		out, err := c.SSOAdmin.ListAccountAssignments(ctx, &ssoadmin.ListAccountAssignmentsInput{InstanceArn: i, PermissionSetArn: ps, AccountId: aws.String(acct), MaxResults: aws.Int32(1)})
		if err != nil {
			return "", err
		}
		if len(out.AccountAssignments) == 0 {
			return "no assignments of " + name + " in " + acct, nil
		}
		principalType, principalID = string(out.AccountAssignments[0].PrincipalType), aws.ToString(out.AccountAssignments[0].PrincipalId)
		return fmt.Sprintf("first assignment: %s %s", strings.ToLower(principalType), principalID), nil
	})
	switch {
	case !ok:
	case c.IdentityStore == nil:
		p.unknown(c, domain, "identitystore:DescribeUser", "no identity store client; principals are kept by ID", true)
	case principalID == "":
		p.unknown(c, domain, "identitystore:DescribeUser", "not tried: no assignment principal to resolve", true)
	case principalType == snapshot.PrincipalGroup:
		p.probe(c, domain, "identitystore:DescribeGroup", false, func() (string, error) {
			out, err := c.IdentityStore.DescribeGroup(ctx, &identitystore.DescribeGroupInput{IdentityStoreId: aws.String(storeID), GroupId: aws.String(principalID)})
			if err != nil {
				return "", err
			}
			return "group " + aws.ToString(out.DisplayName), nil
		})
	default:
		p.probe(c, domain, "identitystore:DescribeUser", false, func() (string, error) {
			out, err := c.IdentityStore.DescribeUser(ctx, &identitystore.DescribeUserInput{IdentityStoreId: aws.String(storeID), UserId: aws.String(principalID)})
			if err != nil {
				return "", err
			}
			return "user " + aws.ToString(out.UserName), nil
		})
	}
}

// member tries to assume the member inspection role in the configured
// accounts plus a sample from the tree.
func (p *prober) member(mgmtOK bool) {
	mem := p.side.Member
	m := p.side.Management
	if mem == nil || m == nil {
		return
	}
	if !mgmtOK {
		p.unknown(m, MemberInspectionDomain, "sts:AssumeRole", "not probed: the management identity check failed", false)
		return
	}
	if mem.STS == nil {
		p.unknown(m, MemberInspectionDomain, "sts:AssumeRole", "no STS client to assume the member role with", false)
		return
	}
	targets := append([]string(nil), mem.Accounts...)
	seen := map[string]bool{}
	for _, a := range targets {
		seen[a] = true
	}
	if mem.Sample != 0 && m.Organizations != nil && p.rootID != "" {
		seen[p.mgmtAccount] = true
		for _, a := range p.sampleAccounts(m, mem.Sample, seen) {
			seen[a] = true
			targets = append(targets, a)
		}
	}
	if len(targets) == 0 {
		p.unknown(m, MemberInspectionDomain, "sts:AssumeRole", "not tried: no member account to try (name accounts under member_inspection.accounts or set sample)", true)
		return
	}
	for _, acct := range targets {
		c := &Clients{Label: "member " + acct, ExpectedAccount: acct, Region: m.Region}
		roleARN := fmt.Sprintf("arn:aws:iam::%s:role/%s", acct, mem.RoleName)
		p.probe(c, MemberInspectionDomain, "sts:AssumeRole", false, func() (string, error) {
			in := &sts.AssumeRoleInput{RoleArn: aws.String(roleARN), RoleSessionName: aws.String("orgshift-preflight"), DurationSeconds: aws.Int32(900)}
			if mem.ExternalID != "" {
				in.ExternalId = aws.String(mem.ExternalID)
			}
			out, err := mem.STS.AssumeRole(p.ctx, in)
			if err != nil {
				return "", err
			}
			who := roleARN
			if out.AssumedRoleUser != nil {
				who = aws.ToString(out.AssumedRoleUser.Arn)
			}
			return "assumed " + who, nil
		})
	}
}

// sampleAccounts walks the tree breadth-first until n active accounts not
// in exclude are found or the call budget runs out. Negative n means every
// account within the budget.
func (p *prober) sampleAccounts(m *Clients, n int, exclude map[string]bool) []string {
	const budget = 25
	calls := 0
	var out []string
	if n < 0 {
		n = 1 << 30
	}
	queue := []string{p.rootID}
	for len(queue) > 0 && len(out) < n && calls < budget {
		parent := queue[0]
		queue = queue[1:]
		acctPager := organizations.NewListAccountsForParentPaginator(m.Organizations, &organizations.ListAccountsForParentInput{ParentId: aws.String(parent)})
		for acctPager.HasMorePages() && len(out) < n && calls < budget {
			calls++
			page, err := acctPager.NextPage(p.ctx)
			if err != nil {
				return out
			}
			for _, a := range page.Accounts {
				id := aws.ToString(a.Id)
				if a.Status == orgtypes.AccountStatusActive && !exclude[id] && len(out) < n {
					out = append(out, id)
				}
			}
		}
		if len(out) >= n || calls >= budget {
			break
		}
		ouPager := organizations.NewListOrganizationalUnitsForParentPaginator(m.Organizations, &organizations.ListOrganizationalUnitsForParentInput{ParentId: aws.String(parent)})
		for ouPager.HasMorePages() && calls < budget {
			calls++
			page, err := ouPager.NextPage(p.ctx)
			if err != nil {
				return out
			}
			for _, ou := range page.OrganizationalUnits {
				queue = append(queue, aws.ToString(ou.Id))
			}
		}
	}
	return out
}

// aggregate reduces the probes to one result per domain.
func (p *prober) aggregate() []DomainResult {
	byDomain := map[string][]Probe{}
	for _, pr := range p.res.Probes {
		byDomain[pr.Domain] = append(byDomain[pr.Domain], pr)
	}
	var out []DomainResult
	for _, d := range domainOrder() {
		probes := byDomain[d]
		dr := DomainResult{Domain: d, Status: Unknown, Required: !unimplemented[d]}
		if len(probes) == 0 {
			dr.Detail = "not probed"
			if _, mismatch := p.identityFailed(); mismatch {
				dr.Detail = "not probed: the management identity check failed"
			}
			out = append(out, dr)
			continue
		}
		worst := Available
		var details []string
		seenOps := map[string]bool{}
		for _, pr := range probes {
			if pr.Operation != "" && !seenOps[pr.Operation] {
				seenOps[pr.Operation] = true
				dr.Operations = append(dr.Operations, pr.Operation)
			}
			s := pr.Status
			if s == Unknown && pr.Optional {
				continue
			}
			if s.severity() > worst.severity() {
				worst = s
			}
			if s != Available {
				label := pr.Operation
				if pr.Access != "management" && pr.Access != "" {
					label = pr.Access + " " + pr.Operation
				}
				details = append(details, strings.TrimSpace(label+" "+string(s)+": "+pr.Detail))
			}
		}
		if worst == Skipped {
			dr.Required = false
		}
		if unimplemented[d] {
			worst = Unknown
			details = []string{probes[0].Detail}
		}
		dr.Status = worst
		dr.Detail = strings.Join(details, "; ")
		if dr.Status == Available {
			dr.Detail = fmt.Sprintf("%d call(s) succeeded", len(probes))
		}
		out = append(out, dr)
	}
	return out
}

func (p *prober) identityFailed() (string, bool) {
	for _, id := range p.res.Identities {
		if id.Access == "management" && id.Status != Available {
			return id.Detail, true
		}
	}
	return "", false
}

// domainOrder is the matrix order: the evaluation's domains, then the
// preflight-only member inspection row.
func domainOrder() []string {
	var out []string
	for _, d := range evaluator.DescribeDomains() {
		out = append(out, d.Domain)
	}
	return append(out, MemberInspectionDomain)
}

// buildMatrix lays the sides out as rows.
func buildMatrix(sides []SideResult) Matrix {
	m := Matrix{SingleSide: len(sides) < 2}
	byDomain := func(s SideResult) map[string]DomainResult {
		out := map[string]DomainResult{}
		for _, d := range s.Domains {
			out[d.Domain] = d
		}
		return out
	}
	var src, dst map[string]DomainResult
	if len(sides) > 0 {
		src = byDomain(sides[0])
	}
	if len(sides) > 1 {
		dst = byDomain(sides[1])
	}
	cell := func(m map[string]DomainResult, d string) Cell {
		if m == nil {
			return Cell{Status: Unknown, Detail: "no side configured"}
		}
		r, ok := m[d]
		if !ok {
			return Cell{Status: Unknown, Detail: "not probed"}
		}
		return Cell{Status: r.Status, Required: r.Required, Detail: r.Detail, Operations: r.Operations}
	}
	descriptions := map[string]evaluator.DomainDescription{}
	for _, d := range evaluator.DescribeDomains() {
		descriptions[d.Domain] = d
	}
	descriptions[MemberInspectionDomain] = evaluator.DomainDescription{Domain: MemberInspectionDomain, Why: "whether the member inspection role can be assumed; later milestones read IAM last-accessed data and networking state through it", Check: ""}
	for _, d := range domainOrder() {
		desc := descriptions[d]
		row := Row{Domain: d, Why: desc.Why, Check: desc.Check, Source: cell(src, d)}
		if m.SingleSide {
			row.Target = Cell{Status: Unknown, Detail: "no destination configured"}
		} else {
			row.Target = cell(dst, d)
		}
		m.Rows = append(m.Rows, row)
	}
	return m
}

// Line summarizes the result in one line.
func (r *Result) Line() string {
	if r.Ready {
		return fmt.Sprintf("ready: every probed capability is available on %d side(s)", len(r.Sides))
	}
	return fmt.Sprintf("not ready: %d blocking item(s)", len(r.Blocking))
}
