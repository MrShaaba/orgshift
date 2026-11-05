package collector

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/controltower"
	cttypes "github.com/aws/aws-sdk-go-v2/service/controltower/types"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	orgtypes "github.com/aws/aws-sdk-go-v2/service/organizations/types"
	"github.com/aws/aws-sdk-go-v2/service/ram"
	"github.com/aws/smithy-go"

	"github.com/MrShaaba/orgshift/internal/snapshot"
)

func denied(op string) error {
	return &smithy.GenericAPIError{Code: "AccessDeniedException", Message: "User is not authorized to perform: " + op}
}

func record(t *testing.T, s *snapshot.Snapshot, domain string) snapshot.DomainCoverage {
	t.Helper()
	recs := s.DomainRecords(domain)
	if len(recs) == 0 {
		t.Fatalf("no coverage record for %s; have %+v", domain, s.Coverage.Domains)
	}
	return recs[len(recs)-1]
}

// fakeRAMDenied is a RAM client whose credentials lack the permission.
type fakeRAMDenied struct{ fakeRAM }

func (fakeRAMDenied) GetResourceShares(context.Context, *ram.GetResourceSharesInput, ...func(*ram.Options)) (*ram.GetResourceSharesOutput, error) {
	return nil, denied("ram:GetResourceShares")
}

// fakeOrgsPartial lists two SCPs over two pages and fails to describe the
// second one, so the first was read before the failure.
type fakeOrgsPartial struct{ fakeOrgs }

func (fakeOrgsPartial) ListPolicies(_ context.Context, in *organizations.ListPoliciesInput, _ ...func(*organizations.Options)) (*organizations.ListPoliciesOutput, error) {
	if in.Filter != orgtypes.PolicyTypeServiceControlPolicy {
		return nil, context.DeadlineExceeded
	}
	if aws.ToString(in.NextToken) == "" {
		return &organizations.ListPoliciesOutput{NextToken: aws.String("page2"), Policies: []orgtypes.PolicySummary{{Id: aws.String("p-FullAWSAccess"), Name: aws.String("FullAWSAccess"), AwsManaged: true, Type: orgtypes.PolicyTypeServiceControlPolicy}}}, nil
	}
	return &organizations.ListPoliciesOutput{Policies: []orgtypes.PolicySummary{{Id: aws.String("p-second"), Name: aws.String("Second"), Type: orgtypes.PolicyTypeServiceControlPolicy}}}, nil
}

func (f fakeOrgsPartial) DescribePolicy(ctx context.Context, in *organizations.DescribePolicyInput, opts ...func(*organizations.Options)) (*organizations.DescribePolicyOutput, error) {
	if aws.ToString(in.PolicyId) == "p-second" {
		return nil, errors.New("ThrottlingException: Rate exceeded")
	}
	return f.fakeOrgs.DescribePolicy(ctx, in, opts...)
}

// fakeOrgsCTTrusted is fakeOrgs with trusted access for Control Tower and
// Identity Center, so an empty regional answer is suspicious.
type fakeOrgsCTTrusted struct{ fakeOrgs }

func (fakeOrgsCTTrusted) ListAWSServiceAccessForOrganization(context.Context, *organizations.ListAWSServiceAccessForOrganizationInput, ...func(*organizations.Options)) (*organizations.ListAWSServiceAccessForOrganizationOutput, error) {
	return &organizations.ListAWSServiceAccessForOrganizationOutput{EnabledServicePrincipals: []orgtypes.EnabledServicePrincipal{{ServicePrincipal: aws.String("controltower.amazonaws.com")}, {ServicePrincipal: aws.String("sso.amazonaws.com")}}}, nil
}

// fakeControlTowerNoZones answers as the service does outside the home region.
type fakeControlTowerNoZones struct{ fakeControlTower }

func (fakeControlTowerNoZones) ListLandingZones(context.Context, *controltower.ListLandingZonesInput, ...func(*controltower.Options)) (*controltower.ListLandingZonesOutput, error) {
	return &controltower.ListLandingZonesOutput{}, nil
}

// fakeControlTowerAuto has auto-enrollment on and a child baseline with a
// parent, so the enrolled account resolves to its OU.
type fakeControlTowerAuto struct{ fakeControlTower }

func (f fakeControlTowerAuto) GetLandingZone(ctx context.Context, in *controltower.GetLandingZoneInput, opts ...func(*controltower.Options)) (*controltower.GetLandingZoneOutput, error) {
	out, err := f.fakeControlTower.GetLandingZone(ctx, in, opts...)
	if err == nil {
		out.LandingZone.RemediationTypes = []cttypes.RemediationType{cttypes.RemediationTypeInheritanceDrift}
		out.LandingZone.LatestAvailableVersion = aws.String("3.4")
	}
	return out, err
}

func (fakeControlTowerAuto) ListEnabledBaselines(context.Context, *controltower.ListEnabledBaselinesInput, ...func(*controltower.Options)) (*controltower.ListEnabledBaselinesOutput, error) {
	status := &cttypes.EnablementStatusSummary{Status: cttypes.EnablementStatusSucceeded}
	return &controltower.ListEnabledBaselinesOutput{EnabledBaselines: []cttypes.EnabledBaselineSummary{
		{Arn: aws.String("arn:aws:controltower:us-east-1:111111111111:enabledbaseline/A"), BaselineIdentifier: aws.String("arn:aws:controltower:us-east-1::baseline/17BSJV3IGJ2QSGA2"),
			TargetIdentifier: aws.String(fakeOUARN), BaselineVersion: aws.String("4.0"), StatusSummary: status},
		{Arn: aws.String("arn:aws:controltower:us-east-1:111111111111:enabledbaseline/C"), BaselineIdentifier: aws.String("arn:aws:controltower:us-east-1::baseline/17BSJV3IGJ2QSGA2"),
			ParentIdentifier:   aws.String("arn:aws:controltower:us-east-1:111111111111:enabledbaseline/A"),
			TargetIdentifier:   aws.String("arn:aws:organizations::111111111111:account/o-fake00000001/111111111112"),
			StatusSummary:      &cttypes.EnablementStatusSummary{Status: cttypes.EnablementStatusUnderChange},
			DriftStatusSummary: &cttypes.EnabledBaselineDriftStatusSummary{Types: &cttypes.EnabledBaselineDriftTypes{Inheritance: &cttypes.EnabledBaselineInheritanceDrift{Status: cttypes.EnabledBaselineDriftStatusDrifted}}}},
		// An account outside the tree is skipped.
		{Arn: aws.String("arn:aws:controltower:us-east-1:111111111111:enabledbaseline/D"), TargetIdentifier: aws.String("999999999999"), StatusSummary: status},
	}}, nil
}

func TestCoverageRecordsAccessDenied(t *testing.T) {
	snap, err := Collect(context.Background(), Options{Organizations: fakeOrgs{}, RAM: []RAMAPI{fakeRAMDenied{}}, RAMLabels: []string{"network"}, Region: "us-east-1", Version: "test"})
	if err != nil {
		t.Fatalf("a denied domain must not fail the collection: %v", err)
	}
	if len(snap.ResourceShares) != 0 {
		t.Fatal("no shares should be recorded")
	}
	rec := record(t, snap, snapshot.DomainResourceShares)
	if rec.Status != snapshot.CoverageAccessDenied || !strings.Contains(rec.Error, "AccessDeniedException") || rec.Region != "us-east-1" || !strings.Contains(rec.Reason, "network") {
		t.Errorf("record: %+v", rec)
	}
	if snap.Coverage.CollectorVersion != "test" || rec.CollectedAt != snap.GeneratedAt {
		t.Errorf("version and timestamp: %+v", rec)
	}
	if got := snap.DomainStatus(snapshot.DomainResourceShares, ""); got != snapshot.CoverageAccessDenied {
		t.Errorf("status %s", got)
	}
	if !strings.Contains(Summary(snap), "coverage gaps") || !strings.Contains(Summary(snap), "resource_shares access_denied") {
		t.Errorf("summary should list the gap: %s", Summary(snap))
	}
}

func TestCoverageRecordsPartialPaginationAndDropsTheHalfReadType(t *testing.T) {
	snap, err := Collect(context.Background(), Options{Organizations: fakeOrgsPartial{}})
	if err != nil {
		t.Fatal(err)
	}
	rec := record(t, snap, snapshot.DomainPoliciesSCP)
	if rec.Status != snapshot.CoveragePartial || rec.Pages < 2 || !strings.Contains(rec.Error, "1 policies read before the failure were dropped") || !strings.Contains(rec.Error, "describe p-second") || !strings.Contains(rec.Error, "ThrottlingException") {
		t.Errorf("record: %+v", rec)
	}
	if len(snap.Policies) != 0 {
		t.Error("a half-read policy type must not be kept as if complete")
	}
	if rec := record(t, snap, snapshot.DomainPoliciesTag); rec.Status != snapshot.CoverageEmpty || !strings.Contains(rec.Reason, "not enabled") {
		t.Errorf("disabled type should be empty with a reason: %+v", rec)
	}
}

func TestCoverageRecordsSkippedAndUnsupported(t *testing.T) {
	snap, err := Collect(context.Background(), Options{Organizations: fakeOrgs{}, SkipReasons: map[string]string{
		snapshot.DomainResourceShares: "--skip-ram", snapshot.DomainEnabledRegions: "--skip-regions", snapshot.DomainControlTower: "--skip-control-tower", snapshot.DomainEnrolledAccounts: "--skip-control-tower",
	}})
	if err != nil {
		t.Fatal(err)
	}
	for domain, reason := range map[string]string{snapshot.DomainResourceShares: "--skip-ram", snapshot.DomainEnabledRegions: "--skip-regions", snapshot.DomainControlTower: "--skip-control-tower", snapshot.DomainEnrolledAccounts: "--skip-control-tower"} {
		if rec := record(t, snap, domain); rec.Status != snapshot.CoverageSkipped || rec.Reason != reason {
			t.Errorf("%s: %+v", domain, rec)
		}
	}
	if rec := record(t, snap, snapshot.DomainIdentityCenter); rec.Status != snapshot.CoverageSkipped || !strings.Contains(rec.Reason, "no client") {
		t.Errorf("identity center without a reason: %+v", rec)
	}
	for _, d := range []string{snapshot.DomainOrgTrails, snapshot.DomainConfigAggregator} {
		if rec := record(t, snap, d); rec.Status != snapshot.CoverageUnsupported {
			t.Errorf("%s should be unsupported: %+v", d, rec)
		}
	}
	// StackSets and the workload inventory are collected by this build; with
	// no client and no account to inspect they are skipped, with the reason.
	if rec := record(t, snap, snapshot.DomainStackSets); rec.Status != snapshot.CoverageSkipped || !strings.Contains(rec.Reason, "no client") {
		t.Errorf("stack_sets without a client: %+v", rec)
	}
	for _, d := range snapshot.WorkloadDomains {
		if rec := record(t, snap, d); rec.Status != snapshot.CoverageSkipped || !strings.Contains(rec.Reason, "member_inspection.accounts") || rec.AccountID != "" {
			t.Errorf("%s without accounts to inspect: %+v", d, rec)
		}
	}
	if snap.Workloads != nil {
		t.Errorf("no inventory without an inspected account: %+v", snap.Workloads)
	}
	for _, d := range []string{snapshot.DomainOrganization, snapshot.DomainTree, snapshot.DomainAccountTags, snapshot.DomainDelegatedAdmins, snapshot.DomainTrustedAccess, snapshot.DomainPoliciesSCP} {
		if rec := record(t, snap, d); rec.Status != snapshot.CoverageObserved || rec.Items == 0 {
			t.Errorf("%s should be observed with items: %+v", d, rec)
		}
	}
	if err := snap.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestWrongRegionIsAnErrorNotAnAbsence(t *testing.T) {
	snap, err := Collect(context.Background(), Options{Organizations: fakeOrgsCTTrusted{}, ControlTower: fakeControlTowerNoZones{}, SSOAdmin: fakeSSOAdmin{fail: true}, Region: "eu-west-3"})
	if err != nil {
		t.Fatal(err)
	}
	if snap.ControlTower != nil {
		t.Fatal("no landing zone must be invented")
	}
	rec := record(t, snap, snapshot.DomainControlTower)
	if rec.Status != snapshot.CoverageError || !strings.Contains(rec.Error, "trusted access for controltower.amazonaws.com is enabled") || !strings.Contains(rec.Error, "control_tower.home_region") || rec.Region != "eu-west-3" {
		t.Errorf("wrong-region record: %+v", rec)
	}
	if rec := record(t, snap, snapshot.DomainEnrolledAccounts); rec.Status != snapshot.CoverageError {
		t.Errorf("enrolled accounts follow the landing zone: %+v", rec)
	}
	if rec := record(t, snap, snapshot.DomainIdentityCenter); rec.Status != snapshot.CoverageError || !strings.Contains(rec.Error, "instance's region") {
		t.Errorf("identity center failure should carry the region hint: %+v", rec)
	}
	// Without trusted access the empty answer is a confirmed absence.
	snap, err = Collect(context.Background(), Options{Organizations: fakeOrgs{}, ControlTower: fakeControlTowerNoZones{}, Region: "eu-west-3"})
	if err != nil {
		t.Fatal(err)
	}
	if rec := record(t, snap, snapshot.DomainControlTower); rec.Status != snapshot.CoverageEmpty {
		t.Errorf("no trusted access: %+v", rec)
	}
}

func TestEnrolledAccountsAndAutoEnrollmentAreRead(t *testing.T) {
	snap, err := Collect(context.Background(), Options{Organizations: fakeOrgs{}, ControlTower: fakeControlTowerAuto{}, Region: "us-east-1"})
	if err != nil {
		t.Fatal(err)
	}
	ct := snap.ControlTower
	if ct == nil || ct.AutoEnrollment != snapshot.AutoEnrollmentEnabled || ct.LatestAvailableVersion != "3.4" {
		t.Fatalf("landing zone: %+v", ct)
	}
	if len(ct.EnrolledAccounts) != 1 {
		t.Fatalf("one enrolled account expected (the one outside the tree is skipped): %+v", ct.EnrolledAccounts)
	}
	e := ct.EnrolledAccounts[0]
	if e.AccountID != "111111111112" || e.Source != snapshot.EnrolledFromBaseline || e.Status != "UNDER_CHANGE" || e.DriftStatus != "DRIFTED" || e.ParentOUID != "ou-fake-work" || e.VendedByAccountFactory || e.ProvenanceKnown() {
		t.Errorf("enrolled record: %+v", e)
	}
	if rec := record(t, snap, snapshot.DomainEnrolledAccounts); rec.Status != snapshot.CoverageObserved || rec.Items != 1 {
		t.Errorf("enrolled coverage: %+v", rec)
	}
	if rec := record(t, snap, snapshot.DomainControlTower); rec.Status != snapshot.CoverageObserved {
		t.Errorf("control tower coverage: %+v", rec)
	}
	if !strings.Contains(Summary(snap), "1 enrolled accounts") || !strings.Contains(Summary(snap), "auto-enrollment enabled") {
		t.Errorf("summary: %s", Summary(snap))
	}
	// The plain fake has no remediation types: auto-enrollment is known to be off.
	snap, _ = Collect(context.Background(), Options{Organizations: fakeOrgs{}, ControlTower: fakeControlTower{}})
	if snap.ControlTower.AutoEnrollment != snapshot.AutoEnrollmentDisabled {
		t.Errorf("auto-enrollment should be disabled, got %q", snap.ControlTower.AutoEnrollment)
	}
}

func TestClassifyErrors(t *testing.T) {
	cases := map[snapshot.CoverageStatus]error{
		snapshot.CoverageAccessDenied: denied("x"),
		snapshot.CoverageUnsupported:  &smithy.GenericAPIError{Code: "AWSOrganizationsNotInUseException", Message: "no org"},
		snapshot.CoverageError:        errors.New("dial tcp: timeout"),
	}
	for want, err := range cases {
		if got, msg := classify(err); got != want || msg == "" {
			t.Errorf("classify(%v) = %s %q want %s", err, got, msg, want)
		}
	}
	if got, _ := classify(nil); got != snapshot.CoverageObserved {
		t.Errorf("nil error is observed, got %s", got)
	}
}
