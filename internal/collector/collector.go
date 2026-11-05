package collector

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"sort"
	"strings"
	"sync"
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
// uses. Every method is a read operation from Catalog.
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

// DefaultConcurrency bounds the parallel per-item calls (one account's
// tags, one share's principals) when Options.Concurrency is zero.
const DefaultConcurrency = 4

// DefaultCheckpointMaxAge is how old a checkpoint may be and still be
// resumed when Options.CheckpointMaxAge is zero.
const DefaultCheckpointMaxAge = 24 * time.Hour

// Options configure a collection run.
type Options struct {
	// Name is the friendly organization name stored in the snapshot.
	Name string
	// Region is the region the Organizations, Account and RAM clients call.
	// It is recorded on the regional coverage records.
	Region string
	// ControlTowerRegion is the landing zone's home region, where the
	// Control Tower client calls. Defaults to Region.
	ControlTowerRegion string
	// IdentityCenterRegion is the instance's region, where the Identity
	// Center clients call; the AWSReservedSSO_* role path carries it.
	// Defaults to Region.
	IdentityCenterRegion string
	// Version is the collector build, recorded in the coverage block and
	// the checkpoint.
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
	// StackSets lists the StackSets administered from the management
	// account with their instances. Optional; nil records the domain as
	// skipped.
	StackSets StackSetsAPI
	// Workloads configures the inventory of member accounts (stacks, a
	// resource sample, policies tied to organization identity). Optional;
	// nil or no accounts records the workload domains as skipped.
	Workloads *WorkloadOptions
	// SkipReasons says why an optional client is nil, keyed by coverage
	// domain ("--skip-ram", say). Domains without a reason are recorded as
	// skipped with a generic note.
	SkipReasons map[string]string
	// Concurrency bounds the parallel per-item calls within a domain. Zero
	// means DefaultConcurrency; one makes the collector sequential.
	Concurrency int
	// Retry bounds the collector's retry loop around every call; zero
	// fields take DefaultRetry.
	Retry RetryOptions
	// Sleep waits between retries. Tests inject one; nil sleeps for real.
	Sleep Sleeper
	// Checkpoint is the path of the checkpoint file. Empty disables
	// checkpointing. When the file exists and is usable the run resumes
	// from it; the file is written after every completed step and removed
	// when every domain was read completely, unless KeepCheckpoint is set.
	Checkpoint string
	// CheckpointMaxAge refuses older checkpoints. Zero means
	// DefaultCheckpointMaxAge.
	CheckpointMaxAge time.Duration
	// KeepCheckpoint leaves the checkpoint file in place after a complete
	// run.
	KeepCheckpoint bool
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
//
// With a checkpoint path, every completed step is saved as it finishes and
// a rerun restores the completed steps instead of reading them again.
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
	if opts.Concurrency <= 0 {
		opts.Concurrency = DefaultConcurrency
	}
	if opts.ControlTowerRegion == "" {
		opts.ControlTowerRegion = opts.Region
	}
	if opts.IdentityCenterRegion == "" {
		opts.IdentityCenterRegion = opts.Region
	}
	if opts.CheckpointMaxAge <= 0 {
		opts.CheckpointMaxAge = DefaultCheckpointMaxAge
	}
	opts.Retry = opts.Retry.withDefaults()
	r := &run{opts: opts, ctx: ctx, retries: map[string]int{}, completed: map[string]bool{}}
	r.snap = r.emptySnapshot()
	r.opts.Logger.Printf("collecting organization")
	if err := r.organization(); err != nil {
		return nil, fmt.Errorf("organization: %w", err)
	}
	r.resume()
	for _, s := range r.steps() {
		if r.completed[s.name] {
			r.opts.Logger.Printf("%s: restored from the checkpoint", s.title)
			continue
		}
		s.reset()
		r.dropRecords(s.domains...)
		r.opts.Logger.Printf("collecting %s", s.title)
		if err := s.run(); err != nil {
			return nil, fmt.Errorf("%s: %w", s.title, err)
		}
		if s.checkpoint && r.stepComplete(s.domains) {
			r.completed[s.name] = true
			r.saveCheckpoint()
		}
	}
	r.snap.Usage = map[string]*snapshot.AccountUsage{}
	r.snap.Coverage = &snapshot.Coverage{CollectorVersion: opts.Version, Domains: r.cov}
	if err := r.snap.Validate(); err != nil {
		return nil, fmt.Errorf("collected snapshot failed validation: %w", err)
	}
	r.finishCheckpoint()
	return r.snap, nil
}

type logDiscard struct{}

func (logDiscard) Write(p []byte) (int, error) { return len(p), nil }

type run struct {
	opts Options
	ctx  context.Context
	snap *snapshot.Snapshot

	mu  sync.Mutex
	cov []snapshot.DomainCoverage
	// retries counts throttling retries per domain until the next record.
	retries  map[string]int
	controls map[string]*controlcatalog.GetControlOutput
	// principals caches identity store lookups by "TYPE:id".
	principals map[string]string
	// completed marks the steps restored from a checkpoint or finished in
	// this run; resumed is the checkpoint the run restored, if any.
	completed map[string]bool
	resumed   *Checkpoint
}

func (r *run) emptySnapshot() *snapshot.Snapshot {
	s := &snapshot.Snapshot{SchemaVersion: snapshot.SchemaVersion, Source: "collector"}
	s.GeneratedAt = r.opts.Now().UTC().Format(time.RFC3339)
	s.Organization.Name = r.opts.Name
	s.ResourceShares = []snapshot.ResourceShare{}
	s.DelegatedAdministrators = []snapshot.DelegatedAdministrator{}
	s.TrustedAccessServices = []string{}
	s.OrganizationTrails = []snapshot.OrganizationTrail{}
	s.ConfigAggregators = []snapshot.ConfigAggregator{}
	s.StackSets = []snapshot.StackSet{}
	return s
}

// step is one checkpointable unit of collection.
type step struct {
	name, title string
	// domains are the coverage domains the step records; they decide
	// whether the step is complete and are dropped before it reruns.
	domains []string
	// reset clears the step's output so a rerun after a partial checkpoint
	// does not duplicate it.
	reset func()
	run   func() error
	// checkpoint says whether a completed step is saved and restored.
	checkpoint bool
}

func (r *run) steps() []step {
	s := r.snap
	ok := func(fn func()) func() error { return func() error { fn(); return nil } }
	steps := []step{
		{name: "tree", title: "roots and tree", domains: []string{snapshot.DomainTree}, checkpoint: true,
			reset: func() { s.Root = snapshot.Root{}; s.OUs = nil; s.Accounts = nil }, run: r.tree},
		{name: "account_tags", title: "account tags", domains: []string{snapshot.DomainAccountTags}, checkpoint: true,
			reset: func() {
				for i := range s.Accounts {
					s.Accounts[i].Tags = nil
				}
			}, run: ok(r.accountTags)},
	}
	for _, t := range snapshot.AllPolicyTypes {
		t := t
		domain := snapshot.PolicyDomain(t)
		steps = append(steps, step{name: domain, title: strings.ToLower(t.Short()) + " policies", domains: []string{domain}, checkpoint: true,
			reset: func() { r.dropPolicyType(t) }, run: ok(func() { r.policyType(t) })})
	}
	steps = append(steps,
		step{name: "delegated_administrators", title: "delegated administrators", domains: []string{snapshot.DomainDelegatedAdmins}, checkpoint: true,
			reset: func() { s.DelegatedAdministrators = []snapshot.DelegatedAdministrator{} }, run: ok(r.delegated)},
		step{name: "trusted_access", title: "trusted access", domains: []string{snapshot.DomainTrustedAccess}, checkpoint: true,
			reset: func() { s.TrustedAccessServices = []string{} }, run: ok(r.trustedAccess)},
		step{name: "resource_shares", title: "resource shares", domains: []string{snapshot.DomainResourceShares}, checkpoint: true,
			reset: func() { s.ResourceShares = []snapshot.ResourceShare{} }, run: ok(r.shares)},
		step{name: "enabled_regions", title: "enabled regions", domains: []string{snapshot.DomainEnabledRegions}, checkpoint: true,
			reset: func() {
				for i := range s.Accounts {
					s.Accounts[i].EnabledRegions = nil
				}
			}, run: ok(r.regions)},
		step{name: "control_tower", title: "control tower", domains: []string{snapshot.DomainControlTower, snapshot.DomainEnrolledAccounts}, checkpoint: true,
			reset: func() { s.ControlTower = nil }, run: ok(r.controlTower)},
		step{name: "identity_center", title: "identity center", domains: []string{snapshot.DomainIdentityCenter}, checkpoint: true,
			reset: func() { s.IdentityCenter = nil }, run: ok(r.identityCenter)},
		step{name: "stack_sets", title: "StackSets", domains: []string{snapshot.DomainStackSets}, checkpoint: true,
			reset: func() { s.StackSets = []snapshot.StackSet{} }, run: ok(r.stackSets)},
		step{name: "workloads", title: "workload inventory of the member accounts", domains: snapshot.WorkloadDomains, checkpoint: true,
			reset: func() { s.Workloads = nil }, run: ok(r.workloads)},
		step{name: "not_collected", title: "organization trails and Config aggregators", domains: []string{snapshot.DomainOrgTrails, snapshot.DomainConfigAggregator},
			reset: func() {}, run: ok(r.notCollected)},
	)
	return steps
}

// stepComplete reports whether every record of the step's domains says the
// lists can be trusted.
func (r *run) stepComplete(domains []string) bool {
	found := false
	for _, d := range r.cov {
		for _, want := range domains {
			if d.Domain == want {
				found = true
				if !d.Status.Complete() {
					return false
				}
			}
		}
	}
	return found
}

// dropRecords removes the coverage records of the given domains.
func (r *run) dropRecords(domains ...string) {
	var kept []snapshot.DomainCoverage
	for _, d := range r.cov {
		drop := false
		for _, want := range domains {
			if d.Domain == want {
				drop = true
			}
		}
		if !drop {
			kept = append(kept, d)
		}
	}
	r.cov = kept
}

func (r *run) dropPolicyType(t snapshot.PolicyType) {
	var kept []snapshot.Policy
	for _, p := range r.snap.Policies {
		if p.Type != t {
			kept = append(kept, p)
		}
	}
	r.snap.Policies = kept
}

// resume restores the completed steps of a usable checkpoint.
func (r *run) resume() {
	path := r.opts.Checkpoint
	if path == "" {
		return
	}
	cp, err := LoadCheckpoint(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return
	case err != nil:
		r.opts.Logger.Printf("checkpoint ignored: %v", err)
		return
	}
	if err := cp.usable(r.opts.Version, r.opts.Region, r.opts.CheckpointMaxAge, r.opts.Now()); err != nil {
		r.opts.Logger.Printf("checkpoint %s ignored: %v", path, err)
		return
	}
	if cp.OrganizationID != r.snap.Organization.ID {
		r.opts.Logger.Printf("checkpoint %s ignored: written for organization %s, this run reads %s", path, cp.OrganizationID, r.snap.Organization.ID)
		return
	}
	fresh := r.snap
	restored := cp.Snapshot
	savedCoverage := restored.Coverage
	restored.SchemaVersion = snapshot.SchemaVersion
	restored.Source = "collector"
	restored.GeneratedAt = fresh.GeneratedAt
	restored.Organization = fresh.Organization
	restored.Coverage = nil
	restored.Usage = nil
	r.snap = restored
	var completedDomains []string
	for _, s := range r.steps() {
		if s.checkpoint && cp.completed(s.name) {
			r.completed[s.name] = true
			completedDomains = append(completedDomains, s.domains...)
		}
	}
	if savedCoverage != nil {
		for _, d := range savedCoverage.Domains {
			if !containsString(completedDomains, d.Domain) {
				continue
			}
			note := "restored from the checkpoint written at " + cp.WrittenAt
			if d.Reason == "" {
				d.Reason = note
			} else {
				d.Reason += "; " + note
			}
			r.cov = append(r.cov, d)
		}
	}
	r.resumed = cp
	names := make([]string, 0, len(r.completed))
	for n := range r.completed {
		names = append(names, n)
	}
	sort.Strings(names)
	r.opts.Logger.Printf("resuming from checkpoint %s written at %s: %d step(s) restored (%s)", path, cp.WrittenAt, len(names), strings.Join(names, ", "))
}

// saveCheckpoint writes the run state after a completed step. A failure to
// write is logged, not fatal.
func (r *run) saveCheckpoint() {
	if r.opts.Checkpoint == "" {
		return
	}
	names := make([]string, 0, len(r.completed))
	for n := range r.completed {
		names = append(names, n)
	}
	sort.Strings(names)
	r.snap.Coverage = &snapshot.Coverage{CollectorVersion: r.opts.Version, Domains: r.cov}
	cp := Checkpoint{SchemaVersion: CheckpointSchemaVersion, CollectorVersion: r.opts.Version, WrittenAt: r.opts.Now().UTC().Format(time.RFC3339),
		OrganizationID: r.snap.Organization.ID, Region: r.opts.Region, Completed: names, Snapshot: r.snap}
	if err := cp.Save(r.opts.Checkpoint); err != nil {
		r.opts.Logger.Printf("warning: checkpoint not written: %v", err)
	}
	r.snap.Coverage = nil
}

// finishCheckpoint removes the checkpoint when no domain failed, or says
// that it is kept for the next run. Skipped and unsupported domains are
// deliberate, not failures, so they do not keep it.
func (r *run) finishCheckpoint() {
	if r.opts.Checkpoint == "" {
		return
	}
	for _, d := range r.cov {
		switch d.Status {
		case snapshot.CoveragePartial, snapshot.CoverageAccessDenied, snapshot.CoverageError:
			r.opts.Logger.Printf("checkpoint kept at %s: %s; a rerun restores the completed steps and reads this one again", r.opts.Checkpoint, d.Label())
			return
		}
	}
	if r.opts.KeepCheckpoint {
		return
	}
	if err := os.Remove(r.opts.Checkpoint); err != nil && !errors.Is(err, os.ErrNotExist) {
		r.opts.Logger.Printf("warning: checkpoint not removed: %v", err)
	}
}

// call runs one API call through the retry loop and counts the retries for
// the domain's coverage record.
func (r *run) call(domain, op string, fn func() error) error {
	n, err := Retry(r.ctx, r.opts.Retry, r.opts.Sleep, fn, func(attempt int, delay time.Duration, err error) {
		r.opts.Logger.Printf("%s: attempt %d throttled (%s); retrying in %s", op, attempt, errorCode(err), delay.Round(time.Millisecond))
	})
	if n > 0 {
		r.mu.Lock()
		r.retries[domain] += n
		r.mu.Unlock()
	}
	return err
}

// errorCode renders an error by its code when it has one.
func errorCode(err error) string {
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		return apiErr.ErrorCode()
	}
	return err.Error()
}

// parallel runs fn for every index with at most Concurrency goroutines and
// waits for all of them. fn must only write to its own slot of a result
// slice; appends to the snapshot happen afterwards, in index order.
func (r *run) parallel(n int, fn func(i int)) {
	workers := r.opts.Concurrency
	if workers > n {
		workers = n
	}
	if workers <= 1 {
		for i := 0; i < n; i++ {
			fn(i)
		}
		return
	}
	var wg sync.WaitGroup
	idx := make(chan int)
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range idx {
				fn(i)
			}
		}()
	}
	for i := 0; i < n; i++ {
		idx <- i
	}
	close(idx)
	wg.Wait()
}

// record appends a coverage record, stamping it with the collection time
// and the retries performed for its domain so far.
func (r *run) record(d snapshot.DomainCoverage) {
	if d.CollectedAt == "" {
		d.CollectedAt = r.snap.GeneratedAt
	}
	r.mu.Lock()
	d.Retries = r.retries[d.Domain]
	delete(r.retries, d.Domain)
	r.mu.Unlock()
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

// ClassifyError maps an API error to a coverage status (access_denied,
// unsupported or error) and a message that keeps the error code. The
// preflight uses the same classification as the collector.
func ClassifyError(err error) (snapshot.CoverageStatus, string) { return classify(err) }

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

// paginate drives a paginator through closures, retrying each page on
// throttling, and reports how many pages were read before an error.
func (r *run) paginate(domain, op string, hasMore func() bool, next func() error) (pages int, err error) {
	for hasMore() {
		if err := r.call(domain, op, next); err != nil {
			return pages, err
		}
		pages++
	}
	return pages, nil
}

func (r *run) organization() error {
	const op = "organizations:DescribeOrganization"
	var out *organizations.DescribeOrganizationOutput
	err := r.call(snapshot.DomainOrganization, op, func() (err error) {
		out, err = r.opts.Organizations.DescribeOrganization(r.ctx, &organizations.DescribeOrganizationInput{})
		return err
	})
	if err != nil {
		r.record(r.failed(snapshot.DomainOrganization, err, 0, 0, op))
		return err
	}
	o := out.Organization
	r.snap.Organization.ID = aws.ToString(o.Id)
	r.snap.Organization.ARN = aws.ToString(o.Arn)
	r.snap.Organization.ManagementAccountID = aws.ToString(o.MasterAccountId)
	r.snap.Organization.FeatureSet = string(o.FeatureSet)
	r.record(r.observed(snapshot.DomainOrganization, 1, 1, op))
	return nil
}

const treeOps = "organizations:ListRoots, organizations:ListOrganizationalUnitsForParent, organizations:ListAccountsForParent"

func (r *run) tree() error {
	ops := strings.Split(treeOps, ", ")
	var roots *organizations.ListRootsOutput
	err := r.call(snapshot.DomainTree, ops[0], func() (err error) {
		roots, err = r.opts.Organizations.ListRoots(r.ctx, &organizations.ListRootsInput{})
		return err
	})
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
	n, err := r.paginate(snapshot.DomainTree, "organizations:ListOrganizationalUnitsForParent", ouPager.HasMorePages, func() error {
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
	n, err = r.paginate(snapshot.DomainTree, "organizations:ListAccountsForParent", acctPager.HasMorePages, func() error {
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

// perAccount is the outcome of one per-account call.
type perAccount struct {
	pages int
	err   error
	tags  map[string]string
	list  []string
}

// accountTags reads the tags of every account, several accounts at a time.
// One failing account makes the domain partial; the others keep their tags.
func (r *run) accountTags() {
	const op = "organizations:ListTagsForResource"
	results := make([]perAccount, len(r.snap.Accounts))
	r.parallel(len(r.snap.Accounts), func(i int) {
		a := r.snap.Accounts[i]
		pager := organizations.NewListTagsForResourcePaginator(r.opts.Organizations, &organizations.ListTagsForResourceInput{ResourceId: aws.String(a.ID)})
		tags := map[string]string{}
		n, err := r.paginate(snapshot.DomainAccountTags, op, pager.HasMorePages, func() error {
			page, err := pager.NextPage(r.ctx)
			if err != nil {
				return err
			}
			for _, t := range page.Tags {
				tags[aws.ToString(t.Key)] = aws.ToString(t.Value)
			}
			return nil
		})
		results[i] = perAccount{pages: n, err: err, tags: tags}
	})
	var failures []string
	var firstErr error
	pages := 0
	for i, res := range results {
		pages += res.pages
		if res.err != nil {
			failures = append(failures, r.snap.Accounts[i].ID)
			if firstErr == nil {
				firstErr = res.err
			}
			continue
		}
		if len(res.tags) > 0 {
			r.snap.Accounts[i].Tags = res.tags
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

// policyType reads every policy of one type: the summaries first, then the
// documents and targets several policies at a time.
func (r *run) policyType(t snapshot.PolicyType) {
	ops := []string{"organizations:ListPolicies", "organizations:DescribePolicy", "organizations:ListTargetsForPolicy"}
	domain := snapshot.PolicyDomain(t)
	if !r.snap.PolicyTypeEnabled(t) {
		r.record(snapshot.DomainCoverage{Domain: domain, Status: snapshot.CoverageEmpty, Reason: "policy type not enabled at the root"})
		return
	}
	var summaries []orgtypes.PolicySummary
	pager := organizations.NewListPoliciesPaginator(r.opts.Organizations, &organizations.ListPoliciesInput{Filter: orgtypes.PolicyType(t)})
	pages, err := r.paginate(domain, ops[0], pager.HasMorePages, func() error {
		page, err := pager.NextPage(r.ctx)
		if err != nil {
			return err
		}
		summaries = append(summaries, page.Policies...)
		return nil
	})
	if err != nil {
		r.record(r.failed(domain, err, pages, 0, ops...))
		return
	}
	type policyResult struct {
		policy snapshot.Policy
		pages  int
		err    error
	}
	results := make([]policyResult, len(summaries))
	r.parallel(len(summaries), func(i int) {
		summary := summaries[i]
		id := aws.ToString(summary.Id)
		var desc *organizations.DescribePolicyOutput
		err := r.call(domain, ops[1], func() (err error) {
			desc, err = r.opts.Organizations.DescribePolicy(r.ctx, &organizations.DescribePolicyInput{PolicyId: aws.String(id)})
			return err
		})
		if err != nil {
			results[i] = policyResult{err: fmt.Errorf("describe %s: %w", id, err)}
			return
		}
		p := snapshot.Policy{
			ID: id, ARN: aws.ToString(summary.Arn), Name: aws.ToString(summary.Name), Description: aws.ToString(summary.Description),
			Type: t, AWSManaged: summary.AwsManaged, Document: []byte(aws.ToString(desc.Policy.Content)), Targets: []string{},
		}
		targets := organizations.NewListTargetsForPolicyPaginator(r.opts.Organizations, &organizations.ListTargetsForPolicyInput{PolicyId: aws.String(id)})
		tn, err := r.paginate(domain, ops[2], targets.HasMorePages, func() error {
			tp, err := targets.NextPage(r.ctx)
			if err != nil {
				return err
			}
			for _, tgt := range tp.Targets {
				p.Targets = append(p.Targets, aws.ToString(tgt.TargetId))
			}
			return nil
		})
		if err != nil {
			results[i] = policyResult{pages: tn, err: fmt.Errorf("targets of %s: %w", id, err)}
			return
		}
		sort.Strings(p.Targets)
		results[i] = policyResult{policy: p, pages: tn}
	})
	items := 0
	var firstErr error
	for _, res := range results {
		pages += res.pages
		if res.err != nil {
			if firstErr == nil {
				firstErr = res.err
			}
			continue
		}
		items++
	}
	if firstErr != nil {
		// Keep nothing of the half-read type so an incomplete attachment
		// list does not pass for the whole picture; the record says what
		// happened.
		d := r.failed(domain, firstErr, pages, items, ops...)
		d.Items = 0
		if items > 0 {
			d.Error = fmt.Sprintf("%d policies read before the failure were dropped: %s", items, d.Error)
		}
		r.record(d)
		return
	}
	for _, res := range results {
		r.snap.Policies = append(r.snap.Policies, res.policy)
	}
	r.record(r.observed(domain, items, pages, ops...))
}

func (r *run) delegated() {
	ops := []string{"organizations:ListDelegatedAdministrators", "organizations:ListDelegatedServicesForAccount"}
	domain := snapshot.DomainDelegatedAdmins
	items, pages := 0, 0
	pager := organizations.NewListDelegatedAdministratorsPaginator(r.opts.Organizations, &organizations.ListDelegatedAdministratorsInput{})
	n, err := r.paginate(domain, ops[0], pager.HasMorePages, func() error {
		page, err := pager.NextPage(r.ctx)
		if err != nil {
			return err
		}
		for _, admin := range page.DelegatedAdministrators {
			id := aws.ToString(admin.Id)
			svcPager := organizations.NewListDelegatedServicesForAccountPaginator(r.opts.Organizations, &organizations.ListDelegatedServicesForAccountInput{AccountId: aws.String(id)})
			sn, err := r.paginate(domain, ops[1], svcPager.HasMorePages, func() error {
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
		r.record(r.failed(domain, err, pages, items, ops...))
		return
	}
	r.record(r.observed(domain, items, pages, ops...))
}

func (r *run) trustedAccess() {
	const op = "organizations:ListAWSServiceAccessForOrganization"
	pager := organizations.NewListAWSServiceAccessForOrganizationPaginator(r.opts.Organizations, &organizations.ListAWSServiceAccessForOrganizationInput{})
	pages, err := r.paginate(snapshot.DomainTrustedAccess, op, pager.HasMorePages, func() error {
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
// only shows shares owned by the caller, so each client is one record. The
// summaries are listed first; principals and resources are then read for
// several shares at a time.
func (r *run) shares() {
	ops := []string{"ram:GetResourceShares", "ram:ListPrincipals", "ram:ListResources"}
	domain := snapshot.DomainResourceShares
	if len(r.opts.RAM) == 0 {
		d := r.skipped(domain)
		d.Region = r.opts.Region
		r.record(d)
		return
	}
	for i, client := range r.opts.RAM {
		label := ""
		if i < len(r.opts.RAMLabels) {
			label = r.opts.RAMLabels[i]
		}
		owner := ""
		var summaries []ramtypes.ResourceShare
		pager := ram.NewGetResourceSharesPaginator(client, &ram.GetResourceSharesInput{ResourceOwner: ramtypes.ResourceOwnerSelf})
		pages, err := r.paginate(domain, ops[0], pager.HasMorePages, func() error {
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
				summaries = append(summaries, sh)
			}
			return nil
		})
		items := 0
		if err == nil {
			type shareResult struct {
				share snapshot.ResourceShare
				pages int
				err   error
			}
			results := make([]shareResult, len(summaries))
			r.parallel(len(summaries), func(i int) {
				sh := summaries[i]
				arn := aws.ToString(sh.ResourceShareArn)
				s := snapshot.ResourceShare{
					ARN: arn, Name: aws.ToString(sh.Name), OwnerAccountID: aws.ToString(sh.OwningAccountId), Status: string(sh.Status),
					AllowExternalPrincipals: aws.ToBool(sh.AllowExternalPrincipals),
					Principals:              []string{}, Resources: []snapshot.SharedResource{},
				}
				// RetainSharingOnAccountLeaveOrganization is set at creation
				// and reported in the share's configuration. Absent, false is
				// the documented default: the share stops when the account
				// leaves the organization.
				if cfg := sh.ResourceShareConfiguration; cfg != nil {
					s.RetainSharingOnAccountLeave = aws.ToBool(cfg.RetainSharingOnAccountLeaveOrganization)
				}
				pp := ram.NewListPrincipalsPaginator(client, &ram.ListPrincipalsInput{ResourceOwner: ramtypes.ResourceOwnerSelf, ResourceShareArns: []string{arn}})
				pn, err := r.paginate(domain, ops[1], pp.HasMorePages, func() error {
					page, err := pp.NextPage(r.ctx)
					if err != nil {
						return err
					}
					for _, p := range page.Principals {
						s.Principals = append(s.Principals, aws.ToString(p.Id))
					}
					return nil
				})
				if err != nil {
					results[i] = shareResult{pages: pn, err: fmt.Errorf("principals of %s: %w", arn, err)}
					return
				}
				rp := ram.NewListResourcesPaginator(client, &ram.ListResourcesInput{ResourceOwner: ramtypes.ResourceOwnerSelf, ResourceShareArns: []string{arn}})
				rn, err := r.paginate(domain, ops[2], rp.HasMorePages, func() error {
					page, err := rp.NextPage(r.ctx)
					if err != nil {
						return err
					}
					for _, res := range page.Resources {
						s.Resources = append(s.Resources, snapshot.SharedResource{ARN: aws.ToString(res.Arn), Type: aws.ToString(res.Type)})
					}
					return nil
				})
				if err != nil {
					results[i] = shareResult{pages: pn + rn, err: fmt.Errorf("resources of %s: %w", arn, err)}
					return
				}
				results[i] = shareResult{share: s, pages: pn + rn}
			})
			for _, res := range results {
				pages += res.pages
				if res.err != nil {
					if err == nil {
						err = res.err
					}
					continue
				}
				r.snap.ResourceShares = append(r.snap.ResourceShares, res.share)
				items++
			}
		}
		var d snapshot.DomainCoverage
		if err != nil {
			d = r.failed(domain, err, pages, items, ops...)
		} else {
			d = r.observed(domain, items, pages, ops...)
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

// regions lists the enabled regions of every account, several accounts at
// a time.
func (r *run) regions() {
	const op = "account:ListRegions"
	domain := snapshot.DomainEnabledRegions
	if r.opts.Account == nil {
		r.record(r.skipped(domain))
		return
	}
	results := make([]perAccount, len(r.snap.Accounts))
	r.parallel(len(r.snap.Accounts), func(i int) {
		a := r.snap.Accounts[i]
		pager := account.NewListRegionsPaginator(r.opts.Account, &account.ListRegionsInput{
			AccountId: aws.String(a.ID),
			RegionOptStatusContains: []accounttypes.RegionOptStatus{
				accounttypes.RegionOptStatusEnabled, accounttypes.RegionOptStatusEnabledByDefault, accounttypes.RegionOptStatusEnabling,
			},
		})
		var regions []string
		n, err := r.paginate(domain, op, pager.HasMorePages, func() error {
			page, err := pager.NextPage(r.ctx)
			if err != nil {
				return err
			}
			for _, reg := range page.Regions {
				regions = append(regions, aws.ToString(reg.RegionName))
			}
			return nil
		})
		sort.Strings(regions)
		results[i] = perAccount{pages: n, err: err, list: regions}
	})
	var failures []string
	var firstErr error
	pages := 0
	for i, res := range results {
		pages += res.pages
		if res.err != nil {
			failures = append(failures, r.snap.Accounts[i].ID)
			if firstErr == nil {
				firstErr = res.err
			}
			// A per-account record so the evaluator knows this account's
			// region list is unknown rather than empty.
			d := r.failed(domain, res.err, 0, 0, op)
			d.AccountID = r.snap.Accounts[i].ID
			r.record(d)
			continue
		}
		r.snap.Accounts[i].EnabledRegions = res.list
	}
	if firstErr != nil {
		r.opts.Logger.Printf("warning: enabled regions failed for %d account(s) (needs account:ListRegions and trusted access for account.amazonaws.com): %v", len(failures), firstErr)
		if len(failures) == len(r.snap.Accounts) {
			return
		}
	}
	d := r.observed(domain, len(r.snap.Accounts)-len(failures), pages, op)
	if len(failures) > 0 {
		d.Reason = fmt.Sprintf("%d account(s) failed and have their own records", len(failures))
	}
	r.record(d)
}

// notCollected records the domains this collector version does not read.
func (r *run) notCollected() {
	for _, d := range []string{snapshot.DomainOrgTrails, snapshot.DomainConfigAggregator} {
		r.record(snapshot.DomainCoverage{Domain: d, Status: snapshot.CoverageUnsupported, Reason: "not collected by this collector version; add the entries by hand (docs/snapshot.md) or wait for the collector that reads them (ROADMAP.md)"})
	}
}

// controlTower reads the landing zone, the registered OUs (OUs with an
// enabled baseline), the enrolled accounts (child enabled baselines whose
// target is an account) and the controls enabled on each registered OU.
func (r *run) controlTower() {
	client := r.opts.ControlTower
	region := r.opts.ControlTowerRegion
	ops := []string{"controltower:ListLandingZones", "controltower:GetLandingZone", "controltower:ListEnabledBaselines", "controltower:ListEnabledControls", "controlcatalog:GetControl"}
	domain := snapshot.DomainControlTower
	regional := func(d snapshot.DomainCoverage) snapshot.DomainCoverage { d.Region = region; return d }
	if client == nil {
		r.record(regional(r.skipped(domain)))
		r.record(regional(r.skipped(snapshot.DomainEnrolledAccounts)))
		return
	}
	var zones *controltower.ListLandingZonesOutput
	err := r.call(domain, ops[0], func() (err error) {
		zones, err = client.ListLandingZones(r.ctx, &controltower.ListLandingZonesInput{})
		return err
	})
	if err != nil {
		d := r.failed(domain, err, 0, 0, ops[0])
		d.Error += "; the landing zone APIs answer only in the home region, set control_tower.home_region (or --region) accordingly"
		r.record(regional(d))
		r.record(regional(snapshot.DomainCoverage{Domain: snapshot.DomainEnrolledAccounts, Status: snapshot.CoverageError, Error: "not read: the landing zone lookup failed"}))
		return
	}
	if len(zones.LandingZones) == 0 {
		if r.trusted("controltower.amazonaws.com") {
			// An empty answer in the wrong region looks like "no Control
			// Tower"; trusted access says it is in use, so do not believe it.
			msg := fmt.Sprintf("no landing zone answered in %s although trusted access for controltower.amazonaws.com is enabled; the landing zone APIs answer only in the home region, re-run with control_tower.home_region (or --region) set to it", region)
			r.record(regional(snapshot.DomainCoverage{Domain: domain, Status: snapshot.CoverageError, Error: msg, Operations: ops[:1]}))
			r.record(regional(snapshot.DomainCoverage{Domain: snapshot.DomainEnrolledAccounts, Status: snapshot.CoverageError, Error: "not read: the landing zone was not found in " + region}))
			return
		}
		r.record(regional(snapshot.DomainCoverage{Domain: domain, Status: snapshot.CoverageEmpty, Operations: ops[:1], Reason: "no landing zone in " + region + " and no trusted access for controltower.amazonaws.com"}))
		r.record(regional(snapshot.DomainCoverage{Domain: snapshot.DomainEnrolledAccounts, Status: snapshot.CoverageEmpty, Reason: "no landing zone"}))
		return
	}
	arn := aws.ToString(zones.LandingZones[0].Arn)
	ct := &snapshot.ControlTower{LandingZoneARN: arn, HomeRegion: arnRegion(arn), RegisteredOUs: []snapshot.RegisteredOU{}, EnabledControls: []snapshot.EnabledControl{}}
	var lz *controltower.GetLandingZoneOutput
	err = r.call(domain, ops[1], func() (err error) {
		lz, err = client.GetLandingZone(r.ctx, &controltower.GetLandingZoneInput{LandingZoneIdentifier: aws.String(arn)})
		return err
	})
	if err != nil {
		d := r.failed(domain, err, 1, 0, ops[:2]...)
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
	n, err := r.paginate(domain, ops[2], baselines.HasMorePages, func() error {
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
		d := r.failed(domain, err, pages, 1+len(ct.RegisteredOUs), ops[:3]...)
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
		cn, err := r.paginate(domain, ops[3], controls.HasMorePages, func() error {
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
		d := r.failed(domain, controlErr, pages, 1+len(ct.RegisteredOUs)+len(ct.EnabledControls), ops...)
		r.record(regional(d))
		return
	}
	r.record(regional(r.observed(domain, 1+len(ct.RegisteredOUs)+len(ct.EnabledControls), pages, ops...)))
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
	r.mu.Lock()
	if r.controls == nil {
		r.controls = map[string]*controlcatalog.GetControlOutput{}
	}
	out, cached := r.controls[ec.ControlIdentifier]
	r.mu.Unlock()
	if !cached {
		err := r.call(snapshot.DomainControlTower, "controlcatalog:GetControl", func() (err error) {
			out, err = r.opts.ControlCatalog.GetControl(r.ctx, &controlcatalog.GetControlInput{ControlArn: aws.String(ec.ControlIdentifier)})
			return err
		})
		if err != nil {
			r.opts.Logger.Printf("warning: control %s: %v (needs controlcatalog:GetControl)", ec.ControlIdentifier, err)
			out = nil
		}
		r.mu.Lock()
		r.controls[ec.ControlIdentifier] = out
		r.mu.Unlock()
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
// assignments on those accounts, several permission sets at a time.
func (r *run) identityCenter() {
	client := r.opts.SSOAdmin
	region := r.opts.IdentityCenterRegion
	domain := snapshot.DomainIdentityCenter
	ops := []string{"sso:ListInstances", "sso:ListPermissionSets", "sso:DescribePermissionSet", "sso:ListManagedPoliciesInPermissionSet", "sso:ListCustomerManagedPolicyReferencesInPermissionSet",
		"sso:GetInlinePolicyForPermissionSet", "sso:GetPermissionsBoundaryForPermissionSet", "sso:ListAccountsForProvisionedPermissionSet", "sso:ListAccountAssignments", "identitystore:DescribeUser", "identitystore:DescribeGroup"}
	regional := func(d snapshot.DomainCoverage) snapshot.DomainCoverage { d.Region = region; return d }
	if client == nil {
		r.record(regional(r.skipped(domain)))
		return
	}
	var instances *ssoadmin.ListInstancesOutput
	err := r.call(domain, ops[0], func() (err error) {
		instances, err = client.ListInstances(r.ctx, &ssoadmin.ListInstancesInput{})
		return err
	})
	if err != nil {
		d := r.failed(domain, err, 0, 0, ops[0])
		d.Error += "; the instance APIs answer only in the instance's region, set identity_center.region (or --region) accordingly"
		r.record(regional(d))
		return
	}
	if len(instances.Instances) == 0 {
		if r.trusted("sso.amazonaws.com") {
			msg := fmt.Sprintf("no Identity Center instance answered in %s although trusted access for sso.amazonaws.com is enabled; the instance APIs answer only in the instance's region, re-run with identity_center.region (or --region) set to it", region)
			r.record(regional(snapshot.DomainCoverage{Domain: domain, Status: snapshot.CoverageError, Error: msg, Operations: ops[:1]}))
			return
		}
		r.record(regional(snapshot.DomainCoverage{Domain: domain, Status: snapshot.CoverageEmpty, Operations: ops[:1], Reason: "no instance in " + region + " and no trusted access for sso.amazonaws.com"}))
		return
	}
	inst := instances.Instances[0]
	ic := &snapshot.IdentityCenter{
		InstanceARN: aws.ToString(inst.InstanceArn), IdentityStoreID: aws.ToString(inst.IdentityStoreId), Region: region,
		OwnerAccountID: aws.ToString(inst.OwnerAccountId), Name: aws.ToString(inst.Name),
		PermissionSets: []snapshot.PermissionSet{}, Assignments: []snapshot.AccountAssignment{},
	}
	known := map[string]bool{}
	for _, a := range r.snap.Accounts {
		known[a.ID] = true
	}
	instanceARN := aws.String(ic.InstanceARN)
	var setARNs []string
	sets := ssoadmin.NewListPermissionSetsPaginator(client, &ssoadmin.ListPermissionSetsInput{InstanceArn: instanceARN})
	pages, err := r.paginate(domain, ops[1], sets.HasMorePages, func() error {
		page, err := sets.NextPage(r.ctx)
		if err != nil {
			return err
		}
		setARNs = append(setARNs, page.PermissionSets...)
		return nil
	})
	pages++ // ListInstances
	if err != nil {
		r.snap.IdentityCenter = ic
		r.record(regional(r.failed(domain, err, pages, 1, ops...)))
		return
	}
	type setResult struct {
		set         snapshot.PermissionSet
		assignments []snapshot.AccountAssignment
		pages       int
		err         error
	}
	results := make([]setResult, len(setARNs))
	r.parallel(len(setARNs), func(i int) {
		arn := setARNs[i]
		ps, err := r.permissionSet(instanceARN, arn)
		if err != nil {
			results[i] = setResult{err: err}
			return
		}
		res := setResult{}
		accounts := ssoadmin.NewListAccountsForProvisionedPermissionSetPaginator(client, &ssoadmin.ListAccountsForProvisionedPermissionSetInput{InstanceArn: instanceARN, PermissionSetArn: aws.String(arn)})
		an, err := r.paginate(domain, ops[7], accounts.HasMorePages, func() error {
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
				asn, err := r.paginate(domain, ops[8], assignments.HasMorePages, func() error {
					asp, err := assignments.NextPage(r.ctx)
					if err != nil {
						return err
					}
					for _, a := range asp.AccountAssignments {
						kind := string(a.PrincipalType)
						id := aws.ToString(a.PrincipalId)
						res.assignments = append(res.assignments, snapshot.AccountAssignment{
							AccountID: acct, PermissionSetARN: arn, PrincipalType: kind, PrincipalID: id,
							PrincipalName: r.principalName(ic.IdentityStoreID, kind, id),
						})
					}
					return nil
				})
				res.pages += asn
				if err != nil {
					return fmt.Errorf("assignments of %s in %s: %w", ps.Name, acct, err)
				}
			}
			return nil
		})
		res.pages += an
		if err != nil {
			res.err = fmt.Errorf("accounts provisioned with %s: %w", ps.Name, err)
			results[i] = res
			return
		}
		sort.Strings(ps.ProvisionedAccounts)
		res.set = ps
		results[i] = res
	})
	var firstErr error
	for _, res := range results {
		pages += res.pages
		if res.err != nil {
			if firstErr == nil {
				firstErr = res.err
			}
			continue
		}
		ic.PermissionSets = append(ic.PermissionSets, res.set)
		ic.Assignments = append(ic.Assignments, res.assignments...)
	}
	r.snap.IdentityCenter = ic
	items := 1 + len(ic.PermissionSets) + len(ic.Assignments)
	if firstErr != nil {
		r.record(regional(r.failed(domain, firstErr, pages, items, ops...)))
		return
	}
	r.record(regional(r.observed(domain, items, pages, ops...)))
}

// permissionSet describes one permission set: name, session, policies and
// boundary.
func (r *run) permissionSet(instanceARN *string, arn string) (snapshot.PermissionSet, error) {
	client := r.opts.SSOAdmin
	domain := snapshot.DomainIdentityCenter
	i, p := instanceARN, aws.String(arn)
	var desc *ssoadmin.DescribePermissionSetOutput
	err := r.call(domain, "sso:DescribePermissionSet", func() (err error) {
		desc, err = client.DescribePermissionSet(r.ctx, &ssoadmin.DescribePermissionSetInput{InstanceArn: i, PermissionSetArn: p})
		return err
	})
	if err != nil {
		return snapshot.PermissionSet{}, fmt.Errorf("describe permission set %s: %w", arn, err)
	}
	ps := snapshot.PermissionSet{ARN: arn}
	if d := desc.PermissionSet; d != nil {
		ps.Name, ps.Description, ps.SessionDuration = aws.ToString(d.Name), aws.ToString(d.Description), aws.ToString(d.SessionDuration)
	}
	managed := ssoadmin.NewListManagedPoliciesInPermissionSetPaginator(client, &ssoadmin.ListManagedPoliciesInPermissionSetInput{InstanceArn: i, PermissionSetArn: p})
	if _, err := r.paginate(domain, "sso:ListManagedPoliciesInPermissionSet", managed.HasMorePages, func() error {
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
	if _, err := r.paginate(domain, "sso:ListCustomerManagedPolicyReferencesInPermissionSet", customer.HasMorePages, func() error {
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
	var inline *ssoadmin.GetInlinePolicyForPermissionSetOutput
	err = r.call(domain, "sso:GetInlinePolicyForPermissionSet", func() (err error) {
		inline, err = client.GetInlinePolicyForPermissionSet(r.ctx, &ssoadmin.GetInlinePolicyForPermissionSetInput{InstanceArn: i, PermissionSetArn: p})
		return err
	})
	if err != nil {
		return ps, fmt.Errorf("inline policy of %s: %w", ps.Name, err)
	}
	if doc := aws.ToString(inline.InlinePolicy); doc != "" {
		ps.InlinePolicy = json.RawMessage(doc)
	}
	var boundary *ssoadmin.GetPermissionsBoundaryForPermissionSetOutput
	err = r.call(domain, "sso:GetPermissionsBoundaryForPermissionSet", func() (err error) {
		boundary, err = client.GetPermissionsBoundaryForPermissionSet(r.ctx, &ssoadmin.GetPermissionsBoundaryForPermissionSetInput{InstanceArn: i, PermissionSetArn: p})
		return err
	})
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
	key := kind + ":" + id
	r.mu.Lock()
	if r.principals == nil {
		r.principals = map[string]string{}
	}
	name, cached := r.principals[key]
	r.mu.Unlock()
	if cached {
		return name
	}
	var err error
	switch kind {
	case snapshot.PrincipalUser:
		var out *identitystore.DescribeUserOutput
		err = r.call(snapshot.DomainIdentityCenter, "identitystore:DescribeUser", func() (err error) {
			out, err = r.opts.IdentityStore.DescribeUser(r.ctx, &identitystore.DescribeUserInput{IdentityStoreId: aws.String(storeID), UserId: aws.String(id)})
			return err
		})
		if err == nil {
			name = aws.ToString(out.UserName)
			if name == "" {
				name = aws.ToString(out.DisplayName)
			}
		}
	case snapshot.PrincipalGroup:
		var out *identitystore.DescribeGroupOutput
		err = r.call(snapshot.DomainIdentityCenter, "identitystore:DescribeGroup", func() (err error) {
			out, err = r.opts.IdentityStore.DescribeGroup(r.ctx, &identitystore.DescribeGroupInput{IdentityStoreId: aws.String(storeID), GroupId: aws.String(id)})
			return err
		})
		if err == nil {
			name = aws.ToString(out.DisplayName)
		}
	}
	if err != nil {
		r.opts.Logger.Printf("warning: %s %s could not be resolved: %v (needs identitystore:DescribeUser and DescribeGroup)", strings.ToLower(kind), id, err)
	}
	r.mu.Lock()
	r.principals[key] = name
	r.mu.Unlock()
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

func containsString(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
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
	if len(s.StackSets) > 0 {
		instances := 0
		for _, ss := range s.StackSets {
			instances += len(ss.Instances)
		}
		out += fmt.Sprintf("; %d StackSets with %d stack instances", len(s.StackSets), instances)
	}
	if len(s.Workloads) > 0 {
		stacks, resources, policies := 0, 0, 0
		for _, w := range s.Workloads {
			stacks += len(w.Stacks)
			resources += len(w.Resources)
			policies += len(w.ResourcePolicies)
		}
		out += fmt.Sprintf("; workload inventory of %d account(s): %d stacks, %d sampled resources, %d policies tied to organization identity", len(s.Workloads), stacks, resources, policies)
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
