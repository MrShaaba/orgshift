package collector

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/organizations"
	"github.com/aws/aws-sdk-go-v2/service/ram"

	"github.com/MrShaaba/orgshift/internal/snapshot"
)

// countingOrgs counts the ListPolicies calls so a resumed run can prove it
// did not read the policies again.
type countingOrgs struct {
	fakeOrgs
	policies *int32
}

func (c countingOrgs) ListPolicies(ctx context.Context, in *organizations.ListPoliciesInput, opts ...func(*organizations.Options)) (*organizations.ListPoliciesOutput, error) {
	atomic.AddInt32(c.policies, 1)
	return c.fakeOrgs.ListPolicies(ctx, in, opts...)
}

func TestResumeSkipsCompletedStepsAndRetriesFailedOnes(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "snap.checkpoint.json")
	var policies int32
	now := time.Date(2026, 11, 2, 10, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	// First run: RAM is denied, everything else completes.
	first, err := Collect(context.Background(), Options{Organizations: countingOrgs{policies: &policies}, RAM: []RAMAPI{fakeRAMDenied{}}, Checkpoint: path, Version: "test", Region: "us-east-1", Now: clock})
	if err != nil {
		t.Fatal(err)
	}
	if record(t, first, snapshot.DomainResourceShares).Status != snapshot.CoverageAccessDenied {
		t.Fatal("the first run should have been denied RAM")
	}
	cp, err := LoadCheckpoint(path)
	if err != nil {
		t.Fatalf("the checkpoint must be kept while a domain is incomplete: %v", err)
	}
	if cp.OrganizationID != first.Organization.ID || cp.Region != "us-east-1" || cp.CollectorVersion != "test" || cp.WrittenAt != "2026-11-02T10:00:00Z" {
		t.Errorf("checkpoint header: %+v", cp)
	}
	if !cp.completed("tree") || !cp.completed("policies.scp") || cp.completed("resource_shares") || cp.completed("not_collected") {
		t.Errorf("completed steps: %v", cp.Completed)
	}
	if int(policies) != 1 {
		t.Fatalf("one ListPolicies call expected for the enabled type, got %d", policies)
	}

	// Second run, an hour later, with RAM granted: the shares are read, the
	// policies are restored, and the checkpoint goes away.
	now = now.Add(time.Hour)
	second, err := Collect(context.Background(), Options{Organizations: countingOrgs{policies: &policies}, RAM: []RAMAPI{fakeRAM{}}, Checkpoint: path, Version: "test", Region: "us-east-1", Now: clock})
	if err != nil {
		t.Fatal(err)
	}
	if int(policies) != 1 {
		t.Errorf("the resumed run must not list policies again (calls: %d)", policies)
	}
	if len(second.Policies) != 1 || len(second.Accounts) != 2 || len(second.ResourceShares) != 1 {
		t.Errorf("resumed snapshot should carry the restored policies and tree and the new shares: %d policies, %d accounts, %d shares", len(second.Policies), len(second.Accounts), len(second.ResourceShares))
	}
	if rec := record(t, second, snapshot.DomainPoliciesSCP); rec.Status != snapshot.CoverageObserved || !strings.Contains(rec.Reason, "restored from the checkpoint written at 2026-11-02T10:00:00Z") || rec.CollectedAt != "2026-11-02T10:00:00Z" {
		t.Errorf("restored record should say so and keep its time: %+v", rec)
	}
	if rec := record(t, second, snapshot.DomainResourceShares); rec.Status != snapshot.CoverageObserved || rec.CollectedAt != "2026-11-02T11:00:00Z" || strings.Contains(rec.Reason, "checkpoint") {
		t.Errorf("re-read record: %+v", rec)
	}
	if rec := record(t, second, snapshot.DomainOrganization); strings.Contains(rec.Reason, "checkpoint") {
		t.Errorf("the organization is always re-read: %+v", rec)
	}
	if second.GeneratedAt != "2026-11-02T11:00:00Z" {
		t.Errorf("generated_at is the final run's time: %s", second.GeneratedAt)
	}
	for _, rec := range second.Coverage.Domains {
		switch rec.Status {
		case snapshot.CoveragePartial, snapshot.CoverageAccessDenied, snapshot.CoverageError:
			t.Errorf("no domain should have failed after the resumed run: %+v", rec)
		}
	}
	if err := second.Validate(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the checkpoint should be removed once every domain is complete: %v", err)
	}
	// A run without a checkpoint path never writes one.
	if _, err := Collect(context.Background(), Options{Organizations: fakeOrgs{}}); err != nil {
		t.Fatal(err)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Errorf("unexpected files: %v", entries)
	}
}

func TestResumeRefusesForeignOrStaleCheckpoints(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cp.json")
	now := time.Date(2026, 11, 2, 10, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	var policies int32
	if _, err := Collect(context.Background(), Options{Organizations: countingOrgs{policies: &policies}, RAM: []RAMAPI{fakeRAMDenied{}}, Checkpoint: path, Version: "test", Region: "us-east-1", Now: clock}); err != nil {
		t.Fatal(err)
	}
	cases := map[string]Options{
		"other build":  {Version: "other", Region: "us-east-1"},
		"other region": {Version: "test", Region: "eu-west-1"},
		"too old":      {Version: "test", Region: "us-east-1", CheckpointMaxAge: time.Minute, Now: func() time.Time { return now.Add(2 * time.Hour) }},
	}
	for name, o := range cases {
		policies = 0
		o.Organizations = countingOrgs{policies: &policies}
		o.RAM = []RAMAPI{fakeRAMDenied{}}
		o.Checkpoint = path
		if o.Now == nil {
			o.Now = clock
		}
		if _, err := Collect(context.Background(), o); err != nil {
			t.Fatal(err)
		}
		if policies != 1 {
			t.Errorf("%s: the checkpoint must be ignored and policies read again (calls: %d)", name, policies)
		}
	}
	// A checkpoint for another organization is ignored too.
	cp, err := LoadCheckpoint(path)
	if err != nil {
		t.Fatal(err)
	}
	cp.OrganizationID = "o-other"
	if err := cp.Save(path); err != nil {
		t.Fatal(err)
	}
	policies = 0
	if _, err := Collect(context.Background(), Options{Organizations: countingOrgs{policies: &policies}, Checkpoint: path, Version: "test", Region: "us-east-1", Now: clock}); err != nil || policies != 1 {
		t.Errorf("foreign organization: err=%v calls=%d", err, policies)
	}
	// Garbage is reported, not fatal.
	if err := os.WriteFile(path, []byte("{"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Collect(context.Background(), Options{Organizations: fakeOrgs{}, Checkpoint: path, Version: "test"}); err != nil {
		t.Errorf("a broken checkpoint must not fail the run: %v", err)
	}
	if _, err := LoadCheckpoint(filepath.Join(dir, "missing.json")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("missing checkpoint: %v", err)
	}
}

// fakeRAMFlaky fails the first GetResourceShares call of a process and
// answers afterwards, so a partial checkpoint is retried.
type fakeRAMFlaky struct {
	fakeRAM
	calls *int32
}

func (f fakeRAMFlaky) GetResourceShares(ctx context.Context, in *ram.GetResourceSharesInput, opts ...func(*ram.Options)) (*ram.GetResourceSharesOutput, error) {
	if atomic.AddInt32(f.calls, 1) == 1 {
		return nil, errors.New("connection reset")
	}
	return f.fakeRAM.GetResourceShares(ctx, in, opts...)
}

func TestKeepCheckpointAndResetBeforeRerun(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cp.json")
	var calls int32
	opts := Options{Organizations: fakeOrgs{}, RAM: []RAMAPI{fakeRAMFlaky{calls: &calls}}, Checkpoint: path, Version: "test", KeepCheckpoint: true}
	if snap, err := Collect(context.Background(), opts); err != nil || record(t, snap, snapshot.DomainResourceShares).Status != snapshot.CoverageError {
		t.Fatalf("first run: %v", err)
	}
	snap, err := Collect(context.Background(), opts)
	if err != nil {
		t.Fatal(err)
	}
	if len(snap.ResourceShares) != 1 || record(t, snap, snapshot.DomainResourceShares).Status != snapshot.CoverageObserved {
		t.Errorf("the failed step is rerun and its output replaced, not duplicated: %+v", snap.ResourceShares)
	}
	if recs := snap.DomainRecords(snapshot.DomainResourceShares); len(recs) != 1 {
		t.Errorf("one record for the rerun step, got %d", len(recs))
	}
	if _, err := os.Stat(path); err != nil {
		t.Errorf("KeepCheckpoint should leave the file: %v", err)
	}
}
