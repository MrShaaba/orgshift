package collector

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/aws-sdk-go-v2/service/account"
	accounttypes "github.com/aws/aws-sdk-go-v2/service/account/types"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	orgtypes "github.com/aws/aws-sdk-go-v2/service/organizations/types"
	"github.com/aws/smithy-go"
	smithyhttp "github.com/aws/smithy-go/transport/http"

	"github.com/MrShaaba/orgshift/internal/snapshot"
)

func throttle() error {
	return &smithy.GenericAPIError{Code: "ThrottlingException", Message: "Rate exceeded"}
}

// recordingSleeper collects the delays instead of waiting.
type recordingSleeper struct {
	mu     sync.Mutex
	delays []time.Duration
}

func (s *recordingSleeper) sleep(ctx context.Context, d time.Duration) error {
	s.mu.Lock()
	s.delays = append(s.delays, d)
	s.mu.Unlock()
	return ctx.Err()
}

func TestRetryBacksOffOnThrottlingOnly(t *testing.T) {
	sl := &recordingSleeper{}
	opts := RetryOptions{Attempts: 5, Base: 100 * time.Millisecond, Cap: time.Second}
	calls := 0
	retries, err := Retry(context.Background(), opts, sl.sleep, func() error {
		calls++
		if calls < 4 {
			return throttle()
		}
		return nil
	}, nil)
	if err != nil || retries != 3 || calls != 4 || len(sl.delays) != 3 {
		t.Fatalf("retries=%d calls=%d delays=%v err=%v", retries, calls, sl.delays, err)
	}
	for i, d := range sl.delays {
		max := opts.Base << uint(i)
		if d < 0 || d > max {
			t.Errorf("delay %d = %s outside [0, %s]", i, d, max)
		}
	}
	// A final error that does not throttle is returned at once.
	sl = &recordingSleeper{}
	calls = 0
	final := errors.New("boom")
	if retries, err := Retry(context.Background(), opts, sl.sleep, func() error { calls++; return final }, nil); err != final || retries != 0 || calls != 1 || len(sl.delays) != 0 {
		t.Errorf("non-throttling error must not be retried: retries=%d calls=%d err=%v", retries, calls, err)
	}
	// Attempts run out: the last throttling error comes back.
	calls = 0
	if retries, err := Retry(context.Background(), RetryOptions{Attempts: 3}, sl.sleep, func() error { calls++; return throttle() }, nil); !Throttled(err) || retries != 2 || calls != 3 {
		t.Errorf("attempts: retries=%d calls=%d err=%v", retries, calls, err)
	}
	// A cancelled context stops the loop and reports both errors.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	calls = 0
	if _, err := Retry(ctx, opts, sl.sleep, func() error { calls++; return throttle() }, nil); err == nil || calls != 1 {
		t.Errorf("cancelled context: calls=%d err=%v", calls, err)
	}
}

func TestBackoffIsCappedWithFullJitter(t *testing.T) {
	o := RetryOptions{Base: time.Second, Cap: 10 * time.Second}
	if d := backoffDelay(1, o, 1); d != time.Second {
		t.Errorf("first delay at jitter 1 = %s", d)
	}
	if d := backoffDelay(3, o, 0.5); d != 2*time.Second {
		t.Errorf("third delay at jitter 0.5 = %s", d)
	}
	if d := backoffDelay(30, o, 1); d != 10*time.Second {
		t.Errorf("capped delay = %s", d)
	}
	if d := backoffDelay(2, o, 0); d != 0 {
		t.Errorf("jitter 0 gives 0, got %s", d)
	}
}

func TestThrottledRecognisesCodesAndStatuses(t *testing.T) {
	cases := map[string]struct {
		err  error
		want bool
	}{
		"throttling code": {throttle(), true},
		"too many":        {&smithy.GenericAPIError{Code: "TooManyRequestsException"}, true},
		"denied":          {denied("x"), false},
		"plain":           {errors.New("dial tcp"), false},
		"http 429":        {httpError(429), true},
		"http 503":        {httpError(503), true},
		"http 403":        {httpError(403), false},
		"nil":             {nil, false},
	}
	for name, c := range cases {
		if got := Throttled(c.err); got != c.want {
			t.Errorf("%s: Throttled = %t", name, got)
		}
	}
}

// fakeOrgsThrottled throttles ListRoots twice before answering.
type fakeOrgsThrottled struct {
	fakeOrgs
	calls *int32
}

func (f fakeOrgsThrottled) ListRoots(ctx context.Context, in *organizations.ListRootsInput, opts ...func(*organizations.Options)) (*organizations.ListRootsOutput, error) {
	if atomic.AddInt32(f.calls, 1) <= 2 {
		return nil, throttle()
	}
	return f.fakeOrgs.ListRoots(ctx, in, opts...)
}

func TestCollectorRetriesThrottledCallsAndRecordsThem(t *testing.T) {
	var calls int32
	sl := &recordingSleeper{}
	snap, err := Collect(context.Background(), Options{Organizations: fakeOrgsThrottled{calls: &calls}, Sleep: sl.sleep, Retry: RetryOptions{Attempts: 4, Base: time.Millisecond, Cap: time.Millisecond}})
	if err != nil {
		t.Fatalf("throttling must be retried, not fatal: %v", err)
	}
	if calls != 3 || len(sl.delays) != 2 {
		t.Errorf("ListRoots calls=%d delays=%v", calls, sl.delays)
	}
	if rec := record(t, snap, snapshot.DomainTree); rec.Status != snapshot.CoverageObserved || rec.Retries != 2 {
		t.Errorf("tree record should count the retries: %+v", rec)
	}
	if rec := record(t, snap, snapshot.DomainOrganization); rec.Retries != 0 {
		t.Errorf("retries are attributed to their own domain: %+v", rec)
	}
	// With too few attempts the throttling error ends the domain, and the
	// tree is required, so the collection fails.
	calls = 0
	if _, err := Collect(context.Background(), Options{Organizations: fakeOrgsThrottled{calls: &calls}, Sleep: sl.sleep, Retry: RetryOptions{Attempts: 2}}); err == nil || !Throttled(errors.Unwrap(errors.Unwrap(err))) && !Throttled(err) {
		t.Errorf("expected the throttling error, got %v", err)
	}
}

// fakeAccountSlow records how many ListRegions calls run at the same time.
type fakeAccountSlow struct {
	running, peak *int32
}

func (f fakeAccountSlow) ListRegions(_ context.Context, in *account.ListRegionsInput, _ ...func(*account.Options)) (*account.ListRegionsOutput, error) {
	n := atomic.AddInt32(f.running, 1)
	for {
		p := atomic.LoadInt32(f.peak)
		if n <= p || atomic.CompareAndSwapInt32(f.peak, p, n) {
			break
		}
	}
	time.Sleep(5 * time.Millisecond)
	atomic.AddInt32(f.running, -1)
	return &account.ListRegionsOutput{Regions: []accounttypes.Region{{RegionName: aws.String("eu-west-1")}, {RegionName: in.AccountId}}}, nil
}

// fakeOrgsMany has eight accounts under the root.
type fakeOrgsMany struct{ fakeOrgs }

func (fakeOrgsMany) ListOrganizationalUnitsForParent(context.Context, *organizations.ListOrganizationalUnitsForParentInput, ...func(*organizations.Options)) (*organizations.ListOrganizationalUnitsForParentOutput, error) {
	return &organizations.ListOrganizationalUnitsForParentOutput{}, nil
}

func (fakeOrgsMany) ListTargetsForPolicy(context.Context, *organizations.ListTargetsForPolicyInput, ...func(*organizations.Options)) (*organizations.ListTargetsForPolicyOutput, error) {
	return &organizations.ListTargetsForPolicyOutput{Targets: []orgtypes.PolicyTargetSummary{{TargetId: aws.String("r-fake")}}}, nil
}

func (fakeOrgsMany) ListAccountsForParent(context.Context, *organizations.ListAccountsForParentInput, ...func(*organizations.Options)) (*organizations.ListAccountsForParentOutput, error) {
	out := &organizations.ListAccountsForParentOutput{}
	for i := 0; i < 8; i++ {
		id := "11111111111" + string(rune('0'+i))
		out.Accounts = append(out.Accounts, orgtypes.Account{Id: aws.String(id), Name: aws.String(id), Status: orgtypes.AccountStatusActive})
	}
	return out, nil
}

func TestConcurrencyIsBoundedAndOrderIsStable(t *testing.T) {
	for _, workers := range []int{1, 3} {
		var running, peak int32
		snap, err := Collect(context.Background(), Options{Organizations: fakeOrgsMany{}, Account: fakeAccountSlow{&running, &peak}, Concurrency: workers})
		if err != nil {
			t.Fatal(err)
		}
		if int(peak) > workers {
			t.Errorf("concurrency %d: %d calls ran at once", workers, peak)
		}
		if workers > 1 && peak < 2 {
			t.Errorf("concurrency %d: calls never overlapped (peak %d)", workers, peak)
		}
		for i, a := range snap.Accounts {
			if a.ID != "11111111111"+string(rune('0'+i)) || len(a.EnabledRegions) != 2 || a.EnabledRegions[0] != a.ID {
				t.Errorf("account %d out of order or regions wrong: %+v", i, a)
			}
		}
		if rec := record(t, snap, snapshot.DomainEnabledRegions); rec.Status != snapshot.CoverageObserved || rec.Items != 8 {
			t.Errorf("regions record: %+v", rec)
		}
	}
}

// httpError builds the SDK's HTTP response error for a status code.
func httpError(status int) error {
	return &awshttp.ResponseError{ResponseError: &smithyhttp.ResponseError{Response: &smithyhttp.Response{Response: &http.Response{StatusCode: status}}, Err: errors.New("http error")}, RequestID: "req"}
}
