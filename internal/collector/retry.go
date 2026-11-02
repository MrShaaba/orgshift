package collector

import (
	"context"
	"errors"
	"math"
	"math/rand"
	"time"

	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/smithy-go"
)

// RetryOptions bound the collector's own retry loop around every API call.
// The SDK clients retry too (adaptive mode, see the CLI); this loop sits
// above them so a call the SDK gave up on after a burst of throttling is
// tried again after a longer, jittered pause instead of ending the domain.
type RetryOptions struct {
	// Attempts is the maximum number of attempts per call, including the
	// first. Zero means DefaultRetry.Attempts.
	Attempts int
	// Base is the delay before the second attempt; it doubles per attempt
	// with full jitter and never exceeds Cap.
	Base time.Duration
	Cap  time.Duration
}

// DefaultRetry is used when Options.Retry is zero.
var DefaultRetry = RetryOptions{Attempts: 5, Base: 500 * time.Millisecond, Cap: 20 * time.Second}

func (o RetryOptions) withDefaults() RetryOptions {
	if o.Attempts <= 0 {
		o.Attempts = DefaultRetry.Attempts
	}
	if o.Base <= 0 {
		o.Base = DefaultRetry.Base
	}
	if o.Cap <= 0 {
		o.Cap = DefaultRetry.Cap
	}
	return o
}

// Sleeper waits for a delay or until the context ends. Tests inject one.
type Sleeper func(ctx context.Context, d time.Duration) error

// sleepWithContext is the default Sleeper.
func sleepWithContext(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// throttleCodes are the error codes AWS services return when a caller is
// rate-limited.
var throttleCodes = map[string]bool{
	"ThrottlingException": true, "Throttling": true, "ThrottledException": true, "RequestThrottledException": true,
	"TooManyRequestsException": true, "RequestLimitExceeded": true, "RequestThrottled": true, "SlowDown": true,
	"ProvisionedThroughputExceededException": true, "EC2ThrottledException": true, "LimitExceededException": false,
}

// Throttled reports whether an error says the caller was rate-limited (a
// throttling error code or HTTP 429) or hit a transient server error (HTTP
// 500, 502, 503, 504). Those are retried; everything else is final.
func Throttled(err error) bool {
	if err == nil {
		return false
	}
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) && throttleCodes[apiErr.ErrorCode()] {
		return true
	}
	var re *awshttp.ResponseError
	if errors.As(err, &re) {
		switch re.HTTPStatusCode() {
		case 429, 500, 502, 503, 504:
			return true
		}
	}
	return false
}

// backoffDelay is the full-jitter exponential delay before attempt n+1
// (n starting at 1): random in [0, min(cap, base*2^(n-1))].
func backoffDelay(attempt int, o RetryOptions, rnd float64) time.Duration {
	exp := float64(o.Base) * math.Pow(2, float64(attempt-1))
	if exp > float64(o.Cap) || math.IsInf(exp, 0) {
		exp = float64(o.Cap)
	}
	return time.Duration(rnd * exp)
}

// Retry calls fn until it succeeds, returns a non-throttling error, the
// attempts run out or the context ends. It returns the number of retries
// performed (attempts minus one) and the final error. onRetry, if set, is
// told about every retry before the pause.
func Retry(ctx context.Context, o RetryOptions, sleep Sleeper, fn func() error, onRetry func(attempt int, delay time.Duration, err error)) (int, error) {
	o = o.withDefaults()
	if sleep == nil {
		sleep = sleepWithContext
	}
	for attempt := 1; ; attempt++ {
		err := fn()
		if err == nil || !Throttled(err) || attempt >= o.Attempts {
			return attempt - 1, err
		}
		if ctx.Err() != nil {
			return attempt - 1, err
		}
		delay := backoffDelay(attempt, o, rand.Float64())
		if onRetry != nil {
			onRetry(attempt, delay, err)
		}
		if serr := sleep(ctx, delay); serr != nil {
			return attempt - 1, errors.Join(err, serr)
		}
	}
}
