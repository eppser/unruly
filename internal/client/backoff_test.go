package client

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// A 429 is the target asking to be left alone for a moment, and the scanner
// used to answer it by asking again immediately.
//
// Bounded only by the steady rate limiter, the retry budget was spent on
// responses that were never going to succeed, and the surface ended up
// reported as unresolved anyway. It matters most where this tool is least
// welcome: pointed at infrastructure nobody involved owns, ignoring an
// explicit slow-down request is the difference between measurement and
// nuisance.
func TestRetryAfterIsHonoured(t *testing.T) {
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hits.Add(1) == 1 {
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := New(Options{BaseURL: srv.URL, AnonKey: "k", RestPrefix: "/", Retries: 2})
	start := time.Now()
	resp := c.Get(context.Background(), srv.URL+"/x", nil)
	waited := time.Since(start)

	if resp.Status != http.StatusOK {
		t.Fatalf("status %d after retry, want 200", resp.Status)
	}
	if waited < 900*time.Millisecond {
		t.Errorf("retried after %v; the target asked for 1 second and was ignored", waited)
	}
	if waited > 5*time.Second {
		t.Errorf("waited %v for a 1 second Retry-After", waited)
	}
}

// An absurd Retry-After must not hang the scan. "Come back in an hour" is not
// a request a scan can usefully wait out; reporting the surface as unassessed
// is the honest answer.
func TestRetryAfterIsCapped(t *testing.T) {
	if got := retryDelay(0, http.Header{"Retry-After": []string{"3600"}}); got > 15*time.Second {
		t.Errorf("delay %v: a server asking for an hour would stall the scan", got)
	}
	// The HTTP-date form is equally valid and equally capped.
	future := time.Now().Add(2 * time.Hour).UTC().Format(http.TimeFormat)
	if got := retryDelay(0, http.Header{"Retry-After": []string{future}}); got > 15*time.Second {
		t.Errorf("delay %v for an HTTP-date Retry-After", got)
	}
	// A date in the past means "now".
	past := time.Now().Add(-time.Hour).UTC().Format(http.TimeFormat)
	if got := retryDelay(0, http.Header{"Retry-After": []string{past}}); got != 0 {
		t.Errorf("delay %v for a Retry-After already elapsed, want 0", got)
	}
}

// Without a header, back off exponentially rather than not at all.
func TestBackoffGrows(t *testing.T) {
	first, second := retryDelay(0, nil), retryDelay(1, nil)
	if first <= 0 {
		t.Error("no wait at all between retries")
	}
	if second <= first {
		t.Errorf("backoff does not grow: %v then %v", first, second)
	}
}

// Cancellation must not be swallowed by a backoff. Otherwise Ctrl-C costs
// fifteen seconds per in-flight request.
func TestBackoffRespectsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	if sleepCtx(ctx, 10*time.Second) {
		t.Error("sleepCtx reported success on a cancelled context")
	}
	if d := time.Since(start); d > time.Second {
		t.Errorf("cancelled backoff still waited %v", d)
	}
}
