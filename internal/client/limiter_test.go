package client

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// -rate-limit is a courtesy control: it exists so an operator can be gentle
// with infrastructure that is not theirs, or that is shared. It is only worth
// having if the number the operator types is the number of requests per second
// the target actually receives.
//
// TestSharedLimiterPacesRequests already covers the limiter PRIMITIVE by
// calling Wait in a loop. This covers something the primitive cannot: that a
// request issued through the client actually reaches Wait at all. The
// difference is not academic -- vocabulary harvesting built its own
// http.Client, never called Wait, and was exempt from -rate-limit entirely
// while the primitive's own test passed.

func TestClientRequestsGoThroughTheLimiter(t *testing.T) {
	var served int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&served, 1)
		w.Header().Set("Content-Range", "0-0/1")
		_, _ = w.Write([]byte(`[{"id":1}]`))
	}))
	t.Cleanup(srv.Close)

	const rps, total = 10, 25
	c := New(Options{
		ProjectRef: "x", BaseURL: srv.URL, RestPrefix: "/", AnonKey: "k",
		Concurrency: 16, RateLimit: rps, Retries: 1,
	})

	start := time.Now()
	names := make([]string, total)
	for i := range names {
		names[i] = "t"
	}
	Map(context.Background(), 16, names, func(ctx context.Context, n string) int {
		return c.Get(ctx, c.RestURL(n), nil).Status
	})
	elapsed := time.Since(start)

	if got := atomic.LoadInt64(&served); got != total {
		t.Fatalf("server saw %d requests, want %d", got, total)
	}
	// The bucket starts full, so the first rps requests are free and the rest
	// are paced. Anything faster means the limiter is not binding.
	min := time.Duration(float64(total-rps)/float64(rps)*float64(time.Second)) - 200*time.Millisecond
	if elapsed < min {
		t.Errorf("%d requests at %d rps finished in %s, faster than the %s floor; "+
			"the limiter is not binding and -rate-limit is decorative",
			total, rps, elapsed.Round(time.Millisecond), min)
	}
	t.Logf("%d requests at %d rps took %s", total, rps, elapsed.Round(time.Millisecond))
}
