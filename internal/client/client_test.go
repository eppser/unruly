package client

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// The retry policy is a correctness rule, not a robustness nicety: a 4xx is a
// REAL ANSWER that the classifiers depend on. Retrying a 401 or a 404 would
// waste requests and, worse, invite the temptation to treat a retried failure
// as inconclusive. Only 5xx and 429 mean "ask again".
func TestRetriesOnlyTransientStatuses(t *testing.T) {
	cases := []struct {
		status       string
		code         int
		wantAttempts int
	}{
		{"401 is a real answer", http.StatusUnauthorized, 1},
		{"403 is a real answer", http.StatusForbidden, 1},
		{"404 is a real answer", http.StatusNotFound, 1},
		{"400 is a real answer", http.StatusBadRequest, 1},
		{"409 is a real answer", http.StatusConflict, 1},
		{"500 is transient", http.StatusInternalServerError, 3},
		{"503 is transient", http.StatusServiceUnavailable, 3},
		{"429 is transient", http.StatusTooManyRequests, 3},
	}
	for _, tc := range cases {
		t.Run(tc.status, func(t *testing.T) {
			var hits int64
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				atomic.AddInt64(&hits, 1)
				w.WriteHeader(tc.code)
			}))
			defer srv.Close()

			c := New(Options{BaseURL: srv.URL, RestPrefix: "/", AnonKey: "k", Retries: 2})
			c.Get(context.Background(), srv.URL, nil)

			if got := atomic.LoadInt64(&hits); got != int64(tc.wantAttempts) {
				t.Errorf("HTTP %d produced %d attempts, want %d", tc.code, got, tc.wantAttempts)
			}
		})
	}
}

// A response that arrived is not a lost request, whatever its status. Counting
// a 404 as a loss would make every enumeration scan look degraded, and the
// degraded signal would stop meaning anything.
func TestLossCounterCountsOnlyMissingAnswers(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	c := New(Options{BaseURL: srv.URL, RestPrefix: "/", AnonKey: "k"})
	for i := 0; i < 5; i++ {
		c.Get(context.Background(), srv.URL, nil)
	}
	sent, failed := c.Stats()
	if sent != 5 || failed != 0 {
		t.Errorf("5 answered 404s: got sent=%d failed=%d, want 5 and 0", sent, failed)
	}
	srv.Close()

	// Now nothing is listening: these are genuine losses.
	for i := 0; i < 3; i++ {
		c.Get(context.Background(), srv.URL, nil)
	}
	sent, failed = c.Stats()
	if failed != 3 {
		t.Errorf("3 unreachable requests: got failed=%d, want 3", failed)
	}
	if sent < 8 {
		t.Errorf("sent should count attempts too, got %d", sent)
	}
}

// The mount path differs between the managed product (Kong at /rest/v1) and a
// bare self-hosted PostgREST (the root). Both must be expressible, and the
// forms a user is likely to type must normalise to the same thing.
func TestRestPrefixNormalisation(t *testing.T) {
	cases := map[string]string{
		"":          "https://x/rest/v1/things",
		"/rest/v1":  "https://x/rest/v1/things",
		"rest/v1":   "https://x/rest/v1/things",
		"/rest/v1/": "https://x/rest/v1/things",
		"/":         "https://x/things",
	}
	for prefix, want := range cases {
		c := New(Options{BaseURL: "https://x", RestPrefix: prefix, AnonKey: "k"})
		if got := c.RestURL("things"); got != want {
			t.Errorf("prefix %q -> %q, want %q", prefix, got, want)
		}
	}
}

// Map must return results in INPUT order regardless of completion order. This
// is what makes a concurrent scan deterministic, so it is asserted with work
// that finishes in deliberately reversed order.
func TestMapPreservesInputOrder(t *testing.T) {
	in := []int{0, 1, 2, 3, 4, 5, 6, 7}
	out := Map(context.Background(), 8, in, func(ctx context.Context, n int) int {
		// Later items finish first.
		time.Sleep(time.Duration(len(in)-n) * 2 * time.Millisecond)
		return n * 10
	})
	for i, got := range out {
		if got != i*10 {
			t.Fatalf("index %d holds %d: results are in completion order, not input order", i, got)
		}
	}
}

// Bounded concurrency is a courtesy to the target as much as a performance
// choice: past the measured saturation point throughput collapses for everyone.
func TestMapRespectsConcurrencyLimit(t *testing.T) {
	var inFlight, peak int64
	items := make([]int, 100)
	Map(context.Background(), 4, items, func(ctx context.Context, _ int) int {
		n := atomic.AddInt64(&inFlight, 1)
		for {
			p := atomic.LoadInt64(&peak)
			if n <= p || atomic.CompareAndSwapInt64(&peak, p, n) {
				break
			}
		}
		time.Sleep(2 * time.Millisecond)
		atomic.AddInt64(&inFlight, -1)
		return 0
	})
	if peak > 4 {
		t.Errorf("concurrency limit of 4 exceeded: peak was %d", peak)
	}
}

// The replayable command must never carry the live credential: reports are
// meant to be shareable.
func TestCurlLineRedactsTheKey(t *testing.T) {
	line := curlLine("GET", "https://x/things", map[string]string{"Prefer": "count=exact"}, nil)
	if want := "$SUPABASE_ANON_KEY"; !contains(line, want) {
		t.Errorf("the command should reference %s, got %s", want, line)
	}
	if contains(line, "eyJ") {
		t.Errorf("the command embeds a credential: %s", line)
	}
	// Header order must be stable or evidence would differ between runs.
	again := curlLine("GET", "https://x/things", map[string]string{"Prefer": "count=exact"}, nil)
	if line != again {
		t.Error("curl line is not deterministic")
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

// -rl is a promise to the target, so it must hold across the whole scan.
// It used to bind only this package, while discovery, vocabulary harvesting,
// route probing and archive fetching each built their own http.Client and were
// governed by nothing: an operator setting -rl 10 to be careful still had
// route discovery firing over a hundred page fetches at full concurrency.
func TestSharedLimiterPacesRequests(t *testing.T) {
	lim := NewLimiter(20) // 20/s
	start := time.Now()
	for i := 0; i < 40; i++ {
		lim.Wait(context.Background())
	}
	// 40 requests at 20/s with a burst of 20: the second 20 must wait ~1s.
	if elapsed := time.Since(start); elapsed < 800*time.Millisecond {
		t.Errorf("40 requests at 20/s completed in %s; the limiter is not pacing", elapsed)
	}
}

// A nil limiter means unlimited and must never panic: it is the default, and
// the stages call Wait unconditionally.
func TestNilLimiterIsUnlimitedAndSafe(t *testing.T) {
	var lim *Limiter
	start := time.Now()
	for i := 0; i < 1000; i++ {
		lim.Wait(context.Background())
	}
	if elapsed := time.Since(start); elapsed > 100*time.Millisecond {
		t.Errorf("a nil limiter should not pace anything, took %s", elapsed)
	}
	if NewLimiter(0) != nil || NewLimiter(-5) != nil {
		t.Error("a non-positive rate must yield a nil (unlimited) limiter")
	}
}
