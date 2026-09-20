package enumerate

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/eppser/unruly/internal/client"
	"github.com/eppser/unruly/internal/finding"
)

// Enumeration counts a 200 or 206 as proof a relation exists, because
// PostgREST had to consult the schema to answer. That reasoning holds only if
// the target answers differently for a relation that is NOT in the schema.
//
// Measured against a host that answers 200 to every path -- Supabase's own
// edge-runtime with a catch-all router, reached on the wrong port -- this
// stage reported 706 relations and the scan emitted 1,412 findings, 706 of
// them critical. Every one was a wordlist entry reflected back. The self-check
// noticed the target was not behaving like PostgREST and said so in a medium
// finding, which was printed alongside those criticals.
//
// A catch-all router, a CDN error page, or a single-page application serving
// index.html for unknown routes all produce this. It is a configuration
// mistake away from any real scan.

// alwaysOK answers 200 with a JSON array to everything, like a catch-all.
func alwaysOK(t *testing.T) *client.Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Range", "0-0/1")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`[{"id":1}]`))
	}))
	t.Cleanup(srv.Close)
	return client.New(client.Options{
		ProjectRef: "x", BaseURL: srv.URL, RestPrefix: "/", AnonKey: "k", Retries: 1,
	})
}

func TestNonDiscriminatingTargetYieldsNoRelations(t *testing.T) {
	res := Run(context.Background(), alwaysOK(t), Options{
		Seeds: []string{"users", "accounts", "orders", "sessions"},
	})
	if res.Discriminating {
		t.Fatal("a host that answers 200 to every name must not be treated as discriminating")
	}
	if len(res.Relations) != 0 {
		t.Errorf("want no relations from a non-discriminating target, got %d: %v",
			len(res.Relations), res.Names())
	}
	if res.ControlDetail == "" {
		t.Error("the refusal must carry a reason a reader can act on")
	}
}

// Returning nothing is only half the fix. An empty relation list reads as a
// clean project, which is the failure this package exists to prevent.
func TestNonDiscriminatingTargetProducesAnExplicitFinding(t *testing.T) {
	res := Run(context.Background(), alwaysOK(t), Options{Seeds: []string{"users"}})
	f, ok := res.ControlFinding("http://x/rest/v1")
	if !ok {
		t.Fatal("a non-discriminating target must produce a finding, not silence")
	}
	if f.ID != "unruly-target-not-discriminating" {
		t.Errorf("ID changed to %q; consumers filter on it", f.ID)
	}
	// The reader has to learn that read and write exposure were skipped too,
	// or they will read zero findings as zero problems.
	for _, want := range []string{"read exposure", "write exposure", "not a clean result"} {
		if !strings.Contains(f.Description, want) {
			t.Errorf("description does not tell the reader %q: %s", want, f.Description)
		}
	}
	if f.Remediation == "" {
		t.Error("the finding must say how to get a usable scan")
	}
	if !strings.Contains(f.Evidence.Request, ControlRelationName) {
		t.Error("evidence must let a reader reproduce the control probe")
	}
}

// The control must not fire against a target that behaves correctly, or every
// real scan loses its relation discovery.
func TestDiscriminatingTargetIsUnaffected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(r.URL.Path, ControlRelationName) {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"code":"42P01","message":"relation does not exist"}`))
			return
		}
		w.Header().Set("Content-Range", "0-0/1")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`[{"id":1}]`))
	}))
	t.Cleanup(srv.Close)
	c := client.New(client.Options{
		ProjectRef: "x", BaseURL: srv.URL, RestPrefix: "/", AnonKey: "k", Retries: 1,
	})

	res := Run(context.Background(), c, Options{Seeds: []string{"users", "orders"}})
	if !res.Discriminating {
		t.Fatal("a target that 404s an absent relation discriminates and must be scanned")
	}
	if len(res.Relations) == 0 {
		t.Error("relations must still be discovered against a well-behaved target")
	}
	if _, ok := res.ControlFinding("http://x"); ok {
		t.Error("a well-behaved target must not produce the control finding")
	}
}

// Rate limiting is silent loss, not misclassification. A 429 says nothing
// about whether a relation exists, and ClassifyRead maps it to unknown rather
// than not-found -- correct, but on its own it means a throttled candidate
// vanishes from the report, and an absent relation looks exactly like one that
// was never there.
//
// Measured against a host throttling half its paths: 360 of 702 probes
// answered 429 after retries, and the scan reported "342 relations discovered"
// with no mention that half the target was never looked at.
func TestThrottledProbesAreCountedNotDropped(t *testing.T) {
	// atomic, not a bare int: the handler runs on one goroutine per connection
	// and enumeration probes concurrently, so `throttled++` is a data race.
	// It was one, undetected for a long time -- `go test` is happy with it and
	// the race detector only catches it when two probes overlap, which they do
	// not reliably do. It surfaced in an audit run that kept its logs.
	var throttled atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(r.URL.Path, ControlRelationName) {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"code":"42P01","message":"does not exist"}`))
			return
		}
		if strings.Contains(r.URL.Path, "throttled") {
			throttled.Add(1)
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte(`{"message":"rate limit exceeded"}`))
			return
		}
		w.Header().Set("Content-Range", "0-0/1")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`[{"id":1}]`))
	}))
	t.Cleanup(srv.Close)
	c := client.New(client.Options{
		ProjectRef: "x", BaseURL: srv.URL, RestPrefix: "/", AnonKey: "k", Retries: 1,
	})

	res := Run(context.Background(), c, Options{
		Seeds: []string{"visible_one", "throttled_one", "throttled_two"},
	})
	if !res.Discriminating {
		t.Fatal("the control probe 404s correctly, so the target discriminates")
	}
	if throttled.Load() == 0 {
		t.Fatal("no probe was throttled; the fixture did not exercise the path")
	}
	if res.Unresolved == 0 {
		t.Fatal("throttled probes must be counted, or they vanish from the report")
	}

	f, ok := res.UnresolvedFinding("http://x/rest/v1", 3)
	if !ok {
		t.Fatal("unresolved probes must produce a finding, not silence")
	}
	if f.ID != "unruly-probes-unresolved" {
		t.Errorf("ID changed to %q; consumers filter on it", f.ID)
	}
	// The reader has to learn the list is incomplete, or they will read it as
	// the full set of relations.
	if !strings.Contains(f.Description, "LOWER BOUND") {
		t.Errorf("the finding must say the relation list is a lower bound: %s", f.Description)
	}
	if f.Remediation == "" {
		t.Error("the finding must say how to get a complete scan")
	}
}

// A scan that resolved everything must not carry the caveat, or it becomes
// noise that readers learn to skip.
func TestFullyResolvedScanCarriesNoUnresolvedFinding(t *testing.T) {
	res := Result{Unresolved: 0}
	if _, ok := res.UnresolvedFinding("http://x", 10); ok {
		t.Error("nothing was unresolved, so there is nothing to caveat")
	}
}

// A scan truncated by its own probe budget did not finish looking, and must
// say so rather than presenting a short list as the whole schema.
func TestBudgetFinding(t *testing.T) {
	f := BudgetFinding("http://x/rest/v1", 3000, 13740)
	if f.ID != "unruly-probe-budget-exhausted" {
		t.Errorf("ID changed to %q; consumers filter on it", f.ID)
	}
	if f.Severity != finding.Info {
		t.Errorf("nothing is known to be wrong with the target, got %s", f.Severity)
	}
	if !strings.Contains(f.Description, "LOWER BOUND") {
		t.Error("the reader must learn the relation list is incomplete")
	}
	if !strings.Contains(f.Remediation, "13740") {
		t.Error("the remediation must name the budget that would finish the search")
	}
}

// The fallback expansion used to replace the first pass rather than merge with
// it, so a retry that found three relations the first pass missed reported
// three instead of twenty-three. The expansion is not a superset of the seeds
// — 92 of 702 survive it — so this was reachable on any scan without a site.
func TestMergeKeepsBothPasses(t *testing.T) {
	first := Result{
		Relations: []Relation{{Name: "orders"}, {Name: "customers"}},
		Requests:  100, SeedCount: 700, Denied: 3, HintsObserved: 5,
		Unresolved:     2,
		Discriminating: true,
	}
	second := Result{
		Relations: []Relation{{Name: "audit_log"}, {Name: "orders"}},
		Requests:  13000, SeedCount: 13740, Denied: 1, HintsObserved: 4,
		Unresolved:     7,
		Discriminating: true,
	}
	got := first.Merge(second)

	if len(got.Relations) != 3 {
		t.Fatalf("want the union of both passes (3 relations), got %d: %v",
			len(got.Relations), got.Names())
	}
	if !sort.SliceIsSorted(got.Relations, func(i, j int) bool {
		return got.Relations[i].Name < got.Relations[j].Name
	}) {
		t.Error("the merged list must stay sorted, or output stops being deterministic")
	}
	// The counters feed the self-check and the unresolved-probe finding.
	// Dropping the first pass's evidence that the oracle works is how a scan
	// concludes it was blind when it was not.
	if got.Requests != 13100 || got.SeedCount != 14440 ||
		got.Denied != 4 || got.HintsObserved != 9 || got.Unresolved != 9 {
		t.Errorf("counters must sum: %+v", got)
	}
}

// Discriminating is an AND. If either pass could not tell an absent relation
// from a present one, nothing either pass reports can be trusted.
func TestMergeKeepsTheStricterDiscriminatingVerdict(t *testing.T) {
	ok := Result{Discriminating: true}
	bad := Result{Discriminating: false, ControlDetail: "answered as though it exists"}
	if ok.Merge(bad).Discriminating {
		t.Error("a non-discriminating pass must poison the merged verdict")
	}
	if got := ok.Merge(bad).ControlDetail; got == "" {
		t.Error("the reason must survive the merge, or the finding cannot explain itself")
	}
}

// A hostile oracle must not be able to make the scan run forever.
//
// Enumeration feeds discovered names back in as fresh probes, so a host that
// volunteers a NEW name in every hint creates more work with every answer. A
// real PostgREST hints at names that exist; a hostile one has an infinite
// supply, and the work queue would belong to the target rather than to the
// scanner.
//
// It is bounded today by MaxRounds, which defaults to 3 -- checked rather than
// assumed, and pinned here because the bound is not obviously load-bearing:
// "keep following hints while new ones appear" is a natural-looking change
// that would hand the queue to the target.
func TestAdversarialHintOracleCannotExpandForever(t *testing.T) {
	// The bound this test is about is the PROBE COUNT, not the clock. Failing
	// on a deadline conflates "enumeration did not terminate" with "the
	// machine was busy": running this package alongside sixteen others on a
	// loaded laptop made it fail at 404,171 probes, and the code was correct.
	//
	// So the server refuses to keep feeding an expansion that has already
	// proved the point. Past the ceiling it stops inventing names, which ends
	// the run quickly and leaves the count assertion below to do the judging.
	const ceiling = 5000
	var issued atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		i := issued.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		if i > ceiling {
			fmt.Fprint(w, `{"code":"PGRST205","message":"no"}`)
			return
		}
		fmt.Fprintf(w, `{"code":"PGRST205","message":"no","hint":"Perhaps you meant the table 'public.gen_%d'"}`, i)
	}))
	defer srv.Close()

	c := client.New(client.Options{
		ProjectRef: "x", BaseURL: srv.URL, RestPrefix: "/", AnonKey: "k", Retries: 0,
	})

	// Generous, because it is now only a backstop against a genuine hang: the
	// server's ceiling ends a runaway expansion long before this fires.
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	done := make(chan Result, 1)
	go func() {
		done <- Run(ctx, c, Options{Seeds: []string{"users", "orders"}, Concurrency: 4})
	}()

	select {
	case res := <-done:
		// The exact number matters less than that it is a function of the
		// seeds and the round cap, not of how many names the host invents.
		if n := issued.Load(); n > 200 {
			t.Errorf("%d probes issued against 2 seeds: the host is choosing how much work "+
				"the scan does", n)
		}
		if len(res.Names()) != 0 {
			t.Errorf("this host answers 404 to everything, so nothing is confirmed; got %v",
				res.Names())
		}
	case <-ctx.Done():
		t.Fatalf("enumeration did not terminate against a host that mints a new hint per "+
			"request; %d probes issued", issued.Load())
	}
}
