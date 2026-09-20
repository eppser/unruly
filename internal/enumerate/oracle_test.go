package enumerate

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"

	"github.com/eppser/unruly/internal/client"
)

// A stand-in for PostgREST's fuzzy-match behaviour, so the oracle can be tested
// without docker. It answers 200 for relations it has and, for anything else,
// 404 with a hint naming the closest relation it does have — which is the
// behaviour the whole enumerator is built on.
// NOTE: the relation list is kept SORTED and ties are broken by name. An
// earlier version iterated a Go map to pick the closest match, and Go
// randomises map iteration, so "order" tied between "orders" and "order_items"
// and the winner changed per run. The determinism test duly failed — on the
// FIXTURE, not on the enumerator.
//
// Worth recording because the instinct was to go looking for a concurrency bug
// in Run(). A control that is itself nondeterministic can only produce noise,
// and this project has now been bitten by an unverified control three times.
func fakePostgREST(relations ...string) *httptest.Server {
	have := map[string]bool{}
	sorted := append([]string{}, relations...)
	sort.Strings(sorted)
	for _, r := range sorted {
		have[r] = true
	}
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := strings.Trim(strings.SplitN(r.URL.Path, "?", 2)[0], "/")
		w.Header().Set("Content-Type", "application/json")
		if have[name] {
			w.Header().Set("Content-Range", "0-0/7")
			w.WriteHeader(http.StatusPartialContent)
			w.Write([]byte(`[{"id":1}]`))
			return
		}
		// Closest relation by shared prefix, mirroring a similarity match.
		// Iterating the SORTED slice keeps ties resolved the same way each run.
		best, bestLen := "", 0
		for _, rel := range sorted {
			n := 0
			for n < len(rel) && n < len(name) && rel[n] == name[n] {
				n++
			}
			// Require a substantial prefix, as a real similarity threshold does.
			if n >= 4 && n > bestLen {
				best, bestLen = rel, n
			}
		}
		w.WriteHeader(http.StatusNotFound)
		body := map[string]any{"code": "PGRST205", "message": "not found"}
		if best != "" {
			body["hint"] = fmt.Sprintf("Perhaps you meant the table 'public.%s'", best)
		}
		json.NewEncoder(w).Encode(body)
	}))
}

func oracleClient(url string) *client.Client {
	return client.New(client.Options{BaseURL: url, RestPrefix: "/", AnonKey: "k", Retries: 0})
}

// The point of the oracle: a relation nobody guessed is reached because the
// server volunteered its name. "reports" is never probed directly; only the
// near-miss "report" is.
func TestOracleFollowsHintsToUnguessedRelations(t *testing.T) {
	srv := fakePostgREST("reports", "sessions")
	defer srv.Close()

	res := Run(context.Background(), oracleClient(srv.URL), Options{
		Seeds: []string{"report", "session"},
	})
	names := res.Names()
	for _, want := range []string{"reports", "sessions"} {
		if !has(names, want) {
			t.Errorf("%q was never reached; the oracle did not follow its hint. got %v",
				want, names)
		}
	}
	if res.HintsObserved == 0 {
		t.Error("hints were followed but not counted; the self-check relies on this")
	}
}

// HintsObserved is evidence the oracle works against THIS target. A synthetic
// probe cannot establish that, which is why the self-check reads this counter.
func TestHintsObservedReflectsRealHints(t *testing.T) {
	srv := fakePostgREST("customers")
	defer srv.Close()

	// A seed nothing resembles: no hint should be produced.
	quiet := Run(context.Background(), oracleClient(srv.URL), Options{Seeds: []string{"zzzz"}})
	if quiet.HintsObserved != 0 {
		t.Errorf("no relation resembles the seed; expected 0 hints, got %d", quiet.HintsObserved)
	}
	// A near miss: the server should volunteer the name.
	loud := Run(context.Background(), oracleClient(srv.URL), Options{Seeds: []string{"custom"}})
	if loud.HintsObserved == 0 {
		t.Error("a near-miss seed should draw a hint")
	}
}

// Determinism is the headline claim and this is where concurrency could break
// it: probes are dispatched in parallel but folded in by input index.
func TestOracleIsDeterministic(t *testing.T) {
	srv := fakePostgREST("orders", "order_items", "customers", "customer_notes")
	defer srv.Close()

	seeds := []string{"order", "custom", "item", "note", "zzz"}
	first := Run(context.Background(), oracleClient(srv.URL), Options{Seeds: seeds}).Names()
	for i := 0; i < 4; i++ {
		again := Run(context.Background(), oracleClient(srv.URL), Options{Seeds: seeds}).Names()
		if len(again) != len(first) {
			t.Fatalf("run %d found %d relations, first run found %d", i, len(again), len(first))
		}
		for j := range first {
			if again[j] != first[j] {
				t.Fatalf("run %d differs at %d: %q vs %q", i, j, again[j], first[j])
			}
		}
	}
}

// Seed order must not change the result. A caller that shuffles its wordlist
// must get the same answer, or the scan is not reproducible across machines.
func TestOracleIsIndependentOfSeedOrder(t *testing.T) {
	srv := fakePostgREST("invoices", "invoice_lines")
	defer srv.Close()

	a := Run(context.Background(), oracleClient(srv.URL),
		Options{Seeds: []string{"invoice", "invoi", "zzz"}}).Names()
	b := Run(context.Background(), oracleClient(srv.URL),
		Options{Seeds: []string{"zzz", "invoi", "invoice"}}).Names()

	if strings.Join(a, ",") != strings.Join(b, ",") {
		t.Errorf("seed order changed the result: %v vs %v", a, b)
	}
}

// A relation that exists is recorded even when it holds nothing readable:
// existence and readability are different questions, and conflating them is
// how 404 gets reported as "SECURE".
func TestOracleRecordsExistenceNotReadability(t *testing.T) {
	srv := fakePostgREST("locked_table")
	defer srv.Close()

	res := Run(context.Background(), oracleClient(srv.URL), Options{Seeds: []string{"locked_table"}})
	if !has(res.Names(), "locked_table") {
		t.Error("a relation that answered must be recorded as existing")
	}
}

// An unreachable target yields nothing rather than hanging or panicking, and
// records no hints — which is what lets the self-check tell a blind scan from
// a clean one.
func TestOracleSurvivesAnUnreachableTarget(t *testing.T) {
	res := Run(context.Background(), oracleClient("http://127.0.0.1:59997"),
		Options{Seeds: []string{"anything"}})
	if len(res.Relations) != 0 || res.HintsObserved != 0 {
		t.Errorf("an unreachable target should yield nothing, got %d relations and %d hints",
			len(res.Relations), res.HintsObserved)
	}
}
