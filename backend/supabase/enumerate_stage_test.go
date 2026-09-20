package supabase

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/eppser/unruly/internal/client"
	"github.com/eppser/unruly/internal/enumerate"
	"github.com/eppser/unruly/internal/wordlist"
	"github.com/eppser/unruly/scan"
)

// hintingFixture answers like a PostgREST whose hint oracle volunteers the
// nearest real relation name, which is the mechanism the retry exists for: a
// vocabulary that is close but wrong.
//
// Modelled on internal/enumerate/oracle_test.go, which cannot be imported --
// it is an internal test -- but whose shape is the one to match if PostgREST's
// hint format ever moves.
func hintingFixture(t *testing.T, real ...string) *client.Client {
	return hintingFixtureServing(t, real, real)
}

// hintingFixtureServing separates what the oracle NAMES from what it SERVES.
// A hint can point at a table in a schema that is not exposed: the server
// volunteers the name and then answers 404 for it, so the first pass observes
// hints and still finds nothing. That is the only shape in which the retry
// fires with a non-empty harvested vocabulary, which is the case this
// distinction exists to reach.
func hintingFixtureServing(t *testing.T, hinted, served []string) *client.Client {
	real := hinted
	_ = real
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := strings.Trim(strings.SplitN(r.URL.Path, "?", 2)[0], "/")
		if slices.Contains(served, name) {
			w.Header().Set("Content-Range", "0-0/1")
			w.WriteHeader(http.StatusPartialContent)
			_, _ = w.Write([]byte(`[{"id":1}]`))
			return
		}
		// Volunteer the nearest real name when the request shares a
		// substantial prefix, as a similarity threshold does.
		best, bestLen := "", 0
		for _, rel := range hinted {
			n := 0
			for n < len(rel) && n < len(name) && rel[n] == name[n] {
				n++
			}
			if n >= 4 && n > bestLen {
				best, bestLen = rel, n
			}
		}
		body := map[string]any{"code": "PGRST205", "message": "not found"}
		if best != "" {
			body["hint"] = fmt.Sprintf("Perhaps you meant the table 'public.%s'", best)
		}
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(body)
	}))
	t.Cleanup(srv.Close)
	return client.New(client.Options{BaseURL: srv.URL, RestPrefix: "/",
		AnonKey: "anon", Concurrency: 2})
}

// The stage must report exactly what the code it replaced reported.
//
// The block below is a faithful transcription of the two enumerate.Run calls
// and the expansion decision between them.
func TestTheEnumerateStageAgreesWithTheCodeItReplaced(t *testing.T) {
	ctx := context.Background()
	// One fixture for both runs: two servers differ by port, and the diff
	// would be noise about ports rather than a disagreement about behaviour.
	c := hintingFixture(t, "orders", "invoices")
	seeds := []string{"orderz"} // a near miss, so the first pass finds nothing

	// --- the original expression, transcribed ---------------------------
	en := enumerate.Run(ctx, c, enumerate.Options{Seeds: seeds, Concurrency: 2})
	oldTotal := en.Requests
	if shouldExpand(en.Discriminating, en.HintsObserved, 0, len(en.Relations)) {
		expanded := wordlist.RelationCandidatesFrom(seeds, en.Names(), 200)
		retry := enumerate.Run(ctx, c, enumerate.Options{Seeds: expanded, Concurrency: 2})
		oldTotal += retry.Requests
		en = en.Merge(retry)
	}

	// --- the same work through the pipeline ------------------------------
	st := &scan.State{Target: "t"}
	scan.Put(st, Vocabulary{Seeds: seeds})
	stage := EnumerateStage{Client: c, MaxRelation: 200, Concurrency: 2}
	if _, err := (scan.Pipeline{stage}).Run(ctx, st); err != nil {
		t.Fatal(err)
	}
	out, ok := scan.Get[EnumerateOutcome](st)
	if !ok {
		t.Fatal("the enumerate stage published no outcome")
	}
	if got, want := out.Result.Names(), en.Names(); !slices.Equal(got, want) {
		t.Errorf("the ported stage found %v, the original found %v", got, want)
	}
	if got := st.Attributed(); got != oldTotal {
		t.Errorf("attributed %d requests, the original counted %d", got, oldTotal)
	}
}

// THE POINT OF THE PORT. The retry only runs when the first pass found
// nothing, so an operator reading a large "relations" figure needs to know
// whether that was one sweep or two. Folding both into one label would look
// correct and lose exactly that.
func TestTheEnumerateStageAttributesTheRetrySeparately(t *testing.T) {
	st := &scan.State{Target: "t"}
	scan.Put(st, Vocabulary{Seeds: []string{"orderz"}})
	stage := EnumerateStage{Client: hintingFixture(t, "orders"),
		MaxRelation: 200, Concurrency: 2}
	if _, err := (scan.Pipeline{stage}).Run(context.Background(), st); err != nil {
		t.Fatal(err)
	}
	out, ok := scan.Get[EnumerateOutcome](st)
	if !ok {
		t.Fatal("the enumerate stage published no outcome")
	}
	if !out.Retried {
		t.Fatal("the retry did not run, so this test grades nothing")
	}
	var labels []string
	for _, e := range st.Spending() {
		labels = append(labels, e.Stage)
	}
	for _, want := range []string{"relations", "relations-retry"} {
		if !slices.Contains(labels, want) {
			t.Errorf("%q missing from the spend breakdown %v; the retry's cost is no "+
				"longer distinguishable from the first pass", want, labels)
		}
	}
}

// The two causes call for different fixes -- repair the -site, or the names
// were wrong -- so the stated reason has to follow the one that fired.
func TestTheEnumerateStageSaysWhyItRetried(t *testing.T) {
	for _, tc := range []struct {
		name      string
		harvested int
		want      string
	}{
		{"nothing harvested from the application", 0,
			"no vocabulary could be harvested from the target"},
		{"harvested names that did not exist", 5,
			"the first pass found no relations"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out EnumerateOutcome
			st := &scan.State{Target: "t"}
			c := hintingFixture(t, "orders")
			if tc.harvested > 0 {
				// hints observed, nothing found: the hinted table is named but
				// not served, as an unexposed schema behaves.
				c = hintingFixtureServing(t, []string{"orders"}, nil)
			}
			// HarvestedCount is now Origins.Harvested on the published
			// vocabulary: the stage that merged the sources is the only
			// thing that knows how many the application contributed.
			scan.Put(st, Vocabulary{Seeds: []string{"orderz"},
				Origins: SeedOrigins{Harvested: tc.harvested}})
			stage := EnumerateStage{Client: c, MaxRelation: 200, Concurrency: 2}
			if _, err := (scan.Pipeline{stage}).Run(context.Background(), st); err != nil {
				t.Fatal(err)
			}
			out, ok := scan.Get[EnumerateOutcome](st)
			if !ok {
				t.Fatal("the enumerate stage published no outcome")
			}
			if !out.Retried {
				t.Fatal("the retry did not run, so this test grades nothing")
			}
			if out.Why != tc.want {
				t.Errorf("Why = %q, want %q", out.Why, tc.want)
			}
		})
	}
}

func TestTheEnumerateStageHasAStableName(t *testing.T) {
	if got := (EnumerateStage{}).Name(); got != "relations" {
		t.Errorf("stage name %q, want \"relations\"", got)
	}
}
