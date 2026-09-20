package supabase

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/eppser/unruly/internal/client"
	"github.com/eppser/unruly/internal/enumerate"
	"github.com/eppser/unruly/internal/probe"
	"github.com/eppser/unruly/scan"
)

// leaky serves the NAMED relations, returning rows to an anonymous key, and
// answers PGRST205 for anything else.
//
// It served every path identically until a scan that asked for a relation
// which does not exist got rows back like any other -- a target no PostgREST
// resembles, and one that cannot tell a scanner asking correctly from a
// scanner asking for gibberish. The names are declared so the fixture and the
// stage cannot disagree about which relations are there.
func leaky(t *testing.T, names ...string) *httptest.Server {
	t.Helper()
	present := make(map[string]bool, len(names))
	for _, n := range names {
		present[n] = true
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if !present[strings.Trim(r.URL.Path, "/")] {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"code":"PGRST205","message":` +
				`"Could not find the table in the schema cache"}`))
			return
		}
		w.Header().Set("Content-Range", "0-0/1")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`[{"id":1,"email":"leaked@example.com"}]`))
	}))
	t.Cleanup(srv.Close)
	return srv
}

// The probing stage runs on its own, against a server, with no main involved.
//
// This is the first stage lifted out of scanTarget and it is the proof the
// harness is real: the same probe the tool ships now, reached through the
// pipeline rather than through 1,390 lines of orchestration, and exercised by
// a test that constructs nothing but a client and a State.
func TestTheProbeStageFindsAnExposedRelationOnItsOwn(t *testing.T) {
	srv := leaky(t, "public_notes")
	c := client.New(client.Options{BaseURL: srv.URL, AnonKey: "k", RestPrefix: "/"})

	st := &scan.State{Target: srv.URL}
	scan.Put(st, EnumerateOutcome{Result: enumerate.Result{
		Relations: []enumerate.Relation{{Name: "public_notes"}},
	}})
	stage := ProbeStage{Client: c,
		Opts: probe.Options{SampleRows: 1, Concurrency: 2}}

	if _, err := (scan.Pipeline{stage}).Run(context.Background(), st); err != nil {
		t.Fatalf("run: %v", err)
	}

	var saw bool
	for _, f := range st.Findings() {
		if strings.Contains(f.ID, "read-exposed") {
			saw = true
			if len(f.Evidence.Sample) == 0 {
				t.Error("the finding carries no sampled row: a finding without evidence is " +
					"the boolean this scanner refuses to emit")
			}
		}
	}
	if !saw {
		t.Errorf("the stage found no read exposure against a server that returns rows to "+
			"anyone: %+v", st.Findings())
	}
}

// The stage attributes what it spent, so the breakdown can say where a scan's
// traffic went.
func TestTheProbeStageAttributesItsRequests(t *testing.T) {
	srv := leaky(t, "a", "b")
	c := client.New(client.Options{BaseURL: srv.URL, AnonKey: "k", RestPrefix: "/"})

	st := &scan.State{Target: srv.URL}
	scan.Put(st, EnumerateOutcome{Result: enumerate.Result{
		Relations: []enumerate.Relation{{Name: "a"}, {Name: "b"}},
	}})
	stage := ProbeStage{Client: c,
		Opts: probe.Options{SampleRows: 1, Concurrency: 2}}
	if _, err := (scan.Pipeline{stage}).Run(context.Background(), st); err != nil {
		t.Fatal(err)
	}
	if st.Attributed() == 0 {
		t.Error("the stage probed two relations and attributed no requests")
	}
	sp := st.Spending()
	if len(sp) != 1 || sp[0].Stage != "probe" {
		t.Errorf("spend attributed to %v, want a single \"probe\" entry", sp)
	}
}

// The stage name is part of the output contract: it appears in the coverage
// breakdown and in any not-assessed finding the pipeline emits for it.
func TestTheProbeStageHasAStableName(t *testing.T) {
	if got := (ProbeStage{}).Name(); got != "probe" {
		t.Errorf("stage name %q, want \"probe\"", got)
	}
}

// The stage publishes its result for the later stages of the SAME provider.
//
// Realtime steers on which relations are writable, and the escalation compare
// needs the whole probe result. Those are PostgREST-shaped facts, so they are
// handed between Supabase stages through a Supabase type -- putting them in
// scan.State would couple the provider-agnostic pipeline to one backend's
// internals, which is the failure this rebuild is trying to avoid. Only things
// every backend has -- findings, request attribution -- belong in State.
func TestTheProbeStagePublishesItsResultForLaterStages(t *testing.T) {
	srv := leaky(t, "public_notes")
	c := client.New(client.Options{BaseURL: srv.URL, AnonKey: "k", RestPrefix: "/"})

	stage := ProbeStage{Client: c,
		Opts: probe.Options{SampleRows: 1, Concurrency: 2}}
	st := &scan.State{}
	scan.Put(st, EnumerateOutcome{Result: enumerate.Result{
		Relations: []enumerate.Relation{{Name: "public_notes"}},
	}})

	if _, err := (scan.Pipeline{stage}).Run(context.Background(), st); err != nil {
		t.Fatal(err)
	}
	out, ok := scan.Get[probe.Result](st)
	if !ok {
		t.Fatal("the probe stage published no result")
	}
	if len(out.ReadExposed()) == 0 {
		t.Errorf("the stage did not publish its result: later stages steer on "+
			"ReadExposed and InsertReachable and would silently see nothing, got %+v", out)
	}
}

// Probing with no enumerate outcome REPORTS rather than finding nothing.
//
// This replaces a test asserting that publishing was optional. It no longer
// is: a probe pass that was handed no relations examined no surface, and
// saying so is the difference between a short scan and a short scan nobody
// noticed.
func TestTheProbeStageWithoutAnEnumerateOutcomeSaysSo(t *testing.T) {
	srv := leaky(t, "n")
	c := client.New(client.Options{BaseURL: srv.URL, AnonKey: "k", RestPrefix: "/"})
	stage := ProbeStage{Client: c, Opts: probe.Options{SampleRows: 1}}
	if err := stage.Run(context.Background(), &scan.State{}); err == nil {
		t.Fatal("the probe stage ran with no relations and reported success; an " +
			"unexamined surface must not read as a clean one")
	}
}
