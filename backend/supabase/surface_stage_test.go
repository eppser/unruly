package supabase

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/eppser/unruly/internal/client"
	"github.com/eppser/unruly/internal/finding"
	"github.com/eppser/unruly/internal/parity"
	"github.com/eppser/unruly/internal/surface"
	"github.com/eppser/unruly/scan"
)

func quiet(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"message":"not found"}`))
	}))
	t.Cleanup(srv.Close)
	return srv
}

// The stage must report exactly what the code it replaced reported.
func TestTheSurfaceStageAgreesWithTheCodeItReplaced(t *testing.T) {
	opts := surface.Options{Concurrency: 2, MaxCandidates: 0}

	srvOld := quiet(t)
	cOld := client.New(client.Options{BaseURL: srvOld.URL, AnonKey: "k", RestPrefix: "/"})
	var old []finding.Finding
	sf := surface.Run(context.Background(), cOld, opts)
	if sf.RoutineBudgetBound {
		old = append(old, surface.RoutineBudgetFinding(cOld.RestBase(), 0,
			sf.RoutineCandidatesWanted))
	}
	old = append(old, sf.Findings...)

	srvNew := quiet(t)
	cNew := client.New(client.Options{BaseURL: srvNew.URL, AnonKey: "k", RestPrefix: "/"})
	st := &scan.State{Target: cNew.RestBase()}
	scan.Put(st, Vocabulary{})
	stage := SurfaceStage{Client: cNew, Opts: opts, RoutineCap: 0}
	if _, err := (scan.Pipeline{stage}).Run(context.Background(), st); err != nil {
		t.Fatal(err)
	}

	normalise(old, srvOld.URL, "http://target")
	got := st.Findings()
	normalise(got, srvNew.URL, "http://target")
	if d := parity.Diff(old, got); d != "" {
		t.Errorf("the ported stage disagrees with the code it replaced:\n%s", d)
	}
}

// Requests are attributed PER SUB-STAGE, not as one opaque "surface" line.
//
// That single line was the largest spender on a real target -- 4,406 of 12,068
// requests -- and said nothing about where they went. A ledger whose biggest
// entry is opaque is the part an operator cannot act on, and this project has
// already lost an investigation to reasoning from one.
func TestSurfaceSpendIsAttributedPerSubStage(t *testing.T) {
	srv := quiet(t)
	c := client.New(client.Options{BaseURL: srv.URL, AnonKey: "k", RestPrefix: "/"})
	st := &scan.State{Target: c.RestBase()}
	scan.Put(st, Vocabulary{})
	if _, err := (scan.Pipeline{SurfaceStage{Client: c,
		Opts: surface.Options{Concurrency: 2}}}).Run(context.Background(), st); err != nil {
		t.Fatal(err)
	}
	for _, sp := range st.Spending() {
		if sp.Stage == "surface" {
			t.Error("spend was recorded under one opaque \"surface\" label; the sub-stage " +
				"breakdown is what makes the largest entry in the ledger actionable")
		}
	}
}

// The stage publishes what later stages steer on.
//
// Two later passes ask whether signup is open -- the escalation compare and
// the routes pass -- so the auth result has to survive the move. It is a
// Supabase type handed between Supabase stages, deliberately not carried on
// scan.State.
func TestTheSurfaceStagePublishesTheAuthResult(t *testing.T) {
	srv := quiet(t)
	c := client.New(client.Options{BaseURL: srv.URL, AnonKey: "k", RestPrefix: "/"})
	st := &scan.State{Target: c.RestBase()}
	scan.Put(st, Vocabulary{})
	if _, err := (scan.Pipeline{SurfaceStage{Client: c,
		Opts: surface.Options{Concurrency: 2}}}).
		Run(context.Background(), st); err != nil {
		t.Fatal(err)
	}
	out, ok := scan.Get[surface.Result](st)
	if !ok {
		t.Fatal("the surface stage published no result")
	}
	if out.Auth.SignupOpen() {
		t.Error("a server that answers 404 to everything was reported as having open " +
			"signup, so the published result is not the one the stage measured")
	}
}

func TestTheSurfaceStageHasAStableName(t *testing.T) {
	if got := (SurfaceStage{}).Name(); got != "surface" {
		t.Errorf("stage name %q", got)
	}
}
