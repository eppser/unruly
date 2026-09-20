package supabase

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/eppser/unruly/internal/client"
	"github.com/eppser/unruly/internal/enumerate"
	"github.com/eppser/unruly/internal/finding"
	"github.com/eppser/unruly/internal/parity"
	"github.com/eppser/unruly/internal/selfcheck"
	"github.com/eppser/unruly/scan"
)

// The stage must report exactly what the code it replaced reported.
//
// This is the check that verifies the scan's OWN oracles before anything
// trusts what they did not find. "No findings" from a blind scan is the exact
// lie every surveyed tool tells, so a port that quietly changed this would
// break the guarantee the whole project rests on.
func TestTheSelfCheckStageAgreesWithTheCodeItReplaced(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"message":"not found"}`))
	}))
	defer srv.Close()

	// The evidence the stage will now DERIVE, so both paths are judged on the
	// same inputs. Four numbers come from the enumerate outcome and two from
	// the transport's own counters; the stage reads the counters when it runs
	// rather than when it is built, which is what main effectively did anyway
	// -- it called Stats() on the line above the construction.
	en := EnumerateOutcome{Result: enumerate.Result{
		Relations:     []enumerate.Relation{{Name: "a"}, {Name: "b"}},
		HintsObserved: 3, Denied: 1, SeedCount: 10,
	}}

	cOld := client.New(client.Options{BaseURL: srv.URL, AnonKey: "k", RestPrefix: "/"})
	oldSent, oldFailed := cOld.Stats()
	ev := selfcheck.Evidence{
		HintsObserved:  en.Result.HintsObserved,
		RelationsFound: len(en.Result.Relations),
		ProbesDenied:   en.Result.Denied,
		ProbesTotal:    en.Result.SeedCount,
		RequestsSent:   oldSent,
		RequestsFailed: oldFailed,
	}
	var old []finding.Finding
	sc := selfcheck.Run(context.Background(), cOld, ev)
	oldRequests := sc.Requests
	old = append(old, sc.Findings...)

	cNew := client.New(client.Options{BaseURL: srv.URL, AnonKey: "k", RestPrefix: "/"})
	st := &scan.State{Target: cNew.RestBase()}
	scan.Put(st, en)
	if _, err := (scan.Pipeline{SelfCheckStage{Client: cNew}}).
		Run(context.Background(), st); err != nil {
		t.Fatal(err)
	}
	if d := parity.Diff(old, st.Findings()); d != "" {
		t.Errorf("the ported stage disagrees with the code it replaced:\n%s", d)
	}
	if st.Attributed() != oldRequests {
		t.Errorf("attributed %d, original counted %d", st.Attributed(), oldRequests)
	}
}

// The stage publishes its result so the command can warn about degraded
// capabilities. A degraded scan that reports nothing is the failure this check
// exists to make impossible, and the operator has to be told at the terminal
// as well as in the report.
func TestTheSelfCheckStagePublishesItsResult(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	c := client.New(client.Options{BaseURL: srv.URL, AnonKey: "k", RestPrefix: "/"})
	st := &scan.State{Target: c.RestBase()}
	// The oracles are judged against what enumeration observed, so that has to
	// have been published first.
	scan.Put(st, EnumerateOutcome{})
	if _, err := (scan.Pipeline{SelfCheckStage{Client: c}}).
		Run(context.Background(), st); err != nil {
		t.Fatal(err)
	}
	out, ok := scan.Get[selfcheck.Result](st)
	if !ok {
		t.Fatal("the self-check stage published no result")
	}
	if out.Capabilities == nil && len(out.Degraded()) == 0 {
		t.Error("the destination was not written: the command cannot tell an operator " +
			"which capabilities are degraded")
	}
}

func TestTheSelfCheckStageHasAStableName(t *testing.T) {
	if got := (SelfCheckStage{}).Name(); got != "selfcheck" {
		t.Errorf("stage name %q", got)
	}
}
