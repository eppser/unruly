package neon

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/eppser/unruly/internal/finding"
	"github.com/eppser/unruly/internal/transcript"
	"github.com/eppser/unruly/scan"
)

const blindID = "unruly-target-not-discriminating"

// An anonymous Neon scan is BLIND, and must say so rather than say nothing.
//
// Measured on the live Data API: with no Authorization header every name
// answers 400 "missing authentication credentials" -- including
// unruly_control_relation_that_cannot_exist, a name that is definitionally
// absent. A response that is identical for a table that exists and one that
// does not carries no information about either.
//
// The failure this guards against is the tempting one. 400 looks like a
// refusal, a refusal looks like protection, and a scan that reads it that way
// reports a clean project having measured nothing. The whole surface is
// unassessed and the report has to say so.
func TestAnonymousScanIsBlindNotClean(t *testing.T) {
	st := runReach(t, "")

	var blind int
	for _, f := range st.Findings() {
		if f.ID == blindID {
			blind++
			if f.Severity != finding.Info {
				t.Errorf("the blind finding is %v; it must be Info. Nothing about the "+
					"target is known to be wrong -- the point is that nothing is known "+
					"at all, and ranking it above real findings buries them", f.Severity)
			}
			continue
		}
		t.Errorf("an anonymous scan emitted %q. No anonymous response distinguishes "+
			"a present table from an absent one, so nothing was measured and "+
			"nothing may be claimed", f.ID)
	}
	if blind != 1 {
		t.Fatalf("got %d blind findings, want exactly 1: an unassessed surface that "+
			"reports nothing is indistinguishable from a clean one", blind)
	}
}

// With a token the surface DOES discriminate, so the blind finding must not fire.
//
// This is the anti-vacuous half. A stage that always emitted the blind finding
// would pass the test above while measuring nothing, and the authenticated
// control probe is what catches it: the same absent name answers 404 PGRST205
// once a JWT is present, which is a real "not there".
func TestAuthenticatedScanIsNotReportedBlind(t *testing.T) {
	st := runReach(t, "replayed.token.value")
	for _, f := range st.Findings() {
		if f.ID == blindID {
			t.Fatal("the scan called itself blind while authenticated, where the " +
				"control name answers 404 PGRST205 and every real table answers " +
				"distinctly. That is a discriminating surface")
		}
	}
}

func runReach(t *testing.T, token string) scan.State {
	t.Helper()
	tr, err := transcript.Load("../../fixtures/neon/transcript.json")
	if err != nil {
		t.Fatalf("loading the recorded lab transcript: %v", err)
	}
	srv := tr.Server(func(msg string) {
		t.Errorf("the stage made a request the lab recording does not cover: %s", msg)
	})
	t.Cleanup(srv.Close)

	var st scan.State
	stage := ReachStage{Base: srv.URL, Tables: allTables, Token: token, Client: testClient(srv.URL)}
	if err := stage.Run(context.Background(), &st); err != nil {
		t.Fatalf("stage: %v", err)
	}
	return st
}

// Deciding whether a surface discriminates is a comparison, not a sweep.
//
// The stage asks one question -- does a name that cannot exist answer like the
// names that can -- and answering it does not require asking about every
// candidate. Neon exposes no enumeration oracle, so candidates come from the
// application's vocabulary and a real scan carries hundreds; sweeping them
// here spent a request each to re-answer a question the first few had already
// settled.
//
// The bound is stated in the finding rather than hidden, because a sample is a
// weaker observation than a sweep and the report should say which it made.
func TestDecidingDiscriminationIsBounded(t *testing.T) {
	// A plain server rather than the recording, and MORE candidates than the
	// bound. The first version of this test passed the six fixture tables --
	// fewer than the sample size -- so removing the cap changed nothing and the
	// check proved nothing. A budget test whose input is smaller than the
	// budget is decoration.
	var seen int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&seen, 1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"message":"missing authentication credentials"}`))
	}))
	defer srv.Close()

	names := make([]string, 40)
	for i := range names {
		names[i] = fmt.Sprintf("table_%02d", i)
	}

	var st scan.State
	stage := ReachStage{Base: srv.URL, Tables: names, Client: testClient(srv.URL)}
	if err := stage.Run(context.Background(), &st); err != nil {
		t.Fatalf("stage: %v", err)
	}
	if got := atomic.LoadInt64(&seen); got > int64(reachSampleSize)+1 {
		t.Errorf("the stage sent %d requests for %d candidates to answer one question; "+
			"the control plus %d candidates is the bound, and Neon scans carry "+
			"hundreds of names because the endpoint offers no enumeration oracle",
			got, len(names), reachSampleSize)
	}
	// The verdict must still be reached, or the bound has been bought by
	// answering nothing.
	var blind int
	for _, f := range st.Findings() {
		if f.ID == blindID {
			blind++
		}
	}
	if blind != 1 {
		t.Errorf("got %d blind findings, want 1: a surface that answers every name "+
			"identically is unassessed and the report has to say so", blind)
	}
}
