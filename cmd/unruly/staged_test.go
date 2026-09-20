package main

import (
	"context"
	"time"

	"github.com/eppser/unruly/internal/client"
	"github.com/eppser/unruly/internal/engine"
	"github.com/eppser/unruly/scan"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/eppser/unruly/internal/provider"
	"github.com/eppser/unruly/internal/testrec"
)

// A backend that contributes stages has them RUN by the scan.
//
// PocketBase implements provider.Staged and its stages were unreachable from
// the binary: main dispatched every non-Supabase backend through
// provider.Assess and never asked whether the provider had stages of its own.
// The README said so plainly -- "PocketBase is NOT yet wired into a full scan"
// -- which is honest and still a backend that detects and then reports
// nothing.
//
// This is the seam's last mile. Without it, Staged is a contract nothing
// consumes, and a contributor implementing it would watch their backend detect
// and go silent.
func TestADetectedStagedBackendActuallyRuns(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(r.URL.Path, "/leaky/") {
			_, _ = w.Write([]byte(`{"items":[{"id":"a1","card":"4111111111111111"}],"totalItems":1}`))
			return
		}
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"message":"Only superusers can perform this action.","status":403}`))
	}))
	defer srv.Close()

	d := provider.Detection{Provider: "pocketbase", Project: srv.URL}
	report := engine.Run(context.Background(), engine.Request{Providers: []engine.ProviderTarget{{
		Detection: d, Inputs: scan.Inputs{Seeds: []string{"leaky", "locked"}, Redact: false, Client: testStagedClient()},
	}}})
	got := report.Findings

	var found bool
	for _, f := range got {
		if f.ID == "pocketbase-anon-read-exposed" && f.Resource == "leaky" {
			found = true
			if len(f.Evidence.Sample) == 0 {
				t.Error("the finding carries no rows")
			}
		}
	}
	if !found {
		t.Errorf("a detected PocketBase target produced no findings, so the backend "+
			"detects and then says nothing: %+v", got)
	}
}

// A staged backend's requests must reach the scan's totals.
//
// runStage folds st.Attributed() into the request count and st.Spending() into
// the ledger. stagedFindings did neither, so every request a staged backend
// made was invisible: both PocketBase stages call st.Attribute(s.Name(), n) and
// all of it was dropped on the floor here.
//
// That is not bookkeeping. ScanSummary tells an operator how many requests the
// run made, and this project's own words are that a scan is not free for the
// person being scanned -- reporting fewer than were sent is a wrong claim about
// somebody else's server. And -stats could say nothing about where a PocketBase
// scan spent its budget, because it was handed no breakdown.
func TestAStagedBackendsRequestsAreCounted(t *testing.T) {
	var served testrec.Log
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		served.Add(r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(r.URL.Path, "/leaky/") {
			_, _ = w.Write([]byte(`{"items":[{"id":"a1","card":"4111111111111111"}],"totalItems":1}`))
			return
		}
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"message":"Only superusers can perform this action.","status":403}`))
	}))
	defer srv.Close()

	d := provider.Detection{Provider: "pocketbase", Project: srv.URL}
	report := engine.Run(context.Background(), engine.Request{Providers: []engine.ProviderTarget{{
		Detection: d, Inputs: scan.Inputs{Seeds: []string{"leaky", "locked"}, Redact: false, Client: testStagedClient()},
	}}})
	requests, spent := report.Requests, report.Spending

	if served.Len() == 0 {
		t.Fatal("the stage sent no requests at all, so this test grades nothing")
	}
	if requests == 0 {
		t.Errorf("the stage sent %d request(s) and reported 0. ScanSummary would tell "+
			"the operator this scan cost nothing.", served.Len())
	}
	if len(spent) == 0 {
		t.Error("no per-stage breakdown came back, so -stats cannot say where a staged " +
			"backend spent its requests")
	}
	for _, e := range spent {
		if e.Stage == "" {
			t.Error("a ledger entry with no stage name is the opaque figure this " +
				"breakdown exists to replace")
		}
		if e.Requests == 0 {
			t.Errorf("stage %q reported 0 requests", e.Stage)
		}
	}
}

// testStagedClient forwards every control an operator would, which is what the
// seam now requires: a stage with no client refuses rather than making one.
func testStagedClient() *client.Client {
	return client.New(client.Options{
		RestPrefix: "/",
		Timeout:    5 * time.Second,
		UserAgent:  "unruly-test",
		Limiter:    client.NewLimiter(0),
	})
}
