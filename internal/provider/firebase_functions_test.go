package provider

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/eppser/unruly/internal/client"
	"github.com/eppser/unruly/internal/finding"
)

// Calling is not reading, so it is gated -- and the gate is the check.
//
// The pinned function wordlist holds 398 names. Probing them across two regions
// would be some eight hundred requests that each RUN somebody's code, and a
// function named send-invoices does what it says when called. So: only names
// the application itself references, capped, and only with -invoke.
func TestFunctionsAreNeverCalledWithoutConsent(t *testing.T) {
	var calls atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	functionHostOverride = srv.URL
	t.Cleanup(func() { functionHostOverride = "" })

	fs := functionFindings(context.Background(),
		Detection{Provider: "firebase", Project: "p"},
		ScanOptions{
			Client:    client.New(client.Options{BaseURL: srv.URL, Retries: 0}),
			Harvested: []string{"sendInvoices", "purgeOldRows"},
			Invoke:    false,
		})
	if n := calls.Load(); n != 0 {
		t.Errorf("%d function(s) were called without -invoke; calling one runs it", n)
	}
	if len(fs) != 1 || fs[0].Severity != finding.Info {
		t.Fatalf("want a single not-assessed notice, got %d findings", len(fs))
	}
	if !strings.Contains(fs[0].Description, "unmeasured, not absent") {
		t.Error("the notice does not say the tier is unmeasured, so a silent report " +
			"reads as a project with no public functions")
	}
}

// Names are never guessed. A guessed name is a stranger's code nobody asked to
// run, and the pinned wordlist is not a licence to run four hundred of them.
func TestFunctionNamesAreNeverGuessed(t *testing.T) {
	var calls atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	functionHostOverride = srv.URL
	t.Cleanup(func() { functionHostOverride = "" })

	fs := functionFindings(context.Background(),
		Detection{Provider: "firebase", Project: "p"},
		ScanOptions{
			Client: client.New(client.Options{BaseURL: srv.URL, Retries: 0}),
			Invoke: true, // consent given, and still nothing to call
		})
	if n := calls.Load(); n != 0 {
		t.Errorf("%d call(s) made for an application that names no functions", n)
	}
	if len(fs) != 1 || !strings.Contains(fs[0].Description, "not guessed") {
		t.Error("with no harvested names the scan must say it called nothing rather " +
			"than fall back to a wordlist")
	}
}

// The candidate set is capped and stable, so the same application produces the
// same probe set and a large harvest cannot turn into a large number of calls.
func TestFunctionCandidatesAreCappedAndStable(t *testing.T) {
	var many []string
	for i := 0; i < 200; i++ {
		many = append(many, "fn"+string(rune('a'+i%26))+string(rune('a'+i/26)))
	}
	got, _ := functionCandidates(nil, many)
	if len(got) > maxFunctionProbes {
		t.Errorf("%d candidates from a harvest of %d; the cap is %d calls into "+
			"somebody's project", len(got), len(many), maxFunctionProbes)
	}
	again, _ := functionCandidates(nil, many)
	for i := range got {
		if got[i] != again[i] {
			t.Fatal("the probe set is not stable between runs")
		}
	}
	// And junk that cannot be a function name is dropped rather than called.
	if names, _ := functionCandidates(nil, []string{"", "a", "has spaces", "9leading"}); len(names) != 0 {
		t.Errorf("%d unusable names would have been called", len(names))
	}
}

// The three answers, and what each is allowed to claim.
func TestFunctionsClassifyEachAnswer(t *testing.T) {
	for _, tc := range []struct {
		name    string
		status  int
		wantIDs []string
	}{
		{"publicly callable", 200, []string{"firebase-function-public"}},
		{"deployed and refused", 403, []string{"firebase-function-private"}},
		{"not deployed", 404, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
			}))
			defer srv.Close()
			functionHostOverride = srv.URL
			t.Cleanup(func() { functionHostOverride = "" })
			fs := functionFindings(context.Background(),
				Detection{Provider: "firebase", Project: "p"},
				ScanOptions{
					Client:    client.New(client.Options{BaseURL: srv.URL, Retries: 0}),
					Harvested: []string{"exportUsers"}, Invoke: true,
				})
			// Only the function VERDICTS are compared. Coverage notes are a
			// different class and are counted separately below: this case is
			// about what each status is allowed to CLAIM, not about whether the
			// scan may describe where it looked.
			var ids []string
			for _, f := range fs {
				if strings.HasPrefix(f.ID, "firebase-function-") {
					ids = append(ids, f.ID)
				}
			}
			if strings.Join(ids, ",") != strings.Join(tc.wantIDs, ",") {
				t.Errorf("got %v, want %v", ids, tc.wantIDs)
			}
			// A name that is not deployed says nothing about the ones that are,
			// so a 404 must never produce a function verdict. It MAY produce a
			// coverage note -- silence about functions has to say which regions
			// produced it, or an unexamined region reads as an empty project.
			if tc.status == 404 && len(ids) != 0 {
				t.Errorf("a 404 produced the verdict(s) %v; absence is not a result here", ids)
			}
			if tc.status == 404 {
				var note bool
				for _, f := range fs {
					if f.ID == "unruly-surface-not-assessed" {
						note = true
					}
				}
				if !note {
					t.Error("nothing answered and the scan named no region, so an " +
						"unexamined region is indistinguishable from an empty project")
				}
			}
		})
	}
}
