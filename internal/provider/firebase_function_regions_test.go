package provider

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/eppser/unruly/internal/client"
)

// Silence about functions must say which regions produced it.
//
// Cloud Functions are addressed per region, and this check tries us-central1
// plus one region inferred from the Realtime Database URL -- which only helps
// when the project HAS an RTDB and it names one of four regions the inference
// knows. Google offers dozens. A project whose functions live in
// asia-northeast1 with no RTDB is probed in us-central1, answers 404 to every
// name, and produces no finding at all.
//
// That output is identical to a project with no functions, which is the same
// confusion this scanner refuses everywhere else: absence of a finding is only
// evidence when the scan could look. Here it could not look in the one place
// that mattered, and said nothing about it.
//
// The fix is not to probe every region -- each probe RUNS somebody's code, and
// dozens of regions times 25 names is hundreds of executions. It is to report
// where the scan actually looked, so a reader can tell an empty result from an
// unexamined one.
func TestFunctionSilenceNamesTheRegionsTried(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound) // nothing deployed where we looked
	}))
	defer srv.Close()
	functionHostOverride = srv.URL
	t.Cleanup(func() { functionHostOverride = "" })

	fs := functionFindings(context.Background(),
		Detection{Provider: "firebase", Project: "p"},
		ScanOptions{
			Client:   client.New(client.Options{BaseURL: srv.URL, Retries: 0}),
			Supplied: []string{"publicEcho"}, Invoke: true,
		})

	var said bool
	for _, f := range fs {
		if strings.Contains(f.Description, "us-central1") {
			said = true
		}
	}
	if !said {
		var got []string
		for _, f := range fs {
			got = append(got, f.ID)
		}
		t.Errorf("every name answered 404 and the scan reported %v, naming no region. "+
			"A project whose functions live somewhere this scan never tried gets exactly "+
			"this output, and so does a project with no functions at all", got)
	}
}

// And when a function IS found, the coverage note must not fire: a report that
// warns about regions on every scan is a report people learn to skip.
func TestFunctionCoverageNoteIsQuietWhenSomethingAnswers(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()
	functionHostOverride = srv.URL
	t.Cleanup(func() { functionHostOverride = "" })

	fs := functionFindings(context.Background(),
		Detection{Provider: "firebase", Project: "p"},
		ScanOptions{
			Client:   client.New(client.Options{BaseURL: srv.URL, Retries: 0}),
			Supplied: []string{"publicEcho"}, Invoke: true,
		})
	for _, f := range fs {
		if strings.Contains(f.Description, "regions this scan tried") {
			t.Errorf("the region coverage note fired on a scan that DID find a function: %s", f.ID)
		}
	}
}
