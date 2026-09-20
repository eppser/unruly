package surface

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/eppser/unruly/internal/client"
	"github.com/eppser/unruly/internal/finding"
	"github.com/eppser/unruly/internal/testrec"
)

// The arbitrary-SQL finding must be BUILT by the offline suite.
//
// The live eval exercises it against a real PostgREST and a real SECURITY
// DEFINER function, but it skips without Docker, so the coverage check counted
// this id as named-but-never-built. A finding only a fixture can produce is a
// finding CI cannot protect -- and this is the most serious one the scanner
// emits.
func newSQLServer(t *testing.T, h http.HandlerFunc) *client.Client {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return client.New(client.Options{BaseURL: srv.URL, RestPrefix: "/", AnonKey: "k", Retries: 1})
}

func TestArbitrarySQLIsReportedOnlyWhenTheStatementRan(t *testing.T) {
	c := newSQLServer(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "exec_sql") && r.URL.Query().Get("query") != "" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`[{"unruly_probe": 42}]`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"code":"PGRST202"}`))
	})

	fs, reqs := sqlExecutionFindings(context.Background(), c, []string{"exec_sql"}, "")
	if reqs == 0 {
		t.Error("no requests were made, so nothing was probed")
	}
	if len(fs) != 1 {
		t.Fatalf("expected one finding, got %d", len(fs))
	}
	f := fs[0]
	if f.ID != "supabase-anon-arbitrary-sql" {
		t.Errorf("id %s", f.ID)
	}
	if f.Severity != finding.Critical {
		t.Errorf("severity %s; executing caller SQL as the function owner is critical", f.Severity)
	}
	if !strings.Contains(f.Description, "did NOT attempt") {
		t.Error("the description raises DROP without saying nothing destructive was sent")
	}
	if !strings.Contains(f.Remediation, "REVOKE EXECUTE") {
		t.Error("remediation does not revoke the grant")
	}
	if !strings.Contains(f.Evidence.Request, "rpc/exec_sql") {
		t.Errorf("evidence does not carry a replayable request: %q", f.Evidence.Request)
	}
}

// A routine that returns its ARGUMENT rather than the result must not be
// reported. Without this, every echo helper becomes a critical finding, which
// is the false-positive design this scanner exists to avoid.
func TestEchoedArgumentIsNotArbitrarySQL(t *testing.T) {
	c := newSQLServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Answers 200, echoes the statement, computes nothing.
		_, _ = w.Write([]byte(`[{"unruly_probe": "SELECT 6*7 AS unruly_probe"}]`))
	})
	if fs, _ := sqlExecutionFindings(context.Background(), c, []string{"exec_sql"}, ""); len(fs) != 0 {
		t.Errorf("an echoing routine was reported as executing SQL: %s", fs[0].Evidence.Reason)
	}
}

// A name that does not look like a SQL executor is never called, however the
// server answers. The probe sends a statement, so the set of names it touches
// has to be decided by the pinned rule rather than by the target.
func TestNonMatchingRoutineIsNeverProbed(t *testing.T) {
	var called testrec.Log
	c := newSQLServer(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "send_invoice_email") {
			called.Add(r.URL.Path)
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"code":"PGRST202"}`))
	})
	sqlExecutionFindings(context.Background(), c, []string{"send_invoice_email"}, "")
	if called.Len() != 0 {
		t.Errorf("send_invoice_email was called %d times; a routine whose name does not "+
			"match the pinned rule must never be invoked with a statement", called.Len())
	}
}
