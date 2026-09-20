package pocketbase

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/eppser/unruly/scan"
)

// lab serves a fixed set of collections with the behaviours measured on the
// real instance, so the stage is graded against PocketBase's actual semantics
// rather than a convenient simplification.
func labServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.Contains(r.URL.Path, "/public_notes/"):
			_, _ = w.Write([]byte(`{"items":[{"id":"a1","secret":"card-4111111111111111"}],"totalItems":1}`))
		case strings.Contains(r.URL.Path, "/users/"):
			// Expression rule: 200, but every row filtered away.
			_, _ = w.Write([]byte(`{"items":[],"totalItems":0}`))
		case strings.Contains(r.URL.Path, "/locked_notes/"):
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"message":"Only superusers can perform this action.","status":403}`))
		default:
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"message":"Missing collection context.","status":404}`))
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// The stage reports the collection that returns rows, and only that one.
func TestTheStageReportsOnlyTheCollectionThatActuallyLeaks(t *testing.T) {
	srv := labServer(t)
	st := &scan.State{Target: srv.URL}
	stage := CollectionStage{Client: pbTestClient(srv.URL), Base: srv.URL,
		Collections: []string{"public_notes", "users", "locked_notes", "absent_thing"}}

	if _, err := (scan.Pipeline{stage}).Run(context.Background(), st); err != nil {
		t.Fatal(err)
	}

	var reported []string
	for _, f := range st.Findings() {
		if f.ID == "pocketbase-anon-read-exposed" {
			reported = append(reported, f.Resource)
		}
	}
	if len(reported) != 1 || reported[0] != "public_notes" {
		t.Errorf("reported %v, want only [public_notes]. users answers 200 with zero "+
			"rows because an expression rule filters them, and reporting it would fire "+
			"on the default collection of every PocketBase install", reported)
	}
}

// The finding carries the rows and a replayable request.
func TestTheFindingCarriesRowsAndAReplayableRequest(t *testing.T) {
	srv := labServer(t)
	st := &scan.State{Target: srv.URL}
	if _, err := (scan.Pipeline{CollectionStage{Client: pbTestClient(srv.URL), Base: srv.URL,
		Collections: []string{"public_notes"}}}).Run(context.Background(), st); err != nil {
		t.Fatal(err)
	}
	fs := st.Findings()
	if len(fs) == 0 {
		t.Fatal("nothing reported")
	}
	f := fs[0]
	if len(f.Evidence.Sample) == 0 {
		t.Error("no sampled row: a finding without evidence is the boolean this scanner " +
			"refuses to emit")
	}
	if !strings.Contains(f.Evidence.Request, "curl") {
		t.Errorf("no replayable request: %q", f.Evidence.Request)
	}
	if f.Protocol != "pocketbase" {
		t.Errorf("protocol %q", f.Protocol)
	}
}

// Remediation must survive being piped into psql.
//
// Operators pipe -fix output straight into a database, and the eval executes
// these blocks verbatim. PocketBase is configured through its rules, not SQL,
// so every line has to be a -- comment: readable to a human, inert to psql.
// The same rule Firebase already follows.
func TestRemediationIsEntirelyCommentedSoItCannotRunAsSQL(t *testing.T) {
	srv := labServer(t)
	st := &scan.State{Target: srv.URL}
	if _, err := (scan.Pipeline{CollectionStage{Client: pbTestClient(srv.URL), Base: srv.URL,
		Collections: []string{"public_notes"}}}).Run(context.Background(), st); err != nil {
		t.Fatal(err)
	}
	for _, f := range st.Findings() {
		for i, line := range strings.Split(f.Remediation, "\n") {
			if strings.TrimSpace(line) == "" {
				continue
			}
			if !strings.HasPrefix(strings.TrimSpace(line), "--") {
				t.Errorf("%s remediation line %d is not a comment and would EXECUTE "+
					"when piped into psql: %q", f.ID, i+1, line)
			}
		}
	}
}

// A hardened instance produces nothing at all.
func TestAHardenedInstanceProducesNoFindings(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"message":"Only superusers can perform this action.","status":403}`))
	}))
	defer srv.Close()

	st := &scan.State{Target: srv.URL}
	if _, err := (scan.Pipeline{CollectionStage{Client: pbTestClient(srv.URL), Base: srv.URL,
		Collections: []string{"public_notes", "locked_notes", "users"}}}).
		Run(context.Background(), st); err != nil {
		t.Fatal(err)
	}
	for _, f := range st.Findings() {
		if f.Severity > 0 && f.ID == "pocketbase-anon-read-exposed" {
			t.Errorf("reported %s on an instance that denies everything", f.Resource)
		}
	}
}

// Output order does not depend on the order collections were supplied.
func TestFindingOrderIsStableRegardlessOfInputOrder(t *testing.T) {
	srv := labServer(t)
	run := func(names []string) string {
		st := &scan.State{Target: srv.URL}
		if _, err := (scan.Pipeline{CollectionStage{Client: pbTestClient(srv.URL), Base: srv.URL, Collections: names}}).
			Run(context.Background(), st); err != nil {
			t.Fatal(err)
		}
		var b strings.Builder
		for _, f := range st.Findings() {
			b.WriteString(f.ID + "/" + f.Resource + ";")
		}
		return b.String()
	}
	a := run([]string{"public_notes", "users", "locked_notes"})
	c := run([]string{"locked_notes", "public_notes", "users"})
	if a != c {
		t.Errorf("order depends on input order:\n  %s\n  %s", a, c)
	}
}
