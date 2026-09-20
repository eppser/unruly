package routes

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// A templated path becomes probeable when the operator supplies a value.
//
// /invoices/{id} is discarded today, and it has to be: {id} is not a resource,
// and inventing one would mean requesting a record belonging to somebody the
// operator never mentioned. But the operator KNOWS an id -- it is their
// application -- and once they say so the path is as probeable as any other.
//
// This is the difference between an identifier that was GIVEN and one that was
// GUESSED, and the whole of this file turns on it.
func TestASuppliedValueMakesATemplatedPathProbeable(t *testing.T) {
	params := Params{"id": "42", "slug": "q3-report"}

	for _, tc := range []struct{ in, want string }{
		{"/invoices/{id}", "/invoices/42"},
		{"/reports/{slug}/export", "/reports/q3-report/export"},
		{"/invoices/:id", "/invoices/42"},
		{"/invoices/[id]", "/invoices/42"},
	} {
		got, ok := fillTemplate(tc.in, params)
		if !ok || got != tc.want {
			t.Errorf("fillTemplate(%q) = %q, %v; want %q", tc.in, got, ok, tc.want)
		}
	}
}

// A template the operator supplied nothing for stays unprobed.
//
// Filling {customer_id} with the value given for {id} would send a request for
// a record nobody named. The path is left alone and the scan says so, rather
// than guessing and calling the result coverage.
func TestATemplateWithNoSuppliedValueIsNotGuessed(t *testing.T) {
	if got, ok := fillTemplate("/customers/{customer_id}", Params{"id": "42"}); ok {
		t.Errorf("a template with no supplied value was filled as %q. Inventing an "+
			"identifier means requesting a record belonging to somebody the operator "+
			"never mentioned, and calling the answer coverage.", got)
	}
	if _, ok := fillTemplate("/invoices/{id}", nil); ok {
		t.Error("a template was filled with no parameters supplied at all")
	}
}

// EVIDENCE SAYS WHERE THE IDENTIFIER CAME FROM.
//
// A finding on /invoices/42 means something different depending on whether 42
// was supplied by the operator or guessed by the scanner. The first says "your
// own record is readable"; the second says "a record we picked at random is
// readable, and we do not know whose". Reporting them identically would let a
// guess be read as a demonstration.
func TestAFindingRecordsWhetherTheIdentifierWasSuppliedOrGuessed(t *testing.T) {
	supplied := paramEvidence("/invoices/{id}", "/invoices/42", SourceSupplied)
	if !strings.Contains(supplied, "supplied") {
		t.Errorf("evidence %q does not say the identifier came from the operator", supplied)
	}
	guessed := paramEvidence("/invoices/{id}", "/invoices/43", SourceGuessed)
	if !strings.Contains(guessed, "guess") {
		t.Errorf("evidence %q does not say the identifier was guessed; a guess read as "+
			"a demonstration is the worst kind of finding", guessed)
	}
	if supplied == guessed {
		t.Error("supplied and guessed identifiers produce identical evidence")
	}
}

// The flag parses as an operator would type it.
func TestRouteParamsParseAsTyped(t *testing.T) {
	got := ParseParams([]string{"id=42", "slug=q3-report", " uuid = 7f3a "})
	for k, want := range map[string]string{"id": "42", "slug": "q3-report", "uuid": "7f3a"} {
		if got[k] != want {
			t.Errorf("param %q = %q, want %q (from %v)", k, got[k], want, got)
		}
	}
	// Nonsense is dropped rather than turned into a request.
	if len(ParseParams([]string{"", "novalue", "=orphan"})) != 0 {
		t.Errorf("malformed parameters produced entries: %v",
			ParseParams([]string{"", "novalue", "=orphan"}))
	}
}

// A TEMPLATE IS NEVER PROBED LITERALLY, whatever names it.
//
// The guarantee that used to live in specPaths, asserted against the scan
// itself now that templates survive parsing. A request for /invoices/%7Bid%7D
// is noise at best; the danger is the shape one step along, where a scanner
// decides {id} probably means 1 and asks for somebody's first invoice.
func TestATemplateIsNeverProbedLiterally(t *testing.T) {
	var mu sync.Mutex
	var asked []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		asked = append(asked, r.URL.Path)
		mu.Unlock()
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			w.Write([]byte(`<script src="/a.js"></script>`))
		case "/a.js":
			w.Header().Set("Content-Type", "application/javascript")
			w.Write([]byte(`fetch("/invoices/{id}");fetch("/reports/:slug");fetch("/open");`))
		default:
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"ok":true}`))
		}
	}))
	defer srv.Close()

	// No parameters supplied: every template must be left alone.
	_ = Run(context.Background(), Options{Site: srv.URL, Concurrency: 2})

	mu.Lock()
	defer mu.Unlock()
	for _, p := range asked {
		if strings.ContainsAny(p, "{}:[]") || strings.Contains(p, "%7B") {
			t.Errorf("the scan requested %q, a path template. {id} is not a resource, "+
				"and the shape one step along is a scanner deciding it probably means 1 "+
				"and asking for somebody's first invoice.", p)
		}
	}
}
