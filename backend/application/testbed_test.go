package application

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/eppser/unruly/internal/finding"
	"github.com/eppser/unruly/scan"
)

// The testbed: an application whose backend is a separate API origin.
//
// Modelled on a real chain an assessor walked by hand, starting from nothing
// but a homepage. Every element here is one they actually used, rebuilt
// synthetically -- no real host, no real address, no real record.
//
//  1. the homepage ships a bundle
//  2. the bundle names an ABSOLUTE API origin on another host
//  3. that origin serves /openapi.json, a full internal specification
//  4. it also serves /docs and /redoc, interactive documentation
//  5. the specification names collection endpoints holding real data
//  6. those endpoints correctly answer 401
//  7. ONE endpoint outside any /api prefix answers 200 with a live record
//     containing an employee email
//
// unruly reported zero application routes against the original. This exists so
// that statement can be measured rather than argued about, and so the fix can
// be shown to work rather than asserted.
type testbed struct {
	App *httptest.Server
	API *httptest.Server
	// hits records every path the API origin was asked for, so a test can
	// assert what was and was not probed.
	//
	// Behind a mutex: handlers run concurrently and a bare map write inside one
	// is a data race the detector catches only when requests happen to overlap.
	// This repository has a check for exactly that, and it caught this.
	mu   sync.Mutex
	hits map[string]int
}

// Hits reports how many times a path was requested.
func (tb *testbed) Hits(path string) int {
	tb.mu.Lock()
	defer tb.mu.Unlock()
	return tb.hits[path]
}

func newTestbed(t *testing.T) *testbed {
	t.Helper()
	tb := &testbed{hits: map[string]int{}}

	spec := map[string]any{
		"openapi": "3.0.0",
		"info":    map[string]any{"title": "internal", "version": "1"},
		// No `security` block at all. That is not evidence the endpoints are
		// open, and it is not evidence they are closed: the assessor's point
		// was that a scanner must probe regardless and report what happened.
		"paths": map[string]any{
			"/crm/customers": op("list customers"),
			"/candidates":    op("list candidates"),
			"/invoices":      op("list invoices"),
			"/documents":     op("list documents"),
			"/internal/logs": op("read internal logs"),
			"/system/mode":   op("read system mode"),
		},
	}
	specJSON, err := json.Marshal(spec)
	if err != nil {
		t.Fatalf("marshal spec: %v", err)
	}

	tb.API = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tb.mu.Lock()
		tb.hits[r.URL.Path]++
		tb.mu.Unlock()
		switch r.URL.Path {
		case "/openapi.json":
			w.Header().Set("Content-Type", "application/json")
			w.Write(specJSON)
		case "/docs", "/redoc":
			w.Header().Set("Content-Type", "text/html")
			w.Write([]byte(`<title>API docs</title><div id="swagger-ui"></div>`))
		case "/system/mode":
			// THE FINDING. A live, database-backed record, to anyone, with an
			// employee address in it. Outside every prefix the extractor knows.
			w.Header().Set("Content-Type", "application/json")
			// The field is named *_email rather than the real record's
			// `updated_by`, and that difference is forced rather than chosen.
			//
			// The real leak was an address in a NAME-NEUTRAL field, which only
			// the value classifier could catch -- and the value classifier
			// deliberately ignores reserved domains, because seed data uses
			// them precisely because they can never belong to a real person.
			// Every domain safe to commit to this repository is reserved. So
			// the value-only case cannot be exercised here at all, which is
			// the same limit recorded in benchmark/corpus/METHOD.md for the
			// same reason.
			//
			// What IS faithful: a live record, served to anyone, holding an
			// employee address. The mechanism under test is the same.
			w.Write([]byte(`{"success":true,"data":{"mode":"maintenance",` +
				`"updated_by_email":"ops.lead@example.invalid",` +
				`"updated_at":"2026-08-21T09:14:00Z"},"error":null}`))
		case "/crm/customers", "/candidates", "/invoices", "/documents", "/internal/logs":
			// Correctly protected. These are the CONTROLS: a scan that reports
			// them as exposed is worse than one that misses /system/mode.
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(`{"detail":"Not authenticated"}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(tb.API.Close)

	tb.App = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			w.Write([]byte(`<!doctype html><script src="/assets/index-a91f2.js"></script>`))
		case "/assets/index-a91f2.js":
			w.Header().Set("Content-Type", "application/javascript")
			// The shape a real bundle uses: the origin as a constant, then
			// paths concatenated onto it. Nothing here starts with "/api".
			w.Write([]byte(`const API_BASE="` + tb.API.URL + `";` +
				`export const getMode=()=>fetch(API_BASE+"/system/mode");` +
				`export const listCustomers=()=>fetch(API_BASE+"/crm/customers");` +
				`export const getInvoice=(id)=>fetch(API_BASE+"/invoices/"+id);`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(tb.App.Close)
	return tb
}

func op(summary string) map[string]any {
	return map[string]any{"get": map[string]any{"summary": summary,
		"responses": map[string]any{"200": map[string]any{"description": "ok"}}}}
}

// THE FALSE NEGATIVE, as a test.
//
// Four independent failures, each verified against the code before this was
// written:
//
//  1. the bundle names an ABSOLUTE origin, and the extractor requires a
//     leading "/" -- zero matches
//  2. /system/mode is outside the six prefixes the extractor accepts -- zero
//     matches even same-origin
//  3. nothing probes /openapi.json, /docs or /redoc outside the Supabase path
//  4. a finding is emitted only for an INCONSISTENT family, so a lone endpoint
//     answering 200 to anyone produces nothing at all
//
// The fourth is the one that makes the others worth fixing: without it, an
// endpoint discovered and probed and returning a live record is still silent.
// knownTestbedGaps is how many steps of the chain unruly still misses.
//
// A ratchet, in the style of the ones that closed the provider boundary. The
// testbed is red on purpose today -- that is the whole point of building it --
// and a permanently failing test is one people learn to ignore, so the failure
// is counted instead. It may only fall.
//
// Lower it in the same commit that closes a gap. Raising it means something
// that worked stopped working.
const knownTestbedGaps = 0

func TestTheTestbedChainIsReproduced(t *testing.T) {
	tb := newTestbed(t)
	fs := runApplicationScan(t, tb.App.URL, tb.API.URL)

	var sawRecord, sawSpec, sawDocs bool
	for _, f := range fs {
		switch {
		case strings.Contains(f.ID, "public-record") || strings.Contains(f.ID, "route-exposed"):
			sawRecord = true
		case strings.Contains(f.ID, "openapi"):
			sawSpec = true
		case strings.Contains(f.ID, "docs"):
			sawDocs = true
		}
	}

	gaps := map[string]bool{
		"the API origin the bundle names was never requested, so nothing downstream " +
			"could have found anything": tb.Hits("/system/mode") == 0,

		"a full OpenAPI specification was served anonymously and nothing reported it; " +
			"that document is what turns 'everything answers 401' into a targeted " +
			"inventory": !sawSpec,

		"interactive API documentation was served anonymously and nothing reported it": !sawDocs,

		"/system/mode returned a live record containing an employee address to an " +
			"anonymous caller and nothing reported it -- the finding the whole chain " +
			"leads to, and the one missed on a real target": !sawRecord,
	}

	var open []string
	for why, stillBroken := range gaps {
		if stillBroken {
			open = append(open, why)
		}
	}
	sort.Strings(open)

	if len(open) > knownTestbedGaps {
		t.Errorf("%d of the chain's steps are missed (ceiling %d):\n  - %s",
			len(open), knownTestbedGaps, strings.Join(open, "\n  - "))
	}
	if len(open) < knownTestbedGaps {
		t.Errorf("only %d steps are still missed, below the ceiling of %d. Lower "+
			"knownTestbedGaps to %d in the same commit -- a ratchet nobody tightens "+
			"stops measuring anything.\nStill open:\n  - %s",
			len(open), knownTestbedGaps, len(open), strings.Join(open, "\n  - "))
	}
}

// And the controls: endpoints that correctly refuse must NOT be reported.
//
// A scan that reports the 401s as exposures is worse than one that misses
// /system/mode -- it sends somebody to fix five things that are already right,
// and it discredits the finding that is real.
func TestProtectedEndpointsAreNotReportedAsExposed(t *testing.T) {
	tb := newTestbed(t)
	for _, f := range runApplicationScan(t, tb.App.URL, tb.API.URL) {
		for _, protected := range []string{"/crm/customers", "/candidates", "/invoices",
			"/documents", "/internal/logs"} {
			if strings.Contains(f.Resource, protected) && f.Severity != finding.Info {
				t.Errorf("%s answers 401 to anonymous callers and was reported as %s (%s)",
					protected, f.Severity, f.ID)
			}
		}
	}
}

// runApplicationScan runs the real application plan against a site, exactly as
// the command does.
//
// Through Stages() and the pipeline rather than by calling routes.Run
// directly: the false negative was partly about what the plan reaches, and a
// helper that skips the plan would test a path no operator uses.
func runApplicationScan(t *testing.T, site string, allowed ...string) []finding.Finding {
	t.Helper()
	st := &scan.State{Target: site}
	stages := Stages(Config{
		Site: site, AllowedOrigins: allowed, Concurrency: 2, MaxBundles: 20,
		Timeout: 10 * time.Second,
	})
	if _, err := scan.Pipeline(stages).Run(context.Background(), st); err != nil {
		t.Fatalf("run: %v", err)
	}
	return st.Findings()
}

// app-public-record-exposure is what the testbed's chain leads to.
//
// Named explicitly so the id is held by a test: if the check stopped working,
// the ratchet above would notice the gap reopening, but nothing would say
// WHICH finding disappeared.
func TestTheExposedRecordIsReportedUnderItsOwnID(t *testing.T) {
	tb := newTestbed(t)
	var got *finding.Finding
	for _, f := range runApplicationScan(t, tb.App.URL, tb.API.URL) {
		if f.ID == "app-public-record-exposure" {
			ff := f
			got = &ff
		}
	}
	if got == nil {
		t.Fatal("no app-public-record-exposure finding; the endpoint that serves a " +
			"live record to anonymous callers is the whole point of the chain")
	}
	if !strings.Contains(got.Matched, "/system/mode") {
		t.Errorf("the finding points at %q rather than the endpoint that leaked", got.Matched)
	}
	if strings.Contains(got.Description+fmt.Sprint(got.Evidence.Sample),
		"ops.lead@example.invalid") {
		t.Error("the finding repeats the exposed address; the report must not be a " +
			"second copy of the leak")
	}
	if len(got.Evidence.Classes) == 0 {
		t.Error("the finding names no data class, so it says something was exposed " +
			"without saying what")
	}
}

// The specification and the documentation are reported under their own ids.
//
// Named explicitly so each id is held by a test. The ratchet above would
// notice a gap reopening, but not WHICH finding vanished -- and these two are
// deliberately separate findings, so a check that collapsed them into one
// would satisfy the ratchet while losing the distinction.
func TestTheSpecificationAndDocsAreReportedUnderTheirOwnIDs(t *testing.T) {
	tb := newTestbed(t)
	fs := runApplicationScan(t, tb.App.URL, tb.API.URL)

	want := map[string]string{
		"app-openapi-schema-exposed": "/openapi.json",
		"app-docs-exposed":           "/docs",
	}
	for id, path := range want {
		var got *finding.Finding
		for _, f := range fs {
			if f.ID == id {
				ff := f
				got = &ff
			}
		}
		if got == nil {
			t.Errorf("no %s finding; the API served %s to an anonymous caller", id, path)
			continue
		}
		if !strings.Contains(got.Matched, path) {
			t.Errorf("%s points at %q rather than %s", id, got.Matched, path)
		}
	}

	// And the specification must not be republished in the finding. It named
	// endpoints an operator has not decided are public; copying the document
	// into a report that gets stored and pasted spreads it further than the
	// server did.
	for _, f := range fs {
		if f.ID != "app-openapi-schema-exposed" {
			continue
		}
		if strings.Contains(f.Description, "\"paths\"") ||
			strings.Contains(fmt.Sprint(f.Evidence.Sample), "\"paths\"") {
			t.Error("the finding carries the specification document itself; it is " +
				"parsed and discarded, and what survives is the count")
		}
	}
}

// An endpoint named ONLY in the specification is still probed.
//
// This is what a published specification is worth, and the testbed did not
// prove it: every endpoint in its spec was also named in its bundle, so
// deleting the spec-to-probe-list wiring changed nothing and the mutation
// SURVIVED. The fixture agreed with the code for the wrong reason.
//
// On the real target the specification named CRM, candidate, invoice,
// document, credential, financial, user and internal-log endpoints -- most of
// which the front end never called from the page an assessor started on. The
// spec's value is precisely that it names what the bundle does not.
func TestAnEndpointNamedOnlyInTheSpecIsProbed(t *testing.T) {
	tb := newTestbed(t)
	_ = runApplicationScan(t, tb.App.URL, tb.API.URL)

	// /internal/logs appears in the specification and in no bundle.
	if tb.Hits("/internal/logs") == 0 {
		t.Error("an endpoint named only in the published specification was never " +
			"probed. The specification's whole value is that it names endpoints the " +
			"front end does not call, and without probing those the document has been " +
			"read and not used.")
	}
	// And the bundle-only path is still probed: the two sources are merged,
	// not swapped.
	if tb.Hits("/system/mode") == 0 {
		t.Error("the bundle-named endpoint stopped being probed; the specification " +
			"must add to what the bundles found rather than replace it")
	}
}

// A REAL bypass is still found after the control probe was added.
//
// The control that stopped five false positives could just as easily have
// stopped every true one. This fixture has an endpoint that genuinely honours
// X-Original-URL -- a reverse proxy authorising the path it received and
// forwarding the one the header names, which is the commonest bypass there is.
//
// Without this, "the controls pass" would mean the check had been switched off.
func TestARealBypassIsStillFound(t *testing.T) {
	var mu sync.Mutex
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		// The misconfiguration: the header is honoured and the check is not
		// re-applied to the path it names.
		if r.Header.Get("X-Original-URL") == "/admin/users" {
			w.Write([]byte(`{"users":[{"role":"admin","contact_email":"a@b.invalid"}]}`))
			return
		}
		switch r.URL.Path {
		case "/":
			w.Write([]byte(`{"service":"api"}`))
		case "/admin/users":
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(`{"detail":"Not authenticated"}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer api.Close()

	app := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			w.Write([]byte(`<script src="/a.js"></script>`))
		case "/a.js":
			w.Header().Set("Content-Type", "application/javascript")
			w.Write([]byte(`const API="` + api.URL + `";fetch(API+"/admin/users");`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer app.Close()

	var found bool
	for _, f := range runApplicationScan(t, app.URL, api.URL) {
		if f.ID == "app-auth-bypass" && strings.Contains(f.Description, "X-Original-URL") {
			found = true
		}
	}
	if !found {
		t.Error("an endpoint that refuses a plain request and serves the data when " +
			"X-Original-URL names it was not reported. The control added to stop five " +
			"false positives must not have stopped the true ones as well.")
	}
}

// One account reading another's record, end to end.
//
// The unit tests fix the three-way comparison; this fixes that the scan
// actually performs it. Two endpoints, deliberately:
//
//	/invoices/42 -- checks that somebody is signed in and NOT whose record it
//	                is. Both identities get the same body. The finding.
//	/profile     -- scoped correctly: each identity gets its own row from the
//	                same URL. Must stay silent, and it is the control that
//	                matters, because a check reporting it would flag every
//	                correctly built endpoint in the application.
func TestOneAccountReadingAnothersRecordIsFoundEndToEnd(t *testing.T) {
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/":
			w.Write([]byte(`{"service":"api"}`))
		case "/invoices/42":
			if auth == "" {
				w.WriteHeader(http.StatusUnauthorized)
				w.Write([]byte(`{"detail":"Not authenticated"}`))
				return
			}
			// The bug: signed in is enough.
			w.Write([]byte(`{"id":42,"customer":"acme","contact_email":"ap@acme.invalid"}`))
		case "/profile":
			if auth == "" {
				w.WriteHeader(http.StatusUnauthorized)
				w.Write([]byte(`{"detail":"Not authenticated"}`))
				return
			}
			// Correct: the row is selected FOR the caller.
			w.Write([]byte(`{"me":"` + strings.TrimPrefix(auth, "Bearer ") + `"}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer api.Close()

	app := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			w.Write([]byte(`<script src="/a.js"></script>`))
		case "/a.js":
			w.Header().Set("Content-Type", "application/javascript")
			w.Write([]byte(`const API="` + api.URL + `";` +
				`fetch(API+"/invoices/{id}");fetch(API+"/profile");`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer app.Close()

	st := &scan.State{Target: app.URL}
	stages := Stages(Config{
		Site: app.URL, AllowedOrigins: []string{api.URL},
		Concurrency: 2, MaxBundles: 20, Timeout: 10 * time.Second,
		RouteParams: map[string]string{"id": "42"},
		Principals:  []string{"a=token-a", "b=token-b"},
	})
	if _, err := scan.Pipeline(stages).Run(context.Background(), st); err != nil {
		t.Fatalf("run: %v", err)
	}

	var onInvoice, onProfile bool
	for _, f := range st.Findings() {
		if f.ID != "app-cross-identity-read" {
			continue
		}
		switch {
		case strings.Contains(f.Matched, "/invoices/42"):
			onInvoice = true
		case strings.Contains(f.Matched, "/profile"):
			onProfile = true
		}
	}
	if !onInvoice {
		t.Error("an endpoint that returns the SAME record to two different accounts, " +
			"and refuses anonymous callers, was not reported. That is a login being " +
			"mistaken for an authorisation.")
	}
	if onProfile {
		t.Error("/profile returns each caller their OWN row from one URL -- the correct " +
			"design -- and was reported as a cross-account read. A check that flags " +
			"that flags every correctly built endpoint in the application.")
	}
}
