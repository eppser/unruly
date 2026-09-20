package surface

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/eppser/unruly/internal/client"
	"github.com/eppser/unruly/internal/finding"
)

// Routine DISCOVERY runs in every scan, including one with no flags at all.
// It must therefore not run the routines it is looking for.
//
// It used to POST {} to every candidate, which for a name that exists is a
// call. Measured against a deliberately side-effecting routine in the lab:
//
//	GET  /rpc/volatile_side_effect -> 405 25006, 0 rows written
//	POST /rpc/volatile_side_effect -> 200,       1 row  written
//
// PostgREST serves GET inside a read-only transaction, so existence stays
// decidable while the write is refused. The whole point is the request method,
// so that is what this asserts -- a test of the discovered NAMES would pass
// against either version and prove nothing about side effects.

type methodRecorder struct {
	mu      sync.Mutex
	methods map[string][]string
}

func newMethodRecorder(handler func(w http.ResponseWriter, r *http.Request)) (*methodRecorder, *httptest.Server) {
	rec := &methodRecorder{methods: map[string][]string{}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec.mu.Lock()
		rec.methods[r.URL.Path] = append(rec.methods[r.URL.Path], r.Method)
		rec.mu.Unlock()
		handler(w, r)
	}))
	return rec, srv
}

func (m *methodRecorder) mutatingCalls() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []string
	for path, methods := range m.methods {
		if !strings.Contains(path, "/rpc/") {
			continue
		}
		for _, meth := range methods {
			if meth != http.MethodGet && meth != http.MethodHead {
				out = append(out, meth+" "+path)
			}
		}
	}
	return out
}

func TestRoutineDiscoveryNeverCallsARoutine(t *testing.T) {
	// Every candidate is answered as a near-miss, so the oracle yields a name
	// and discovery does the most work it can.
	rec, srv := newMethodRecorder(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"code":"PGRST202","message":"Could not find the function",` +
			`"hint":"Perhaps you meant to call the function public.audit_log"}`))
	})
	defer srv.Close()

	c := client.New(client.Options{BaseURL: srv.URL, AnonKey: "test", RestPrefix: "/"})
	res := Result{}
	names := enumerateRoutines(context.Background(), c, Options{
		Concurrency:    4,
		RoutineSeeds:   []string{"audit", "log", "admin"},
		RoutineGuesses: []string{"purge_all_rows", "send_invoice_emails"},
	}, &res)

	if calls := rec.mutatingCalls(); len(calls) > 0 {
		t.Errorf("routine discovery issued %d mutating request(s) -- on a routine that "+
			"exists each one RUNS it, in a scan that may have passed no flags at all:\n  %s",
			len(calls), strings.Join(calls, "\n  "))
	}
	// Guard against the trivial pass where discovery probed nothing.
	if len(rec.methods) == 0 {
		t.Fatal("discovery sent no requests at all; the assertion above is vacuous")
	}
	if len(names) == 0 {
		t.Fatal("discovery found no routines, so recall was traded away for the safety")
	}
}

// A direct hit returns no hint. Discovery used to discard it, learning a real
// name only via a near-miss for it; now the two states that soundly prove
// existence are counted.
func TestRoutineDiscoveryCountsDirectHits(t *testing.T) {
	_, srv := newMethodRecorder(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/readable_routine"):
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`[{"id":1}]`))
		case strings.HasSuffix(r.URL.Path, "/writing_routine"):
			// PostgREST refusing a write inside its read-only GET transaction.
			w.WriteHeader(http.StatusMethodNotAllowed)
			w.Write([]byte(`{"code":"25006","message":"cannot execute INSERT in a read-only transaction"}`))
		default:
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte(`{"code":"PGRST202","message":"Could not find the function"}`))
		}
	})
	defer srv.Close()

	c := client.New(client.Options{BaseURL: srv.URL, AnonKey: "test", RestPrefix: "/"})
	res := Result{}
	names := enumerateRoutines(context.Background(), c, Options{
		Concurrency:    4,
		RoutineGuesses: []string{"readable_routine", "writing_routine", "absent_routine"},
	}, &res)

	found := map[string]bool{}
	for _, n := range names {
		found[n] = true
	}
	for _, want := range []string{"readable_routine", "writing_routine"} {
		if !found[want] {
			t.Errorf("direct hit on %q was discarded; it is sound evidence the routine exists", want)
		}
	}
	// A routine anon may not EXECUTE also answers 404 PGRST202, so absence and
	// no-permission are indistinguishable and neither may be claimed.
	if found["absent_routine"] {
		t.Error("404 PGRST202 was read as a routine that exists; that response is also " +
			"what a routine the caller may not execute returns")
	}
}

// A direct hit is only evidence where a miss looks different.
//
// A single-page app serves index.html with 200 for every unknown route, which
// is how essentially every React deployment is configured. The 200 branch above
// was added without a control and the not-Supabase precision eval immediately
// reported a routine per candidate prefix -- admin, admin_, admin_ad,
// admin_app. That eval needs Docker; this does not.
func TestDirectHitsAreIgnoredOnAHostThatAnswersEverything(t *testing.T) {
	_, srv := newMethodRecorder(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`<!doctype html><html><body>app</body></html>`))
	})
	defer srv.Close()

	c := client.New(client.Options{BaseURL: srv.URL, AnonKey: "test", RestPrefix: "/"})
	res := Result{}
	names := enumerateRoutines(context.Background(), c, Options{
		Concurrency:    4,
		RoutineGuesses: []string{"admin", "admin_purge", "reset_all"},
	}, &res)

	if len(names) != 0 {
		t.Errorf("a host that answers 200 to every path produced %d routine(s) %v; "+
			"a response given to every name is not evidence about any name", len(names), names)
	}
}

// The control must not be so strict that it disables direct hits on a real
// PostgREST, which would silently give back the recall the branch exists for.
func TestDirectHitsSurviveARealPostgRESTControl(t *testing.T) {
	_, srv := newMethodRecorder(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/real_routine") {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`[{"ok":true}]`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"code":"PGRST202","message":"Could not find the function"}`))
	})
	defer srv.Close()

	c := client.New(client.Options{BaseURL: srv.URL, AnonKey: "test", RestPrefix: "/"})
	res := Result{}
	names := enumerateRoutines(context.Background(), c, Options{
		Concurrency: 4, RoutineGuesses: []string{"real_routine"},
	}, &res)

	if len(names) != 1 || names[0] != "real_routine" {
		t.Errorf("the control disabled direct hits against a host that DOES discriminate; got %v", names)
	}
}

// Severity must track what was DEMONSTRATED, not what a name suggests.
//
// Found by mutation: raising the unknown-callability case from Low back to
// Medium -- so a guess is rated exactly like a proven-callable routine -- left
// every offline test green. The distinction was pinned only by the hardened
// fixture eval, which needs Docker, and Docker has been down for a large part
// of the last several sessions. A safety-relevant classification should not
// depend on a VM being up.
func TestRoutineSeverityTracksWhatWasProven(t *testing.T) {
	c := client.New(client.Options{BaseURL: "http://example.invalid", AnonKey: "k", RestPrefix: "/"})

	cases := []struct {
		name            string
		routine         string
		callable, known bool
		want            finding.Severity
		why             string
	}{
		{
			name:    "privileged name, callability never established",
			routine: "internal_recalculate_ledger", callable: false, known: false,
			want: finding.Low,
			why: "the routine takes arguments the scan cannot guess, so PostgREST " +
				"answered from its schema cache and the privilege check was never " +
				"reached; a correctly hardened project hits this exact case",
		},
		{
			name:    "privileged name, PROVEN callable by anon",
			routine: "admin_delete_everything", callable: true, known: true,
			want: finding.Medium,
			why:  "this one was demonstrated, so it must outrank the guess above",
		},
		{
			name:    "privileged name, proven NOT callable",
			routine: "admin_delete_everything", callable: false, known: true,
			want: finding.Info,
			why: "EXECUTE is revoked; the name still leaks, which is worth recording " +
				"and not worth alarming about",
		},
		{
			name:    "ordinary name, callability unknown",
			routine: "get_public_stats", callable: false, known: false,
			want: finding.Info,
			why:  "nothing about it suggests privilege and nothing was proven",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := routineFinding(c, tc.routine, tc.callable, tc.known, "")
			if got.Severity != tc.want {
				t.Errorf("severity %v, want %v: %s", got.Severity, tc.want, tc.why)
			}
		})
	}

	// The ordering is the actual claim, stated once so it cannot drift apart
	// case by case: proven-callable must always outrank unproven.
	proven := routineFinding(c, "admin_delete_everything", true, true, "").Severity
	guessed := routineFinding(c, "admin_delete_everything", false, false, "").Severity
	if !(proven > guessed) {
		t.Errorf("a routine PROVEN callable (%v) must outrank one merely suspected (%v); "+
			"rating them alike is how a hardened project gets a medium it cannot act on",
			proven, guessed)
	}
}

// Edge Functions were the other finding site the offline suite never executed:
// covered only by the fixture eval that runs the real edge-runtime, so covered
// only while Docker is up.
//
// The classification carries real weight. A deployed function with verify_jwt
// off is invoked by the act of detecting it, and functions commonly hold the
// service_role key -- so both directions matter: missing one hides an
// anonymously callable endpoint, and inventing one puts a finding on a host
// that merely answers everything.
func TestEdgeFunctionClassificationOffline(t *testing.T) {
	for _, tc := range []struct {
		status int
		want   functionState
		why    string
	}{
		{404, functionAbsent, "no function by that name"},
		{405, functionAbsent, "the platform rejects the method before any function runs"},
		{501, functionAbsent, "not implemented: no functions endpoint here"},
		{302, functionAbsent, "a redirect is a router answering, not a function"},
		{401, functionProtected, "deployed, and verify_jwt rejected the anonymous caller"},
		{403, functionProtected, "deployed and refused"},
		{200, functionReached, "the request reached the function, which means it RAN"},
		{500, functionReached, "the function ran and threw; it is still deployed and reachable"},
	} {
		if got := classifyFunction(tc.status); got != tc.want {
			t.Errorf("status %d classified %v, want %v: %s", tc.status, got, tc.want, tc.why)
		}
	}
}

// And the finding built from a reached function must say it is anonymously
// invokable, at a severity that rises when the name implies privilege.
func TestEdgeFunctionFindingSeverity(t *testing.T) {
	c := client.New(client.Options{BaseURL: "http://example.invalid", AnonKey: "k", RestPrefix: "/"})

	ordinary := functionFinding(c, EdgeFunction{
		Name: "render-og-image", Status: 200, Snippet: "ok",
	}, false)
	privileged := functionFinding(c, EdgeFunction{
		Name: "admin-delete-user", Status: 200, Snippet: "ok",
	}, false)

	if ordinary.ID != "supabase-edge-function-no-jwt" {
		t.Errorf("unexpected id %q", ordinary.ID)
	}
	if !(privileged.Severity > ordinary.Severity) {
		t.Errorf("a function whose name implies privilege (%v) must outrank an ordinary "+
			"one (%v); an anonymously callable admin-delete-user is not the same finding "+
			"as an anonymously callable image renderer",
			privileged.Severity, ordinary.Severity)
	}

	// The response body is arbitrary application output -- a user record, a
	// token, whatever the function returns -- so -redact must drop it. This
	// leaked verbatim under -redact once already.
	redacted := functionFinding(c, EdgeFunction{
		Name: "whoami", Status: 200, Snippet: "eyJhbGciOiJIUzI1NiJ9.secret.payload",
	}, true)
	if strings.Contains(redacted.Description+redacted.Evidence.Reason, "secret.payload") {
		t.Error("-redact must not emit the function's response body: it is arbitrary " +
			"application output and commonly contains credentials")
	}
}

// The Edge Function finding must be reachable BY A SCAN, not merely buildable
// by a test.
//
// The coverage audit prints exactly this caveat -- "a unit test calling the
// constructor covers the emit site while the path to it stays unreachable" --
// and the first attempt at covering this site did precisely that. Deleting the
// one direct functionFinding call put the site straight back on the uncovered
// list, which means the offline suite was proving the builder works and
// nothing about whether a scan ever gets there.
//
// This drives surface.Run against a fake functions endpoint, so the finding is
// produced the way a real scan produces it.
func TestEdgeFunctionFindingIsReachedByAScan(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := strings.TrimPrefix(r.URL.Path, "/functions/v1/")
		switch {
		case !strings.HasPrefix(r.URL.Path, "/functions/v1/"):
			// Auth, storage and PostgREST all answer "nothing here".
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte(`{"code":"PGRST202","message":"not found"}`))
		case name == ControlFunctionName:
			// The control MUST be refused or nothing else means anything.
			w.WriteHeader(http.StatusNotFound)
		case name == "public-webhook" || name == "admin-purge":
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"ok":true}`))
		case name == "secure-fn":
			w.WriteHeader(http.StatusUnauthorized)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	c := client.New(client.Options{BaseURL: srv.URL, AnonKey: "k", RestPrefix: "/"})
	res := Run(context.Background(), c, Options{
		AllowFunctions: true,
		FunctionSeeds:  []string{"public-webhook", "admin-purge", "secure-fn", "absent-fn"},
		Concurrency:    4,
	})

	got := map[string]finding.Severity{}
	for _, f := range res.Findings {
		if f.ID == "supabase-edge-function-no-jwt" {
			got[f.Resource] = f.Severity
		}
	}
	for _, want := range []string{"public-webhook", "admin-purge"} {
		if _, ok := got[want]; !ok {
			t.Errorf("%s answered 200 to an anonymous call -- it ran -- and no finding "+
				"reached the report", want)
		}
	}
	if _, ok := got["secure-fn"]; ok {
		t.Error("secure-fn answered 401: verify_jwt refused the anonymous caller, which is " +
			"the CORRECT configuration and must not be reported")
	}
	if _, ok := got["absent-fn"]; ok {
		t.Error("absent-fn is not deployed and must not be reported")
	}
	if len(got) == 2 && !(got["admin-purge"] > got["public-webhook"]) {
		t.Errorf("an anonymously callable admin-purge (%v) must outrank an anonymously "+
			"callable webhook (%v)", got["admin-purge"], got["public-webhook"])
	}
}

// And the control probe must still suppress everything on a host that answers
// every path -- the case that once produced 392 findings against example.com.
func TestEdgeFunctionsSuppressedWhenTheHostAnswersEverything(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`<!doctype html><html><body>app</body></html>`))
	}))
	defer srv.Close()

	c := client.New(client.Options{BaseURL: srv.URL, AnonKey: "k", RestPrefix: "/"})
	res := Run(context.Background(), c, Options{
		AllowFunctions: true,
		FunctionSeeds:  []string{"a", "b", "c"},
		Concurrency:    4,
	})

	for _, f := range res.Findings {
		if f.ID == "supabase-edge-function-no-jwt" {
			t.Errorf("a host that answers 200 to every path produced an Edge Function "+
				"finding for %q; a response given to every name is not evidence about "+
				"any name", f.Resource)
		}
	}
}

// The CRITICAL routine finding must name the schema its SQL will resolve in.
//
// Both routine constructors build SQL about a routine. When relations were
// schema-qualified, only one of the two was fixed, and the one missed was this
// one -- so a routine in a reporting schema got
//
//	REVOKE EXECUTE ON FUNCTION public.rebuild_daily_revenue FROM ...
//
// which does not fail safe: pasted into a console it errors, and an operator
// who reads the error as "already revoked" moves on. Found by executing the
// emitted SQL against a fixture rather than reading it.
func TestRoutineDataRemediationIsSchemaQualified(t *testing.T) {
	c := client.New(client.Options{BaseURL: "http://x", AnonKey: "k", RestPrefix: "/"})
	rows := []map[string]any{{"id": 1}}

	inSchema := routineDataFinding(c, "rebuild_daily_revenue", 1, rows, false, "reporting", 200)
	if !strings.Contains(inSchema.Remediation, "FUNCTION reporting.rebuild_daily_revenue") {
		t.Errorf("the SQL must name the schema Postgres will resolve in:\n%s",
			inSchema.Remediation)
	}
	if strings.Contains(inSchema.Remediation, "FUNCTION public.rebuild_daily_revenue") {
		t.Error("the remediation still says public. for a routine in reporting")
	}
	if inSchema.Resource != "reporting.rebuild_daily_revenue" {
		t.Errorf("resource %q must be qualified too, or it is indistinguishable from a "+
			"routine of the same name in the default schema", inSchema.Resource)
	}

	// And the default schema is still spelled public, which is what a reader
	// of the SQL expects.
	def := routineDataFinding(c, "admin_read_audit_log", 5, rows, false, "", 200)
	if !strings.Contains(def.Remediation, "FUNCTION public.admin_read_audit_log") {
		t.Errorf("default-schema remediation should name public:\n%s", def.Remediation)
	}
}

// An Edge Function's response must not carry a live credential into the report.
//
// This package's own finding text says functions commonly hold the
// service_role key. Quoted verbatim, a report saying "this function answers
// without credentials" would ship the credential it found -- and the report is
// something people paste into tickets. Masking is unconditional: -redact is a
// choice about the target's data, not a precondition for the tool declining to
// republish a key.
func TestFunctionSnippetMasksCredentials(t *testing.T) {
	const jwt = "eyJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoic2VydmljZV9yb2xlIn0.QUJDREVGR0hJSktMTU5PUA"
	body := `{"ok":true,"key":"` + jwt + `","secret":"sb_secret_abcdefghijklmnop"}`

	out := redactSnippet(body, false)
	if strings.Contains(out, jwt) {
		t.Errorf("the whole service_role key survived into the report:\n  %s", out)
	}
	if strings.Contains(out, "sb_secret_abcdefghijklmnop") {
		t.Errorf("the whole secret key survived:\n  %s", out)
	}
	// Identifiable, not erased: the reader must be able to tell WHICH key.
	if !strings.Contains(out, "eyJhbGciOiJIUzI1") {
		t.Errorf("the prefix that identifies the key was removed too:\n  %s", out)
	}
	if !strings.Contains(out, `"ok":true`) {
		t.Errorf("the rest of the body should survive; only credentials are cut:\n  %s", out)
	}

	// -redact still replaces the body wholesale.
	if r := redactSnippet(body, true); strings.Contains(r, "eyJ") {
		t.Errorf("-redact must not emit any part of the body: %s", r)
	}
}

// A control probe that never completed must not be read as a control that
// passed.
//
// The guard was written `if ctrl.Err == nil && notAbsent { bail }`, so a
// transport failure on the control skipped it and probing continued as though
// discrimination had been established. Against a host that answers every path
// -- which the exploit lab's own Cloudflare Worker does, serving 200 and HTML
// for /functions/v1/anything -- that turns the pinned function wordlist into
// findings, and any privileged-looking name in it into a HIGH.
//
// This is the could-not-measure/nothing-wrong confusion this scanner exists to
// refuse, sitting in the place where it costs the most.
func TestEdgeFunctionControlFailureIsNotAPass(t *testing.T) {
	var controlHits, otherHits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, ControlFunctionName) {
			controlHits.Add(1)
			// Fail at the transport, the way a dropped connection does.
			hj, ok := w.(http.Hijacker)
			if !ok {
				t.Fatal("cannot hijack; the fixture cannot simulate a transport failure")
			}
			conn, _, err := hj.Hijack()
			if err != nil {
				t.Fatalf("hijack: %v", err)
			}
			conn.Close()
			return
		}
		// A catch-all: every other path is answered as though something is
		// deployed there.
		otherHits.Add(1)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`<!doctype html><html><body>app</body></html>`))
	}))
	defer srv.Close()

	c := client.New(client.Options{BaseURL: srv.URL, AnonKey: "k", RestPrefix: "/", Retries: 0})
	res := &Result{}
	fns := enumerateFunctions(context.Background(), c, Options{
		FunctionSeeds: []string{"delete-user-test", "internal", "admin"},
	}, res)

	if controlHits.Load() == 0 {
		t.Fatal("the control was never probed, so this test asserts nothing")
	}
	if len(fns) != 0 {
		var names []string
		for _, f := range fns {
			names = append(names, f.Name)
		}
		t.Errorf("a host whose control probe failed reported %d deployed Edge Functions "+
			"(%v). Nothing was established about this host's ability to tell a deployed "+
			"function from an absent one", len(fns), names)
	}
	var unassessed bool
	for _, f := range res.Findings {
		if f.Resource == "edge-functions" {
			unassessed = true
		}
	}
	if !unassessed {
		t.Error("the surface was silently skipped: no finding says Edge Functions could " +
			"not be assessed, so their absence from the report reads as a project with none")
	}
	if n := otherHits.Load(); n > 0 {
		t.Errorf("%d candidate names were probed after the control failed; probing a host "+
			"whose answers cannot be interpreted is wasted traffic against somebody else's "+
			"server", n)
	}
}

// A public bucket is not a misconfiguration; it is how Supabase serves avatars.
//
// Measured over 200 real sites: 24 public buckets found, every one reported at
// MEDIUM, and they were called things like "images". A severity that fires on
// the documented way to serve a logo is a severity people learn to ignore, and
// then the one bucket called "invoices" scrolls past with it.
//
// The name is the only signal available without downloading somebody's
// objects, which this scanner will not do. It is a heuristic and the finding
// says so; the object names in the evidence are what a reader actually grades
// it on.
func TestPublicBucketSeverityFollowsTheName(t *testing.T) {
	for _, tc := range []struct {
		name string
		want finding.Severity
	}{
		// Meant to be public. Reported, but not as a problem.
		{"images", finding.Info},
		{"avatars", finding.Info},
		{"public", finding.Info},
		{"product-images", finding.Info},
		// Not meant for the open web.
		{"documents", finding.Medium},
		{"invoices", finding.Medium},
		{"backups", finding.Medium},
		{"kyc-uploads", finding.Medium},
		{"user-uploads", finding.Medium},
		{"internal-reports", finding.Medium},
		// No indication either way: say so rather than guess.
		{"bucket1", finding.Low},
		{"data", finding.Low},
	} {
		got, why := bucketSeverity(tc.name)
		if got != tc.want {
			t.Errorf("%q graded %v, want %v (%s)", tc.name, got, tc.want, why)
		}
		if why == "" {
			t.Errorf("%q graded without a stated reason", tc.name)
		}
	}
}

// The finding must carry the basis for its grade, because the grade is a guess
// about contents from a name.
func TestPublicBucketFindingStatesItsBasis(t *testing.T) {
	c := client.New(client.Options{ProjectRef: "abcdefghijklmnopqrst", AnonKey: "k"})
	f := bucketFinding(c, Bucket{Name: "invoices", Objects: []string{"inv-001.pdf"}})

	if f.Severity != finding.Medium {
		t.Errorf("severity %v for a bucket called invoices", f.Severity)
	}
	if !strings.Contains(f.Description, "heuristic") {
		t.Error("the description does not admit the grade came from the name, so a reader " +
			"cannot tell how much to trust it")
	}
	if !strings.Contains(f.Description, "object names") {
		t.Error("the description does not point at the object list, which is the real signal")
	}

	// The case that distinguishes grading from not grading: an asset bucket
	// must come out of the constructor BELOW medium. Testing only "invoices"
	// passes whether or not the grade is applied, because it is medium either
	// way -- which is exactly what the mutation harness caught.
	asset := bucketFinding(c, Bucket{Name: "images", Objects: []string{"logo.png"}})
	if asset.Severity >= finding.Medium {
		t.Errorf("a bucket called images is %v; Supabase documents public buckets as the "+
			"way to serve exactly this, and grading it the same as one called invoices is "+
			"how a severity stops meaning anything", asset.Severity)
	}
}
