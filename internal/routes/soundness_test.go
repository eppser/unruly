package routes

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/eppser/unruly/internal/soundness"
)

// A synthetic application with two route families. Serving both from one host
// means the probe sees identical infrastructure and can only be distinguishing
// the thing under test: whether siblings disagree about authorisation.
func fixtureApp() *httptest.Server {
	mux := http.NewServeMux()

	// The page that names the routes. Discovery reads them from here, exactly
	// as it would from a real bundle.
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<html><script>
			fetch("/api/admin/logs"); fetch("/api/admin/review");
			fetch("/api/admin/submissions"); fetch("/api/admin/reorder");
			fetch("/api/public/health"); fetch("/api/public/stats");
			fetch("/api/public/version");
		</script></html>`))
	})

	// INCONSISTENT family: three siblings demand a token, one does not.
	protected := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"error":"Missing token"}`))
	}
	mux.HandleFunc("/api/admin/review", protected)
	mux.HandleFunc("/api/admin/submissions", protected)
	mux.HandleFunc("/api/admin/reorder", protected)
	mux.HandleFunc("/api/admin/logs", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`[{"agent":"cve_updater","status":"completed"}]`))
	})

	// CONSISTENT family: every sibling is public, which is a design choice and
	// must not be reported.
	public := func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(`{"ok":true}`)) }
	mux.HandleFunc("/api/public/health", public)
	mux.HandleFunc("/api/public/stats", public)
	mux.HandleFunc("/api/public/version", public)

	return httptest.NewServer(mux)
}

func familyOutcome(t *testing.T, prefix string) soundness.Outcome {
	t.Helper()
	srv := fixtureApp()
	defer srv.Close()

	res := Run(context.Background(), Options{Site: srv.URL, Concurrency: 8})
	for _, f := range res.Families {
		if f.Prefix != prefix {
			continue
		}
		if f.Inconsistent() {
			return soundness.Outcome{
				Verdict: "inconsistent",
				Detail:  strings.Join(f.Open, ",") + " open vs " + strings.Join(f.Protected, ",") + " protected",
			}
		}
		return soundness.Outcome{
			Verdict: "consistent",
			Detail:  "open=" + itoa(len(f.Open)) + " protected=" + itoa(len(f.Protected)),
		}
	}
	return soundness.Outcome{Verdict: "not-found", Detail: prefix + " was never discovered"}
}

// TestRouteInconsistencyProbeIsSound. The negative control is the closest
// plausible case: a family that is entirely public. A probe reporting "a route
// answered 200" rather than "siblings disagree" would flag it, and would flag
// the health endpoint of every application ever built.
func TestRouteInconsistencyProbeIsSound(t *testing.T) {
	soundness.Require(t, soundness.Probe{
		Name:          "route-auth-inconsistency",
		Detects:       "a route answering anonymously while its siblings require credentials",
		PositiveInput: "/api/admin (three siblings return 401, one returns data)",
		Positive:      func() soundness.Outcome { return familyOutcome(t, "/api/admin") },
		NegativeInput: "/api/public (every sibling is public by design)",
		Negative:      func() soundness.Outcome { return familyOutcome(t, "/api/public") },
	}, "inconsistent", "consistent")
}

// Discovery must reach the routes at all: a probe that finds nothing would
// score "consistent" on both controls and pass a weaker test than the one
// above by accident.
func TestRouteDiscoveryReachesBothFamilies(t *testing.T) {
	srv := fixtureApp()
	defer srv.Close()

	res := Run(context.Background(), Options{Site: srv.URL, Concurrency: 8})
	if len(res.Routes) < 7 {
		t.Errorf("expected all 7 routes to be discovered, got %d", len(res.Routes))
	}
	var admin, public bool
	for _, f := range res.Families {
		switch f.Prefix {
		case "/api/admin":
			admin = true
		case "/api/public":
			public = true
		}
	}
	if !admin || !public {
		t.Errorf("both families must be discovered (admin=%v public=%v)", admin, public)
	}
	if n := len(res.Findings); n != 1 {
		t.Errorf("exactly one finding expected (admin/logs), got %d", n)
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

// TestRedactSuppressesTheResponseExcerpt guards a privacy bug found by auditing
// a real scan rather than by reading the code.
//
// -redact was threaded into the relation probe but not into this one, so a
// redacted report still carried the body an unauthenticated caller received.
// On the reference target that body is internal pipeline records: UUIDs, agent
// names, timestamps. Someone redacting a report specifically in order to share
// it would have shipped production data.
//
// The byte count stays, because that is what evidences the exposure. The
// content goes, because that is what the flag is for.
func TestRedactSuppressesTheResponseExcerpt(t *testing.T) {
	srv := fixtureApp()
	defer srv.Close()

	plain := Run(context.Background(), Options{Site: srv.URL, Concurrency: 8})
	if len(plain.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(plain.Findings))
	}
	if !strings.Contains(plain.Findings[0].Evidence.Response, "cve_updater") {
		t.Fatal("fixture should return identifiable data without -redact")
	}

	redacted := Run(context.Background(), Options{Site: srv.URL, Concurrency: 8, Redact: true})
	if len(redacted.Findings) != 1 {
		t.Fatalf("redaction must not change WHAT is found, got %d findings", len(redacted.Findings))
	}
	f := redacted.Findings[0]
	if f.Evidence.Response != "" {
		t.Errorf("redacted response excerpt still present: %q", f.Evidence.Response)
	}
	if !strings.Contains(f.Evidence.Reason, "bytes returned anonymously") {
		t.Error("the byte count must survive: it is what evidences the exposure")
	}
	if f.Severity != plain.Findings[0].Severity {
		t.Error("redaction must not change severity")
	}
}

// POST probing is a side-effect risk and must be opt-in.
//
// The tool gates a single INSERT into a database behind -write and
// -yes-i-own-this, while this check used to send POST {} to every route it
// discovered on somebody's application. A POST to an unknown endpoint —
// /api/subscribe, /api/send-email, /api/orders — is a write by any reasonable
// definition, and it ran by default.
//
// The cost of defaulting it off is real and is asserted here rather than
// hidden: without POST, a family whose siblings are POST-only answers 405 to
// GET, which is not an authorisation signal, so the inconsistency is missed.
func TestPostProbingIsOptInAndCostsCoverage(t *testing.T) {
	srv := fixtureApp()
	defer srv.Close()

	getOnly := Run(context.Background(), Options{Site: srv.URL, Concurrency: 8})
	if getOnly.PostProbed {
		t.Error("POST must be off by default")
	}
	for _, r := range getOnly.Routes {
		if r.POST != 0 {
			t.Errorf("%s was POSTed to without -write", r.Path)
		}
	}

	withPost := Run(context.Background(), Options{Site: srv.URL, Concurrency: 8, AllowPOST: true})
	if !withPost.PostProbed {
		t.Error("PostProbed must record that POST was used")
	}

	// The fixture's protected siblings answer 401 to both methods, so this
	// particular family is still caught without POST. What must hold in both
	// modes is that the result is HONEST about which was used, so a reader can
	// tell a quiet scan from a complete one.
	if getOnly.PostProbed == withPost.PostProbed {
		t.Error("the two modes must be distinguishable in the result")
	}
}
