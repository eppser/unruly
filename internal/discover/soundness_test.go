package discover

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/eppser/unruly/internal/finding"

	"github.com/eppser/unruly/internal/soundness"
	"github.com/eppser/unruly/internal/testrec"
)

// Discovery is the entry point for every scan, and it is the one probe whose
// false positive is not a wrong finding but a wrong TARGET: a scan aimed at
// somebody else's project. Nothing downstream can catch that, because every
// later stage would be behaving correctly against the origin it was handed.

func siteWithHeader(csp string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if csp != "" {
			w.Header().Set("Content-Security-Policy", csp)
		}
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<html><body>an application</body></html>`))
	}))
}

func refOutcome(csp string) soundness.Outcome {
	srv := siteWithHeader(csp)
	defer srv.Close()
	res := Run(context.Background(), Options{Site: srv.URL})
	if res.ProjectRef == "" {
		return soundness.Outcome{Verdict: "no-ref", Detail: "nothing recovered"}
	}
	return soundness.Outcome{Verdict: "ref-found", Detail: res.ProjectRef + " via " + res.RefSource}
}

// The negative control is a site that HAS a Content-Security-Policy, just not
// one naming a Supabase origin. A probe keying on "the header exists" rather
// than on its contents would pass a weaker test and fail this one.
func TestProjectRefDiscoveryIsSound(t *testing.T) {
	soundness.Require(t, soundness.Probe{
		Name:          "csp-project-ref-disclosure",
		Detects:       "a Supabase project reference named in a response header",
		PositiveInput: "CSP with connect-src https://abcdefghijklmnopqrst.supabase.co",
		Positive: func() soundness.Outcome {
			return refOutcome("default-src 'self'; connect-src 'self' https://abcdefghijklmnopqrst.supabase.co")
		},
		NegativeInput: "CSP present but naming no Supabase origin",
		Negative: func() soundness.Outcome {
			return refOutcome("default-src 'self'; connect-src 'self' https://api.stripe.com")
		},
	}, "ref-found", "no-ref")
}

// A ref must be extracted exactly. Scanning a project ref that is off by one
// character is scanning a stranger.
func TestExtractedRefIsExact(t *testing.T) {
	const want = "abcdefghijklmnopqrst"
	srv := siteWithHeader("connect-src 'self' https://" + want + ".supabase.co wss://" + want + ".supabase.co")
	defer srv.Close()

	res := Run(context.Background(), Options{Site: srv.URL})
	if res.ProjectRef != want {
		t.Errorf("got project ref %q, want %q", res.ProjectRef, want)
	}
	if res.RefSource != "content-security-policy" {
		t.Errorf("source should name the channel it leaked through, got %q", res.RefSource)
	}
}

// A 20-character run inside an unrelated hostname must not be mistaken for a
// project ref. The pattern is anchored on .supabase.co for exactly this reason.
func TestUnrelatedHostsAreNotMistakenForRefs(t *testing.T) {
	for _, csp := range []string{
		"connect-src 'self' https://abcdefghijklmnopqrst.example.com",
		"connect-src 'self' https://cdn.jsdelivr.net",
		"connect-src 'self'",
	} {
		if got := refOutcome(csp); got.Verdict != "no-ref" {
			t.Errorf("csp %q produced %s; no Supabase origin is present", csp, got)
		}
	}
}

// A service_role key shipped to the browser must outrank an anon key, which is
// expected to be public. Reporting them alike is how a critical gets buried.
func TestServiceKeyOutranksAnonKey(t *testing.T) {
	// {"role":"service_role"} and {"role":"anon"}, base64url, unsigned.
	const svc = "eyJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoic2VydmljZV9yb2xlIn0.QUJDREVGR0hJSktMTU5PUA"
	const anon = "eyJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoiYW5vbiJ9.QUJDREVGR0hJSktMTU5PUA"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<html><script>createClient("https://abcdefghijklmnopqrst.supabase.co","` +
			anon + `");var admin="` + svc + `";</script></html>`))
	}))
	defer srv.Close()

	res := Run(context.Background(), Options{Site: srv.URL})
	if res.AnonKey != anon {
		t.Error("the anon key should be adopted as the scanning credential")
	}
	var critical bool
	for _, f := range res.Findings {
		if f.ID == "supabase-service-key-exposed" && f.Severity.String() == "critical" {
			critical = true
		}
	}
	if !critical {
		t.Error("a service_role key in client-side content must be reported critical")
	}
}

// mintUnsigned builds a token with the given role claim. Built rather than
// written out because CI scans content for JWT-shaped strings, and a test
// fixture that trips the secret scanner is a test nobody can commit.
func mintUnsigned(role string) string {
	seg := func(s string) string {
		return base64.RawURLEncoding.EncodeToString([]byte(s))
	}
	return seg(`{"alg":"HS256"}`) + "." + seg(`{"role":"`+role+`"}`) + "." +
		seg("not-a-real-signature-0123456789")
}

// The finding that says a key is exposed must not be the thing exposing it.
//
// Reports are pasted into tickets. A critical finding quoting the whole
// service_role key turns "here is my scan output" into a credential
// disclosure, and it does so at the exact moment the finding is telling
// somebody that too many people have this key.
//
// The live eval already asserted this against the report of a real scan, and
// catches it: replacing the truncation with the raw key fails it. But that eval
// needs Docker and credentials. The offline suite -- what a fork runs, what CI
// runs without fixtures, and what the mutation harness runs -- asserted only
// that the finding is CRITICAL, so the republish was invisible to every check
// that does not need a container.
//
// Both halves are asserted here. A scanner that redacted the key entirely would
// pass the first and leave the operator unable to tell WHICH key leaked.
func TestServiceKeyFindingDoesNotRepublishTheKey(t *testing.T) {
	svc := mintUnsigned("service_role")
	anon := mintUnsigned("anon")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<html><script>createClient("https://abcdefghijklmnopqrst.supabase.co","` +
			anon + `");var admin="` + svc + `";</script></html>`))
	}))
	defer srv.Close()

	res := Run(context.Background(), Options{Site: srv.URL})

	var found *finding.Finding
	for i := range res.Findings {
		if res.Findings[i].ID == "supabase-service-key-exposed" {
			found = &res.Findings[i]
		}
	}
	if found == nil {
		t.Fatal("no service-key finding, so this test asserts nothing about its contents")
	}

	rendered := found.Description + "\x00" + found.Remediation + "\x00" +
		found.Evidence.Reason + "\x00" + found.Evidence.Response + "\x00" +
		found.Evidence.Request + "\x00" + found.Matched + "\x00" + found.Resource
	if strings.Contains(rendered, svc) {
		t.Error("the finding carries the whole service_role key: a report is something " +
			"people paste into tickets, and this one would carry the credential with it")
	}
	// Usable evidence survives: enough to identify the key, not enough to use.
	if !strings.Contains(rendered, svc[:12]) {
		t.Error("the finding carries no prefix of the key, so an operator holding several " +
			"keys cannot tell which one leaked")
	}
}

// The most serious finding this scanner emits must be reproducible by hand.
//
// A critical that says "your service_role key is public" and offers no way to
// check it asks to be trusted, which is the one thing a scanner should never
// ask for. It shipped that way: the finding carried a truncated key prefix as
// proof and no request at all, while its sibling header finding carried one.
//
// Caught first by a live eval over a real report, which needs Docker and
// credentials -- so the mutation harness, running offline, reported the defect
// as unchecked. Asserted here instead, where a fork can run it.
func TestServiceKeyFindingIsReproducible(t *testing.T) {
	svc := mintUnsigned("service_role")
	anon := mintUnsigned("anon")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<html><script>createClient("https://abcdefghijklmnopqrst.supabase.co","` +
			anon + `");var admin="` + svc + `";</script></html>`))
	}))
	defer srv.Close()

	res := Run(context.Background(), Options{Site: srv.URL})

	for _, f := range res.Findings {
		if f.ID != "supabase-service-key-exposed" {
			continue
		}
		if strings.TrimSpace(f.Evidence.Request) == "" {
			t.Fatal("the critical finding carries no request, so nobody can reproduce the " +
				"most serious claim this scanner makes without reverse-engineering it")
		}
		// It has to point at the place the key was actually found, or it
		// reproduces something else.
		if !strings.Contains(f.Evidence.Request, srv.URL) {
			t.Errorf("the request does not name the URL the key was found at: %q",
				f.Evidence.Request)
		}
		// And it must not smuggle the key back in as part of the command.
		if strings.Contains(f.Evidence.Request, svc) {
			t.Error("the request embeds the whole key, so the reproduction instructions " +
				"republish the credential")
		}
		return
	}
	t.Fatal("no service-key finding was produced, so this test asserts nothing")
}

// A leaked Postgres URI is worse than any key this scanner looked for, and it
// looked for none.
//
// A service_role key is bounded by the APIs that accept it. A connection
// string is the database: it bypasses PostgREST entirely, so row-level
// security, the anon role and every policy discussed elsewhere in a report are
// irrelevant to whoever holds it. They reach auth.users and the schema itself.
//
// The scanner already fetches pages, JS bundles, archived assets and preview
// deployments, so the content was in hand the whole time and nothing looked at
// it for this.
func TestConnectionStringInClientContentIsCritical(t *testing.T) {
	const pw = "s3cr3t-lab-pw-9f3a2b7c"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<html><script>
			const DB = "postgresql://postgres:` + pw + `@db.abcdefghijklmnopqrst.supabase.co:5432/postgres";
		</script></html>`))
	}))
	defer srv.Close()

	res := Run(context.Background(), Options{Site: srv.URL})

	var f *finding.Finding
	for i := range res.Findings {
		if res.Findings[i].ID == "supabase-db-connection-string-exposed" {
			f = &res.Findings[i]
		}
	}
	if f == nil {
		t.Fatal("a Postgres URI with a password was served to the browser and nothing was " +
			"reported; this is direct database access and the most serious thing this " +
			"scanner can find")
	}
	if f.Severity != finding.Critical {
		t.Errorf("severity %v: a credential that bypasses RLS entirely cannot rank below "+
			"the RLS findings it makes irrelevant", f.Severity)
	}
	// The password must never travel in the report, by the same rule the
	// service_role finding follows: reports are pasted into tickets.
	rendered := f.Description + "\x00" + f.Remediation + "\x00" + f.Evidence.Reason +
		"\x00" + f.Evidence.Response + "\x00" + f.Evidence.Request
	if strings.Contains(rendered, pw) {
		t.Error("the finding carries the password, so the report that says the database " +
			"is exposed would be another copy of the thing exposing it")
	}
	// But it must still identify WHICH connection leaked.
	if !strings.Contains(f.Evidence.Response, "db.abcdefghijklmnopqrst.supabase.co") {
		t.Errorf("the finding does not name the host, so an operator holding several "+
			"projects cannot tell which one leaked: %q", f.Evidence.Response)
	}
	if strings.TrimSpace(f.Evidence.Request) == "" {
		t.Error("no request: the most serious finding this scanner makes must be " +
			"reproducible by hand")
	}
}

// The precision half, and the reason this check needs a guard at all.
//
// Supabase's own dashboard hands out a connection string containing
// [YOUR-PASSWORD], and applications ship that line in comments and .env
// examples constantly. Reporting it would put a CRITICAL on a string that
// grants nothing, which is exactly how a scanner trains people to ignore its
// most serious severity.
func TestConnectionStringTemplatesAreNotReported(t *testing.T) {
	templates := []string{
		"postgresql://postgres:[YOUR-PASSWORD]@db.abcdefghijklmnopqrst.supabase.co:5432/postgres",
		"postgres://postgres:password@localhost:5432/postgres",
		"postgresql://postgres:${DB_PASSWORD}@db.abcdefghijklmnopqrst.supabase.co:5432/postgres",
		"postgres://user:<password>@host:5432/db",
		"postgresql://postgres:changeme@db.abcdefghijklmnopqrst.supabase.co:5432/postgres",
	}
	for _, tmpl := range templates {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			w.Write([]byte(`<html><!-- example: ` + tmpl + ` --></html>`))
		}))
		res := Run(context.Background(), Options{Site: srv.URL})
		srv.Close()

		for _, f := range res.Findings {
			if f.ID == "supabase-db-connection-string-exposed" {
				t.Errorf("a template was reported as a leaked credential, at CRITICAL:\n  %s",
					tmpl)
			}
		}
	}
}

// The widest blast radius of anything this scanner can find, and it had no
// pattern for it.
//
// A service_role key compromises one project's data. A connection string
// compromises one project's database. A Supabase personal access token
// compromises the ACCOUNT: every project in the organisation, their keys,
// their database passwords, and the ability to delete them. It is the one
// credential whose exposure is not bounded by the project being scanned.
func TestManagementTokenInClientContentIsCritical(t *testing.T) {
	// Built at runtime, not written out: 44 characters with an sbp_ prefix is
	// exactly what the content secret scan is looking for.
	token := "sbp_" + strings.Repeat("a1b2c3d4e5", 4)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<html><script>const ADMIN_TOKEN = "` + token + `";</script></html>`))
	}))
	defer srv.Close()

	res := Run(context.Background(), Options{Site: srv.URL})

	var f *finding.Finding
	for i := range res.Findings {
		if res.Findings[i].ID == "supabase-management-token-exposed" {
			f = &res.Findings[i]
		}
	}
	if f == nil {
		t.Fatal("a Management API token was served to the browser and nothing was reported; " +
			"this is account-wide compromise, not a project finding")
	}
	if f.Severity != finding.Critical {
		t.Errorf("severity %v: a credential that reaches every project in the account "+
			"cannot rank below the single-project findings around it", f.Severity)
	}
	rendered := f.Description + "\x00" + f.Remediation + "\x00" + f.Evidence.Reason +
		"\x00" + f.Evidence.Response + "\x00" + f.Evidence.Request
	if strings.Contains(rendered, token) {
		t.Error("the finding carries the whole token: the report saying the account is " +
			"compromised would be another way to compromise it")
	}
	if !strings.Contains(rendered, token[:12]) {
		t.Error("no prefix, so somebody holding several tokens cannot tell which leaked")
	}
	if strings.TrimSpace(f.Evidence.Request) == "" {
		t.Error("no request: an account-wide claim must be reproducible by hand")
	}
}

// The false negative that the three-way decoder split actually caused.
//
// A service_role key whose payload contains one space -- which is what
// Python's json.dumps produces by default, and therefore what any key minted
// by an ordinary script looks like -- was not recognised as service_role here.
// It was not reported as a critical exposure. It was not even adopted as a
// key. It was silently ignored, in the channel whose whole job is finding
// credentials in client-side content.
func TestSpacedServiceRoleKeyIsStillCritical(t *testing.T) {
	seg := func(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }
	// The space after the colon is the entire bug.
	spaced := seg(`{"alg":"HS256"}`) + "." + seg(`{"role": "service_role", "ref": "abcdefghijklmnopqrst"}`) +
		"." + seg("not-a-real-signature")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<html><script>var admin = "` + spaced + `";</script></html>`))
	}))
	defer srv.Close()

	res := Run(context.Background(), Options{Site: srv.URL})

	var critical bool
	for _, f := range res.Findings {
		if f.ID == "supabase-service-key-exposed" && f.Severity == finding.Critical {
			critical = true
		}
	}
	if !critical {
		t.Error("a service_role key formatted with ordinary JSON whitespace was not " +
			"reported. Nothing about the key is unusual except a space, and the scanner " +
			"walked past the most severe thing it can find")
	}
	// And it must not be mistaken for a usable anon key.
	if res.AnonKey == spaced {
		t.Error("the service_role key was adopted as the scanning credential, which would " +
			"make every relation read as exposed")
	}
}

// Target lists carry real URLs, not tidy origins.
//
// A prospect list of live sites contains entries like
//
//	https://host/project/FirstClimate?site=IkotAbasi%2FSite1&view3d=false
//
// and the site was used by appending "/" to it, which put the slash inside the
// query: ...&view3d=false/. That is a different request from the one intended,
// and every finding built from it carried a nonsense URL that would not
// reproduce.
func TestSiteURLsWithPathsAndQueriesAreNormalised(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"https://h.example/project/X?site=A&view3d=false", "https://h.example/project/X"},
		{"https://h.example/app/#/dashboard", "https://h.example/app/"},
		{"https://h.example", "https://h.example/"},
		{"https://h.example/", "https://h.example/"},
		{"https://h.example/a/b", "https://h.example/a/b"},
	} {
		if got := normaliseSite(tc.in); got != tc.want {
			t.Errorf("normaliseSite(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// And the whole path is fetched, not just the origin: an application under a
// path ships its bundle references relative to that path.
func TestDiscoveryFetchesThePathItWasGiven(t *testing.T) {
	var asked testrec.Log
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The FULL request URI, not just the path. Appending "/" to a URL that
		// carries a query leaves the path untouched and corrupts the query
		// instead -- ?tab=1 becomes ?tab=1/ -- so a test that looked only at
		// r.URL.Path passed against the bug it was written for.
		asked.Add(r.URL.RequestURI())
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<html></html>`))
	}))
	defer srv.Close()

	Run(context.Background(), Options{Site: srv.URL + "/app/dash?tab=1"})

	if asked.Len() == 0 || asked.Entries()[0] != "/app/dash" {
		t.Errorf("fetched %v, want /app/dash exactly: the document that ships an "+
			"application's credentials is the one at the path it was given, and a query "+
			"left on (or a slash appended to) it requests something else", asked.Entries())
	}
}

// "No anon key found" says two very different things, and the scan should not
// conflate them.
//
// Measured over a list of real sites: a large share of no-key verdicts are
// applications sitting behind a sign-in screen. Their key ships in the bundle
// loaded AFTER authenticating, so the public page genuinely has none -- but
// reading that as "not a Supabase application" is wrong in a way the operator
// cannot see from the output.
//
// The detection is conservative on purpose. A password input decides it alone;
// otherwise it needs a form AND sign-in wording, because either by itself
// fires on any marketing page with a header link.
func TestLoginWallIsDistinguishedFromNotAnApplication(t *testing.T) {
	for _, tc := range []struct {
		name string
		html string
		want bool
	}{
		{"password input", `<html><form><input type="password"></form></html>`, true},
		{"single-quoted password", `<html><form><input type='password'></form></html>`, true},
		{"form plus wording", `<html><h1>Sign In</h1><form><input name="email"></form></html>`, true},
		{"german", `<html><form><input name="email"></form><p>Anmelden</p></html>`, true},
		{"marketing page with a login link", `<html><a href="/login">Login</a><p>Welcome</p></html>`, false},
		{"form with no sign-in wording", `<html><form><input name="q"></form></html>`, false},
		{"plain app shell", `<html><div id="root"></div></html>`, false},
	} {
		if got := looksLikeLogin(tc.html); got != tc.want {
			t.Errorf("%s: looksLikeLogin = %v, want %v", tc.name, got, tc.want)
		}
	}
}
