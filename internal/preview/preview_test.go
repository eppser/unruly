package preview

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/eppser/unruly/internal/client"
	"github.com/eppser/unruly/internal/discover"
	"github.com/eppser/unruly/internal/finding"
)

func discoverResult(key, source string) discover.Result {
	return discover.Result{AnonKey: key, KeySource: source}
}

func TestCandidatesDerivesNetlifyHosts(t *testing.T) {
	got := Candidates("https://acme.netlify.app", nil)
	index := map[string]bool{}
	for _, g := range got {
		index[g] = true
	}
	for _, want := range []string{
		"main--acme.netlify.app",
		"staging--acme.netlify.app",
		"deploy-preview-1--acme.netlify.app",
	} {
		if !index[want] {
			t.Errorf("expected candidate %q", want)
		}
	}
	// The production host is already scanned; reporting its key here would
	// double-count what discovery found.
	if index["acme.netlify.app"] {
		t.Error("the production host must not be probed as its own preview")
	}
}

func TestCandidatesDerivesPagesHosts(t *testing.T) {
	got := Candidates("https://myproject.pages.dev", nil)
	index := map[string]bool{}
	for _, g := range got {
		index[g] = true
	}
	if !index["develop.myproject.pages.dev"] {
		t.Error("expected a branch host under the project")
	}
	if index["myproject.pages.dev"] {
		t.Error("the production host must not be probed as its own preview")
	}
}

// Vercel preview hosts embed a team slug that cannot be guessed from outside,
// so nothing is derived for them. Claiming coverage there would be inventing
// hostnames and reporting the 404s as a clean result.
func TestCandidatesDerivesNothingForVercel(t *testing.T) {
	if got := Candidates("https://acme.vercel.app", nil); len(got) != 0 {
		t.Errorf("vercel previews are not derivable, got %v", got)
	}
	// They can still be supplied.
	got := Candidates("https://acme.vercel.app",
		[]string{"acme-git-main-team.vercel.app"})
	if len(got) != 1 || got[0] != "acme-git-main-team.vercel.app" {
		t.Errorf("an explicit host must be probed, got %v", got)
	}
}

func TestCandidatesIsDeterministicAndDeduplicated(t *testing.T) {
	a := Candidates("https://acme.netlify.app", []string{"x.example", "x.example"})
	b := Candidates("https://acme.netlify.app", []string{"x.example", "x.example"})
	if len(a) != len(b) {
		t.Fatalf("run-to-run length differs: %d vs %d", len(a), len(b))
	}
	for i := range a {
		if a[i] != b[i] {
			t.Fatalf("run-to-run difference at %d: %q vs %q", i, a[i], b[i])
		}
	}
	var dupes int
	for i := 1; i < len(a); i++ {
		if a[i] == a[i-1] {
			dupes++
		}
	}
	if dupes != 0 {
		t.Errorf("%d duplicate candidates", dupes)
	}
}

// An ordinary domain yields nothing, so a scan of a normal site does not fire
// dozens of requests at hostnames that were never going to exist.
func TestCandidatesIgnoresUnknownPlatforms(t *testing.T) {
	if got := Candidates("https://example.com", nil); len(got) != 0 {
		t.Errorf("no platform pattern matches, got %v", got)
	}
}

// A key that differs from production is the one worth waking somebody for: it
// is live and rotating production would not have touched it.
func TestKeyFindingRanksADifferentKeyHigher(t *testing.T) {
	same := keyFinding("main--acme.netlify.app",
		discoverResult("KEY", "bundle"), "KEY")
	diff := keyFinding("main--acme.netlify.app",
		discoverResult("OTHER", "bundle"), "KEY")
	if !(diff.Severity > same.Severity) {
		t.Errorf("a different key must outrank the same one: %s vs %s",
			diff.Severity, same.Severity)
	}
	if !strings.Contains(diff.Description, "may not know is live") {
		t.Error("the finding must say why a different key matters")
	}
	if diff.ID != "supabase-preview-deployment-key" {
		t.Errorf("ID changed to %q; consumers filter on it", diff.ID)
	}
}

// Run is the path that actually touches the network, and it had no test: the
// derivation and the finding constructor were covered, and the sweep itself
// had fired exactly once, by hand. That is the state this project's own rule
// calls "not known to work".
func TestRunReportsOnlyHostsThatServeAKey(t *testing.T) {
	withKey := serve(t, `<script>const SUPABASE_ANON_KEY="`+fakeJWT+`";</script>`)
	noKey := serve(t, `<html><body>a perfectly ordinary page</body></html>`)

	res := Run(context.Background(), Options{
		Hosts:      []string{hostOnly(withKey), hostOnly(noKey), "127.0.0.1:1"},
		CurrentKey: "a-different-production-key",
	})

	if len(res.Probed) != 3 {
		t.Fatalf("every candidate must be recorded as probed, got %v", res.Probed)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("only the host serving a key should produce a finding, got %d", len(res.Findings))
	}
	if res.Findings[0].Resource != hostOnly(withKey) {
		t.Errorf("the wrong host was reported: %s", res.Findings[0].Resource)
	}
	// A host that answered but served nothing is not a finding, and a host
	// that never answered is not "reachable". Conflating the two is how a
	// sweep reports a dead hostname as clean.
	for _, r := range res.Reachable {
		if r == "127.0.0.1:1" {
			t.Error("an unreachable host must not be recorded as reachable")
		}
	}
}

// The sweep must not invent work. Nothing supplied and no derivable platform
// means no requests at all.
func TestRunDoesNothingWithoutCandidates(t *testing.T) {
	res := Run(context.Background(), Options{Site: "https://example.com"})
	if len(res.Probed) != 0 || len(res.Findings) != 0 || res.Requests != 0 {
		t.Errorf("no candidates means no work: %+v", res)
	}
}

// A syntactically valid anon JWT. Not a credential: the extractor reads the
// shape, and a scanner holding a signing secret would be a worse problem than
// the one it reports.
// The signature segment must be at least eight characters: the extractor's
// regex requires three substantial base64 segments, and a stub ending ".sig"
// silently matched nothing, which read as "the sweep found no key" rather than
// "the fixture was not a JWT".
const fakeJWT = "eyJhbGciOiJIUzI1NiJ9." +
	"eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImFiY2RlZmdoaWprbG1ubyIsInJvbGUiOiJhbm9uIn0." +
	"c2lnbmF0dXJlLXdpdGhvdXQtYS1zZWNyZXQ"

func serve(t *testing.T, body string) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

// The test servers speak http, and a candidate carrying its own scheme must
// be honoured rather than forced to https.
func hostOnly(u string) string { return u }

// -rate-limit is a courtesy control, and this sweep sends requests to hosts
// that may not even be the operator's. A stage that bypasses the limiter has
// happened twice in this codebase already: vocabulary harvesting built its own
// client and never called Wait, and before that three other stages did. The
// limiter's own unit test cannot catch it, because a stage that never reaches
// the limiter is not testing the limiter. So this watches the server.
func TestRunHonoursTheRateLimit(t *testing.T) {
	var served int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&served, 1)
		_, _ = w.Write([]byte("<html>nothing here</html>"))
	}))
	t.Cleanup(srv.Close)

	const rps = 4
	// DISTINCT hosts. The first version passed the same URL twelve times, and
	// Candidates deduplicates — so one request was made, the pacing assertion
	// never engaged, and the test passed having measured nothing. A path
	// suffix keeps them distinct while still hitting the one test server.
	hosts := make([]string, 12)
	for i := range hosts {
		hosts[i] = fmt.Sprintf("%s/h%d", srv.URL, i)
	}
	start := time.Now()
	res := Run(context.Background(), Options{
		Hosts: hosts, Limiter: client.NewLimiter(rps),
	})
	elapsed := time.Since(start)

	n := atomic.LoadInt64(&served)
	if n == 0 {
		t.Fatal("no requests reached the server; the sweep did not run")
	}
	// The bucket starts full, so the first rps requests are free.
	if n > rps {
		floor := time.Duration(float64(n-rps)/float64(rps)*float64(time.Second)) - 150*time.Millisecond
		if elapsed < floor {
			t.Errorf("%d requests at %d rps finished in %s, under the %s floor; this "+
				"stage is not paced and -rate-limit does not cover it",
				n, rps, elapsed.Round(time.Millisecond), floor.Round(time.Millisecond))
		}
	}
	t.Logf("%d requests at %d rps took %s (%d candidates deduplicated to %d)",
		n, rps, elapsed.Round(time.Millisecond), len(hosts), len(res.Probed))
}

// A preview deployment shipping a service_role key is the single most valuable
// thing this package can find, and it was silently dropped.
//
// discover does not put a privileged key in AnonKey — it turns it into a
// critical supabase-service-key-exposed finding — so a host serving only a
// secret key hit the "nothing found" branch, produced no finding, and was not
// even recorded as reachable. An audit found it.
func TestRunReportsAServiceRoleKeyOnAPreviewHost(t *testing.T) {
	const serviceJWT = "eyJhbGciOiJIUzI1NiJ9." +
		"eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImFiY2RlZmdoaWprbG1ubyIsInJvbGUiOiJzZXJ2aWNlX3JvbGUifQ." +
		"c2lnbmF0dXJlLXdpdGhvdXQtYS1zZWNyZXQ"
	host := serve(t, `<script>const SUPABASE_SERVICE_KEY="`+serviceJWT+`";</script>`)

	res := Run(context.Background(), Options{Hosts: []string{host}})

	if len(res.Findings) == 0 {
		t.Fatal("a preview deployment serving a service_role key must be reported")
	}
	var critical bool
	for _, f := range res.Findings {
		if f.Severity == finding.Critical {
			critical = true
		}
		if !strings.Contains(f.Description, "preview deployment") {
			t.Errorf("the finding must say where it was found: %s", f.Description)
		}
		if f.Resource == "" {
			t.Error("the finding must name the host")
		}
	}
	if !critical {
		t.Error("a key that bypasses row-level security is critical wherever it is served")
	}
	if len(res.Reachable) != 1 {
		t.Errorf("the host answered and must be recorded as reachable, got %v", res.Reachable)
	}
}

// -timeout must bind this stage. Options.Timeout was declared, never passed to
// discover, and never set by the caller, so every host got a 20-second default
// however short the operator asked for — up to 23 derived hosts, seven minutes
// of it. Every other stage honours the flag; this one arrived later and missed
// it.
func TestRunHonoursTheTimeout(t *testing.T) {
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(3 * time.Second)
		_, _ = w.Write([]byte("<html>too late</html>"))
	}))
	t.Cleanup(slow.Close)

	start := time.Now()
	res := Run(context.Background(), Options{
		Hosts:   []string{slow.URL},
		Timeout: 300 * time.Millisecond,
	})
	elapsed := time.Since(start)

	t.Logf("slow host abandoned after %s (server sleeps 3s; the test's own duration "+
		"includes httptest waiting for that handler to return)", elapsed.Round(time.Millisecond))
	if elapsed > 2*time.Second {
		t.Errorf("a 300ms timeout must abandon a slow host quickly, took %s", elapsed)
	}
	// Abandoning it is not the same as finding nothing there, but the sweep
	// reports only what it saw — the host simply does not appear.
	if len(res.Findings) != 0 {
		t.Errorf("a host that never answered cannot have served a key: %v", res.Findings)
	}
}
