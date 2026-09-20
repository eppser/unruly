package history

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/eppser/unruly/internal/client"
)

// Historical key exposure had two findings with no positive-path test, for a
// structural reason: the Wayback origin was a string literal in three places,
// so the package could only ever be exercised against the live archive. That
// made the interesting cases untestable — a bundle carrying a service_role
// key, and a key that has since been rotated — because you cannot ask the real
// archive to have captured one.
//
// ArchiveBase now names the origin. It is not test-only scaffolding: it also
// allows a mirror, a corporate proxy, or an offline replay of a CDX response.
//
// Removing a key from a build does not revoke it, which is the whole point of
// this check. A key archived in 2019 works today unless someone rotated it.

// mintJWT builds an unsigned JWT with the given role claim. The scanner reads
// the claim to decide severity and never verifies the signature, because a
// scanner holding a signing secret would be a worse problem than the one it
// reports.
func mintJWT(role string) string {
	enc := func(s string) string {
		return base64.RawURLEncoding.EncodeToString([]byte(s))
	}
	return enc(`{"alg":"HS256","typ":"JWT"}`) + "." +
		enc(`{"iss":"supabase","ref":"abcdefghijklmno","role":"`+role+`","iat":1600000000}`) +
		".c2lnbmF0dXJlLXdpdGhvdXQtYS1zZWNyZXQ"
}

// fakeArchive serves a CDX index and the archived asset bodies keyed by path.
func fakeArchive(t *testing.T, assets map[string]string) string {
	t.Helper()
	var cdx strings.Builder
	for path := range assets {
		cdx.WriteString("20190101000000 https://target.example" + path + "\n")
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/cdx/search/cdx") {
			_, _ = w.Write([]byte(cdx.String()))
			return
		}
		for path, body := range assets {
			if strings.HasSuffix(r.URL.Path, path) {
				_, _ = w.Write([]byte(body))
				return
			}
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

func runHistory(t *testing.T, o Options) Result {
	t.Helper()
	if o.Site == "" {
		o.Site = "https://target.example"
	}
	o.Limiter = client.NewLimiter(8)
	o.Timeout = 10 * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return Run(ctx, o)
}

// A service_role key is the whole database: it bypasses RLS entirely. Finding
// one in an archived bundle is the most severe thing this scanner can report,
// and until now nothing verified it was reported at all.
func TestArchivedServiceRoleKeyIsCritical(t *testing.T) {
	key := mintJWT("service_role")
	base := fakeArchive(t, map[string]string{
		"/static/app.js": "const SUPABASE_SERVICE_KEY='" + key + "';",
	})
	res := runHistory(t, Options{ArchiveBase: base})

	if len(res.Snapshots) != 1 {
		t.Fatalf("want 1 snapshot, got %d", len(res.Snapshots))
	}
	if res.Snapshots[0].Role != "service_role" {
		t.Fatalf("role claim not read: %q", res.Snapshots[0].Role)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("want 1 finding, got %d", len(res.Findings))
	}
	f := res.Findings[0]
	if f.ID != "supabase-historic-service-key-exposed" {
		t.Errorf("ID changed to %q; consumers filter on it", f.ID)
	}
	if f.Severity.String() != "critical" {
		t.Errorf("a service_role key bypasses RLS entirely; got severity %s", f.Severity)
	}
}

// The distinction that makes this check worth running: a key still in use is
// an open door, a rotated one is history. Reporting both identically would
// bury the first under the second.
func TestArchivedKeyRotatedVersusStillCurrent(t *testing.T) {
	old, current := mintJWT("anon"), mintJWT("anon")
	// Same role, different tokens: only the payload iat differs in real life,
	// so force a difference the way an actual rotation would.
	old = strings.Replace(old, ".c2ln", ".b2xk", 1)

	base := fakeArchive(t, map[string]string{
		"/static/old.js": "createClient(url,'" + old + "')",
	})

	rotated := runHistory(t, Options{ArchiveBase: base, CurrentKey: current})
	if len(rotated.Findings) != 1 {
		t.Fatalf("want 1 finding, got %d", len(rotated.Findings))
	}
	if got := rotated.Findings[0].ID; got != "supabase-historic-key-rotated" {
		t.Errorf("an archived key that is no longer the live key is history, "+
			"not an open door; got id %q", got)
	}

	stillLive := runHistory(t, Options{ArchiveBase: base, CurrentKey: old})
	if len(stillLive.Findings) != 1 {
		t.Fatalf("want 1 finding, got %d", len(stillLive.Findings))
	}
	if got := stillLive.Findings[0].ID; got != "supabase-historic-key-not-rotated" {
		t.Errorf("an archived key that is still live is the finding that matters; "+
			"got id %q", got)
	}
	if !(stillLive.Findings[0].Severity > rotated.Findings[0].Severity) {
		t.Errorf("a live archived key must outrank a rotated one: %v vs %v",
			stillLive.Findings[0].Severity, rotated.Findings[0].Severity)
	}
}

// Evidence must point at the archive actually used, or a reader replaying it
// gets a 404 from a host that never held the capture.
func TestEvidenceHonoursTheConfiguredArchive(t *testing.T) {
	base := fakeArchive(t, map[string]string{
		"/static/app.js": "k='" + mintJWT("anon") + "'",
	})
	res := runHistory(t, Options{ArchiveBase: base})
	if len(res.Findings) != 1 {
		t.Fatalf("want 1 finding, got %d", len(res.Findings))
	}
	f := res.Findings[0]
	if !strings.Contains(f.Matched, base) {
		t.Errorf("matched URL points elsewhere than the archive used: %s", f.Matched)
	}
	if !strings.Contains(f.Evidence.Request, base) {
		t.Errorf("replay command points elsewhere than the archive used: %s",
			f.Evidence.Request)
	}
}

// An archive that holds no captures is not a site with no exposed keys. The
// two must not produce the same result.
func TestEmptyArchiveIsNotACleanResult(t *testing.T) {
	base := fakeArchive(t, map[string]string{})
	res := runHistory(t, Options{ArchiveBase: base})
	if res.Captures != 0 || len(res.Findings) != 0 {
		t.Fatalf("want no captures and no findings, got %d and %d",
			res.Captures, len(res.Findings))
	}
	if res.Scanned != 0 {
		t.Fatalf("nothing was fetched, so Scanned must be 0, got %d", res.Scanned)
	}
}
