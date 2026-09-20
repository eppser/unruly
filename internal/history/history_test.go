package history

import (
	"github.com/eppser/unruly/internal/finding"
	"strings"
	"testing"
)

// The severity split is the point of this check. "Leaked and rotated" is
// history; "leaked and still current" is a live credential in a public archive.
func TestSeverityDependsOnRotation(t *testing.T) {
	notRotated := snapshotFinding(DefaultArchiveBase, "https://x.test", Snapshot{
		Timestamp: "20260317185220", URL: "https://x.test/a.js",
		KeyPrefix: "eyJhbGciOiJIUz", Role: "anon", StillCurrent: true}, false)
	if notRotated.Severity.String() != "high" {
		t.Errorf("an unrotated exposed key must be high, got %s", notRotated.Severity)
	}
	if notRotated.ID != "supabase-historic-key-not-rotated" {
		t.Errorf("wrong rule id: %s", notRotated.ID)
	}

	rotated := snapshotFinding(DefaultArchiveBase, "https://x.test", Snapshot{
		Timestamp: "20260317185220", URL: "https://x.test/a.js",
		KeyPrefix: "eyJhbGciOiJIUz", Role: "anon", StillCurrent: false}, false)
	if rotated.Severity.String() != "info" {
		t.Errorf("a rotated key is informational, got %s", rotated.Severity)
	}

	service := snapshotFinding(DefaultArchiveBase, "https://x.test", Snapshot{
		Timestamp: "20260317185220", URL: "https://x.test/a.js",
		KeyPrefix: "eyJhbGciOiJIUz", Role: "service_role", StillCurrent: false}, false)
	if service.Severity.String() != "critical" {
		t.Errorf("an exposed service_role key is critical regardless of rotation, got %s",
			service.Severity)
	}
}

// Remediation must say ROTATE. Removing a key from the current build is what
// produced this finding in the first place.
func TestRemediationSaysRotateNotRemove(t *testing.T) {
	f := snapshotFinding(DefaultArchiveBase, "https://x.test", Snapshot{
		Timestamp: "20260101000000", Role: "anon", StillCurrent: true}, false)
	if !strings.Contains(f.Remediation, "Rotate the key rather than only removing it") {
		t.Error("remediation must distinguish rotation from removal")
	}
	if !strings.Contains(f.Remediation, "does not revoke it") {
		t.Error("remediation must state that removal is not revocation")
	}
}

func TestClaimedRole(t *testing.T) {
	// {"role":"anon"} and {"role":"service_role"}, base64url, unsigned.
	anon := "eyJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoiYW5vbiJ9.sig"
	svc := "eyJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoic2VydmljZV9yb2xlIn0.sig"
	if got := claimedRole(anon); got != "anon" {
		t.Errorf("anon role = %q", got)
	}
	if got := claimedRole(svc); got != "service_role" {
		t.Errorf("service role = %q", got)
	}
	if got := claimedRole("not-a-jwt"); got != "" {
		t.Errorf("garbage should yield no role, got %q", got)
	}
}

func TestCredentialsExtraction(t *testing.T) {
	// Signatures here are realistic length: the matcher requires 8+ characters
	// per segment so short placeholders do not masquerade as tokens.
	body := `var c=createClient("https://abc.supabase.co","eyJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoiYW5vbiJ9.QUJDREVGR0hJSktMTU5PUA");
	         var p="sb_publishable_abcdefghijk";`
	got := credentials(body)
	if len(got) != 2 {
		t.Fatalf("expected 2 credentials, got %d: %v", len(got), got)
	}
	// A JWT with no recognisable Supabase role is not a Supabase credential.
	if n := len(credentials(`t="eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3OCJ9.QUJDREVGR0hJSktMTU5PUA"`)); n != 0 {
		t.Errorf("unrelated JWTs must be ignored, got %d", n)
	}
}

func TestHostOf(t *testing.T) {
	for in, want := range map[string]string{
		"https://example-app.test": "example-app.test",
		"https://a.test/path":      "a.test",
		"example-app.test":         "example-app.test",
	} {
		if got := hostOf(in); got != want {
			t.Errorf("hostOf(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestHumanTimestamp(t *testing.T) {
	if got := humanTimestamp("20250304185220"); got != "2025-03-04" {
		t.Errorf("got %q", got)
	}
}

// An archive is the one place a "removed" secret demonstrably still works, so
// it must be searched for every credential shape -- including the two worst
// ones, which for a while it was not.
//
// Postgres connection strings and Management API tokens were added to the
// live-site channel and reached nowhere else, because each channel carried its
// own copy of the patterns. Both are now in internal/creds; this asserts the
// archive channel actually looks for them.
func TestArchiveScansForConnectionStringsAndManagementTokens(t *testing.T) {
	token := "sbp_" + strings.Repeat("9z8y7x6w5v", 4)
	const uri = "postgresql://postgres:r3al-lab-pw-4d5e6f@db.abcdefghijklmnopqrst.supabase.co:5432/postgres"

	got := credentials(`<html><script>
		const ADMIN = "` + token + `";
		const DB = "` + uri + `";
		// example, must be ignored:
		const TEMPLATE = "postgresql://postgres:[YOUR-PASSWORD]@db.abcdefghijklmnopqrst.supabase.co:5432/postgres";
	</script></html>`)

	var sawToken, sawURI, sawTemplate bool
	for _, c := range got {
		switch {
		case c == token:
			sawToken = true
		case c == uri:
			sawURI = true
		case strings.Contains(c, "YOUR-PASSWORD"):
			sawTemplate = true
		}
	}
	if !sawToken {
		t.Error("a Management API token in an archived page was not recovered; that token " +
			"reaches every project in the account, and an archive is where a revoked-in-" +
			"name-only secret survives")
	}
	if !sawURI {
		t.Error("a Postgres connection string in an archived page was not recovered; it is " +
			"direct database access and the archive still serves it")
	}
	if sawTemplate {
		t.Error("the [YOUR-PASSWORD] template was recovered as a credential; Supabase's own " +
			"dashboard hands that string out and reporting it teaches people to ignore the " +
			"finding")
	}
}

// And the classification: an account-wide token must not be filed as a
// rotated anon key, which is what the pre-existing switch would have done with
// it -- info severity, "no action needed".
func TestArchivedManagementTokenIsCritical(t *testing.T) {
	f := snapshotFinding("https://web.archive.org", "https://app.example.com", Snapshot{
		Timestamp: "20240101000000",
		URL:       "https://app.example.com/",
		KeyPrefix: "sbp_9z8y7x6w5v",
	}, false)

	if f.Severity != finding.Critical {
		t.Errorf("an archived Management API token is %v; it reaches every project in the "+
			"account, and the default branch would have called it a superseded anon key "+
			"needing no action", f.Severity)
	}
	if !strings.Contains(strings.ToLower(f.Name), "management") {
		t.Errorf("the finding does not say what leaked: %q", f.Name)
	}
}
