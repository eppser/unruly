package provider

import (
	"strings"
	"testing"

	"github.com/eppser/unruly/internal/finding"
)

// A Neon Data API endpoint in a bundle is a detection; the word "neon" is not.
//
// Verified shape, neon.com/docs/data-api/get-started:
//
//	https://ep-example.apirest.us-east-1.aws.neon.tech/neondb/rest/v1/posts
func TestNeonDetectsADataAPIEndpoint(t *testing.T) {
	d, ok := neon{}.Detect(Surface{
		Site: "https://app.example",
		Scripts: map[string]string{
			"https://app.example/main.js": `const r = await fetch(
				"https://ep-example.apirest.us-east-1.aws.neon.tech/neondb/rest/v1/posts")`,
		},
	})
	if !ok {
		t.Fatal("a Data API endpoint in a bundle was not detected")
	}
	if d.Provider != "neon" {
		t.Errorf("provider is %q", d.Provider)
	}
	if d.Project != "ep-example.apirest.us-east-1.aws.neon.tech/neondb" {
		t.Errorf("project is %q; it must identify the endpoint AND the database, "+
			"because two databases on one endpoint are two different surfaces", d.Project)
	}
	// Neon maps a request with no Authorization header onto the anonymous
	// role, so there is no key to recover. An empty credential here is the
	// correct answer, not a failure to find one.
	if d.Credential != "" {
		t.Errorf("credential is %q; Neon has no publishable key to recover", d.Credential)
	}
	if d.Source == "" {
		t.Error("detection does not say where it came from, so a reader cannot check it")
	}
}

// APIBase must carry the database segment, so the shared client's RestPrefix
// "/rest/v1/" appends with no Neon-shaped special case in the core. This is
// the abstraction test: Supabase's origin is https://<ref>.supabase.co and
// Neon's is https://<host>/<database>, and both are just the thing /rest/v1/
// hangs off.
func TestNeonAPIBaseCarriesTheDatabaseSegment(t *testing.T) {
	d := Detection{Provider: "neon",
		Project: "ep-example.apirest.us-east-1.aws.neon.tech/neondb"}
	got := neon{}.APIBase(d)
	want := "https://ep-example.apirest.us-east-1.aws.neon.tech/neondb"
	if got != want {
		t.Fatalf("APIBase is %q, want %q. Dropping the database segment points every "+
			"request at a path the endpoint does not serve.", got, want)
	}
}

// The product name alone must never be a detection.
//
// The PocketBase detector documents why: without requiring the origin, a blog
// post or a dependency list produces a confident scan of a host nobody owns.
// "neon" is a worse offender than "PocketBase" -- it is a colour, a CSS
// keyword and a dozen unrelated packages.
func TestNeonDoesNotFireOnTheWordAlone(t *testing.T) {
	for _, body := range []string{
		`import neon from "@neondatabase/serverless"`,
		`// powered by Neon`,
		`.neon-glow { color: #39ff14 }`,
		`https://neon.tech/docs/data-api`,
		`https://console.neon.tech/app/projects`,
		// A Neon Postgres connection host is NOT a Data API endpoint: no
		// apirest label, no /rest/v1/.
		`postgres://user:pw@ep-example.us-east-1.aws.neon.tech/neondb`,
	} {
		if _, ok := (neon{}).Detect(Surface{Site: "https://x", HTML: body}); ok {
			t.Errorf("detected a Neon backend from %q, which names no endpoint. A "+
				"confident scan of a host nobody owns is the worst false positive "+
				"this tool can produce.", body)
		}
	}
}

// Two endpoints in one bundle resolve to the lowest, not to whichever the
// minifier emitted first: detection order feeds report order and
// eval-determinism grades byte identity.
func TestNeonPicksAStableEndpointWhenTheBundleNamesSeveral(t *testing.T) {
	body := `a("https://ep-zzz.apirest.eu-west-1.aws.neon.tech/prod/rest/v1/x")
	         b("https://ep-aaa.apirest.eu-west-1.aws.neon.tech/prod/rest/v1/y")`
	first, ok := (neon{}).Detect(Surface{Site: "https://x", HTML: body})
	if !ok {
		t.Fatal("not detected")
	}
	if first.Project != "ep-aaa.apirest.eu-west-1.aws.neon.tech/prod" {
		t.Errorf("picked %q; the lowest origin is the stable choice", first.Project)
	}
}

// Every capability this scan does NOT assess must say so.
//
// Without this the scan is worse than silent: providerName feeds the summary,
// so a bare detection reports "neon, 0 names probed" -- a count that measures
// nothing, in a stored report an operator keeps. That is the exact shape this
// project treats as a defect elsewhere. Declaring the limits is how it says
// "could not look" instead of implying "looked and found nothing".
//
// CapEscalate and CapWrite are deliberately absent from the list below:
// backend/neon measures both. It is named here rather than dropped silently, so that adding
// a stage always means editing this list and stating which capability moved.
// Anything still on the list and unlisted in Cannot() fails.
func TestNeonDeclaresEveryUnmeasuredCapability(t *testing.T) {
	c := neon{}.Cannot()
	// CapListing joined the measured set: the OpenAPI root is
	// not served, which is true and was the wrong conclusion -- PostgREST's
	// hint oracle volunteers table names on a near miss, and backend/neon now
	// uses it through internal/enumerate unchanged.
	for _, measured := range []Capability{CapEscalate, CapWrite, CapListing} {
		if _, still := c[measured]; still {
			t.Errorf("%v is measured by backend/neon but is still declared "+
				"unmeasurable; the report would say it could not look at a check "+
				"it ran", measured)
		}
	}
	for _, cap := range []Capability{
		CapRead, CapStorage, CapExecute, CapRealtime,
	} {
		why, ok := c[cap]
		if !ok {
			t.Errorf("%q is not declared. An undeclared capability reads as one that "+
				"was measured and found clean.", cap)
			continue
		}
		if len(why) < 40 {
			t.Errorf("%q is declared with %q, which does not say why", cap, why)
		}
	}
}

// The reason must say the scan sent nothing, because that is the fact an
// operator needs: a Neon endpoint in a bundle belongs to whoever owns the
// project, and this tool did not touch it.
func TestNeonSaysItSentNothing(t *testing.T) {
	why := neon{}.Cannot()[CapRead]
	for _, want := range []string{"sent nothing", "not permission"} {
		if !strings.Contains(why, want) {
			t.Errorf("the declared limit never says %q: %q", want, why)
		}
	}
}

// The declaration must reach a report through the REGISTRY, not just exist.
//
// Every other test in this file constructs neon{} directly, so all of them
// would still pass if the init() registration were dropped -- and the scan
// would then detect a Neon endpoint and say nothing about it. That is the exact
// failure the seam already had once: "a provider could declare its stages and
// nothing would run them, which is exactly where PocketBase was -- detecting a
// target and then reporting nothing about it."
//
// NotMeasuredFor is the path cmd/unruly actually takes (main.go calls it for
// every detection), and it looks the provider up BY NAME in the registry.
func TestNeonsDeclaredLimitsReachTheReportThroughTheRegistry(t *testing.T) {
	d := Detection{Provider: "neon",
		Project: "ep-example.apirest.us-east-1.aws.neon.tech/neondb"}

	fs := NotMeasuredFor(d)
	if len(fs) == 0 {
		t.Fatal("a detected Neon backend produces no coverage findings. Either the " +
			"provider is not registered or it no longer declares its limits, and " +
			"either way the scan reports a backend it silently did not assess.")
	}
	if len(fs) != len(neon{}.Cannot()) {
		t.Errorf("got %d findings for %d declared limits", len(fs), len(neon{}.Cannot()))
	}
	for _, f := range fs {
		// The id the exit-code contract reads as blindness. A new id here would
		// be a coverage gap exit 3 does not know about.
		if f.ID != "unruly-surface-not-assessed" {
			t.Errorf("coverage finding carries id %q", f.ID)
		}
		if f.Severity != finding.Info {
			t.Errorf("%q is severity %v; a scanner diagnostic must never reach a "+
				"reader filtering for things to fix", f.Resource, f.Severity)
		}
		if !strings.Contains(f.Matched, "neon.tech") {
			t.Errorf("finding does not name the endpoint it is about: %q", f.Matched)
		}
	}
}

// Registered() must list it, because the README control keys on that list and
// a backend nobody is told about is a capability nobody uses.
func TestNeonIsRegistered(t *testing.T) {
	for _, n := range Registered() {
		if n == "neon" {
			return
		}
	}
	t.Fatalf("neon is not in Registered(): %v", Registered())
}
