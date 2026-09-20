package eval_test

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/eppser/unruly/internal/client"
	"github.com/eppser/unruly/internal/discover"
	"github.com/eppser/unruly/internal/enumerate"
	"github.com/eppser/unruly/internal/escalate"
	"github.com/eppser/unruly/internal/finding"
	"github.com/eppser/unruly/internal/postgrest"
	"github.com/eppser/unruly/internal/preview"
	"github.com/eppser/unruly/internal/probe"
	"github.com/eppser/unruly/internal/routes"
	"github.com/eppser/unruly/internal/schemas"
	"github.com/eppser/unruly/internal/surface"
	"github.com/eppser/unruly/internal/wordlist"
)

// Supabase projects routinely expose more than one PostgREST schema -- the
// reference target exposes three. A scanner that probes only the default sees
// nothing in the others, reports nothing, and nothing is what a clean project
// looks like: the same false-negative shape as depending on the OpenAPI root.
//
// The fixture adds a `reporting` schema with a readable table and a table
// protected by REVOKE rather than by RLS.
func TestFixtureScansASecondSchema(t *testing.T) {
	_, c := loadFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	sch := schemas.Discover(ctx, c)
	if !sch.Answered {
		t.Fatal("PostgREST names its exposed schemas when asked for one that cannot exist; " +
			"the oracle did not answer, so the multi-schema pass has nothing to work from")
	}
	var sawReporting bool
	for _, s := range sch.Extra {
		if s == "reporting" {
			sawReporting = true
		}
	}
	if !sawReporting {
		t.Fatalf("the fixture exposes public and reporting; extra schemas found: %v", sch.Extra)
	}

	rc := c.WithSchema("reporting")
	en := enumerate.Run(ctx, rc, enumerate.Options{
		Seeds:       wordlist.Merge([]string{"daily", "revenue", "daily_revenue", "revenue_secrets"}, wordlist.Relations()),
		Concurrency: 8,
	})
	if !en.Discriminating {
		t.Fatal("the control probe must show this schema distinguishes present from absent")
	}

	names := map[string]bool{}
	for _, n := range en.Names() {
		names[n] = true
	}
	if !names["daily_revenue"] {
		t.Errorf("reporting.daily_revenue is readable by anon and was not discovered; "+
			"found %v", en.Names())
	}
	// Protected by REVOKE: PostgREST answers 401 with SQLSTATE 42501 and names
	// the table, which proves it exists. Dropping it made a whole schema read
	// as empty against a real project.
	if !names["revenue_secrets"] {
		t.Errorf("reporting.revenue_secrets is protected with REVOKE, so Postgres answers "+
			"42501 and names it -- that is proof it exists. found %v", en.Names())
	}

	pr := probe.Run(ctx, rc, en.Names(), probe.Options{SampleRows: 2, Concurrency: 8})
	state := map[string]postgrest.ReadState{}
	rows := map[string]int{}
	for _, rel := range pr.Relations {
		state[rel.Name] = rel.Read
		rows[rel.Name] = rel.Rows
	}
	if state["daily_revenue"] != postgrest.ReadExposed {
		t.Errorf("reporting.daily_revenue grants SELECT to anon and must read as exposed, got %v",
			state["daily_revenue"])
	}
	if rows["daily_revenue"] != 14 {
		t.Errorf("the fixture seeds 14 rows; got %d", rows["daily_revenue"])
	}
	if state["revenue_secrets"] == postgrest.ReadExposed {
		t.Error("reporting.revenue_secrets has no grants; reporting it as exposed would be " +
			"a false positive on a correctly protected table")
	}

	// Findings must be schema-qualified, or one for reporting.daily_revenue is
	// indistinguishable from one for a default-schema table of the same name.
	var qualified bool
	for _, f := range pr.Findings(c.RestBase(), false) {
		if f.Resource == "daily_revenue" {
			qualified = true // the probe package emits the bare name; main.go qualifies it
		}
	}
	if !qualified {
		t.Error("expected a finding for daily_revenue to hand to the qualifier")
	}
	if strings.Contains(c.WithSchema("reporting").Schema(), "public") {
		t.Error("WithSchema must address the named schema")
	}
}

// A SECURITY DEFINER routine in a non-default schema is the shape this whole
// feature exists for: anon may EXECUTE it, it runs with the owner's rights,
// and it returns rows from a table anon cannot read. Both direct signals say
// "protected" -- the relation refuses the read, and a scanner that probes
// routines only in the default schema sees nothing -- while the data is one
// RPC call away.
//
// Verified by hand against the fixture before this test was written:
//
//	GET  reporting.revenue_secrets          -> 401
//	POST reporting.rebuild_daily_revenue()  -> [{"id":1,"secret":"do-not-leak"}]
func TestFixtureFindsARoutineInASecondSchema(t *testing.T) {
	_, c := loadFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	rc := c.WithSchema("reporting")
	res := surface.Routines(ctx, rc, surface.Options{
		RoutineSeeds:   []string{"rebuild", "daily", "revenue", "rebuild_daily_revenue"},
		RoutineGuesses: []string{"rebuild_daily_revenue"},
		Concurrency:    8,
		AllowInvoke:    true,
	})

	var found bool
	for _, r := range res.Routines {
		if r == "rebuild_daily_revenue" {
			found = true
		}
	}
	if !found {
		t.Fatalf("the routine in the reporting schema was not discovered; found %v", res.Routines)
	}
	if !res.Callable["rebuild_daily_revenue"] {
		t.Error("anon holds EXECUTE on it, so it must be reported as callable rather than " +
			"as an unproven name")
	}

	// The rows it returns are the point: reporting.revenue_secrets refuses the
	// direct read, so this is data reachable only through the routine.
	var critical bool
	for _, f := range res.Findings {
		if f.ID == "supabase-rpc-returns-data" && f.Resource == "rebuild_daily_revenue" {
			critical = true
			if len(f.Evidence.Sample) == 0 {
				t.Error("a routine that handed over rows must carry them as proof")
			}
		}
	}
	if !critical {
		t.Error("the routine returned rows from a table anon cannot read; that is " +
			"supabase-rpc-returns-data, not a name disclosure")
	}
}

// Auth, storage and Edge Functions are project-wide. Re-running them per schema
// would issue the same requests again and report the same findings several
// times, which is why the per-schema pass calls Routines rather than Run.
func TestFixturePerSchemaPassDoesNotRepeatProjectWideSurfaces(t *testing.T) {
	_, c := loadFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	res := surface.Routines(ctx, c.WithSchema("reporting"), surface.Options{
		RoutineSeeds: []string{"rebuild"}, Concurrency: 4,
	})
	for _, f := range res.Findings {
		switch f.Protocol {
		case "gotrue", "storage", "functions":
			t.Errorf("the per-schema pass emitted a %s finding (%s); those surfaces are "+
				"project-wide and are covered once by the main pass", f.Protocol, f.ID)
		}
	}
	if res.Buckets != nil || res.Auth.Reachable {
		t.Error("Routines must not touch auth or storage")
	}
}

// The elevated pass must cover every exposed schema, not just the default one.
//
// It ran only over the default schema at first, which made it NARROWER than
// the anonymous pass -- the wrong way round, since the whole point is that the
// authenticated role sees more. Where signup is open anyone can hold that role,
// so a relation granted to authenticated in a reporting schema is effectively
// public while an anonymous scan records it as protected.
//
// Fixture: reporting.member_invoices is revoked from anon and granted to
// authenticated. Verified by hand -- anon 401, authenticated returns rows.
func TestFixtureEscalationCoversASecondSchema(t *testing.T) {
	_, c := loadFixture(t)
	elevated := os.Getenv("UNRULY_FIXTURE_AUTHED_KEY")
	if elevated == "" {
		t.Skip("UNRULY_FIXTURE_AUTHED_KEY is required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	rc := c.WithSchema("reporting")
	names := []string{"member_invoices", "daily_revenue", "revenue_secrets"}
	base := probe.Run(ctx, rc, names, probe.Options{SampleRows: 2, Concurrency: 4})

	esc := escalate.Compare(ctx, rc, base, escalate.Options{
		Relations:   names,
		ElevatedKey: elevated,
		SampleRows:  2,
		Concurrency: 4,
	})

	gained := map[string]bool{}
	for _, g := range esc.Gains {
		gained[g.Relation] = true
	}
	if !gained["member_invoices"] {
		t.Errorf("reporting.member_invoices is revoked from anon and granted to "+
			"authenticated, which is the definition of a gain; gains found: %v", esc.Gains)
	}
	if gained["daily_revenue"] {
		t.Error("anon can already read reporting.daily_revenue, so it is not a gain; " +
			"reporting it would double-count every public relation")
	}
	if gained["revenue_secrets"] {
		t.Error("neither role can read reporting.revenue_secrets; it must not be a gain")
	}

	var critical bool
	for _, f := range esc.Findings {
		if f.ID == "supabase-authenticated-escalation" && f.Resource == "member_invoices" {
			critical = f.Severity == finding.Critical
		}
	}
	if !critical {
		t.Error("the gained rows carry member_email, so the finding must be critical")
	}
}

// supabase-service-key-exposed is the tool's clearest critical -- a
// service_role key shipped to the browser bypasses RLS entirely -- and its
// end-to-end path had never executed.
//
// A sweep of every documented finding id against every available target showed
// it was produced only by unit tests calling the constructor. Building a
// fixture that actually serves such a key found two defects at once: the
// scanner reported nothing, because an explicit -site was being discarded when
// -target was also given, so the page was never fetched.
//
// The key is minted at fixtures-up time, never committed. A JWT-shaped string
// in the tree trips this repository's own secret scan, and a fixture is not a
// reason to keep a credential around.
func TestFixtureServiceKeyExposedIsReported(t *testing.T) {
	if os.Getenv("UNRULY_LIVE") != "1" {
		t.Skip("set UNRULY_LIVE=1 to run live evals")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	d := discover.Run(ctx, discover.Options{Site: "http://127.0.0.1:54322"})

	var found *finding.Finding
	for i := range d.Findings {
		if d.Findings[i].ID == "supabase-service-key-exposed" {
			found = &d.Findings[i]
		}
	}
	if found == nil {
		t.Fatalf("the fixture site ships a service_role key in its JavaScript and no "+
			"finding was produced; got %d finding(s)", len(d.Findings))
	}
	if found.Severity != finding.Critical {
		t.Errorf("severity %v: a service_role key in the browser bypasses RLS for every "+
			"table in the project", found.Severity)
	}
	// The proof must not be the key itself.
	if strings.Contains(found.Evidence.Reason+found.Description, "eyJhbGciOiJIUzI1NiJ9.eyJyb2xl") {
		t.Error("the finding quotes the whole key; a prefix is enough to identify it and " +
			"the report is an artifact people paste into tickets")
	}
}

// app-route-auth-inconsistency was another id no real scan had ever produced.
//
// It is a genuine class -- a route answering anonymously while its siblings
// demand credentials is usually one somebody forgot, and routes under an admin
// prefix commonly run with the service_role key -- and it had been built only
// by unit tests.
//
// The fixture serves two families so this grades precision as well as recall:
//
//	/api/admin/users     200   flagged, high (privileged prefix)
//	/api/admin/settings  401
//	/api/admin/logs      401
//	/api/public/*        200   all open, and NOT a finding
//
// A public API is not a misconfiguration. A scanner that flags one is unusable
// on the applications people actually run, so the consistent family matters as
// much as the broken one.
func TestFixtureRouteInconsistencyIsFoundWithoutFlaggingPublicAPIs(t *testing.T) {
	if os.Getenv("UNRULY_LIVE") != "1" {
		t.Skip("set UNRULY_LIVE=1 to run live evals")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	res := routes.Run(ctx, routes.Options{Site: "http://127.0.0.1:54322", Concurrency: 4})

	if len(res.Routes) < 6 {
		t.Fatalf("expected the six referenced routes to be discovered, got %d; without "+
			"them this test grades nothing", len(res.Routes))
	}

	var flagged []string
	for _, f := range res.Findings {
		if f.ID == "app-route-auth-inconsistency" {
			flagged = append(flagged, f.Resource)
			if strings.HasPrefix(f.Resource, "/api/public/") {
				t.Errorf("%s is one of three siblings that are ALL open; a public API is "+
					"not a finding", f.Resource)
			}
			if f.Severity != finding.High {
				t.Errorf("%s sits under an admin prefix, which is where service_role "+
					"routes live; severity %v", f.Resource, f.Severity)
			}
			if f.Evidence.Reason == "" {
				t.Errorf("%s carries no evidence", f.Resource)
			}
		}
	}
	if len(flagged) != 1 || flagged[0] != "GET /api/admin/users" {
		t.Errorf("expected exactly GET /api/admin/users to be flagged, got %v", flagged)
	}
}

// unruly-probes-unresolved is the scanner's "I could not measure this"
// signal, and it is the closest thing the tool has to a thesis statement: a
// candidate that got no readable answer is indistinguishable in a report from
// one that was measured and found absent, unless something says so.
//
// It had never been produced by a scan of any target. The fixture reproduces
// what actually happens in the field -- a project under a rate limit where
// most probes answer and some do not -- rather than a host that refuses
// everything, which is a different and louder finding.
func TestFixtureThrottledProbesAreReportedAsUnresolved(t *testing.T) {
	if os.Getenv("UNRULY_LIVE") != "1" {
		t.Skip("set UNRULY_LIVE=1 to run live evals")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	c := client.New(client.Options{
		BaseURL: "http://127.0.0.1:54323", AnonKey: "x", RestPrefix: "/", Retries: 1,
	})
	res := enumerate.Run(ctx, c, enumerate.Options{
		Seeds:       []string{"user", "users", "token", "tokens", "order", "orders"},
		Concurrency: 4,
	})

	// The control answers 404, so the target DOES discriminate. Without that
	// this would be the non-discriminating case instead, and the unresolved
	// counter would never be the thing under test.
	if !res.Discriminating {
		t.Fatal("the control relation answers 404 on this fixture, so absent and present " +
			"are distinguishable and the unresolved path is what should fire")
	}
	if res.Unresolved == 0 {
		t.Fatal("four seed names are answered with 429 and none of them resolved; " +
			"counting them as measured-and-absent is exactly the false negative this " +
			"signal exists to prevent")
	}

	f, ok := res.UnresolvedFinding("http://127.0.0.1:54323", res.Unresolved)
	if !ok {
		t.Fatal("unresolved probes must produce a finding, not a log line: the artifact is " +
			"what gets stored and diffed")
	}
	if f.ID != "unruly-probes-unresolved" {
		t.Errorf("id %q; consumers filter on it", f.ID)
	}
	if !strings.Contains(f.Description, "LOWER BOUND") {
		t.Errorf("the reader has to learn the relation list is incomplete, or they will "+
			"read it as the full set: %s", f.Description)
	}
}

// supabase-preview-deployment-key: a branch build nobody remembers, still
// serving a live credential. That is where a key survives a production
// rotation, and the rule had only ever been built by unit tests.
//
// The fixture serves a DIFFERENT anon key from production's, so the medium
// branch fires. Building it found that mint-jwt accepted --sub and silently
// ignored it for anon tokens, so the two keys came out byte identical and the
// finding took its "already public" branch -- the fixture would have
// documented the wrong expectation.
func TestFixturePreviewDeploymentKeyIsReported(t *testing.T) {
	if os.Getenv("UNRULY_LIVE") != "1" {
		t.Skip("set UNRULY_LIVE=1 to run live evals")
	}
	production := os.Getenv("UNRULY_FIXTURE_KEY")
	if production == "" {
		t.Skip("UNRULY_FIXTURE_KEY is required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	res := preview.Run(ctx, preview.Options{
		Hosts:      []string{"http://127.0.0.1:54324"},
		CurrentKey: production,
	})

	var f *finding.Finding
	for i := range res.Findings {
		if res.Findings[i].ID == "supabase-preview-deployment-key" {
			f = &res.Findings[i]
		}
	}
	if f == nil {
		t.Fatalf("the preview host serves an anon key and no finding was produced; got %d",
			len(res.Findings))
	}
	if f.Severity != finding.Medium {
		t.Errorf("severity %v: the preview key DIFFERS from production's, so it is a "+
			"credential a production rotation would not have touched -- not merely "+
			"another copy of something already public", f.Severity)
	}
	if !strings.Contains(f.Description, "differs") {
		t.Errorf("the description must say which case this is: %s", f.Description)
	}
}
