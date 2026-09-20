package eval_test

// Evals against the local fixture. Skipped unless the stack is up.
//
//	cd fixtures/lab && docker compose up -d
//	export UNRULY_FIXTURE_KEY=$(cat anon.jwt)
//	UNRULY_LIVE=1 go test ./internal/eval -run Fixture -v
//
// The cloud target checks realism; this one checks coverage. It exercises
// states the real application does not contain, including the probe's cleanup
// path, which no cloud relation has ever triggered.

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/eppser/unruly/internal/client"
	"github.com/eppser/unruly/internal/enumerate"
	"github.com/eppser/unruly/internal/escalate"
	"github.com/eppser/unruly/internal/eval"
	"github.com/eppser/unruly/internal/probe"
	"github.com/eppser/unruly/internal/surface"
)

func loadFixture(t *testing.T) (*eval.Target, *client.Client) {
	t.Helper()
	if os.Getenv("UNRULY_LIVE") != "1" {
		t.Skip("set UNRULY_LIVE=1 to run live evals")
	}
	tgt, err := eval.LoadTarget(filepath.Join("..", "..", "evals", "targets", "lab-fixture.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	key, err := tgt.AnonKey()
	if err != nil {
		t.Skip(err)
	}
	c := client.New(client.Options{
		ProjectRef: tgt.ProjectRef,
		BaseURL:    tgt.BaseURL,
		RestPrefix: tgt.RestPrefix,
		AnonKey:    key,
		Retries:    1,
	})
	// Before grading anything, prove the fixture is answering. A dead Docker
	// daemon otherwise reports as a scanner regression.
	if err := eval.Reachable(context.Background(), c, eval.ReachabilityProbe); err != nil {
		t.Fatal(err)
	}
	return tgt, c
}

// TestFixtureProbeAccuracy grades read and write classification against a
// posture that is known by construction rather than by observation.
func TestFixtureProbeAccuracy(t *testing.T) {
	tgt, c := loadFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	start := time.Now()
	pr := probe.Run(ctx, c, tgt.RelationNames(), probe.Options{
		Write:      true,
		SampleRows: 3,
	})
	elapsed := time.Since(start)

	graded := eval.Grade(tgt, eval.Observation{
		Relations:       tgt.RelationNames(),
		ReadExposed:     pr.ReadExposed(),
		InsertReachable: pr.InsertReachable(),
		Rows:            pr.Rows(),
	})
	t.Logf("probed %d relations in %s (%d requests)",
		len(tgt.RelationNames()), elapsed.Round(time.Millisecond), pr.Requests)
	t.Logf("\n%s", graded)

	// This test runs only the probe stage, so dimensions belonging to other
	// stages are graded by their own dedicated tests.
	elsewhere := map[string]bool{
		"routine-discovery": true, // TestFixtureRoutineDiscovery
		"escalation-gains":  true, // TestFixtureEscalation
	}
	for _, s := range graded.Scores {
		if elsewhere[s.Dimension] {
			continue
		}
		if !s.Perfect() {
			t.Errorf("%s", s)
		}
	}
	if len(graded.RowCountErrors) > 0 {
		t.Errorf("row-count mismatches: %v", graded.RowCountErrors)
	}
	for _, rel := range pr.Relations {
		if rel.CleanupErr != "" {
			t.Errorf("probe row left behind in %s: %s", rel.Name, rel.CleanupErr)
		}
	}
}

// TestFixtureCleanupRestoresRowCount is the regression guard for the one probe
// path that never runs against the cloud target: a relation where every column
// is nullable or defaulted, so an empty INSERT genuinely succeeds. The probe
// must create the row, delete it, and leave the count exactly where it started.
func TestFixtureCleanupRestoresRowCount(t *testing.T) {
	tgt, c := loadFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	const rel = "all_defaults_insertable"
	var want int
	for _, r := range tgt.Expect.Relations {
		if r.Name == rel {
			want = r.Rows
		}
	}
	if want == 0 {
		t.Fatalf("%s missing from ground truth", rel)
	}

	before := probe.Run(ctx, c, []string{rel}, probe.Options{SampleRows: 1})
	if got := before.Rows()[rel]; got != want {
		t.Fatalf("baseline drifted: %s has %d rows, ground truth says %d "+
			"(a previous run may have left a probe row behind)", rel, got, want)
	}

	// This INSERT actually lands a row.
	wr := probe.Run(ctx, c, []string{rel}, probe.Options{Write: true, SampleRows: 1})
	if len(wr.InsertReachable()) != 1 {
		t.Errorf("expected %s to be reported writable, got %v", rel, wr.InsertReachable())
	}
	for _, r := range wr.Relations {
		if r.CleanupErr != "" {
			t.Fatalf("cleanup failed, fixture now polluted: %s", r.CleanupErr)
		}
		t.Logf("write verdict: %s (%s)", r.Write, r.WriteWhy)
	}

	after := probe.Run(ctx, c, []string{rel}, probe.Options{SampleRows: 1})
	if got := after.Rows()[rel]; got != want {
		t.Errorf("probe changed the database: %s went from %d to %d rows", rel, want, got)
	} else {
		t.Logf("row count preserved across a write probe that genuinely inserted: %d", got)
	}
}

// TestFixtureWriteOnlyRelationIsNotMissed pins the case every read-only scanner
// gets wrong: a relation that reads empty but accepts anonymous writes.
func TestFixtureWriteOnlyRelationIsNotMissed(t *testing.T) {
	tgt, c := loadFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	pr := probe.Run(ctx, c, []string{"write_only_policy", "protected_rls_no_policy"},
		probe.Options{Write: true, SampleRows: 1})

	if len(pr.ReadExposed()) != 0 {
		t.Errorf("neither relation leaks rows; got read exposure for %v", pr.ReadExposed())
	}
	got := pr.InsertReachable()
	if len(got) != 1 || got[0] != "write_only_policy" {
		t.Errorf("expected exactly write_only_policy to be writable, got %v", got)
	}
	_ = tgt
}

// TestFixtureSensitiveColumnsRaiseSeverity checks the classifier against a
// relation built to contain credentials and PII.
func TestFixtureSensitiveColumnsRaiseSeverity(t *testing.T) {
	tgt, c := loadFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	pr := probe.Run(ctx, c, tgt.ReadExposed(), probe.Options{SampleRows: 2})
	fs := pr.Findings(c.RestBase(), false)
	if len(fs) == 0 {
		t.Fatal("expected findings")
	}
	if fs[0].Resource != "leaky_credentials" {
		t.Errorf("the credential-bearing relation must rank first, got %s", fs[0].Resource)
	}
	if fs[0].Severity.String() != "critical" {
		t.Errorf("expected critical, got %s", fs[0].Severity)
	}
	t.Logf("top finding: [%s] %s columns=%v", fs[0].Severity, fs[0].Resource, fs[0].Evidence.Columns)
}

// TestFixtureRoutineDiscovery measures the function hint oracle against known
// routines, seeded only with generic vocabulary rather than the answers.
func TestFixtureRoutineDiscovery(t *testing.T) {
	tgt, c := loadFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	// Deliberately generic seeds: the point is to measure what a real scan
	// would recover, not to hand the oracle its own answers.
	seeds := []string{
		"admin_purge", "admin_delete", "admin_create", "admin_update",
		"public_stats", "stats_summary", "summary_report", "user_profile",
		"purge_records", "list_items", "review_items",
	}
	sf := surface.Run(ctx, c, surface.Options{RoutineSeeds: seeds})
	score := eval.Compare("routine-discovery", tgt.Routines(), sf.Routines)
	t.Logf("%s", score)
	if !score.Perfect() {
		t.Errorf("routine discovery incomplete: %s", score)
	}
}

// TestFixtureEscalation is the privilege-boundary check. An anon-only scan
// calls authenticated_only "protected", which is true and misleading: where
// signup is open, anyone can hold the authenticated role.
//
// The precision half matters as much as the recall half. owner_scoped is also
// invisible to anon, but its policy is scoped to the owning user, so elevating
// gains nothing and reporting it would be a false alarm.
func TestFixtureEscalation(t *testing.T) {
	tgt, c := loadFixture(t)
	elevated := os.Getenv("UNRULY_FIXTURE_AUTHED_KEY")
	if elevated == "" {
		t.Skip("set UNRULY_FIXTURE_AUTHED_KEY to run the escalation eval")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	rels := tgt.RelationNames()
	base := probe.Run(ctx, c, rels, probe.Options{SampleRows: 2})

	res := escalate.Compare(ctx, c, base, escalate.Options{
		Relations:   rels,
		ElevatedKey: elevated,
		SampleRows:  2,
	})

	if res.Role != "authenticated" {
		t.Errorf("elevated credential claims role %q, want authenticated", res.Role)
	}
	score := eval.Compare("escalation-gains", tgt.EscalationGains(), res.GainedRelations())
	t.Logf("%s", score)
	if !score.Perfect() {
		t.Errorf("escalation measurement wrong: %s", score)
	}

	// Assert findings EXIST before asserting things about them. Ranging over
	// an empty slice executes no body and passes, so every property below was
	// previously conditional on the check having worked -- which is the one
	// thing a test must not assume. The lab fixture defines exactly one
	// relation that authenticated can read and anon cannot.
	if len(res.Findings) == 0 {
		t.Fatal("authenticated_only is readable to authenticated and invisible to anon; " +
			"the escalation check must produce a finding for it")
	}
	var sawEscalation bool
	for _, f := range res.Findings {
		if f.ID == "supabase-authenticated-escalation" {
			sawEscalation = true
		}
		if len(f.Evidence.Sample) == 0 {
			t.Errorf("%s carries no proof", f.Resource)
		}
		if f.Remediation == "" {
			t.Errorf("%s carries no remediation", f.Resource)
		}
		// owner_scoped is correctly scoped: authenticated sees only its own
		// rows, so escalation gains nothing and reporting it would be a false
		// positive of exactly the kind this fixture exists to catch.
		if f.Resource == "owner_scoped" {
			t.Errorf("owner_scoped is scoped to the owning user and must not be " +
				"reported as an escalation gain")
		}
	}
	if !sawEscalation {
		t.Errorf("no finding carried the id supabase-authenticated-escalation; got %d "+
			"findings with other ids", len(res.Findings))
	}
	if len(res.Gains) > 0 {
		t.Logf("gained %q: %d rows as %s, invisible to anon",
			res.Gains[0].Relation, res.Gains[0].Rows, res.Role)
	}
}

// Harvesting must be both cheaper and no less complete than brute force.
//
// The site fixture used to name none of the schema's tables, so the harvest
// produced vocabulary matching nothing while still being non-empty. That
// suppressed the retry fallback -- whose trigger is "nothing was harvested",
// not "what was harvested was useless" -- and the scan found 18 relations
// instead of 21 while the harvest path looked exercised.
//
// Measured after the page was made realistic: 21 of 21 at 7,127 requests,
// against 18,300 for the brute-force sweep that runs when no vocabulary is
// available. This pins both halves, because either one alone can be met by
// making the tool worse: full recall is trivial if cost is unbounded, and low
// cost is trivial if recall is abandoned.
func TestFixtureHarvestBeatsBruteForceOnBothCountAndCost(t *testing.T) {
	tgt, c := loadFixture(t)
	_ = tgt
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	v := enumerate.Harvest(ctx, enumerate.HarvestOptions{
		Site: "http://127.0.0.1:54322", Timeout: 30 * time.Second, MaxBundles: 10, MaxSeeds: 2000,
	})
	if len(v.Seeds) < 20 {
		t.Fatalf("only %d seeds harvested from the application; the page is supposed to "+
			"name the tables it queries, and without that the harvest path is untested "+
			"while looking tested", len(v.Seeds))
	}

	// The names the application actually queries must be among them, or the
	// seeds are noise that happens to be numerous.
	got := map[string]bool{}
	for _, s := range v.Seeds {
		got[s] = true
	}
	for _, want := range []string{"open_no_rls", "leaky_credentials", "verb_read_only"} {
		if !got[want] {
			t.Errorf("%s is queried by the application and was not harvested", want)
		}
	}
	// And the one the answer key says is named nowhere must NOT be harvested:
	// it is what keeps the hint oracle honest once harvesting works.
	if got["open_no_rls_archive"] {
		t.Error("open_no_rls_archive is documented as named nowhere in any application, " +
			"and the fixture page now names it; the oracle-only path is no longer tested")
	}

	res := enumerate.Run(ctx, c, enumerate.Options{Seeds: v.Seeds, Concurrency: 16})
	if len(res.Relations) < 20 {
		t.Errorf("harvested vocabulary recovered %d relations; the brute-force sweep "+
			"finds 21, and harvesting must not cost recall", len(res.Relations))
	}
}

// A self-hosted layout must not read as a clean project.
//
// The managed product routes PostgREST through Kong at /rest/v1, which is the
// default. A self-hosted or bare deployment serves it at the root, and asking
// in the wrong place is not a degraded scan -- it is a confidently empty one.
//
// Measured on this fixture before the correction existed: 18,208 requests, 0
// relations, 9 findings none above info. With the prefix pinned by hand the
// same target yields 21 relations and 6 critical findings. The difference
// between those two reports was one flag the operator had to already know to
// pass, and nothing in the output named it.
func TestSelfHostedLayoutIsFoundWithoutBeingToldWhereItIs(t *testing.T) {
	requireLiveEvals(t)
	requireReachable(t, "http://127.0.0.1:54321")
	key := os.Getenv("UNRULY_FIXTURE_KEY")
	if key == "" {
		t.Skip("set UNRULY_FIXTURE_KEY")
	}

	// Deliberately NO -rest-prefix: discovering it is the capability.
	out := filepath.Join(t.TempDir(), "scan.json")
	runScanner(t, "-u", "http://127.0.0.1:54321", "-provider", "supabase",
		"-k", key, "-j", "-o", out)

	b, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("scan produced no report: %v", err)
	}
	var relations, corrected int
	var worst string
	rank := map[string]int{"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
	for _, line := range strings.Split(string(b), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var f struct {
			ID       string `json:"id"`
			Severity string `json:"severity"`
		}
		if json.Unmarshal([]byte(line), &f) != nil {
			t.Fatalf("report line is not JSON: %q", line)
		}
		switch f.ID {
		case "supabase-anon-read-exposed":
			relations++
		case "unruly-rest-prefix-corrected":
			corrected++
		}
		if rank[f.Severity] > rank[worst] {
			worst = f.Severity
		}
	}
	if corrected != 1 {
		t.Errorf("the scan did not report moving to the prefix it found (%d notices); "+
			"a scan that changes where it is looking has changed what its result means",
			corrected)
	}
	// The fixture leaks a lot; the exact count belongs to the recall eval. This
	// only has to separate "found the database" from "reported an empty one".
	if relations < 5 {
		t.Errorf("%d read-exposed relations: PostgREST was not found at the root, so "+
			"this reads as a clean project when it has critical findings", relations)
	}
	if worst != "critical" {
		t.Errorf("worst severity %q; the fixture has critical exposures and a scan "+
			"that misses the mount path reports none of them", worst)
	}
}

// A self-hosted target must be scanned with ITS key, not the operator's.
//
// Anyone who works on a Supabase project has SUPABASE_ANON_KEY exported. The
// tool preferred the key the target ships -- but only when both project
// references were known and differed, which quietly meant "managed projects
// only". A self-hosted deployment has no reference, so the ambient key was
// kept, every request was answered 401, and the report said 0 relations.
//
// Two failures compound here and this eval covers both: the scan must find the
// API origin the application DECLARES (a self-hosted target's URL carries no
// reference to discover it from), and must then use the credential that target
// ships rather than one belonging to somebody else's project.
func TestSelfHostedTargetIsScannedWithItsOwnKeyNotTheEnvironments(t *testing.T) {
	requireLiveEvals(t)
	requireReachable(t, "http://127.0.0.1:54324")

	out := filepath.Join(t.TempDir(), "scan.json")
	cmd := exec.Command(buildScanner(t), "-u", "http://127.0.0.1:54324",
		"-j", "-o", out, "-silent")
	// A well-formed key for a DIFFERENT project, exactly as a developer's
	// shell carries. Deliberately not cleared: clearing it is the workaround
	// that hid this bug.
	cmd.Env = append(os.Environ(),
		"SUPABASE_ANON_KEY=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."+
			"eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Inp6enp6enp6enp6enp6enp6enp6Iiwicm9sZSI6ImFub24ifQ.x")
	_ = cmd.Run() // non-zero means findings, which is the expected case

	b, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("scan produced no report: %v", err)
	}
	var relations, rejected int
	var worst string
	rank := map[string]int{"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
	for _, line := range strings.Split(string(b), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var f struct {
			ID       string `json:"id"`
			Severity string `json:"severity"`
		}
		if json.Unmarshal([]byte(line), &f) != nil {
			t.Fatalf("report line is not JSON: %q", line)
		}
		switch f.ID {
		case "supabase-anon-read-exposed":
			relations++
		case "unruly-credential-rejected":
			rejected++
		}
		if rank[f.Severity] > rank[worst] {
			worst = f.Severity
		}
	}
	if rejected > 0 {
		t.Error("the scan used the ambient key, which this target does not accept, " +
			"instead of the working one the target ships")
	}
	if relations < 5 {
		t.Errorf("%d read-exposed relations; the scan did not reach the API the "+
			"application declares, or did not use the key it ships", relations)
	}
	if worst != "critical" {
		t.Errorf("worst severity %q, want critical: this fixture leaks credentials "+
			"and personal data", worst)
	}
}
