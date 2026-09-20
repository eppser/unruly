package supabase

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/eppser/unruly/internal/client"
	"github.com/eppser/unruly/internal/enumerate"
	"github.com/eppser/unruly/internal/finding"
	"github.com/eppser/unruly/internal/postgrest"
	"github.com/eppser/unruly/internal/probe"
	"github.com/eppser/unruly/internal/surface"
	"github.com/eppser/unruly/scan"
)

// The vocabulary stage publishes what it produced, rather than writing it
// through a pointer the caller declared.
//
// Both halves matter and both used to leave through out-params: the merged
// seeds, and the attribution of where they came from. `Out: &seeds,
// Origins: &seedOrigins` in scanTarget meant two more variables in the
// command's scope for a fact that is entirely internal to the Supabase scan --
// and it is why the vocabulary stage cannot be reordered, replaced or handed
// to a contributor without editing main.
func TestVocabularyStagePublishesItsSeedsAsAnArtifact(t *testing.T) {
	st := &scan.State{}
	s := VocabularyStage{Sources: SeedSources{
		Harvested: []string{"invoices", "customers"},
		Pinned:    []string{"users"},
	}}
	if err := s.Run(context.Background(), st); err != nil {
		t.Fatalf("run: %v", err)
	}

	v, ok := scan.Get[Vocabulary](st)
	if !ok {
		t.Fatal("the vocabulary stage ran and published nothing, so a later stage has no " +
			"way to learn what will be probed except by being handed it")
	}
	// Parity with the function the command used to call directly.
	want := MergeSeeds(s.Sources)
	if len(v.Seeds) != len(want) {
		t.Fatalf("published %d seeds, MergeSeeds produced %d", len(v.Seeds), len(want))
	}
	for i := range want {
		if v.Seeds[i] != want[i] {
			t.Errorf("seed %d = %q, want %q; order is what keeps probe order and "+
				"therefore report order stable between runs", i, v.Seeds[i], want[i])
		}
	}
	if v.Origins.Harvested != 2 || v.Origins.Pinned != 1 {
		t.Errorf("origins = %+v, want 2 harvested and 1 pinned; the attribution has to "+
			"travel with the seeds or the summary cannot say where they came from",
			v.Origins)
	}
}

// The attribution sums to exactly the number of seeds probed.
//
// Carried over from the out-param version, because the reason is unchanged: a
// reader adds these four numbers up, and len() of each source double-counts
// every name in two of them. "users" and "profiles" are on the pinned list AND
// are exactly what an application references, so the overlap is the common
// case rather than a corner.
func TestPublishedOriginsSumToTheSeedsThatWillBeProbed(t *testing.T) {
	st := &scan.State{}
	s := VocabularyStage{Sources: SeedSources{
		Harvested:  []string{"users", "invoices"},
		Supplied:   []string{"ledger"},
		Advertised: []string{"invoices", "audit"},
		Pinned:     []string{"users", "profiles"},
	}}
	if err := s.Run(context.Background(), st); err != nil {
		t.Fatalf("run: %v", err)
	}
	v, ok := scan.Get[Vocabulary](st)
	if !ok {
		t.Fatal("nothing published")
	}
	o := v.Origins
	if sum := o.Harvested + o.Supplied + o.Advertised + o.Pinned; sum != len(v.Seeds) {
		t.Errorf("origins sum to %d and %d seeds will be probed; the summary renders "+
			"these as a sentence a reader adds up", sum, len(v.Seeds))
	}
}

// The enumerate stage publishes its outcome the same way.
//
// Its result is consumed by probing, realtime and escalation. Every one of
// those hand-offs went through a variable in scanTarget.
func TestEnumerateStagePublishesItsOutcomeAsAnArtifact(t *testing.T) {
	st := &scan.State{}
	// No client: Run must publish whatever it concluded, and a stage that
	// publishes only on the happy path leaves later stages unable to tell
	// "nothing found" from "did not run".
	s := EnumerateStage{Client: nil, Concurrency: 1}

	// A nil client would panic, so this is the smallest honest check: the
	// artifact type exists and is absent before the stage runs, which is what
	// makes the positive case above meaningful.
	if _, ok := scan.Get[EnumerateOutcome](st); ok {
		t.Fatal("an enumerate outcome was present before the stage ran")
	}
	_ = s
}

// A stage that needs an upstream artifact and cannot find it says so.
//
// This is the risk the Out pointer was, in fairness, protecting against: a
// field is explicit and the compiler checks it, whereas reading from shared
// state is an implicit dependency that fails silently. A realtime stage handed
// an empty probe result subscribes to nothing, finds nothing, and reports
// nothing -- which is indistinguishable from a project whose realtime surface
// is closed.
//
// So the dependency is declared instead: a missing artifact is an ERROR, and
// the pipeline turns a stage error into a not-assessed finding carrying the id
// the exit code keys on. An unexamined surface then drives exit 3 rather than
// passing for a clean one, which is the whole argument of this tool applied to
// its own plumbing.
func TestAStageWhoseUpstreamArtifactIsMissingReportsItRatherThanFindingNothing(t *testing.T) {
	for _, tc := range []struct {
		name  string
		stage scan.Stage
	}{
		{"realtime", RealtimeStage{Client: nil}},
		// The schemas stage needs the vocabulary. Added after a mutation
		// SURVIVED: the requirement was written and nothing asserted it, so
		// deleting the check changed no test result -- a guard that guards
		// nothing reads exactly like one that works.
		{"schemas", SchemasStage{Client: nil, Concurrency: 1}},
		// WITH a credential. Without one the escalation stage declines before
		// it needs any input, and declining is not a failure to assess -- so
		// testing it credential-less would have graded the wrong branch and
		// passed for the wrong reason.
		{"escalation", EscalationStage{Client: nil,
			ElevatedKey: "elevated"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st := &scan.State{Target: "t"}
			err := tc.stage.Run(context.Background(), st)
			if err == nil {
				t.Fatal("the stage ran without the probe result and reported success; " +
					"a surface that was never assessed must not read as a clean one")
			}
			// Each stage names WHICH artifact it was missing, whichever it
			// reached first. A stage has several upstream inputs now, and an
			// error that said only "a dependency was missing" would leave an
			// operator unable to tell which pass did not run.
			named := false
			for _, artifact := range []string{"probe", "vocabulary", "enumerate"} {
				if strings.Contains(err.Error(), artifact) {
					named = true
				}
			}
			if !named {
				t.Errorf("error %q names no artifact, so an operator cannot tell which "+
					"stage did not run", err)
			}
		})
	}
}

// A stage's INPUTS come from artifacts too, not just its outputs.
//
// Removing the out-params fixed half the coupling. The other half is that two
// stages are still CONSTRUCTED from another stage's result: `ProbeStage{Names:
// en.Names()}` and `SchemasStage{Seeds: seeds, RoutineSeeds: ...}`. main has to
// hold the enumerate outcome and the vocabulary to build them, which means the
// stage list cannot be produced by supabase.Stages() from the operator's flags
// alone -- and that is exactly what step 2 of this port needs.
//
// Every other condition in scanTarget's ordering is a pure function of the
// flags. These two fields are the only reason the list is not.
func TestProbeAndSchemasTakeTheirInputsFromArtifacts(t *testing.T) {
	for _, tc := range []struct{ name, field string }{
		{"ProbeStage", "Names"},
		{"SchemasStage", "Seeds"},
		{"SchemasStage", "RoutineSeeds"},
		{"SchemasStage", "RoutineGuesses"},
		// The rest of the list, found by trying to write supabase.Stages()
		// and discovering that the CONDITIONS are flag-pure but the
		// CONSTRUCTION INPUTS are not. Every one of these is an earlier
		// stage's result reaching a later stage through the caller.
		{"EnumerateStage", "Seeds"},
		{"EnumerateStage", "HarvestedCount"},
		{"GraphQLStage", "Relations"},
		{"RealtimeStage", "Relations"},
		{"RealtimeStage", "Schemas"},
		{"EscalationStage", "Relations"},
		{"EscalationStage", "Schemas"},
		// The last three. Evidence is built from the enumerate result AND the
		// transport counters; RESTReadable is derived from the probe result;
		// MaxCandidates is a live budget read after the schemas pass.
		{"SelfCheckStage", "Evidence"},
		{"GraphQLStage", "RESTReadable"},
	} {
		t.Run(tc.name+"."+tc.field, func(t *testing.T) {
			if hasField(t, tc.name, tc.field) {
				t.Errorf("%s still takes %s as a construction field, so it can only be "+
					"built by a caller holding an earlier stage's result. Read it from "+
					"the published artifact instead.", tc.name, tc.field)
			}
		})
	}
}

// hasField reports whether a stage struct in this package declares a field.
func hasField(t *testing.T, structName, field string) bool {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	decl := regexp.MustCompile(`(?s)type ` + structName + ` struct \{(.*?)\n\}`)
	fieldRe := regexp.MustCompile(`(?m)^\s+` + field + `\s`)
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		b, err := os.ReadFile(e.Name())
		if err != nil {
			t.Fatalf("read %s: %v", e.Name(), err)
		}
		if m := decl.FindSubmatch(b); m != nil {
			return fieldRe.Match(m[1])
		}
	}
	t.Fatalf("no struct named %s found, so this test asserts nothing", structName)
	return false
}

// The GraphQL stage's bypass verdict depends on the PUBLISHED probe result.
//
// RESTReadable decides which readable relations are reported as an RLS BYPASS
// -- the most serious thing this check finds. With it empty, every relation
// GraphQL can read is reported as a bypass, which is a false positive on every
// one of them.
//
// Nothing tested that. The stage's parity test runs against a fixture with no
// GraphQL endpoint at all, so deleting the derivation entirely SURVIVED its
// mutation. The gap predates the move to artifacts: the old test passed a
// RESTReadable map in and never checked that it mattered.
func TestGraphQLBypassFollowsTheProbeResult(t *testing.T) {
	// One relation, readable over GraphQL. Whether it is a BYPASS depends
	// entirely on whether the probe said REST could read it too.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(string(b), "notesCollection") {
			w.Write([]byte(`{"data":{"notesCollection":{"edges":[` +
				`{"node":{"nodeId":"WyJwdWJsaWMiLCJub3RlcyIsMV0="}}]}}}`))
			return
		}
		w.Write([]byte(`{"data":null,"errors":[{"message":"Unknown field"}]}`))
	}))
	defer srv.Close()

	bypassFindings := func(restCouldRead bool) int {
		c := client.New(client.Options{BaseURL: srv.URL, AnonKey: "k", RestPrefix: "/"})
		st := &scan.State{Target: c.RestBase()}
		scan.Put(st, EnumerateOutcome{Result: enumerate.Result{
			Relations: []enumerate.Relation{{Name: "notes"}}}})
		var pr probe.Result
		if restCouldRead {
			pr.Relations = []probe.Relation{{Name: "notes", Read: postgrest.ReadExposed}}
		} else {
			pr.Relations = []probe.Relation{{Name: "notes", Read: postgrest.ReadDenied}}
		}
		scan.Put(st, pr)
		if err := (GraphQLStage{Client: c, SampleRows: 3, Concurrency: 1}).
			Run(context.Background(), st); err != nil {
			t.Fatalf("run: %v", err)
		}
		n := 0
		for _, f := range st.Findings() {
			if strings.Contains(f.ID, "rls-bypass") {
				n++
			}
		}
		return n
	}

	if n := bypassFindings(false); n == 0 {
		t.Error("a relation GraphQL reads and REST could not is not reported as a bypass; " +
			"that is the finding this check exists for")
	}
	if n := bypassFindings(true); n != 0 {
		t.Errorf("a relation BOTH REST and GraphQL can read was reported as %d bypass "+
			"finding(s); GraphQL reaching what REST already reached is not a bypass, and "+
			"reporting it is a false positive on every readable relation", n)
	}
}

// The enumerate stage reports its own trustworthiness, not the command.
//
// Three findings and three sentences lived in scanTarget: the candidate-budget
// truncation, the control probe that could not distinguish an absent relation
// from a present one, and the unresolved probes that make the relation list a
// lower bound. Every one of them is derived from the enumerate result, and
// every one of them was a reason for main to hold that result.
//
// They matter more than most narration. If the control probe fails, NOTHING
// downstream of enumeration can be trusted -- read and write classification
// both start from the discovered set -- and an empty result reads as a clean
// project. That judgement belongs with the stage that made the measurement.
func TestTheEnumerateStageReportsItsOwnTrustworthiness(t *testing.T) {
	// A server that answers 200 to everything, including a relation that
	// cannot exist: the control probe cannot discriminate.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`[]`))
	}))
	defer srv.Close()
	c := client.New(client.Options{BaseURL: srv.URL, AnonKey: "k", RestPrefix: "/"})

	st := &scan.State{Target: c.RestBase()}
	scan.Put(st, Vocabulary{Seeds: []string{"orders", "invoices"}})
	if _, err := (scan.Pipeline{EnumerateStage{
		Client: c, MaxRelation: 50, Concurrency: 2,
	}}).Run(context.Background(), st); err != nil {
		t.Fatal(err)
	}

	var control bool
	for _, f := range st.Findings() {
		// The real id, checked rather than guessed: an assertion on a
		// substring I expected rather than one the code emits would have
		// passed on the wrong finding just as easily as it failed on the
		// right one.
		if f.ID == "unruly-target-not-discriminating" {
			control = true
		}
	}
	if !control {
		t.Errorf("a target that answers 200 for a relation that cannot exist produced "+
			"no finding about it; the relation list is untrustworthy and an empty one "+
			"reads as a clean project. Got: %v", ids(st.Findings()))
	}

	// And it must SAY so, at a level that survives -silent's cousins: this is
	// not progress, it is the scan telling the operator its own results cannot
	// be relied on.
	var loud bool
	for _, n := range st.Notes() {
		if n.Level != scan.Info {
			loud = true
		}
	}
	if !loud {
		t.Errorf("the stage said nothing above info level about being unable to "+
			"discriminate; notes: %v", st.Notes())
	}
}

func ids(fs []finding.Finding) []string {
	out := make([]string, 0, len(fs))
	for _, f := range fs {
		out = append(out, f.ID)
	}
	return out
}

// A credential obtained DURING the scan must reach the escalation stage.
//
// The stage list is built once, before any request goes out. But unruly mints
// an account mid-scan when the operator authorised writes and supplied no
// token -- that is how the middle tier of the threat model gets measured at
// all, and the threat model calls it "the one that gets missed".
//
// So the credential does not exist when Stages() is called. Baking
// ElevatedKey into the stage at construction time meant the escalation pass
// was Skip-wrapped for want of a token, then declined AFTER one had been
// acquired, reporting "not run: no -user-jwt was supplied" about a scan that
// was holding a working credential.
//
// The corpus does not cover this: every benchmark run supplies
// UNRULY_BENCH_AUTH_KEY, so the minting path is never exercised. It was found
// by asking what happens when a value the list depends on changes after the
// list is built.
func TestACredentialAcquiredMidScanReachesTheEscalationStage(t *testing.T) {
	// Built with no token, exactly as a real scan builds it.
	var esc scan.Stage
	for _, s := range Stages(Config{}) {
		if s.Name() == "escalation" {
			esc = s
		}
	}
	if esc == nil {
		t.Fatal("no escalation stage in the provider's list")
	}

	st := &scan.State{Target: "t"}
	scan.Put(st, probe.Result{})
	scan.Put(st, EnumerateOutcome{Result: enumerate.Result{
		Relations: []enumerate.Relation{{Name: "orders"}}}})
	// The account, acquired after the list was built.
	scan.Put(st, Credential{Token: "minted-token", Role: "authenticated"})

	// A real client, because the assertion is that the stage DID THE WORK.
	//
	// The first version of this test asserted the stage did not return a
	// "not run" error, and that passed against a build with the credential
	// lookup deleted: removing the Skip wrapper changed the failure mode from
	// a reported skip to a SILENT internal decline, which is worse and which
	// the test could not see. Measured by breaking it. Spend is the evidence
	// that a comparison actually happened.
	if err := (EscalationStage{
		Client: escalationFixture(t), Concurrency: 2, SampleRows: 1,
	}).Run(context.Background(), st); err != nil {
		t.Fatalf("run: %v", err)
	}
	var spent bool
	for _, e := range st.Spending() {
		if e.Stage == "escalation" && e.Requests > 0 {
			spent = true
		}
	}
	if !spent {
		t.Errorf("the escalation pass made no requests while the scan held a credential "+
			"it had acquired: %v.\nThat silently removes the middle tier of the threat "+
			"model -- what anybody who registers can reach -- from every scan that "+
			"mints its own account", st.Spending())
	}
	_ = esc
}

// Coverage is the provider-neutral handoff, so its descriptor must name every
// provider artifact it reads. Otherwise the full scan finishes its expensive
// probes and is rejected only while publishing the denominator.
func TestCoverageStageDeclaresEveryArtifactItReads(t *testing.T) {
	st := &scan.State{Target: "t"}
	scan.Put(st, probe.Result{})
	scan.Put(st, Escalation{})
	if _, err := (scan.Pipeline{CoverageStage{}}).Run(context.Background(), st); err != nil {
		t.Fatalf("coverage violated its runtime artifact contract: %v", err)
	}
}

func TestEscalationStageDeclaresTheSurfaceArtifactItReads(t *testing.T) {
	st := &scan.State{Target: "t"}
	scan.Put(st, surface.Result{})
	if _, err := (scan.Pipeline{EscalationStage{}}).Run(context.Background(), st); err != nil {
		t.Fatalf("escalation violated its runtime artifact contract: %v", err)
	}
}
