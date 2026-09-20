package supabase

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/eppser/unruly/internal/client"
	"github.com/eppser/unruly/internal/enumerate"
	"github.com/eppser/unruly/internal/finding"
	"github.com/eppser/unruly/internal/parity"
	"github.com/eppser/unruly/internal/schemas"
	"github.com/eppser/unruly/internal/surface"
	"github.com/eppser/unruly/internal/wordlist"
	"github.com/eppser/unruly/scan"
)

// exposing serves a PostgREST that admits to a second exposed schema.
//
// Discover asks for a schema that cannot exist and reads the names out of the
// error hint. Everything else answers 404, so enumeration finds nothing there
// -- which is the case that matters most: a schema the scan can see is exposed
// but cannot enumerate must be reported as UNMEASURED, not omitted.
func exposing(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Header.Get("Accept-Profile") == schemas.ProbeSchemaName {
			w.WriteHeader(http.StatusNotAcceptable)
			_, _ = w.Write([]byte(`{"code":"PGRST106","message":"schema not exposed",` +
				`"hint":"Only the following schemas are exposed: public, reporting"}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"code":"PGRST205","message":"not found"}`))
	}))
	t.Cleanup(srv.Close)
	return srv
}

// The stage must report exactly what the code it replaced reported.
func TestTheSchemasStageAgreesWithTheCodeItReplaced(t *testing.T) {
	srvOld := exposing(t)
	cOld := client.New(client.Options{BaseURL: srvOld.URL, AnonKey: "k", RestPrefix: "/"})

	// --- the original expression, transcribed ---------------------------
	var old []finding.Finding
	sch := schemas.Discover(context.Background(), cOld)
	oldRequests := sch.Requests
	old = append(old, sch.Findings...)
	for _, schema := range sch.Extra {
		sc := cOld.WithSchema(schema)
		sen := enumerate.Run(context.Background(), sc, enumerate.Options{
			Seeds:       wordlist.Merge(nil, wordlist.Relations()),
			Concurrency: 2,
		})
		oldRequests += sen.Requests
		if !sen.Discriminating {
			old = append(old, finding.NotAssessedSchema(cOld.RestBase(), schema,
				"the control probe was answered as though a relation that cannot exist does, "+
					"so no answer about this schema distinguishes anything"))
			continue
		}
		// Routines run BEFORE the relation guard, exactly as in the original:
		// a schema whose relation names are not in the vocabulary can still
		// have a discoverable routine.
		srt := surface.Routines(context.Background(), sc, surface.Options{
			Concurrency: 2, MaxCandidates: 0, Schema: schema,
		})
		oldRequests += srt.Requests
		if srt.RoutineBudgetBound {
			old = append(old, surface.RoutineBudgetFinding(sc.RestBase(), 0,
				srt.RoutineCandidatesWanted))
		}
		old = append(old, srt.Findings...)
		if len(sen.Names()) == 0 {
			if sen.HintsObserved == 0 {
				old = append(old, finding.NotAssessedSchema(cOld.RestBase(), schema,
					"no relation name was recovered and the hint oracle produced nothing here, "+
						"so this schema's contents are unknown rather than known to be empty"))
			}
			continue
		}
	}

	// --- the same work through the pipeline ------------------------------
	srvNew := exposing(t)
	cNew := client.New(client.Options{BaseURL: srvNew.URL, AnonKey: "k", RestPrefix: "/"})
	st := &scan.State{Target: cNew.RestBase()}
	// The vocabulary the transcribed original used, published as the
	// vocabulary stage now would.
	scan.Put(st, Vocabulary{Seeds: wordlist.Merge(nil, wordlist.Relations())})
	stage := SchemasStage{Client: cNew, Concurrency: 2,
		ExtraRoutines: scan.NewBudget(0), RPCRoutines: scan.NewBudget(0)}
	if _, err := (scan.Pipeline{stage}).Run(context.Background(), st); err != nil {
		t.Fatal(err)
	}

	normalise(old, srvOld.URL, "http://target")
	got := st.Findings()
	normalise(got, srvNew.URL, "http://target")

	if len(old) == 0 {
		t.Fatal("the transcribed original produced nothing, so this test would pass " +
			"vacuously; an exposed but unenumerable schema must be reported")
	}
	if d := parity.Diff(old, got); d != "" {
		t.Errorf("the ported stage disagrees with the code it replaced:\n%s", d)
	}
}

// An exposed schema the scan cannot enumerate is REPORTED, not omitted.
//
// Silence about a schema is not the same as a schema with nothing in it, and
// the loop this replaces used to `continue` on both.
func TestAnUnenumerableSchemaIsReportedRatherThanOmitted(t *testing.T) {
	srv := exposing(t)
	c := client.New(client.Options{BaseURL: srv.URL, AnonKey: "k", RestPrefix: "/"})
	st := &scan.State{Target: c.RestBase()}
	// Seeds arrive as the published vocabulary now, not as a construction
	// field, so the test publishes what the vocabulary stage would have.
	scan.Put(st, Vocabulary{Seeds: []string{"orders"}})
	if _, err := (scan.Pipeline{SchemasStage{Client: c, Concurrency: 2}}).
		Run(context.Background(), st); err != nil {
		t.Fatal(err)
	}
	var saw bool
	for _, f := range st.Findings() {
		if f.ID == "unruly-surface-not-assessed" && strings.Contains(f.Resource, "reporting") {
			saw = true
		}
	}
	if !saw {
		t.Errorf("the reporting schema is exposed and was not enumerable, and the report "+
			"does not say so: %+v", st.Findings())
	}
}

// The stage publishes the per-schema results later stages steer on.
func TestTheSchemasStagePublishesItsScans(t *testing.T) {
	srv := exposing(t)
	c := client.New(client.Options{BaseURL: srv.URL, AnonKey: "k", RestPrefix: "/"})
	st := &scan.State{Target: c.RestBase()}
	// Seeds arrive as the published vocabulary now, not as a construction
	// field, so the test publishes what the vocabulary stage would have.
	scan.Put(st, Vocabulary{Seeds: []string{"orders"}})
	if _, err := (scan.Pipeline{SchemasStage{Client: c, Concurrency: 2}}).
		Run(context.Background(), st); err != nil {
		t.Fatal(err)
	}
	// PRESENCE is the property. Nothing is enumerated against this fixture, so
	// the scan list is legitimately empty -- and a later stage must still be
	// able to tell that from a schemas stage that never ran.
	//
	// The previous assertion here could not fail: it read
	// `out == nil && len(out) != 0`, and a nil slice always has length zero,
	// so the condition was unsatisfiable. It was checking an out-param that
	// the caller had already initialised, which is the shape of check that
	// looks like coverage and measures nothing.
	if _, ok := scan.Get[Schemas](st); !ok {
		t.Error("the schemas stage published nothing, so a later stage cannot tell " +
			"\"no other schemas are exposed\" from \"the schema pass did not run\"")
	}
}

// A budget already spent stops the routine sweep rather than letting it run
// unbounded, and the exhaustion is visible to the caller.
func TestAnExhaustedBudgetIsNotOverspent(t *testing.T) {
	srv := exposing(t)
	c := client.New(client.Options{BaseURL: srv.URL, AnonKey: "k", RestPrefix: "/"})
	extra := scan.NewBudget(0)
	rpc := scan.NewBudget(0)
	st := &scan.State{Target: c.RestBase()}
	scan.Put(st, Vocabulary{Seeds: wordlist.Merge(nil, wordlist.Relations())})
	if _, err := (scan.Pipeline{SchemasStage{
		Client: c, Concurrency: 2, ExtraRoutines: extra, RPCRoutines: rpc,
	}}).Run(context.Background(), st); err != nil {
		t.Fatal(err)
	}
	if !extra.Exhausted() || extra.Left() != 0 {
		t.Errorf("the extra-schema routine budget moved to %d from an exhausted start",
			extra.Left())
	}
	if rpc.Left() != 0 {
		t.Errorf("the shared RPC budget moved to %d from an exhausted start", rpc.Left())
	}
}

// TestPerSchemaProbeInheritsEverySetting: each field here is a promise the
// operator made on the command line, and a schema other than the default must
// not quietly get a different deal.
//
// This existed as a mutation (repeated-stage-loses-a-control) that had never
// been graded by a test: it is scoped to ./internal/eval/, and the eval that
// would notice -- eval-noresidue -- needs the live lab, so it skips offline.
// The mutation was scored "caught" because it tripped the harness's own
// bookkeeping check instead. With that check silenced under a mutation, it
// SURVIVED, which is how this gap surfaced.
func TestPerSchemaProbeInheritsEverySetting(t *testing.T) {
	s := SchemasStage{
		Write: true, NoResidue: true, Measure: true,
		SampleRows: 7, Concurrency: 3, MaxColumnProbes: 11,
	}
	got := s.probeOptions("reporting")

	for _, c := range []struct {
		field string
		ok    bool
		why   string
	}{
		{"NoResidue", got.NoResidue, "a scan promising to create nothing would leave " +
			"rows behind in every schema but the default"},
		{"Measure", got.Measure, "-measure would retrieve a stranger's data from a " +
			"non-default schema"},
		{"Write", got.Write == s.Write, "write probing would differ by schema"},
		{"SampleRows", got.SampleRows == s.SampleRows, "evidence volume would differ by schema"},
		{"Concurrency", got.Concurrency == s.Concurrency, "the rate promise would not hold"},
		{"MaxColumnProbes", got.MaxColumnProbes == s.MaxColumnProbes,
			"the column-probe budget would not hold"},
	} {
		if !c.ok {
			t.Errorf("%s is not inherited by the per-schema probe: %s", c.field, c.why)
		}
	}
	if got.Schema != "reporting" {
		t.Errorf("Schema = %q, want the schema being probed", got.Schema)
	}
}
