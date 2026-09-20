package supabase

import (
	"context"
	"errors"
	"strings"

	"github.com/eppser/unruly/internal/client"
	"github.com/eppser/unruly/internal/enumerate"
	"github.com/eppser/unruly/internal/finding"
	"github.com/eppser/unruly/internal/probe"
	"github.com/eppser/unruly/internal/schemas"
	"github.com/eppser/unruly/internal/surface"
	"github.com/eppser/unruly/internal/wordlist"
	"github.com/eppser/unruly/scan"
)

// SchemasStage examines every schema PostgREST exposes beyond the default one.
//
// Ported from the "// ---- other exposed schemas ----" section of scanTarget.
// Every scan before that section existed probed the default schema and
// stopped, which is the same false-negative shape as trusting the OpenAPI
// root: relations in another exposed schema are never asked about, and silence
// reads as safety. PostgREST names them when asked for a schema that cannot
// exist, so this costs one request on projects that expose nothing extra.
type SchemasStage struct {
	Client          *client.Client
	Concurrency     int
	Write           bool
	NoResidue       bool
	Measure         bool
	Invoke          bool
	Redact          bool
	SampleRows      int
	MaxColumnProbes int

	// ExtraRoutines caps how much routine discovery the non-default schemas
	// may do; RPCRoutines is the whole scan's routine allowance, which a LATER
	// stage also draws on. Spending charges both, which is why they are
	// budgets rather than ints: the auth/storage/rpc pass that runs after this
	// one must see what was already spent.
	//
	// Nil means uncapped, so a caller that has not adopted budgets is not
	// silently reduced to zero work.
	ExtraRoutines *scan.Budget
	RPCRoutines   *scan.Budget
}

func (SchemasStage) Name() string { return "schemas" }

// Run discovers the extra schemas and examines each one.
func (s SchemasStage) Run(ctx context.Context, st *scan.State) error {
	// Seeds come from the published vocabulary, not from a construction field.
	//
	// A DECLARED REQUIREMENT for the same reason the probe result is one: a
	// stage silently handed no seeds probes nothing, finds nothing and reports
	// nothing, which is indistinguishable from a project with nothing in it.
	vocab, ok := scan.Get[Vocabulary](st)
	if !ok {
		return errors.New("no vocabulary was published, so there is nothing to probe " +
			"for: this surface was not assessed")
	}
	sch := schemas.Discover(ctx, s.Client)
	requests := sch.Requests
	st.Add(sch.Findings...)

	var scans []SchemaScan
	for _, schema := range sch.Extra {
		sc := s.Client.WithSchema(schema)
		sen := enumerate.Run(ctx, sc, enumerate.Options{
			Seeds:       wordlist.Merge(vocab.Seeds, wordlist.Relations()),
			Concurrency: s.Concurrency,
		})
		requests += sen.Requests

		// Silence about a schema is not the same as a schema with nothing in
		// it, and this loop used to continue on both. The oracle answering at
		// all is the discriminator: hints observed means it worked and found
		// nothing matching the vocabulary, which is a real if seed-limited
		// measurement. No hints at all means the scan is blind here and must
		// say so rather than leaving the schema out of the report entirely.
		if !sen.Discriminating {
			st.Add(finding.NotAssessedSchema(s.Client.RestBase(), schema,
				"the control probe was answered as though a relation that cannot exist does, "+
					"so no answer about this schema distinguishes anything"))
			continue
		}

		// Routines run BEFORE the relation guard below, which continues. A
		// schema whose RELATION names are not in the scan's vocabulary can
		// still have a discoverable routine, and the first version of this
		// skipped routine discovery for exactly those schemas -- including the
		// one in the cloud lab it was written against.
		before := s.ExtraRoutines.Left()
		srt := surface.Routines(ctx, sc, surface.Options{
			RoutineSeeds:   vocab.RoutineSeeds,
			RoutineGuesses: vocab.Composed,
			Concurrency:    s.Concurrency,
			MaxCandidates:  before,
			AllowInvoke:    s.Invoke,
			Redact:         s.Redact,
			Schema:         schema,
		})
		requests += srt.Requests
		// Charge both allowances: the sub-cap for extra schemas, and the whole
		// scan's routine budget that a later stage still has to draw on.
		granted := s.ExtraRoutines.Take(spentOn(srt, before))
		s.RPCRoutines.Take(granted)
		if srt.RoutineBudgetBound {
			// Previously only the default schema's truncation was reported, so
			// a secondary schema whose routine sweep ran out said nothing at
			// all -- a silent coverage gap in the surface most likely to be
			// forgotten.
			st.Add(surface.RoutineBudgetFinding(sc.RestBase(), before,
				srt.RoutineCandidatesWanted))
		}
		// surface qualifies its own names, because its SQL must.
		st.Add(srt.Findings...)

		if len(sen.Names()) == 0 {
			if sen.HintsObserved == 0 {
				st.Add(finding.NotAssessedSchema(s.Client.RestBase(), schema,
					"no relation name was recovered and the hint oracle produced nothing here, "+
						"so this schema's contents are unknown rather than known to be empty"))
			}
			continue
		}

		spr := probe.Run(ctx, sc, sen.Names(), s.probeOptions(schema))
		requests += spr.Requests
		// probe qualifies its own names, because the SQL it emits has to.
		// Re-qualifying here would produce reporting.reporting.x.
		st.Add(spr.Findings(s.Client.RestBase(), s.Redact)...)
		scans = append(scans, SchemaScan{
			Name: schema, Relations: sen.Names(), Result: spr,
		})
	}

	// One artifact, because the two are one fact: which schemas PostgREST
	// exposes, and what was found in each. Splitting them let a caller hold a
	// scan list without the discovery that explains it.
	scan.Put(st, Schemas{Scans: scans, Discovered: sch})

	// What was found, said here. PostgREST exposing a second schema is the
	// false-negative this pass exists for: relations there were never asked
	// about before, and silence read as safety.
	if len(sch.Extra) > 0 {
		st.Note(scan.Info, "PostgREST also exposes %s; scanning them too",
			strings.Join(sch.Extra, ", "))
	}
	scanned := map[string]bool{}
	for _, ss := range scans {
		scanned[ss.Name] = true
		st.Note(scan.Info, "schema %s: %d relations, %d readable",
			ss.Name, len(ss.Relations), len(ss.Result.ReadExposed()))
	}
	// A schema that produced no scan is still a schema the operator should
	// hear about: it was exposed, and the scan reached less of it than that.
	// The report carries the not-assessed finding; this is the terminal echo.
	for _, name := range sch.Extra {
		if !scanned[name] {
			st.Note(scan.Info, "schema %s: nothing enumerated; see the report for "+
				"whether that is emptiness or blindness", name)
		}
	}
	st.Attribute(s.Name(), requests)
	return nil
}

// spentOn is how many candidates a routine sweep actually probed: everything
// it wanted, or the budget it was given, whichever is smaller.
func spentOn(r surface.Result, budget int) int {
	if r.RoutineCandidatesWanted < budget {
		return r.RoutineCandidatesWanted
	}
	return budget
}

// probeOptions is how a non-default schema is probed: the same settings as the
// default schema, plus the schema's own name.
//
// A function rather than a literal at the call site because EVERY field here
// is a promise the operator made and a repeated literal is where one gets
// quietly dropped. It has happened twice: -measure was once omitted and the
// per-schema probe retrieved a stranger's data, and -no-residue was omitted so
// a scan promising to create nothing left rows behind in every schema but the
// default.
//
// Neither omission was caught by a test. The second was reported "caught" for
// years by a mutation that only tripped the harness's own bookkeeping check --
// see the UNRULY_MUTATION_ACTIVE note in scripts/mutate.py. With the options
// built here, a dropped field is a visible diff in one place and the test
// below asserts each one individually.
func (s SchemasStage) probeOptions(schema string) probe.Options {
	return probe.Options{
		Write:           s.Write,
		SampleRows:      s.SampleRows,
		Concurrency:     s.Concurrency,
		NoResidue:       s.NoResidue,
		Schema:          schema,
		Measure:         s.Measure,
		MaxColumnProbes: s.MaxColumnProbes,
	}
}
