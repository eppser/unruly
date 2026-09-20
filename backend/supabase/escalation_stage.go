package supabase

import (
	"context"
	"errors"

	"github.com/eppser/unruly/internal/client"
	"github.com/eppser/unruly/internal/escalate"
	"github.com/eppser/unruly/internal/probe"
	"github.com/eppser/unruly/internal/surface"
	"github.com/eppser/unruly/scan"
)

// EscalationStage measures what an authenticated role reads that anonymous
// cannot -- for the default schema and for every other exposed schema.
//
// Ported from the "// ---- privilege escalation ----" section of scanTarget.
//
// WHY THIS ONE MATTERS BEYOND TIDINESS. Inline, this was the only work in the
// scan that spent requests with no ledger attribution at all: the other ported
// stages attribute through runStage/State.Spending, and the remaining inline
// work carries explicit spend.add labels (discovery, prefix, providers,
// relations, relations-retry). Escalation had neither. Since the printed
// breakdown is spend.summary(4) -- the top four, LARGEST FIRST -- a pass that
// re-probes every relation and every exposed schema with an elevated key could
// be the single biggest spender in the scan and still never appear in the list
// an operator reads to decide what to cap. Being a stage fixes that as a side
// effect of the move.
//
// WHAT IS DELIBERATELY NOT HERE: escalate.Acquire. Acquisition signs up and
// hands back a credential, and inline it assigns o.userJWT -- a stage that
// mutates its caller's options is not a stage. It stays where it is and its
// result arrives here as ElevatedKey, so the ordering constraint is visible in
// this struct rather than implied by where the code happens to sit.
type EscalationStage struct {
	Client      *client.Client
	ElevatedKey string
	Concurrency int
	SampleRows  int
	Redact      bool
	Measure     bool
}

// SchemaEscalation pairs a schema with what the elevated role read in it.
type SchemaEscalation struct {
	Name   string
	Result escalate.Result
}

func (EscalationStage) Name() string { return "escalation" }

func (s EscalationStage) Run(ctx context.Context, st *scan.State) error {
	// A token supplied on the command line is known when the list is built; one
	// the scan MINTS is not. Reading the published credential is what lets a
	// stage constructed before the account existed still use it.
	key := s.ElevatedKey
	if key == "" {
		if c, ok := scan.Get[Credential](st); ok {
			key = c.Token
		}
	}
	if key == "" {
		// Open signup makes the absent credential a MEASURABLE gap rather than
		// an inapplicable check: anyone can obtain the role this pass would
		// have used, so declining leaves a reachable surface unexamined.
		if sf, ok := scan.Get[surface.Result](st); ok && sf.Auth.SignupOpen() {
			st.Note(scan.Warn, "public signup is open; pass -user-jwt to measure what "+
				"an authenticated account can reach that anon cannot")
		}
		// No credential, no comparison. This is not the same as "the
		// authenticated role reads nothing extra" -- the caller decides
		// whether to run this stage, and a stage that ran and found nothing
		// attributes a zero, which reads as a measurement.
		return nil
	}

	// Relations come from the published enumerate outcome.
	en, ok := scan.Get[EnumerateOutcome](st)
	if !ok {
		return errors.New("no enumerate outcome was published, so there are no " +
			"relations to examine: this surface was not assessed")
	}
	relations := en.Result.Names()
	// Other exposed schemas, if the schemas pass ran. Absent is legitimate
	// here and NOT an error: it means no extra schema was discovered, which
	// is the common case, and the default schema is examined either way.
	schemas, _ := scan.Get[Schemas](st)

	// The probe result is a DECLARED REQUIREMENT, not an assumption.
	//
	// Checked AFTER the credential guard, deliberately. A stage that declines
	// for want of a credential has not failed to assess anything, and
	// reporting a missing dependency it was never going to use would turn a
	// deliberate skip into a not-assessed finding and an exit 3.
	//
	// A field was explicit and compiler-checked; reading from shared state is
	// not, so the dependency is stated here instead. Without this, a stage
	// handed no probe result subscribes to nothing, finds nothing and reports
	// nothing -- indistinguishable from a project whose surface is closed.
	//
	// Returning an error makes the pipeline emit a not-assessed finding
	// carrying the id the exit code keys on, so an unexamined surface drives
	// exit 3 instead of passing for a clean one.
	pr, ok := scan.Get[probe.Result](st)
	if !ok {
		return errors.New("no probe result was published, so there is nothing to " +
			"compare against: this surface was not assessed")
	}

	esc := escalate.Compare(ctx, s.Client, pr, escalate.Options{
		Relations:   relations,
		ElevatedKey: key,
		Concurrency: s.Concurrency,
		SampleRows:  s.SampleRows,
		Redact:      s.Redact,
		Measure:     s.Measure,
	})
	st.Attribute(s.Name(), esc.Requests)
	st.Add(esc.Findings...)

	var per []SchemaEscalation
	for _, ss := range schemas.Scans {
		sesc := escalate.Compare(ctx, s.Client.WithSchema(ss.Name), ss.Result, escalate.Options{
			Relations:   ss.Relations,
			ElevatedKey: key,
			Concurrency: s.Concurrency,
			SampleRows:  s.SampleRows,
			Redact:      s.Redact,
			Measure:     s.Measure,
			Schema:      ss.Name,
		})
		st.Attribute(s.Name(), sesc.Requests)
		// escalate qualifies its own names, because its SQL must.
		st.Add(sesc.Findings...)
		per = append(per, SchemaEscalation{Name: ss.Name, Result: sesc})
	}
	// Published once, at the end, carrying both passes. The default schema's
	// comparison and the per-schema ones are one answer to one question --
	// what does signing up gain -- and a caller that held only the first
	// would under-report every project with an extra exposed schema.
	st.Note(scan.Info, "role %s reads %d relations that anon cannot",
		esc.Role, len(esc.Gains))
	for _, se := range per {
		if len(se.Result.Gains) > 0 {
			st.Note(scan.Info, "schema %s: role %s reads %d relations that anon cannot",
				se.Name, se.Result.Role, len(se.Result.Gains))
		}
	}
	scan.Put(st, Escalation{Result: esc, PerSchema: per})
	return nil
}
