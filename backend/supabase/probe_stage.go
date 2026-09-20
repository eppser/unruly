// Package supabase holds the Supabase scan expressed as pipeline stages.
//
// It is the destination of the port. Today the whole Supabase scan lives in
// scanTarget() in cmd/unruly/main.go -- one 1,390-line function whose twelve
// author-marked sections are the stages below. Each section moves here one at
// a time, with its own test, and the old call site is retired only once parity
// is proven: the existing code encodes PostgREST behaviour learned the hard
// way (206 is a counted read, 204 means a write succeeded, a zero-match
// DELETE returns 204 whether or not it was allowed) that must survive the move.
package supabase

import (
	"context"
	"errors"

	"github.com/eppser/unruly/internal/client"
	"github.com/eppser/unruly/internal/probe"
	"github.com/eppser/unruly/scan"
)

// ProbeStage establishes what an anonymous caller can actually do to each
// discovered relation.
//
// Ported from the "// ---- probing ----" section of scanTarget. The stage owns
// the probing and the accounting; the operator warnings that used to sit
// alongside it stay with the command, because telling a human what is about to
// happen is a property of the interface rather than of the scan.
type ProbeStage struct {
	// Client speaks to the target's PostgREST. It is held by the stage rather
	// than by scan.State on purpose: a client is the most backend-specific
	// thing there is, and putting it in the shared state would make every
	// future backend accept a field only Supabase and Neon can populate.
	Client *client.Client
	// Opts carries the probe budget and behaviour the operator chose.
	Opts probe.Options
	// Redact removes sampled values while keeping the finding usable.
	Redact bool
}

// Name is stable: it appears in the spend breakdown and in the not-assessed
// finding the pipeline emits if this stage fails.
func (p ProbeStage) Name() string { return "probe" }

// Run probes every discovered relation and records what it found.
func (p ProbeStage) Run(ctx context.Context, st *scan.State) error {
	// Names come from the published enumerate outcome, not a construction
	// field. Declared, so a probing pass that was handed nothing says so
	// instead of reporting a clean project.
	en, ok := scan.Get[EnumerateOutcome](st)
	if !ok {
		return errors.New("no enumerate outcome was published, so there are no " +
			"relations to probe: this surface was not assessed")
	}
	names := en.Result.Names()
	r := probe.Run(ctx, p.Client, names, p.Opts)
	// Published for the LATER STAGES OF THIS PROVIDER to steer on: realtime
	// needs the writable relations, the escalation compare needs the whole
	// result.
	//
	// Through scan.Put, which is generic, so the provider-agnostic pipeline
	// still never names a PostgREST type -- that was the standing objection to
	// putting probe.Result on State and it remains a good one. The artifact
	// type stays here, in the package that defines it.
	scan.Put(st, r)
	st.Attribute(p.Name(), r.Requests)
	st.Add(r.Findings(p.Client.RestBase(), p.Redact)...)
	// A column budget that bound is a lower bound the reader is owed: columns
	// that went unprobed are columns whose exposure is unknown, not columns
	// known to be safe.
	if r.ColumnBudgetBound {
		st.Add(probe.ColumnBudgetFinding(p.Client.RestBase(), r.ColumnProbesUsed,
			p.Opts.MaxColumnProbes, r.ColumnsUnprobedCount))
	}
	return nil
}
