package supabase

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/eppser/unruly/internal/client"
	"github.com/eppser/unruly/internal/probe"
	"github.com/eppser/unruly/internal/realtime"
	"github.com/eppser/unruly/scan"
)

// RealtimeStage establishes whether anonymous listeners receive future changes.
//
// Ported from the "// ---- realtime ----" section of scanTarget. REST answers
// "can anon read this now"; Realtime answers "does anon receive every future
// change". A relation can look quiet to one and stream to the other.
type RealtimeStage struct {
	Client  *client.Client
	AnonKey string
	// Write and NoResidue gate the delivery probe. See wouldTrigger.
	Write     bool
	NoResidue bool
	// Timeout is the operator's -timeout. realtime.Options declares it and
	// internal/realtime reads it, but no caller ever set one, so every
	// subscription used the package's own 20s default no matter what was
	// asked for -- a control present in the API and absent from the
	// behaviour.
	Timeout time.Duration
}

// RealtimeOutcome is what the stage established, for the command to report.
type RealtimeOutcome struct {
	Default realtime.Result
	// PerSchema is a slice, not a map: two scans of an unchanged project must
	// produce identical bytes, and map iteration is not ordered.
	PerSchema []SchemaRealtime
}

// SchemaRealtime pairs a schema with what Realtime did there.
type SchemaRealtime struct {
	Name   string
	Result realtime.Result
}

func (RealtimeStage) Name() string { return "realtime" }

// wouldTrigger reports whether the delivery probe is armed.
//
// The delivery probe WRITES, so it is offered only under -write. It causes a
// change on a relation already shown to accept anonymous INSERT, which is a
// write the operator consented to and which the probing stage already
// performed once.
//
// -no-residue withdraws that justification. Under it the probing stage creates
// nothing, so this would be the only row-creating write in the scan, and a
// Realtime change cannot be made residue-free the way an INSERT probe can: a
// write that collides with a unique constraint changes no row and therefore
// delivers no payload. The check is DECLINED, not silently downgraded -- with
// no trigger installed the result reports a skipped check rather than a clean
// one. Found by counting rows on the lab after a -no-residue scan and getting
// one more than it started with.
func (r RealtimeStage) wouldTrigger() bool { return r.Write && !r.NoResidue }

// Run subscribes as an anonymous listener and records what was delivered.
func (r RealtimeStage) Run(ctx context.Context, st *scan.State) error {
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

	readExposed := map[string]bool{}
	for _, n := range pr.ReadExposed() {
		readExposed[n] = true
	}
	opts := realtime.Options{
		BaseURL: r.Client.BaseURL(), AnonKey: r.AnonKey,
		Relations: relations, ReadExposed: readExposed,
		Timeout: r.Timeout,
	}
	if r.wouldTrigger() {
		opts.Writable = pr.InsertReachable()
		opts.Trigger = func(ctx context.Context, rel string) bool {
			return probe.Trigger(ctx, r.Client, rel)
		}
	}

	rt := realtime.Run(ctx, opts)
	requests := rt.Requests
	st.Add(rt.Findings...)

	out := RealtimeOutcome{Default: rt}
	for _, ss := range schemas.Scans {
		sOpts := opts
		sOpts.Schema = ss.Name
		sOpts.Relations = ss.Relations
		readable := map[string]bool{}
		for _, n := range ss.Result.ReadExposed() {
			readable[n] = true
		}
		sOpts.ReadExposed = readable
		if r.wouldTrigger() {
			sOpts.Writable = ss.Result.InsertReachable()
			sc := r.Client.WithSchema(ss.Name)
			sOpts.Trigger = func(ctx context.Context, rel string) bool {
				return probe.Trigger(ctx, sc, rel)
			}
		}
		srt := realtime.Run(ctx, sOpts)
		requests += srt.Requests
		// Qualified, because the fix must name the right relation: an
		// unqualified CREATE POLICY resolves against search_path and either
		// errors or targets a different table entirely.
		for _, f := range srt.Findings {
			f.Resource = ss.Name + "." + f.Resource
			st.Add(f)
		}
		out.PerSchema = append(out.PerSchema, SchemaRealtime{Name: ss.Name, Result: srt})
	}

	// Absence of a delivered payload is only evidence when delivery was
	// actually attempted. Unreachable, attempted-and-silent, and never-tried
	// are three different results and none of them is clean.
	if !rt.Reachable || (len(rt.Delivered) == 0 && len(rt.DeliveryTested) > 0) ||
		!rt.Informative() {
		if f, ok := rt.CoverageFinding(r.Client.BaseURL()); ok {
			st.Add(f)
		}
	}

	scan.Put(st, out)
	for _, sr := range out.PerSchema {
		if len(sr.Result.Delivered) > 0 {
			st.Note(scan.Info, "schema %s: realtime delivered payloads for %d relation(s)",
				sr.Name, len(sr.Result.Delivered))
		}
	}
	lvl, text := realtimeVerdict(out.Default, len(relations))
	st.Note(lvl, "%s", text)
	st.Attribute(r.Name(), requests)
	return nil
}

// realtimeVerdict is what the realtime pass concluded, as one sentence.
//
// A pure function so the distinctions can be tested without standing up a
// websocket server. They are the point of the whole pass and they are easy to
// collapse: "caused a change and nothing arrived" is INCONCLUSIVE, not clean,
// and an acknowledgement is not proof of exposure on a deployment that
// acknowledges joins for relations that do not exist.
func realtimeVerdict(d realtime.Result, relations int) (scan.NoteLevel, string) {
	switch {
	case !d.Reachable:
		return scan.Info, "realtime endpoint not reachable"
	case len(d.Delivered) > 0:
		return scan.Info, fmt.Sprintf("realtime delivered change payloads for %d of %d "+
			"relations to an anonymous listener", len(d.Delivered), len(d.DeliveryTested))
	case len(d.DeliveryTested) > 0:
		// INCONCLUSIVE, not clean: a change was caused and nothing arrived,
		// which is a different claim from never having looked.
		return scan.Info, fmt.Sprintf("realtime: caused a change on %d relations and no "+
			"payload was delivered; with no delivery anywhere this is inconclusive, "+
			"not clean", len(d.DeliveryTested))
	case !d.Informative():
		// Measured: Supabase acknowledges a join for a relation that does not
		// exist, so the acknowledgement cannot prove exposure. The delivery
		// probe does not share that flaw but needs -write.
		return scan.Info, "realtime reachable; subscription acknowledgements are not a " +
			"reliable exposure signal on this deployment, so none are reported. " +
			"Pass -write to test delivery, which is sound"
	}
	return scan.Info, fmt.Sprintf("realtime reachable, %d of %d relations stream to anon",
		len(d.Streaming()), relations)
}
