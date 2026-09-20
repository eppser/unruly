package supabase

import (
	"context"

	"github.com/eppser/unruly/internal/postgrest"
	"github.com/eppser/unruly/internal/probe"
	"github.com/eppser/unruly/internal/surface"
	"github.com/eppser/unruly/scan"
)

// CoverageStage translates this provider's artifacts into the neutral shape
// the command reports on.
//
// It is the provider's side of the boundary: the command needs a handful of
// scan-level numbers for the stored summary and for the coverage finding, and
// it used to obtain them by reading four Supabase types. Only this package
// knows what those types mean, so the translation belongs here and the command
// reads scan.Coverage alone.
//
// Deliberately LAST and deliberately cheap. It issues no requests and makes no
// decisions; it reads what the earlier stages published and states it once.
type CoverageStage struct{}

func (CoverageStage) Name() string { return "coverage" }

// Run publishes the neutral summary.
//
// Every input is optional. A scan cut short by a cancelled context, or one
// whose enumeration failed, still has a coverage figure -- a smaller one -- and
// refusing to publish would leave the command unable to tell "covered nothing"
// from "said nothing", which is the distinction it needs most when a scan ends
// early.
func (CoverageStage) Run(_ context.Context, st *scan.State) error {
	var c scan.Coverage
	var access scan.Access

	if en, ok := scan.Get[EnumerateOutcome](st); ok {
		c.Relations = len(en.Result.Relations)
	}
	if v, ok := scan.Get[Vocabulary](st); ok {
		c.SeedOrigins = v.Origins
	}
	// The default schema always counts: it is examined whether or not any
	// other schema was discovered, so a project with no extra schemas has
	// covered one rather than none.
	c.Schemas = 1
	if sch, ok := scan.Get[Schemas](st); ok {
		c.Schemas += len(sch.Scans)
		for _, ss := range sch.Scans {
			c.Relations += len(ss.Relations)
		}
	}
	if sf, ok := scan.Get[surface.Result](st); ok {
		c.OpenSignup = sf.Auth.SignupOpen()
	}
	if pr, ok := scan.Get[probe.Result](st); ok {
		access.Observed = append(access.Observed, accessFacts(pr)...)
	}
	if sch, ok := scan.Get[Schemas](st); ok {
		for _, ss := range sch.Scans {
			access.Observed = append(access.Observed, accessFacts(ss.Result)...)
		}
	}
	if esc, ok := scan.Get[Escalation](st); ok {
		for _, name := range esc.Result.GainedRelations() {
			access.Observed = append(access.Observed, scan.AccessFact{
				Resource: name, Operation: "read", Subject: "authenticated",
				Allowed: true,
			})
		}
		for _, se := range esc.PerSchema {
			for _, name := range se.Result.GainedRelations() {
				access.Observed = append(access.Observed, scan.AccessFact{
					Resource: se.Name + "." + name, Operation: "read",
					Subject: "authenticated", Allowed: true,
				})
			}
		}
	}

	scan.Put(st, c)
	scan.Put(st, access)
	return nil
}

func accessFacts(pr probe.Result) []scan.AccessFact {
	var out []scan.AccessFact
	for _, rel := range pr.Relations {
		resource := rel.Qualified()
		addRead := func(allowed bool) {
			out = append(out, scan.AccessFact{Resource: resource, Operation: "read",
				Subject: "anonymous", Allowed: allowed})
		}
		switch rel.Read {
		case postgrest.ReadExposed:
			addRead(true)
		case postgrest.ReadDenied:
			addRead(false)
			// ReadEmpty is intentionally absent: empty and RLS-filtered are
			// indistinguishable, so it cannot satisfy an intent expectation.
		}
		for _, verb := range []struct {
			name  string
			state postgrest.WriteState
		}{{"insert", rel.Write}, {"update", rel.Update}, {"delete", rel.Delete}} {
			switch verb.state {
			case postgrest.WriteReached:
				out = append(out, scan.AccessFact{Resource: resource, Operation: verb.name,
					Subject: "anonymous", Allowed: true})
			case postgrest.WriteBlockedRLS:
				out = append(out, scan.AccessFact{Resource: resource, Operation: verb.name,
					Subject: "anonymous", Allowed: false})
			}
		}
	}
	return out
}
