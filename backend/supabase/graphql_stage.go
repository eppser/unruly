package supabase

import (
	"context"
	"errors"

	"github.com/eppser/unruly/internal/client"
	"github.com/eppser/unruly/internal/graphql"
	"github.com/eppser/unruly/internal/probe"
	"github.com/eppser/unruly/scan"
)

// GraphQLStage checks pg_graphql, a second read path over the same tables.
//
// Ported from the "// ---- auth / storage / rpc ----" section of scanTarget.
// It is the one interface no surveyed scanner looks at, and it needs no
// consent flag: every query it issues is a read the REST pass already made.
type GraphQLStage struct {
	Client      *client.Client
	SampleRows  int
	Concurrency int
	Redact      bool
	// Measure DECLINES this check rather than weakening it. See Run.
	Measure bool
}

func (GraphQLStage) Name() string { return "graphql" }

// Run queries pg_graphql unless -measure forbids it.
//
// GraphQL cannot participate in a measurement run. It distinguishes a readable
// relation from an RLS-filtered one by asking for node ids, and a node id
// decodes to a real row's primary key -- data. There is no count-only form of
// that question, so the check is skipped and SAID to be skipped rather than
// quietly weakened into something that looks like a clean result.
func (g GraphQLStage) Run(ctx context.Context, st *scan.State) error {
	// Relations come from the published enumerate outcome.
	en, ok := scan.Get[EnumerateOutcome](st)
	if !ok {
		return errors.New("no enumerate outcome was published, so there are no " +
			"relations to examine: this surface was not assessed")
	}
	relations := en.Result.Names()
	// Which relations REST already reads, derived from the published probe
	// result. GraphQL tells a readable relation from an RLS-filtered one by
	// asking for node ids, so it needs to know what REST managed -- and the
	// probing stage is what measured that.
	pr, ok := scan.Get[probe.Result](st)
	if !ok {
		return errors.New("no probe result was published, so there is nothing to " +
			"compare GraphQL against: this surface was not assessed")
	}
	restReadable := map[string]bool{}
	for _, name := range pr.ReadExposed() {
		restReadable[name] = true
	}
	r := graphql.Result{}
	if !g.Measure {
		r = graphql.Run(ctx, g.Client, graphql.Options{
			Relations:    relations,
			RESTReadable: restReadable,
			SampleRows:   g.SampleRows,
			Concurrency:  g.Concurrency,
			Redact:       g.Redact,
		})
	}
	scan.Put(st, r)
	switch r.State {
	case graphql.Disabled:
		st.Note(scan.Info, "graphql: pg_graphql is not enabled on this project")
	case graphql.Enabled:
		st.Note(scan.Info, "graphql: enabled, %d relation(s) readable anonymously",
			len(r.Proof))
	}
	st.Attribute(g.Name(), r.Requests)
	st.Add(r.Findings...)
	return nil
}
