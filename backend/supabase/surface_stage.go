package supabase

import (
	"context"
	"errors"

	"github.com/eppser/unruly/internal/client"
	"github.com/eppser/unruly/internal/surface"
	"github.com/eppser/unruly/scan"
)

// SurfaceStage examines auth, storage, routines and Edge Functions.
//
// Ported from the "// ---- auth / storage / rpc ----" section of scanTarget.
// These are project-wide rather than per-schema, which is why they run once
// and are deliberately not repeated for every exposed schema: doing so would
// re-issue the same requests and report the same findings several times.
type SurfaceStage struct {
	Client *client.Client
	Opts   surface.Options
	// RoutineCap is the allowance the routine sweep was given, carried
	// separately because the truncation finding reports what the cap WAS
	// rather than what remained.
	RoutineCap int
	// RPCRoutines is the LIVE routine allowance, shared with the schemas
	// stage. Carried as the budget rather than as an int because the schemas
	// pass spends from it first: an int captured at construction time would be
	// the allowance as it stood before that pass ran, so this stage would
	// either over-spend the operator's -max-rpc or under-use it, depending on
	// when the caller happened to read it.
	//
	// This is also what let the stage list stop depending on scan order.
	RPCRoutines *scan.Budget
}

func (SurfaceStage) Name() string { return "surface" }

// Run examines the project-wide surfaces and records what it found.
func (s SurfaceStage) Run(ctx context.Context, st *scan.State) error {
	st.Note(scan.Info, "inspecting auth, storage and RPC surfaces")

	// Seed lists come from the published vocabulary. Both are derived from the
	// harvested words the vocabulary stage already owns.
	vocab, ok := scan.Get[Vocabulary](st)
	if !ok {
		return errors.New("no vocabulary was published, so there are no routine or " +
			"bucket candidates: this surface was not assessed")
	}
	opts := s.Opts
	opts.RoutineSeeds = vocab.RoutineSeeds
	opts.RoutineGuesses = vocab.Composed
	if s.RPCRoutines != nil {
		opts.MaxCandidates = s.RPCRoutines.Left()
	}
	r := surface.Run(ctx, s.Client, opts)
	scan.Put(st, r)

	// Attributed PER SUB-STAGE rather than as one "surface" line.
	//
	// That single line was the largest spender on a real target -- 4,406 of
	// 12,068 requests -- and said nothing about where they went. A ledger
	// whose biggest entry is opaque is the part an operator cannot act on,
	// and this project has already lost an investigation to reasoning from
	// one. surface reports its own breakdown; this preserves it.
	for name, n := range r.RequestsBy {
		st.Attribute(name, n)
	}

	// Not invoking is a DELIBERATE limit, and saying so is the difference
	// between "no callable routine was found" and "nobody asked".
	if !s.Opts.AllowInvoke && len(r.Routines) > 0 {
		st.Note(scan.Info, "routines were not invoked: learning whether one is callable "+
			"means calling it, and a callable routine runs. Pass -write to determine it")
	}
	st.Note(scan.Info, "%d routines, %d functions, %d buckets, signup %s",
		len(r.Routines), len(r.Functions), len(r.Buckets),
		map[bool]string{true: "OPEN", false: "closed"}[r.Auth.SignupOpen()])
	if !s.Opts.AllowFunctions {
		st.Note(scan.Info, "Edge Functions were not probed: detecting one requires a POST "+
			"that invokes it, and functions send email, charge cards and write to queues. "+
			"Pass -write -invoke to include them; without it this scan says nothing about them")
	}

	if r.RoutineBudgetBound {
		st.Add(surface.RoutineBudgetFinding(s.Client.RestBase(), s.RoutineCap,
			r.RoutineCandidatesWanted))
	}
	st.Add(r.Findings...)
	return nil
}
