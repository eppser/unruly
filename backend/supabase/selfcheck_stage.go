package supabase

import (
	"context"
	"errors"
	"strings"

	"github.com/eppser/unruly/internal/client"
	"github.com/eppser/unruly/internal/selfcheck"
	"github.com/eppser/unruly/scan"
)

// SelfCheckStage verifies the scan's own oracles before anything trusts what
// they did NOT find.
//
// Ported from the "// ---- self-check ----" section of scanTarget. A scan that
// cannot see must say so: "no findings" from a blind scan is the exact lie
// every surveyed tool tells, and this is the check that makes it impossible
// here. It runs after enumeration so it can judge on what the scan actually
// observed rather than on a synthetic guess.
type SelfCheckStage struct {
	Client *client.Client
}

func (SelfCheckStage) Name() string { return "selfcheck" }

// Run verifies the oracles and records what was degraded.
func (s SelfCheckStage) Run(ctx context.Context, st *scan.State) error {
	// What the scan observed so far, assembled here rather than handed in.
	//
	// Four of the six numbers come from the published enumerate outcome. The
	// other two are the transport's own counters, and reading them HERE rather
	// than at construction time is a correction, not just a move: main built
	// this stage's evidence before running it, so the sent/failed counts were
	// whatever they had been when the struct was built. Now they are what they
	// are when the oracles are judged.
	en, ok := scan.Get[EnumerateOutcome](st)
	if !ok {
		return errors.New("no enumerate outcome was published, so there is nothing to " +
			"judge the oracles against: this surface was not assessed")
	}
	sent, failed := s.Client.Stats()
	ev := selfcheck.Evidence{
		HintsObserved:  en.Result.HintsObserved,
		RelationsFound: len(en.Result.Relations),
		ProbesDenied:   en.Result.Denied,
		ProbesTotal:    en.Result.SeedCount,
		RequestsSent:   sent,
		RequestsFailed: failed,
	}
	r := selfcheck.Run(ctx, s.Client, ev)
	scan.Put(st, r)
	st.Attribute(s.Name(), r.Requests)
	st.Add(r.Findings...)

	// The verdict, said by the thing that reached it. Degraded is a WARNING
	// because it means the results below are incomplete -- the scan can still
	// look, but not everywhere, and an operator who reads a short report
	// without this line reads it as a clean one.
	if d := r.Degraded(); len(d) > 0 {
		st.Note(scan.Warn, "degraded capabilities: %s — results are incomplete",
			strings.Join(d, ", "))
	} else {
		st.Note(scan.Info, "self-check ok (%d capabilities verified)", len(r.Capabilities))
	}
	return nil
}
