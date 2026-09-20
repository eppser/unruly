package scan

import "github.com/eppser/unruly/internal/finding"

// Coverage is what a provider says about the scan as a whole.
//
// It exists to end the last coupling between the command and a backend. The
// command has to produce two scan-level outputs -- the stored scan summary and
// the coverage finding that records what was NOT examined -- and it was
// obtaining the numbers for them by reading supabase.Vocabulary,
// supabase.Schemas, supabase.EnumerateOutcome and surface.Result. Four backend
// types, to produce four integers and a boolean.
//
// THE PROVIDER TRANSLATES, THE COMMAND READS. Only the provider knows what its
// own artifacts mean, so only the provider can fill this in; the command never
// interprets a backend type to do it. A second backend fills in the same
// fields or leaves them zero, and neither the command nor this struct changes.
//
// Nil-vs-zero applies as everywhere else here: a provider that published no
// Coverage has said nothing about how much it covered, which is different from
// one that covered nothing. Get's bool is what separates them, and the command
// must not print "0 relations discovered" -- a measurement -- for a provider
// that never reported.
type Coverage struct {
	// Relations discovered, across every schema examined.
	Relations int
	// Schemas examined, including the default one.
	Schemas int
	// SeedOrigins is where the candidate names came from, so the summary can
	// say how much of the scan was the application's own vocabulary and how
	// much was a pinned list. The four parts sum to the number actually
	// probed.
	SeedOrigins finding.SeedOrigins
	// OpenSignup reports that anyone can obtain an authenticated role.
	//
	// It belongs here rather than in a backend artifact because it changes a
	// SCAN-LEVEL judgement: an unmeasured escalation surface is an
	// inapplicable check when signup is closed and a genuine blind spot when
	// it is open.
	OpenSignup bool
}
