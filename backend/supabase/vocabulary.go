package supabase

import (
	"context"

	"github.com/eppser/unruly/internal/finding"
	"github.com/eppser/unruly/internal/wordlist"
	"github.com/eppser/unruly/scan"
)

// SeedSources are the candidate names, kept apart by where they came from.
//
// They are merged, never chosen between. Measured on a second project: the
// pinned list alone reached 2 of 7 relations while the hint oracle would have
// answered for all 7, so preferring one source loses recall another already
// had.
type SeedSources struct {
	// Pinned ships with the binary and is the same on every scan, so it says
	// nothing about this target.
	Pinned []string
	// Harvested comes from the application's own pages and bundles, and is the
	// reason a scan with a site beats one without.
	Harvested []string
	// Advertised is what the OpenAPI document names. Not trusted and not
	// relied on -- on the managed product it is service_role-only and answers
	// 401 -- but where a self-hosted deployment serves it, it names the schema
	// outright.
	Advertised []string
	// Supplied came from outside this process: an operator who knows the
	// schema, or an agent that read a document this scanner cannot parse.
	Supplied []string
}

// SeedOrigins is finding.SeedOrigins, aliased so this package can name it
// without the reporting layer having to import a backend.
type SeedOrigins = finding.SeedOrigins

// MergeSeeds combines every source into the candidate list.
//
// Delegates to wordlist.Merge in the same order main used -- harvested and
// supplied together, then advertised, then pinned -- so the result is
// identical to the expression this replaced. Merge folds, trims, deduplicates
// and sorts, which is what keeps probe order and therefore report order stable
// between runs.
func MergeSeeds(s SeedSources) []string {
	// Supplied names travel with harvested ones because both describe THIS
	// target, as against the pinned list which is the same everywhere.
	local := append(append([]string(nil), s.Harvested...), s.Supplied...)
	return wordlist.Merge(wordlist.Merge(local, s.Advertised), s.Pinned)
}

// Vocabulary is what the vocabulary stage publishes: the candidate names every
// later stage probes, and where they came from.
//
// A typed artifact rather than two out-params. `Out: &seeds,
// Origins: &seedOrigins` put two variables in scanTarget's scope for a fact
// entirely internal to the Supabase scan, which is what made this stage
// impossible to reorder or replace without editing the command.
type Vocabulary struct {
	// Seeds is the merged candidate list, in MergeSeeds' order. The order is
	// load-bearing: it fixes probe order and therefore report order, and two
	// scans of an unchanged target have to produce identical bytes.
	Seeds []string
	// Origins is what each source contributed AFTER the merge, so the four
	// parts sum to exactly len(Seeds). The stage that merges is the only
	// thing that can know this.
	Origins SeedOrigins
	// RoutineSeeds are the candidates for routine discovery: harvested
	// vocabulary merged with the pinned routine list.
	RoutineSeeds []string
	// Composed are compound routine candidates built from harvested
	// vocabulary. A routine named admin_read_audit_log is invisible to a seed
	// list of single tokens, because PostgREST's hint matches on similarity
	// and a compound is not similar enough to either of its parts.
	//
	// Both live here rather than being computed at a call site because they
	// are derived from the SAME harvested vocabulary this stage already owns.
	// Computing them in the command meant the schemas and surface stages could
	// only be constructed by a caller holding the harvest -- which is the one
	// thing that stopped the stage list being a pure function of the flags.
	Composed []string
}

// VocabularyStage produces the candidate names every later stage probes.
//
// This is the Enumerate phase of the provider contract: it does not assess
// anything, it decides what will be asked about. Its output is exactly what
// scan.Inputs.Seeds carries to the other backends.
type VocabularyStage struct {
	Sources SeedSources
	// MaxRPC bounds compound routine candidates, honouring the same budget the
	// rest of routine discovery does.
	MaxRPC int
	// Site and HarvestSources describe where the vocabulary came from, so this
	// stage can report a SHORTFALL: falling back to the pinned list is a
	// CHOICE when no site was supplied and a LOSS when one was and could not
	// be read. Those two need different words and only one of them is a
	// warning, and the command used to decide which -- from counts it was
	// holding purely to make that call.
	Site           string
	HarvestSources int
}

func (VocabularyStage) Name() string { return "vocabulary" }

// Run merges the sources and reports what each contributed.
func (v VocabularyStage) Run(_ context.Context, st *scan.State) error {
	merged := MergeSeeds(v.Sources)
	origins := SeedOrigins{}
	{
		// Attributed AFTER the merge, in MergeSeeds' own precedence, so the
		// four parts sum to exactly len(merged).
		//
		// len() of each source double-counts every name that appears in two of
		// them, and that is not a corner case: "users" and "profiles" are on
		// the pinned list and are exactly the names an application references,
		// so the pinned/harvested overlap is the common case. The summary
		// renders these as a sentence a reader will add up, and the total has
		// to be a number the scan actually probed.
		//
		// Harvested wins a shared name over pinned, which is both Merge's
		// order and the more informative attribution: it says the application
		// itself references the name.
		n := wordlist.Contributions(v.Sources.Harvested, v.Sources.Supplied,
			v.Sources.Advertised, v.Sources.Pinned)
		origins = SeedOrigins{
			Harvested: n[0], Supplied: n[1], Advertised: n[2], Pinned: n[3],
		}
	}
	// Published, not written through a caller's pointer. Unconditional: a
	// stage that publishes only when somebody asked for the result leaves a
	// later stage unable to tell "found nothing" from "did not run".
	// Where the candidates came from, and what it cost if they came from a
	// list rather than from the application.
	if n := vocabularyShortfall(v.Site, len(v.Sources.Supplied),
		len(v.Sources.Harvested), v.HarvestSources); n.Msg != "" {
		lvl := scan.Info
		if n.Warn {
			lvl = scan.Warn
		}
		st.Note(lvl, "%s", n.Msg)
		if n.Report != nil {
			st.Add(*n.Report)
		}
	}

	routineSeeds := wordlist.Merge(v.Sources.Harvested, wordlist.Routines())
	st.Note(scan.Info, "%d relation seeds, %d routine seeds (harvested + pinned)",
		len(merged), len(routineSeeds))
	scan.Put(st, Vocabulary{
		Seeds:        merged,
		Origins:      origins,
		RoutineSeeds: routineSeeds,
		Composed:     wordlist.Compose(v.Sources.Harvested, v.MaxRPC),
	})
	// No requests: merging is arithmetic. Attributing zero keeps the stage out
	// of the spend breakdown rather than showing a line that always reads 0.
	return nil
}
