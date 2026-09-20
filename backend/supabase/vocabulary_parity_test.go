package supabase

import (
	"testing"

	"github.com/eppser/unruly/internal/wordlist"
)

// The stage must merge exactly what the code it replaced merged.
//
// This is the regression test the vocabulary port hangs on, and it was the one
// ported stage that never got one: the others each carry an
// AgreesWithTheCodeItReplaced test, and VocabularyStage had four unit tests
// about its own behaviour and nothing tying it to the line it replaced.
//
// That line, transcribed from cmd/unruly/main.go as it stood before b9f440d:
//
//	seeds := wordlist.Merge(wordlist.Merge(harvested, advertised), wordlist.Relations())
//
// Order matters here in a way it does not for findings. Report order follows
// probe order follows seed order, and eval-determinism grades byte identity --
// so a merge that produced the same SET in a different order would still be a
// regression, and this compares element by element rather than as sets.
func TestTheVocabularyStageAgreesWithTheCodeItReplaced(t *testing.T) {
	// Deliberately awkward: a duplicate within a source, a case difference
	// across sources, and a name that appears in two sources at once. Those
	// are the inputs where a merge can disagree with itself.
	//
	// Every name here is one the PINNED list does not already contain. The
	// first version of this test used "profiles" and "ledger", which the pinned
	// list carries -- so dropping the advertised source entirely still produced
	// an identical merge and the test passed against a stage that had stopped
	// reading one of its inputs. A parity fixture whose sources overlap the
	// pinned list cannot see a source disappear.
	harvested := []string{"zz_invoices", "ZZ_Ledger", "zz_invoices"}
	advertised := []string{"zz_openapi_only", "zz_ledger"}

	// --- the original expression, transcribed ---------------------------
	old := wordlist.Merge(wordlist.Merge(harvested, advertised), wordlist.Relations())

	// --- the stage ------------------------------------------------------
	got := MergeSeeds(SeedSources{
		Pinned:     wordlist.Relations(),
		Harvested:  harvested,
		Advertised: advertised,
	})

	if len(got) != len(old) {
		t.Fatalf("the stage merged %d seeds, the code it replaced merged %d",
			len(got), len(old))
	}
	for i := range old {
		if got[i] != old[i] {
			t.Fatalf("seed %d differs: stage has %q, the code it replaced had %q. "+
				"Probe order follows seed order and eval-determinism grades byte "+
				"identity, so this is a behaviour change, not a reordering.",
				i, got[i], old[i])
		}
	}
}

// Supplied names are a DELIBERATE difference from the code above.
//
// The old expression had no notion of a supplied source -- -vocab did not
// exist -- so parity is asserted for the three sources it knew and the fourth
// is asserted to be additive: it adds its names and changes nothing else.
// Recording that here is the point. A port that silently grows an input is
// indistinguishable from a port that silently drops one unless somebody writes
// down which it was.
func TestSuppliedSeedsAreAnAdditionToWhatTheOldPathMerged(t *testing.T) {
	harvested := []string{"invoices"}
	advertised := []string{"profiles"}

	without := MergeSeeds(SeedSources{
		Pinned: wordlist.Relations(), Harvested: harvested, Advertised: advertised})
	with := MergeSeeds(SeedSources{
		Pinned: wordlist.Relations(), Harvested: harvested, Advertised: advertised,
		Supplied: []string{"zzz_supplied_only"}})

	if len(with) != len(without)+1 {
		t.Fatalf("adding one supplied name changed the merged set from %d to %d; a "+
			"supplied source must add its names and nothing else",
			len(without), len(with))
	}
	if !contains(with, "zzz_supplied_only") {
		t.Error("the supplied name never reached the merged set")
	}
	for _, s := range without {
		if !contains(with, s) {
			t.Fatalf("%q was dropped when a supplied name was added", s)
		}
	}
}
