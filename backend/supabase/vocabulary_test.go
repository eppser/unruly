package supabase

import (
	"context"
	"testing"

	"github.com/eppser/unruly/scan"
)

// The stage merges every source rather than preferring one.
//
// Pinned lists cover conventional names; harvested vocabulary covers the
// domain-specific ones a list can never guess; the OpenAPI document names what
// the target admits to; supplied names come from an operator or an agent that
// read something this scanner cannot parse. Measured on the reference target,
// the pinned list alone reached 2 of 7 relations. Preferring any single source
// loses recall that another source already had.
func TestEverySeedSourceReachesTheMergedSet(t *testing.T) {
	got := MergeSeeds(SeedSources{
		Harvested:  []string{"invoices"},
		Advertised: []string{"ledger"},
		Supplied:   []string{"secret_notes"},
		Pinned:     []string{"users"},
	})
	for _, want := range []string{"invoices", "ledger", "secret_notes", "users"} {
		if !contains(got, want) {
			t.Errorf("%q is missing from the merged seeds, so a source was preferred "+
				"over another rather than added to it", want)
		}
	}
}

// The merged set is sorted and deduplicated.
//
// Report order follows probe order follows seed order, and eval-determinism
// grades byte identity. A name that appears in two sources must not be probed
// twice either: that is wasted traffic against somebody else's project.
func TestTheMergedSetIsSortedAndDeduplicated(t *testing.T) {
	got := MergeSeeds(SeedSources{
		Harvested: []string{"beta", "alpha"},
		Pinned:    []string{"alpha", "gamma"},
	})
	want := []string{"alpha", "beta", "gamma"}
	if len(got) != len(want) {
		t.Fatalf("merged to %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("merged to %v, want %v", got, want)
		}
	}
}

// PROVENANCE: the counts come from the stage that produced them.
//
// Carried unlanded for forty iterations because the design kept looking
// awkward, and the awkwardness was the signal: the counts were being
// re-derived at a call site that had no business knowing them. The stage that
// merges the sources is the only thing that knows how many each contributed.
func TestTheStageReportsWhereItsSeedsCameFrom(t *testing.T) {
	st := &scan.State{}
	stage := VocabularyStage{
		Sources: SeedSources{
			Pinned:     []string{"users", "posts"},
			Harvested:  []string{"invoices"},
			Advertised: []string{"ledger"},
			Supplied:   []string{"secret_notes"},
		},
	}
	if _, err := (scan.Pipeline{stage}).Run(context.Background(), st); err != nil {
		t.Fatal(err)
	}
	// Read from the published artifact rather than an out-param the caller
	// declared. Same fact, no longer routed through the command's scope.
	v, ok := scan.Get[Vocabulary](st)
	if !ok {
		t.Fatal("the stage published no vocabulary")
	}
	origins := v.Origins
	if origins.Pinned != 2 || origins.Harvested != 1 ||
		origins.Advertised != 1 || origins.Supplied != 1 {
		t.Errorf("origins %+v do not match what was supplied: a report that cannot say "+
			"how many of its findings began as somebody else's suggestion cannot be "+
			"audited for it", origins)
	}
}

// A scan with nothing but the pinned list says so, rather than implying the
// application was consulted.
//
// 24 relations found from a pinned English list is a different result from 24
// found because the application named them, and the remedy for a low count
// differs in each case.
func TestAPinnedOnlyScanIsDistinguishable(t *testing.T) {
	st := &scan.State{}
	if _, err := (scan.Pipeline{VocabularyStage{
		Sources: SeedSources{Pinned: []string{"users"}},
	}}).Run(context.Background(), st); err != nil {
		t.Fatal(err)
	}
	v, ok := scan.Get[Vocabulary](st)
	if !ok {
		t.Fatal("the stage published no vocabulary")
	}
	origins := v.Origins
	if origins.Harvested != 0 || origins.Advertised != 0 || origins.Supplied != 0 {
		t.Errorf("origins %+v claim sources that contributed nothing", origins)
	}
	if origins.Pinned == 0 {
		t.Error("the pinned list is always a source and its count must be stated")
	}
}

func contains(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}

// TestOriginsSumToCandidates is the invariant the old counting broke: the
// provenance sentence must describe the set that was probed, not a larger one.
//
// The sources deliberately OVERLAP. Every other Origins test in this package
// uses disjoint sources, which is exactly why four passing tests coexisted
// with a summary that over-reported.
func TestOriginsSumToCandidates(t *testing.T) {
	s := VocabularyStage{
		Sources: SeedSources{
			Pinned:    []string{"users", "posts"},
			Harvested: []string{"users", "invoices"}, // "users" in both
			Supplied:  []string{"posts"},             // "posts" in both
		},
	}
	st := &scan.State{Target: "t"}
	if err := s.Run(context.Background(), st); err != nil {
		t.Fatal(err)
	}
	v, ok := scan.Get[Vocabulary](st)
	if !ok {
		t.Fatal("the stage published no vocabulary")
	}
	seeds, origins := v.Seeds, v.Origins
	sum := origins.Pinned + origins.Harvested + origins.Advertised + origins.Supplied
	if sum != len(seeds) {
		t.Errorf("provenance claims %d candidates, the scan probes %d (%v)",
			sum, len(seeds), seeds)
	}
	if origins.Harvested != 2 {
		t.Errorf("harvested owns the shared name: got %d, want 2", origins.Harvested)
	}
}
