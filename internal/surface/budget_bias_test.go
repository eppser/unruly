package surface

import (
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/eppser/unruly/internal/sample"
)

// prefixesReached names the distinct leading words of a stem list.
func prefixesReached(xs []string) []string {
	m := map[string]bool{}
	for _, x := range xs {
		if i := strings.Index(x, "_"); i > 0 {
			m[x[:i]] = true
		}
	}
	var out []string
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// vocabulary spanning many prefixes, of the shape a real harvest produces.
func spanningSeeds() []string {
	var seeds []string
	for _, p := range []string{"admin", "audit", "batch", "cache", "delete", "export",
		"fetch", "grant", "handle", "import", "list", "merge", "notify", "order",
		"purge", "queue", "refresh", "search", "sync", "trigger", "update", "user",
		"validate", "verify", "write"} {
		for i := 0; i < 40; i++ {
			seeds = append(seeds, fmt.Sprintf("%s_record_%02d", p, i))
		}
	}
	return seeds
}

// A probe budget decides what is NOT looked at, so how it chooses matters as
// much as its size.
//
// The seeds are sorted and the cap used to be applied by taking them in order,
// which made the probed set the alphabetically first ones. The cap binds on
// every real scan -- 1,200 of 7,547 candidates against the reference project --
// so on a vocabulary spanning 25 prefixes the budget reached 10 and stopped at
// "import". Routines named update_*, validate_*, verify_* or write_* were
// unreachable on any project, and the report disclosed only "1200 of 7547
// candidates probed": true, and silent about the 1,200 all coming from the
// front of the alphabet.
//
// A biased lower bound is worse than a smaller unbiased one, because an
// operator cannot correct for a bias nobody stated.
func TestBudgetSamplesTheWholeNameSpace(t *testing.T) {
	seeds := spanningSeeds()
	full := routineCandidates(seeds, len(seeds)*3+1)
	capped := routineCandidates(seeds, 1200)

	// The budget has to actually truncate, or this test says nothing about how
	// truncation chooses. That is a property of the RAW candidate slots, not of
	// the distinct result: with a stride the same 1,200 slots now recover every
	// distinct stem, which is the improvement rather than a reason to skip.
	if raw := len(seeds) * 3; raw <= 1200 {
		t.Fatalf("the fixture produces %d candidate slots, which the 1200 budget does not "+
			"truncate", raw)
	}

	wantAll, gotCapped := prefixesReached(full), prefixesReached(capped)
	if len(wantAll) < 20 {
		t.Fatalf("the fixture vocabulary only spans %d prefixes; it cannot demonstrate "+
			"coverage", len(wantAll))
	}
	missing := map[string]bool{}
	for _, p := range wantAll {
		missing[p] = true
	}
	for _, p := range gotCapped {
		delete(missing, p)
	}
	if len(missing) > 0 {
		var lost []string
		for p := range missing {
			lost = append(lost, p)
		}
		sort.Strings(lost)
		t.Errorf("a binding budget reached %d of %d prefixes; these are unreachable on any "+
			"project whose routines are named after them: %v", len(gotCapped), len(wantAll), lost)
	}
}

// The stride must not drop or duplicate anything: it reorders, and the budget
// alone decides what is reached. A permutation that lost elements would shrink
// the full-budget candidate list, quietly costing recall on unbudgeted scans.
func TestSharedStrideIsAPermutation(t *testing.T) {
	in := []string{"a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k"}
	got := sample.Strided(in, 3)
	if len(got) != len(in) {
		t.Fatalf("strided returned %d elements from %d", len(got), len(in))
	}
	seen := append([]string{}, got...)
	sort.Strings(seen)
	for i := range in {
		if seen[i] != in[i] {
			t.Fatalf("strided is not a permutation: %v vs %v", seen, in)
		}
	}
	// And a prefix of it must span the input rather than cluster at the front.
	if got[0] == "a" && got[1] == "b" && got[2] == "c" {
		t.Error("the first three of a strided list are the first three of the input, so " +
			"a binding budget would still only see the opening pages")
	}
	// Determinism: the scan path may not vary between runs.
	for i := 0; i < 5; i++ {
		again := sample.Strided(in, 3)
		for j := range got {
			if again[j] != got[j] {
				t.Fatal("strided is not deterministic, which breaks byte-identical reports")
			}
		}
	}
}
