package sample

import (
	"fmt"
	"sort"
	"testing"
)

// alphabet returns sorted tokens spread over 26 leading letters, which is the
// shape a harvested vocabulary has after sort.Strings.
func alphabet(perLetter int) []string {
	var xs []string
	for c := 'a'; c <= 'z'; c++ {
		for i := 0; i < perLetter; i++ {
			xs = append(xs, fmt.Sprintf("%c_token_%03d", c, i))
		}
	}
	sort.Strings(xs)
	return xs
}

func leadingLetters(xs []string) map[byte]int {
	m := map[byte]int{}
	for _, x := range xs {
		m[x[0]]++
	}
	return m
}

// The case this package exists for, measured on the reference project: the
// harvested vocabulary yields 4,112 tokens against a cap of 2,000, so half of
// what the application says about itself is discarded before any probe is sent.
// Cutting at the front discards it alphabetically.
func TestTakeSpansTheWholeList(t *testing.T) {
	xs := alphabet(100) // 2,600 tokens across 26 letters
	const budget = 1000

	got := Take(xs, budget)
	if len(got) != budget {
		t.Fatalf("Take returned %d items, want %d", len(got), budget)
	}
	letters := leadingLetters(got)
	if len(letters) != 26 {
		var missing []string
		for c := byte('a'); c <= 'z'; c++ {
			if letters[c] == 0 {
				missing = append(missing, string(c))
			}
		}
		t.Errorf("a budget of %d out of %d reached %d of 26 letters; nothing beginning "+
			"%v would ever be probed", budget, len(xs), len(letters), missing)
	}

	// The front-cut it replaces, for contrast: this is what the code did
	// before, and it is what the assertion above must keep failing against.
	if front := leadingLetters(xs[:budget]); len(front) >= 26 {
		t.Fatal("the fixture is too small to distinguish a front cut from a spread one, " +
			"so the assertion above proves nothing")
	}
}

// Nothing is invented and nothing is lost: Take must return a subset, and
// Strided a permutation. A sampler that duplicated items would waste budget on
// repeats; one that invented them would probe names the target never suggested.
func TestSamplesAreSubsetsOfTheInput(t *testing.T) {
	xs := alphabet(10)
	in := map[string]bool{}
	for _, x := range xs {
		in[x] = true
	}
	for _, n := range []int{1, 7, 99, len(xs) - 1, len(xs), len(xs) + 5} {
		got := Take(xs, n)
		seen := map[string]bool{}
		for _, g := range got {
			if !in[g] {
				t.Fatalf("Take(%d) returned %q, which is not in the input", n, g)
			}
			if seen[g] {
				t.Fatalf("Take(%d) returned %q twice, wasting budget on a repeat", n, g)
			}
			seen[g] = true
		}
		if want := min(n, len(xs)); n > 0 && len(got) != want {
			t.Errorf("Take(%d) returned %d items, want %d", n, len(got), want)
		}
	}
}

// A list that already fits must come back untouched, so an unbudgeted scan
// probes in plain sorted order and reports stay comparable across runs.
func TestUnbudgetedListIsUnchanged(t *testing.T) {
	xs := alphabet(2)
	for _, budget := range []int{0, -1, len(xs), len(xs) + 1} {
		got := Strided(xs, budget)
		if len(got) != len(xs) {
			t.Fatalf("budget %d changed the list length", budget)
		}
		for i := range xs {
			if got[i] != xs[i] {
				t.Fatalf("budget %d reordered a list that fits", budget)
			}
		}
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
