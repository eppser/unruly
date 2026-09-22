package browserscan_test

import (
	"strings"
	"testing"

	"github.com/eppser/unruly/internal/browserscan"
)

// The browser build shipped a scan that probed NOTHING and said "nothing found".
//
// cmd/unruly-wasm called wordlist.RelationCandidates(nil, 240). That function
// expands SEEDS; it is not the pinned list, and with no seeds it returns an
// empty slice. So the scan asked about zero names, every bucket came back
// empty, and the page reported "Nothing readable was found" for a project the
// CLI finds 23 relations on.
//
// That is the exact failure this project exists to refuse: silence from not
// looking, presented as a clean result. It reached a browser because the
// candidate list was built inline in a file tagged `js && wasm`, which no test
// on this machine can even compile. Hence this package: the decision lives
// somewhere a test can reach it.
func TestThereIsAlwaysSomethingToProbe(t *testing.T) {
	got := browserscan.Candidates("", 240)
	if len(got) == 0 {
		t.Fatal("no candidates without harvested text, so a scan would probe nothing " +
			"and report a clean result it never earned")
	}
	if len(got) > 240 {
		t.Errorf("budget 240 produced %d candidates", len(got))
	}
}

// Names from the app's own code are what find a real schema.
//
// The CLI harvests the bundle and reaches 23 relations on the target used
// during this work; the pinned list alone reaches none of them, because a
// vibe-coded schema is named after its domain and not after conventions.
func TestNamesFromTheAppItselfAreProbedFirst(t *testing.T) {
	bundle := `const {data}=await supabase.from("kundenauftrag").select("*");
	           const r=await supabase.from("rechnungsposten").select("id")`
	got := browserscan.Candidates(bundle, 240)
	idx := map[string]int{}
	for i, n := range got {
		idx[n] = i
	}
	for _, want := range []string{"kundenauftrag", "rechnungsposten"} {
		if _, ok := idx[want]; !ok {
			t.Errorf("%q appears in the app's own code and was not probed", want)
		}
	}
	// And ahead of the generic list, because the budget is spent in order.
	if i, ok := idx["kundenauftrag"]; ok && i > 40 {
		t.Errorf("harvested name ranked %d; the app's own vocabulary has to come "+
			"before conventional guesses or the budget is spent on the wrong names", i)
	}
}

// A budget of nothing is the one case where probing nothing is correct, and
// the caller has to be able to tell that apart from the bug above.
func TestAZeroBudgetIsEmptyAndSaysSo(t *testing.T) {
	if got := browserscan.Candidates("x", 0); len(got) != 0 {
		t.Errorf("budget 0 produced %d candidates", len(got))
	}
}

func TestHarvestIgnoresNoise(t *testing.T) {
	got := strings.Join(browserscan.Candidates(`a bb ccc "select" from const function`, 60), " ")
	for _, junk := range []string{" a ", " bb ", " ccc "} {
		if strings.Contains(" "+got+" ", junk) {
			t.Errorf("harvested %q, which is too short to be a table name", strings.TrimSpace(junk))
		}
	}
}
