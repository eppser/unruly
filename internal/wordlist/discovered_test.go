package wordlist

import (
	"strings"
	"testing"
)

// The expansion must start from what the scan already found.
//
// Measured on the reference target: the first pass recovers 20 of 21
// relations, including v3_cves, v3_exploits, v3_tte and v3_nvd_references. The
// one it misses is v3_fetch_progress -- a fifth member of a family whose
// prefix is sitting in the results. The expansion then spends 15,180 requests
// working through combinations of a generic English list to find it, and the
// budget binds at 15,000, so WHICH combinations get tried is decided by their
// order.
//
// A name observed on this target is worth more than any pinned noun, for the
// same reason harvested vocabulary beats a wordlist: it is evidence about this
// schema rather than a guess about schemas in general.
func TestCandidatesLeadWithFamiliesAlreadyFound(t *testing.T) {
	found := []string{"v3_cves", "v3_exploits", "v3_tte", "orders"}
	got := RelationCandidatesFrom([]string{"progress", "status"}, found, 400)
	if len(got) == 0 {
		t.Fatal("no candidates produced")
	}

	// The observed prefix crossed with a seed noun must be reached, and early:
	// the budget binds on real targets, so a candidate at position 12,000 is
	// one that never runs.
	want := "v3_progress"
	pos := -1
	for i, c := range got {
		if c == want {
			pos = i
			break
		}
	}
	if pos < 0 {
		t.Fatalf("%q is not among %d candidates; the scan found four v3_ relations "+
			"and the expansion never tried a fifth", want, len(got))
	}
	if pos > 100 {
		t.Errorf("%q is candidate %d of %d; on a target where the budget binds that "+
			"is a candidate nobody probes", want, pos, len(got))
	}

	// A family of one is not a family. Crossing every single discovered name
	// with every noun would drown the list in combinations no evidence
	// supports.
	if strings.Join(got, ",") == "" {
		t.Fatal("empty")
	}
	var fromSingleton int
	for _, c := range got {
		if strings.HasPrefix(c, "orders_") {
			fromSingleton++
		}
	}
	if fromSingleton > 0 {
		t.Errorf("%d candidates derive from orders, which appeared once and names no "+
			"family; that is a guess dressed as evidence", fromSingleton)
	}
}

// And with nothing discovered it behaves exactly as before.
func TestCandidatesWithoutDiscoveriesAreUnchanged(t *testing.T) {
	seeds := []string{"orders", "users", "invoices"}
	a := RelationCandidates(seeds, 200)
	b := RelationCandidatesFrom(seeds, nil, 200)
	if strings.Join(a, ",") != strings.Join(b, ",") {
		t.Error("supplying no discoveries changed the candidate list; the fallback " +
			"path is the one every first-time scan takes")
	}
}
