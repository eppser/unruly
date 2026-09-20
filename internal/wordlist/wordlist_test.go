package wordlist

import (
	"sort"
	"strings"
	"testing"
)

func TestListsLoad(t *testing.T) {
	if n := len(Relations()); n < 300 {
		t.Errorf("relation list looks truncated: %d entries", n)
	}
	if n := len(Routines()); n < 800 {
		t.Errorf("routine list looks truncated: %d entries", n)
	}
}

func TestListsAreSortedAndClean(t *testing.T) {
	for name, list := range map[string][]string{"relations": Relations(), "routines": Routines()} {
		prev := ""
		for _, s := range list {
			if s <= prev {
				t.Errorf("%s: not strictly sorted at %q (after %q)", name, s, prev)
				break
			}
			if strings.TrimSpace(s) != s || strings.HasPrefix(s, "#") {
				t.Errorf("%s: unclean entry %q", name, s)
			}
			prev = s
		}
	}
}

// The lists are a cross product, not a curated set. Spot-check that the rule
// held: if admin_review is present, so must its siblings be. A list that
// contained only the names needed to pass an eval would fail this.
func TestRoutinesAreCombinatorialNotCherryPicked(t *testing.T) {
	set := map[string]bool{}
	for _, r := range Routines() {
		set[r] = true
	}
	siblings := []string{
		"admin_review", "admin_approve", "admin_reject", "admin_delete",
		"admin_export", "admin_ban", "admin_promote", "admin_list",
	}
	for _, s := range siblings {
		if !set[s] {
			t.Errorf("expected %q from the prefix x verb cross product", s)
		}
	}
}

func TestMergeIsDeterministicAndDeduplicated(t *testing.T) {
	a := Merge([]string{"Zebra", "alpha", "alpha"}, []string{"beta", "ALPHA"})
	b := Merge([]string{"alpha", "Zebra"}, []string{"ALPHA", "beta"})
	if len(a) != 3 {
		t.Fatalf("expected 3 unique names, got %v", a)
	}
	for i := range a {
		if a[i] != b[i] {
			t.Fatalf("merge is order-dependent: %v vs %v", a, b)
		}
	}
	if a[0] != "alpha" || a[2] != "zebra" {
		t.Errorf("merge must sort and lowercase: %v", a)
	}
}

// Compose exists because PostgREST's hint matches on similarity, and a
// compound routine name is not similar enough to either of its parts. A
// project with a routine named admin_read_audit_log was invisible to a seed
// list of single tokens.
func TestComposeJoinsVerbsToHarvestedNouns(t *testing.T) {
	got := Compose([]string{"audit_log", "customer", "admin", "ab"}, 500)
	if len(got) == 0 {
		t.Fatal("no compounds produced")
	}
	want := map[string]bool{"admin_audit_log": false, "get_customer": false}
	for _, g := range got {
		if _, ok := want[g]; ok {
			want[g] = true
		}
		// A verb glued to a verb names almost nothing and doubles the budget.
		if g == "admin_admin" || g == "get_admin" {
			t.Errorf("composed a verb onto a verb: %q", g)
		}
		// Too-short tokens make noise, not names.
		if strings.HasSuffix(g, "_ab") {
			t.Errorf("composed a two-character token: %q", g)
		}
	}
	for k, found := range want {
		if !found {
			t.Errorf("expected compound %q", k)
		}
	}
}

// Determinism: same input, same output, and truncation drops the tail rather
// than an arbitrary slice.
func TestComposeIsDeterministicAndBounded(t *testing.T) {
	in := []string{"orders", "customers", "invoices", "audit_log"}
	a, b := Compose(in, 20), Compose(in, 20)
	if len(a) != 20 {
		t.Fatalf("cap not applied: got %d", len(a))
	}
	for i := range a {
		if a[i] != b[i] {
			t.Fatalf("run-to-run difference at %d: %q vs %q", i, a[i], b[i])
		}
	}
	if !sort.StringsAreSorted(a) {
		t.Error("output must be sorted so truncation is stable")
	}
	if Compose(nil, 10) != nil || Compose(in, 0) != nil {
		t.Error("empty input or zero budget must produce nothing")
	}
}

// RelationCandidates decides recall when there is no application to harvest.
// It was written after a second target reached 2 of 7 relations on project
// reference and anon key alone, while the hint oracle would have answered for
// all seven — the seeds were the limit, not the oracle.
func TestRelationCandidatesProducesNearMisses(t *testing.T) {
	got := RelationCandidates([]string{"records", "tokens", "logs"}, 5000)
	if len(got) == 0 {
		t.Fatal("no candidates produced")
	}
	index := map[string]bool{}
	for _, g := range got {
		index[g] = true
	}
	// The compound must be SINGULAR. customer_record hints customer_records;
	// customer_records is the name itself and hints nothing, which is the
	// whole mechanism.
	for _, want := range []string{"customer_record", "api_token", "audit_log"} {
		if !index[want] {
			t.Errorf("expected near-miss candidate %q", want)
		}
	}
	if index["customer_records"] {
		t.Error("a candidate identical to the real name is not a near miss")
	}
	// n-1 stems reach a name whose plural differs by one character.
	if !index["record"] {
		t.Error("expected the n-1 stem of a seed")
	}
}

func TestRelationCandidatesIsDeterministicAndBounded(t *testing.T) {
	in := []string{"orders", "customers", "invoices", "sessions"}
	a, b := RelationCandidates(in, 40), RelationCandidates(in, 40)
	if len(a) != 40 {
		t.Fatalf("cap not applied: got %d", len(a))
	}
	for i := range a {
		if a[i] != b[i] {
			t.Fatalf("run-to-run difference at %d: %q vs %q", i, a[i], b[i])
		}
	}
	if !sort.StringsAreSorted(a) {
		t.Error("output must be sorted so truncation drops the tail, not a random slice")
	}
	if RelationCandidates(in, 0) != nil || RelationCandidates(nil, 10) != nil {
		t.Error("a zero budget or no seeds must produce nothing")
	}
	// Junk in, nothing out: a two-character seed makes noise, not a name.
	for _, c := range RelationCandidates([]string{"ab"}, 100) {
		if strings.HasSuffix(c, "_ab") || c == "a" {
			t.Errorf("too-short seed leaked into a candidate: %q", c)
		}
	}
}

// TestContributionsSumToMerged is the invariant the scan summary depends on:
// the parts must describe the set that was probed, not a larger one.
func TestContributionsSumToMerged(t *testing.T) {
	harvested := []string{"alpha", "beta"}
	pinned := []string{"alpha", "gamma"} // "alpha" is in BOTH
	got := Contributions(harvested, pinned)
	merged := Merge(harvested, pinned)
	if sum := got[0] + got[1]; sum != len(merged) {
		t.Errorf("parts sum to %d but Merge produced %d (%v)", sum, len(merged), merged)
	}
	if got[0] != 2 || got[1] != 1 {
		t.Errorf("the first source owns a shared name: got %v, want [2 1]", got)
	}
}

// TestContributionsFoldLikeMerge: counting must normalise exactly as Merge
// does, or the summary describes a different set than the one probed.
func TestContributionsFoldLikeMerge(t *testing.T) {
	got := Contributions([]string{"Users", " users "}, []string{"USERS"})
	if got[0] != 1 || got[1] != 0 {
		t.Errorf("one distinct name after folding: got %v, want [1 0]", got)
	}
}
