package wordlist

import "testing"

// Merge must not fold a name that Postgres does not fold.
//
// Lower-casing every seed is right for ASCII: Postgres folds an unquoted
// identifier, so `Customers` in a bundle is `customers` in the catalogue, and
// probing both would double the work for one relation. It is wrong for
// everything else. Postgres does not fold non-ASCII without a collation, and
// the benchmark corpus holds Ünïcödé and ünïcödé as two separate relations to
// pin that down.
//
// Measured: supplying all fourteen relation names of that project recovered
// thirteen. The missing one was Ünïcödé, folded here into a duplicate of its
// lower-case twin before it ever reached the oracle -- so a name an operator
// typed in correctly could not be probed.
func TestMergeDoesNotFoldNamesPostgresKeeps(t *testing.T) {
	got := Merge([]string{"Ünïcödé", "ünïcödé", "Customers"}, nil)
	set := map[string]bool{}
	for _, g := range got {
		set[g] = true
	}
	if !set["Ünïcödé"] || !set["ünïcödé"] {
		t.Errorf("Merge produced %v; these are two different relations and folding "+
			"them loses one of them before it can be asked about", got)
	}
	if !set["customers"] {
		t.Errorf("Merge produced %v; an unquoted Customers in a bundle is a table "+
			"called customers, and folding THAT is correct", got)
	}
}
