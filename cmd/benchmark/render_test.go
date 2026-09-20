package main

import (
	"strings"
	"testing"
)

// The results table must say which scanner produced it.
//
// benchmark/RESULTS.md is the evidence behind the README's central claim -- that
// this tool is more accurate than the alternatives -- and it carried no commit
// and no Go version, so nothing in it distinguished a fresh run from one taken
// 62 scanner commits earlier. Which is what it was.
func TestRenderCarriesProvenance(t *testing.T) {
	got := render(nil, nil, "commit: `abc1234` (clean)\ngo: `go1.26.0`\n\n")

	if !strings.Contains(got, "commit: `abc1234`") {
		t.Error("the rendered report drops the commit it was produced at, so a reader " +
			"cannot tell whether these numbers describe the current scanner")
	}
	if !strings.Contains(got, "go1.26.0") {
		t.Error("the rendered report drops the Go version")
	}
	// Provenance belongs above the numbers: a reader who stops after the first
	// table has still seen it.
	if i, j := strings.Index(got, "commit: `abc1234`"), strings.Index(got, "| project |"); i > j {
		t.Error("provenance is printed after the results table")
	}
}

// provenance() must report an uncommitted tree as such, in the same words the
// audit report uses. Numbers produced from a dirty tree describe code that is
// not in any commit, and a reviewer cannot reproduce them.
func TestProvenanceNamesTheDirtyState(t *testing.T) {
	got := provenance()
	if !strings.Contains(got, "commit: `") || !strings.Contains(got, "go: `") {
		t.Fatalf("provenance is not in the audit report's shape: %q", got)
	}
	if !strings.Contains(got, "(clean)") &&
		!strings.Contains(got, "MODIFIED (results describe uncommitted code)") {
		t.Errorf("provenance names neither state: %q", got)
	}
}
