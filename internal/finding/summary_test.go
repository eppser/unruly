package finding

import (
	"strings"
	"testing"
)

// The scan summary is built here, so it is tested here.
//
// It lived in cmd/unruly first, and two audit checks failed on it. The
// end-to-end test runs the compiled binary as a subprocess, which proves the
// behaviour and proves nothing to the coverage check -- Go cannot see an emit
// site executed in another process. Moving the test into package main did not
// help either: the coverage profile instruments ./internal/... only, so no
// finding constructed in main.go can ever satisfy the check.
//
// The right answer was the one the audit was pointing at. finding.Coverage
// already lives here and does exactly this kind of job; a constructor in
// main.go was the anomaly.
func TestScanSummaryCarriesTheDenominator(t *testing.T) {
	f := ScanSummary("https://app.example.com", 21, 2, 12780, SeedOrigins{Pinned: 867})

	if f.ID != "unruly-scan-summary" {
		t.Fatalf("id %q", f.ID)
	}
	if f.Severity != Info {
		t.Errorf("severity %v: the summary is the denominator for the rest of the report, "+
			"not a claim that anything is wrong", f.Severity)
	}
	if len(f.Evidence.Sample) != 1 {
		t.Fatal("no machine-readable counts")
	}
	got := f.Evidence.Sample[0]
	for k, want := range map[string]any{"relations": 21, "schemas": 2, "requests": 12780} {
		if got[k] != want {
			t.Errorf("%s = %v, want %v", k, got[k], want)
		}
	}
	// The number has to appear in prose too: a reader skimming severities sees
	// the description, not the evidence block.
	if !strings.Contains(f.Description, "21 relation") {
		t.Errorf("the description does not state the relation count: %q", f.Description)
	}
}

// Zero relations is the case the finding exists for, and it must still be
// emitted: that is precisely when a report would otherwise look clean.
func TestScanSummaryIsEmittedWhenNothingWasFound(t *testing.T) {
	f := ScanSummary("https://app.example.com", 0, 1, 940, SeedOrigins{Pinned: 867})
	if !strings.Contains(f.Evidence.Reason, "0 relations") {
		t.Errorf("reason %q does not say zero relations were found, which is the one "+
			"result a reader most needs distinguished from a hardened project",
			f.Evidence.Reason)
	}
}

func TestSurfaceSummaryDoesNotInventRelations(t *testing.T) {
	f := ScanSummarySurfaces("https://app.example.com", 94, 2, 1, 343)
	if strings.Contains(strings.ToLower(f.Description+f.Evidence.Reason), "relation") {
		t.Fatalf("a non-relational scan invented a relation measurement: %q", f.Description)
	}
	for _, want := range []string{"94 application routes", "2 origins", "1 provider names", "343 requests"} {
		if !strings.Contains(f.Evidence.Reason, want) {
			t.Errorf("surface summary reason %q does not contain %q", f.Evidence.Reason, want)
		}
	}
	if f.ID != "unruly-scan-summary" || f.Severity != Info {
		t.Errorf("surface denominator has id=%q severity=%v", f.ID, f.Severity)
	}
}

// The summary must never contradict the findings it summarises.
//
// The line it replaced was a constant: "write probing covered INSERT only:
// UPDATE and DELETE were NOT tested". It kept printing that after both verbs
// were implemented, in runs that emitted nine UPDATE and three DELETE findings
// on the same screen. A reader has no way to know which half to believe, and
// the half that says "not tested" is the one that makes somebody stop looking.
func TestWriteCoverageCannotContradictTheFindings(t *testing.T) {
	fs := []Finding{
		{ID: "supabase-anon-insert-allowed", Resource: "agent_runs"},
		{ID: "supabase-anon-update-allowed", Resource: "agent_runs"},
		{ID: "supabase-anon-update-allowed", Resource: "api_tokens"},
		{ID: "supabase-anon-delete-allowed", Resource: "queue"},
		{ID: "unruly-surface-not-assessed", Resource: "delete:cve_articles"},
	}
	got := WriteCoverage(fs)

	// The specific regression: a verb that IS reported must never be described
	// as untested.
	for _, verb := range []string{"UPDATE", "DELETE"} {
		if strings.Contains(got, verb+" on none") {
			t.Errorf("%s findings are present, but the summary says %q:\n  %s",
				verb, verb+" on none", got)
		}
	}
	for _, want := range []string{"INSERT on 1", "UPDATE on 2", "DELETE on 1"} {
		if !strings.Contains(got, want) {
			t.Errorf("summary does not report %q:\n  %s", want, got)
		}
	}
	// A declined verdict is part of coverage and has to survive into the line,
	// or "DELETE on 1" reads as the whole story.
	if !strings.Contains(got, "not assessed") {
		t.Errorf("the declined DELETE probe is not mentioned:\n  %s", got)
	}
}

// With nothing found, the line must say so plainly rather than being empty --
// silence after a write scan reads as "not run".
func TestWriteCoverageOnACleanProject(t *testing.T) {
	got := WriteCoverage([]Finding{{ID: "supabase-anon-read-exposed", Resource: "public_notes"}})
	for _, verb := range []string{"INSERT on none", "UPDATE on none", "DELETE on none"} {
		if !strings.Contains(got, verb) {
			t.Errorf("a clean write scan does not report %q:\n  %s", verb, got)
		}
	}
}

// Stable order: reports are diffed between runs, and a map iteration would
// reorder this line on every scan of an unchanged project.
func TestWriteCoverageIsStable(t *testing.T) {
	fs := []Finding{
		{ID: "supabase-anon-delete-allowed", Resource: "a"},
		{ID: "supabase-anon-insert-allowed", Resource: "b"},
		{ID: "supabase-anon-update-allowed", Resource: "c"},
	}
	first := WriteCoverage(fs)
	for i := 0; i < 20; i++ {
		if got := WriteCoverage(fs); got != first {
			t.Fatalf("unstable across calls:\n  %s\n  %s", first, got)
		}
	}
	if i, j, k := strings.Index(first, "INSERT"), strings.Index(first, "UPDATE"),
		strings.Index(first, "DELETE"); !(i < j && j < k) {
		t.Errorf("verbs are not in a fixed order: %s", first)
	}
}
