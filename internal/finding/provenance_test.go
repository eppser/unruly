package finding

import (
	"strings"
	"testing"
)

// Where the candidates came from is part of what the scan examined.
//
// The summary says how many relations were discovered and how many requests it
// took. It did not say how the candidates were reached, and that is the number
// an operator needs to act on: 24 relations found from a pinned English list is
// a different result from 24 found because the application named them, and the
// remedy for a low count differs in each case.
//
// It is also the audit trail for a name this scan did not invent. Names may be
// supplied from outside -- by an operator who knows the schema, by a tool that
// parses an artifact unruly cannot, or by a model reading the product's own
// documentation -- and every one is probed like any other candidate. A report
// that cannot say how many of its findings began as somebody else's suggestion
// cannot be audited for it.
func TestTheSummarySaysWhereTheCandidatesCameFrom(t *testing.T) {
	f := ScanSummary("https://ref.supabase.co/rest/v1", 24, 2, 5955,
		SeedOrigins{Pinned: 867, Harvested: 305, Advertised: 24, Supplied: 12})
	for _, want := range []string{"867", "305", "24", "12", "supplied"} {
		if !strings.Contains(f.Description, want) {
			t.Errorf("the summary does not carry %q:\n%s", want, f.Description)
		}
	}
	if !strings.Contains(f.Description, "OpenAPI") {
		t.Errorf("the document-advertised names are not named as such:\n%s", f.Description)
	}
}

// A scan nobody supplied anything to says nothing about supplied names, rather
// than saying zero. A sentence that is always present and almost always zero is
// a sentence readers learn to skip.
func TestTheSummaryIsQuietAboutSourcesThatContributedNothing(t *testing.T) {
	f := ScanSummary("https://ref.supabase.co/rest/v1", 7, 1, 900,
		SeedOrigins{Pinned: 867})
	for _, unwanted := range []string{"supplied", "OpenAPI", "harvested from"} {
		if strings.Contains(f.Description, unwanted) {
			t.Errorf("mentions %q on a scan where it contributed nothing:\n%s",
				unwanted, f.Description)
		}
	}
	if !strings.Contains(f.Description, "867") {
		t.Errorf("the pinned list is always a source and must be stated:\n%s", f.Description)
	}
}

// And the counts survive into the machine-readable evidence, because a
// spreadsheet of scans is where a drift in recall shows up first.
func TestTheProvenanceReachesTheEvidence(t *testing.T) {
	f := ScanSummary("https://x/rest/v1", 24, 2, 5955,
		SeedOrigins{Pinned: 867, Supplied: 12})
	if len(f.Evidence.Sample) == 0 {
		t.Fatal("no evidence sample")
	}
	got := f.Evidence.Sample[0]
	if got["seeds_pinned"] != 867 || got["seeds_supplied"] != 12 {
		t.Errorf("evidence does not carry the provenance: %v", got)
	}
}
