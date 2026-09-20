package finding

import (
	"strings"
	"testing"
)

// Coverage limits belong in the findings stream, not only in the log.
//
// With -silent -json a default scan emitted 13 findings and no trace that write
// exposure, routine callability, Edge Functions and route POST probing had
// never run. The log said so; the log is not what gets stored, diffed in CI,
// pasted into a ticket or read by someone who was not watching the terminal.
func TestCoverageRecordsWhatDidNotRun(t *testing.T) {
	f, ok := Coverage("https://x", []SkippedCheck{
		{Name: "write-exposure", Reason: "attempting one is a write", Enable: "-write"},
		{Name: "edge-functions", Reason: "detecting invokes", Enable: "-write"},
	})
	if !ok {
		t.Fatal("skipped checks must produce a finding")
	}
	if f.Severity != Info {
		t.Errorf("a coverage gap is not a vulnerability; got %s", f.Severity)
	}
	if !strings.Contains(f.Description, "is not evidence that it is sound") {
		t.Error("the finding must say that absence of findings for a skipped check proves nothing")
	}
	for _, want := range []string{"write-exposure", "edge-functions", "-write"} {
		if !strings.Contains(f.Resource+f.Description, want) {
			t.Errorf("the finding must name %q so a reader knows what is missing", want)
		}
	}
}

// A complete scan must produce nothing, or the notice becomes wallpaper.
func TestCoverageIsSilentWhenNothingWasSkipped(t *testing.T) {
	if _, ok := Coverage("https://x", nil); ok {
		t.Error("a scan that skipped nothing must not emit a coverage finding")
	}
	if _, ok := Coverage("https://x", []SkippedCheck{}); ok {
		t.Error("an empty slice must not emit a coverage finding")
	}
}

// One finding, listing everything, rather than one per stage: a reader should
// see the whole gap at once.
func TestCoverageIsASingleConsolidatedFinding(t *testing.T) {
	f, _ := Coverage("https://x", []SkippedCheck{
		{Name: "b", Reason: "r", Enable: "-w"},
		{Name: "a", Reason: "r", Enable: "-w"},
		{Name: "c", Reason: "r", Enable: "-w"},
	})
	if !strings.HasPrefix(f.Name, "3 checks") {
		t.Errorf("the count must be visible in the title, got %q", f.Name)
	}
	// Sorted, so two scans of the same target produce identical output.
	if f.Resource != "a,b,c" {
		t.Errorf("skipped checks must be listed in a stable order, got %q", f.Resource)
	}
}

func TestCoveragePluralisesOne(t *testing.T) {
	f, _ := Coverage("https://x", []SkippedCheck{{Name: "a", Reason: "r", Enable: "-w"}})
	if !strings.HasPrefix(f.Name, "1 check did not run") {
		t.Errorf("got %q, want singular", f.Name)
	}
}

// The coverage finding is the one that says what was NOT measured. If its ID
// drifts, a report can lose its own caveat and read as complete.
func TestCoverageFindingID(t *testing.T) {
	f, ok := Coverage("https://x.example", []SkippedCheck{
		{Name: "write-exposure", Reason: "no consent", Enable: "-write -yes-i-own-this"},
	})
	if !ok {
		t.Fatal("a skipped check must produce a coverage finding")
	}
	if f.ID != "unruly-checks-skipped" {
		t.Errorf("ID changed to %q; a report that loses this loses its caveat", f.ID)
	}
	if _, ok := Coverage("https://x.example", nil); ok {
		t.Error("nothing skipped must produce no coverage finding")
	}
}

// A scan truncated by its own probe budget did not finish looking. It must
// reach the exit code, or `unruly -max-relation-probes 100 && echo clean`
// prints clean after probing a hundredth of the candidates.
func TestBudgetExhaustionCountsAsIncompleteCoverage(t *testing.T) {
	incomplete, what := CoverageIncomplete([]Finding{
		{ID: "unruly-probe-budget-exhausted", Resource: "relation-discovery"},
	})
	if !incomplete {
		t.Error("a truncated search is not a completed one")
	}
	if len(what) != 1 || what[0] != "relation-discovery" {
		t.Errorf("the unmeasured surface must be named, got %v", what)
	}
	// The consent-based skip stays out: it fires whenever -write is absent,
	// which is the default, and counting it would make almost every scan
	// report incomplete coverage until the signal meant nothing.
	if in, _ := CoverageIncomplete([]Finding{{ID: "unruly-checks-skipped"}}); in {
		t.Error("a check the operator declined is not a surface that could not be measured")
	}
}

// The routine budget binds on almost every real project — 1,200 candidates
// against 7,547 on the reference target — so counting it as blindness would
// put nearly every scan at exit 3 and the code would stop distinguishing
// anything. That mistake was already made once with Realtime delivery.
//
// The finding is still emitted: "1200 of 7547 probed" is a fact the reader is
// owed. It is the exit code that has to stay a signal.
func TestRoutineBudgetIsNotCountedAsBlindness(t *testing.T) {
	in, _ := CoverageIncomplete([]Finding{
		{ID: "unruly-probe-budget-exhausted", Resource: "routine-discovery"},
	})
	if in {
		t.Error("the default routine cap is designed behaviour, not a surface that " +
			"could not be measured")
	}
	// The relation budget is exceptional and must still count.
	in, what := CoverageIncomplete([]Finding{
		{ID: "unruly-probe-budget-exhausted", Resource: "relation-discovery"},
	})
	if !in || len(what) != 1 {
		t.Errorf("a truncated relation expansion means the fallback did not finish: %v", what)
	}
}

// Every ID that means "the scan could not look" must drive CoverageIncomplete,
// and therefore exit 3.
//
// Found by mutation: removing unruly-target-not-discriminating from
// blindIDs -- so a target that answers every relation name exits 0 instead of
// 3 -- left the whole finding package green. The exit-code contract was pinned
// only by an eval that needs Docker.
//
// The list is written out here rather than read from blindIDs, deliberately. A
// test that iterates the map under test passes whatever the map says, including
// after somebody empties it; naming the IDs is what makes a deletion fail.
func TestEveryBlindnessIDDrivesExitThree(t *testing.T) {
	mustBeBlind := []string{
		"unruly-target-not-discriminating",
		"unruly-capability-degraded",
		"unruly-surface-not-assessed",
		"unruly-probes-unresolved",
		"unruly-probe-budget-exhausted",
	}

	for _, id := range mustBeBlind {
		incomplete, what := CoverageIncomplete([]Finding{
			{ID: id, Resource: "some-surface", Severity: Info},
		})
		if !incomplete {
			t.Errorf("%s means the scan could not see %s, but coverage reported complete; "+
				"the scan would exit 0 and read as clean", id, "some-surface")
		}
		if len(what) != 1 || what[0] != "some-surface" {
			t.Errorf("%s must name what went unmeasured, got %v", id, what)
		}
	}

	// The opposite error matters just as much: if ordinary findings counted as
	// blindness, every real scan would exit 3 and the code would stop meaning
	// anything. A previous fix did exactly that by reporting a DECLINED check
	// as blindness, which put every default scan at exit 3.
	for _, id := range []string{
		"supabase-anon-read-exposure",
		"supabase-rpc-discoverable",
		"unruly-checks-skipped",
	} {
		if incomplete, what := CoverageIncomplete([]Finding{
			{ID: id, Resource: "r", Severity: High},
		}); incomplete {
			t.Errorf("%s is a finding ABOUT the target, not a gap in the scan, but it "+
				"was counted as unmeasured (%v); that makes exit 3 fire on healthy "+
				"scans and stop distinguishing anything", id, what)
		}
	}

	// The one documented exception, kept honest: routine discovery hitting its
	// probe budget is a bounded search, not blindness.
	if incomplete, _ := CoverageIncomplete([]Finding{
		{ID: "unruly-probe-budget-exhausted", Resource: "routine-discovery", Severity: Info},
	}); incomplete {
		t.Error("routine-discovery's own budget cap is excluded from blindness by design; " +
			"if that changes, change it here too rather than in silence")
	}
}

// The vocabulary disclosure must not move the exit code.
//
// It binds on ordinary sites -- 2,000 of 4,112 on the reference project -- so
// counting it as a surface the scan could not see would put nearly every scan
// with a -site at exit 3, which is the mistake already made once with Realtime
// delivery and once nearly made with the routine budget. The finding is still
// emitted: a lower bound the reader is not told about is the failure this
// scanner exists to avoid. It is the EXIT CODE that has to stay a signal.
func TestVocabularyBudgetDoesNotDriveExitThree(t *testing.T) {
	fs := []Finding{{
		ID: "unruly-probe-budget-exhausted", Resource: "vocabulary",
		Severity: Info,
	}}
	if incomplete, what := CoverageIncomplete(fs); incomplete {
		t.Errorf("a truncated vocabulary drove exit 3 (%v); it binds on ordinary sites, so "+
			"every scan with a -site would report incomplete coverage and the code would "+
			"stop meaning anything", what)
	}
	// But a budget that is exceptional still must: relation discovery's cap is
	// 15,000 against an expansion of ~13,700, so truncation there means the
	// fallback did not finish.
	fs = append(fs, Finding{
		ID: "unruly-probe-budget-exhausted", Resource: "relation-discovery",
		Severity: Info,
	})
	if incomplete, _ := CoverageIncomplete(fs); !incomplete {
		t.Error("relation discovery hitting its budget no longer drives exit 3, so a scan " +
			"whose fallback expansion was cut short reports as complete")
	}
}
