package finding

import (
	"bytes"
	"strings"
	"testing"
)

// -proven keeps the findings somebody can act on, and drops the rest.
//
// The bar is deliberately not "severity >= high". Severity is a judgement the
// scanner makes; this filter asks what the scanner actually GOT. A relation
// that answered 200 with nothing in it, a routine that merely exists, a
// backend named in a header -- each can be argued into a severity, and none of
// them is a row anybody can read. Three things clear the bar:
//
//   - rows came back (a dump is possible),
//   - a write was accepted (an insert is possible),
//   - the rows were classified as holding sensitive data.
//
// The membership test reuses internal/finding's own capability table, the one
// that drives -plain, rather than a second list of ids kept in step by hand.
// A finding absent from that table reaches no data by construction, and a
// second copy of the rule is how this repository has twice shipped a check
// that could not fail for the reason the real rule would.
func TestProvenKeepsOnlyWhatWasRetrieved(t *testing.T) {
	rows := Evidence{Rows: 17, Sample: []map[string]any{{"id": 1}},
		Request: "curl ...", Status: 200}
	empty := Evidence{Rows: 0, Request: "curl ...", Status: 200}
	classified := Evidence{Rows: 0, Request: "curl ...", Status: 200,
		Classes: []string{"credential"}}

	for _, tc := range []struct {
		name string
		f    Finding
		keep bool
		why  string
	}{{
		name: "rows retrieved from an exposed relation",
		f:    Finding{ID: "supabase-anon-read-exposed", Severity: Critical, Resource: "sessions", Evidence: rows},
		keep: true, why: "17 rows came back; this is the case the flag exists for",
	}, {
		name: "high read with rows but no classification",
		f:    Finding{ID: "supabase-anon-read-exposed", Severity: High, Resource: "agent_runs", Evidence: rows},
		keep: true, why: "a dump is possible whether or not the columns look sensitive",
	}, {
		name: "high read where nothing came back",
		f:    Finding{ID: "supabase-anon-read-exposed", Severity: High, Resource: "empty_table", Evidence: empty},
		keep: false, why: "an empty relation is readable and holds nothing to read",
	}, {
		name: "insert accepted, no rows to sample",
		f:    Finding{ID: "supabase-anon-insert-allowed", Severity: High, Resource: "signups", Evidence: empty},
		keep: true, why: "the accepted write IS the retrieval; demanding rows here would " +
			"drop every write finding the tool has",
	}, {
		name: "anonymous storage write",
		f:    Finding{ID: "supabase-storage-anon-write", Severity: High, Resource: "avatars", Evidence: empty},
		keep: true, why: "same shape as an insert: somebody can put data there",
	}, {
		name: "classified data with no row count",
		f:    Finding{ID: "supabase-anon-read-exposed", Severity: High, Resource: "profiles", Evidence: classified},
		keep: true, why: "the classifier saw sensitive values in what came back",
	}, {
		name: "medium, even with rows",
		f:    Finding{ID: "supabase-anon-read-exposed", Severity: Medium, Resource: "public_docs", Evidence: rows},
		keep: false, why: "below the floor the operator asked for",
	}, {
		name: "a routine that merely exists",
		f:    Finding{ID: "supabase-rpc-discoverable", Severity: High, Resource: "admin_reset", Evidence: empty},
		keep: false, why: "discoverable is not callable and returns nothing; this is the " +
			"noise the flag is for",
	}, {
		name: "the scan describing itself",
		f:    Finding{ID: "unruly-surface-not-assessed", Severity: Info, Resource: "backend"},
		keep: false, why: "coverage, not a finding about the target",
	}} {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			w := Writer{Out: &buf, NoColor: true, JSON: true, Proven: true, MinSev: High}
			if err := w.Write(tc.f); err != nil {
				t.Fatalf("write: %v", err)
			}
			got := buf.Len() > 0
			if got != tc.keep {
				verb := map[bool]string{true: "kept", false: "dropped"}
				t.Errorf("-proven %s %s/%s; it should have been %s: %s",
					verb[got], tc.f.ID, tc.f.Resource, verb[tc.keep], tc.why)
			}
		})
	}
}

// Without the flag, nothing changes.
//
// A filter that leaks into the default path silences findings for operators
// who never asked, which is the worst failure a security tool has: the report
// looks clean because the reporter was told to be quiet.
func TestProvenIsOffByDefault(t *testing.T) {
	quiet := Finding{ID: "supabase-rpc-discoverable", Severity: High,
		Resource: "admin_reset", Evidence: Evidence{Request: "curl ..."}}

	var buf bytes.Buffer
	w := Writer{Out: &buf, NoColor: true, JSON: true, MinSev: Info}
	if err := w.Write(quiet); err != nil {
		t.Fatalf("write: %v", err)
	}
	if buf.Len() == 0 {
		t.Fatal("a finding that -proven would drop was dropped WITHOUT -proven; the " +
			"filter has leaked into the default path, and every operator who did not " +
			"ask for it now gets a quieter report than the scan produced")
	}
	if !strings.Contains(buf.String(), "supabase-rpc-discoverable") {
		t.Errorf("wrote something other than the finding: %s", buf.String())
	}
}

// The filter is presentational, and the exit code must not follow it.
//
// "Nothing was proven" and "nothing was found" are different results, and a
// flag that made them look identical would turn a quiet report into a clean
// one -- which is the thing this scanner exists not to do.
func TestProvenDoesNotDecideTheVerdict(t *testing.T) {
	// The severity a finding carries is what the caller tallies for the exit
	// code; the writer must not alter it while deciding whether to print.
	f := Finding{ID: "supabase-rpc-discoverable", Severity: High, Resource: "x"}
	before := f.Severity

	var buf bytes.Buffer
	w := Writer{Out: &buf, NoColor: true, JSON: true, Proven: true, MinSev: High}
	if err := w.Write(f); err != nil {
		t.Fatalf("write: %v", err)
	}
	if f.Severity != before {
		t.Errorf("the writer changed the finding's severity from %s to %s; the exit "+
			"code is computed from these values and a display filter must not move them",
			before, f.Severity)
	}
}
