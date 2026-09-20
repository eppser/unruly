package finding

import (
	"regexp"
	"strings"
	"testing"
)

// ansi strips colour so a column's WIDTH can be measured rather than its
// byte count.
var ansi = regexp.MustCompile(`\x1b\[[0-9;]*m`)

// The columns must line up when the output is coloured.
//
// They did not. The severity cell was rendered with %-9s applied to the
// PAINTED string, and the escape sequences alone are nine bytes -- so every
// severity was already "wide enough", no padding was ever added, and the
// column collapsed to the raw word plus two spaces. "critical" is eight
// characters and "high" is four, so RELATION started four columns further
// left on every high row than on every critical one.
//
// It only misaligned in colour, which is why nothing caught it: every existing
// table test passes noColor=true. A check that only ever looks at the
// uncoloured rendering cannot see a bug in the coloured one.
func TestTheColumnsLineUpWhenColoured(t *testing.T) {
	out := Table(tableFixture(), false)

	if !strings.Contains(out, "\x1b[") {
		t.Fatal("premise broken: noColor=false produced no escape sequences, so this " +
			"test is measuring the uncoloured rendering and proves nothing")
	}

	var offsets []int
	var lines []string
	for _, line := range strings.Split(out, "\n") {
		plain := ansi.ReplaceAllString(line, "")
		for _, rel := range []string{"sessions", "agent_runs", "salaries"} {
			if i := strings.Index(plain, rel); i > 0 {
				offsets = append(offsets, i)
				lines = append(lines, plain)
			}
		}
	}
	if len(offsets) < 2 {
		t.Fatalf("found %d relation rows, need at least two to compare alignment", len(offsets))
	}
	for i := 1; i < len(offsets); i++ {
		if offsets[i] != offsets[0] {
			t.Errorf("RELATION starts at column %d on %q but at column %d on %q; the columns do not line up",
				offsets[i], strings.TrimSpace(lines[i]), offsets[0], strings.TrimSpace(lines[0]))
		}
	}
}

// What the VALUE classifier found must reach the HOLDS column.
//
// The table read its classes by parsing Evidence.Reason: splitting on commas
// and taking whatever followed the last colon. That recovers "column:kind"
// pairs and recovers nothing at all from the sentence the value classifier
// produces, so every kind found by looking at the DATA -- the whole point of
// that classifier, and the only one that works on a schema not written in
// English -- was silently absent from a column headed HOLDS.
func TestHoldsShowsClassesFoundInValuesNotJustInColumnNames(t *testing.T) {
	fs := []Finding{{
		ID: "supabase-anon-read-exposed", Severity: Critical, Resource: "notes_table",
		Evidence: Evidence{
			// Exactly what a value-only classification produces: no
			// "column:kind" pair anywhere in the prose.
			Reason:  "sampled rows contain credential data, though no column NAME matched the sensitive list",
			Classes: []string{"credential"},
		},
	}}

	out := Table(fs, true)
	if !strings.Contains(out, "passwords or access tokens") {
		t.Errorf("HOLDS is empty for a relation whose VALUES were classified as a credential.\n%s", out)
	}
}

// The row count in the table is the count the SERVER reported.
//
// Evidence.Rows is the exact total from PostgREST's Content-Range under
// Prefer: count=exact -- how many rows are actually retrievable, not how many
// were sampled. Printing the sample size in a column headed ROWS would tell an
// operator that three rows are exposed when the number is three million.
func TestRowsColumnShowsTheServersCount(t *testing.T) {
	fs := []Finding{{
		ID: "supabase-anon-read-exposed", Severity: Critical, Resource: "sessions",
		Evidence: Evidence{Rows: 41233, Sample: []map[string]any{{"a": 1}, {"b": 2}, {"c": 3}}},
	}}

	out := Table(fs, true)
	if !strings.Contains(out, "41233") {
		t.Errorf("the row count the server reported is absent from the table:\n%s", out)
	}
	if strings.Contains(out, " 3 ") {
		t.Errorf("the table shows the SAMPLE size where the retrievable total belongs:\n%s", out)
	}
}

// A count the server never reported is shown as unknown, not as zero.
//
// Rows is 0 both for "the server said zero" and for "the server said nothing",
// and those are different facts. A table printing 0 for the second turns an
// unmeasured quantity into a measured one, which is the defect this project
// exists to avoid.
func TestAnUnreportedRowCountReadsAsUnknown(t *testing.T) {
	fs := []Finding{{
		ID: "supabase-anon-read-exposed", Severity: High, Resource: "agent_runs",
		Evidence: Evidence{Rows: 0},
	}}

	out := Table(fs, true)
	var row string
	for _, l := range strings.Split(out, "\n") {
		if strings.Contains(l, "agent_runs") {
			row = l
		}
	}
	if row == "" {
		t.Fatal("no row for agent_runs")
	}
	if strings.Contains(row, " 0 ") {
		t.Errorf("a row count the server never reported is printed as 0, which claims a "+
			"measurement that was never made: %q", row)
	}
	if !strings.Contains(row, "?") {
		t.Errorf("an unreported row count is not marked unknown: %q", row)
	}
}

// The header names every column the rows carry.
func TestTheHeaderNamesTheRowsColumn(t *testing.T) {
	out := Table(tableFixture(), true)
	header := strings.Split(strings.TrimLeft(out, "\n"), "\n")[0]
	if !strings.Contains(header, "ROWS") {
		t.Errorf("header %q does not name the ROWS column", header)
	}
}
