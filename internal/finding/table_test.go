package finding

import (
	"strings"
	"testing"
)

func tableFixture() []Finding {
	return []Finding{
		{ID: "supabase-anon-read-exposed", Severity: Critical, Resource: "sessions",
			Evidence: Evidence{Reason: "access_token:credential"}},
		{ID: "supabase-anon-insert-allowed", Severity: Critical, Resource: "sessions"},
		{ID: "supabase-anon-delete-allowed", Severity: Critical, Resource: "sessions"},
		{ID: "supabase-anon-read-exposed", Severity: High, Resource: "agent_runs"},
		{ID: "supabase-authenticated-escalation", Severity: Critical, Resource: "salaries",
			Evidence: Evidence{Reason: "iban:financial"}},
		{ID: "unruly-scan-summary", Severity: Info, Resource: "scan"},
		{ID: "unruly-surface-not-assessed", Severity: Info, Resource: "delete:x"},
	}
}

// The question this exists to answer is "which tables are worst, and what can
// be done to them" -- which the per-finding stream makes the reader
// reconstruct by hand from four scattered lines.
func TestTableIsOneRowPerRelation(t *testing.T) {
	got := Table(tableFixture(), true)
	if n := strings.Count(got, "sessions"); n != 1 {
		t.Errorf("sessions appears %d times; three findings on one relation must "+
			"consolidate into one row", n)
	}
	var row string
	for _, l := range strings.Split(got, "\n") {
		if strings.Contains(l, "sessions") {
			row = l
		}
	}
	// READ, INSERT and DELETE open; UPDATE not. Losing that in consolidation
	// would make the table prettier and useless.
	got = Table(tableFixture(), true)
	for col, want := range map[string]string{
		"READ": "yes", "INSERT": "yes", "UPDATE": "-", "DELETE": "yes",
	} {
		if v := cell(t, got, "sessions", col); v != want {
			t.Errorf("sessions %s = %q, want %q", col, v, want)
		}
	}
	if !strings.Contains(row, "passwords or access tokens") {
		t.Errorf("the row does not say what kind of data is in it: %q", row)
	}
}

// Worst first: attention runs out from the top.
func TestTableIsOrderedWorstFirst(t *testing.T) {
	got := Table(tableFixture(), true)
	if strings.Index(got, "sessions") > strings.Index(got, "agent_runs") {
		t.Error("a high relation is listed above a critical one")
	}
}

// A signed-up caller is its own column: it is a different attacker, at a
// different price, and collapsing it into READ would say anonymous callers can
// see data they cannot.
func TestTableSeparatesTheSignedUpColumn(t *testing.T) {
	got := Table(tableFixture(), true)
	for _, l := range strings.Split(got, "\n") {
		if !strings.Contains(l, "salaries") {
			continue
		}
		_ = l
		if v := cell(t, got, "salaries", "READ"); v != "-" {
			t.Errorf("salaries is not readable anonymously but READ says %q", v)
		}
		if v := cell(t, got, "salaries", "SIGNUP"); v != "yes" {
			t.Errorf("salaries is readable after signup but SIGNUP says %q", v)
		}
	}
}

// Scan commentary has no verb, and giving it one would be a lie in a table
// that reads as fact.
func TestTableExcludesScanCommentary(t *testing.T) {
	got := Table(tableFixture(), true)
	for _, unwanted := range []string{"scan-summary", "delete:x", "surface-not-assessed"} {
		if strings.Contains(got, unwanted) {
			t.Errorf("scan commentary reached the table: %q", unwanted)
		}
	}
	if Table([]Finding{{ID: "unruly-scan-summary", Resource: "scan"}}, true) != "" {
		t.Error("a report with nothing reachable produced a table")
	}
}

// -nc means no escape codes anywhere, including in the severity column.
func TestTableHonoursNoColor(t *testing.T) {
	if strings.Contains(Table(tableFixture(), true), "\x1b[") {
		t.Error("escape codes present with noColor set")
	}
	if !strings.Contains(Table(tableFixture(), false), "\x1b[") {
		t.Error("no colour at all when colour was permitted")
	}
}

func TestTableIsDeterministic(t *testing.T) {
	first := Table(tableFixture(), true)
	for i := 0; i < 20; i++ {
		if Table(tableFixture(), true) != first {
			t.Fatal("table rendering is not stable across calls")
		}
	}
}

// cell returns one column of the row for a relation, looked up by COLUMN NAME
// rather than by a hard-coded field index.
//
// The indices were hard-coded, and adding a ROWS column moved every one of
// them: two tests began asserting about the wrong column and reported the verb
// table was broken when it was fine. A test that hard-codes a position tests
// the layout as much as the behaviour, and fails for the wrong reason the day
// the layout changes.
//
// Only the single-token columns can be addressed this way. HOLDS is prose and
// is deliberately last, so callers match it with strings.Contains instead.
func cell(t *testing.T, out, relation, column string) string {
	t.Helper()
	lines := strings.Split(strings.TrimLeft(out, "\n"), "\n")
	head := strings.Fields(lines[0])
	idx := -1
	for i, h := range head {
		if h == column {
			idx = i
			break
		}
	}
	if idx < 0 {
		t.Fatalf("no column named %q in header %q", column, lines[0])
	}
	for _, l := range lines[1:] {
		if !strings.Contains(l, relation) {
			continue
		}
		f := strings.Fields(l)
		if idx >= len(f) {
			t.Fatalf("row for %s has %d fields, no column %d (%s): %q", relation, len(f), idx, column, l)
		}
		return f[idx]
	}
	t.Fatalf("no row for %s in:\n%s", relation, out)
	return ""
}
