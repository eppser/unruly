package finding

import (
	"strings"
	"testing"
)

func planFixture() []Finding {
	return []Finding{
		{ID: "supabase-anon-read-exposed", Severity: Critical, Resource: "sessions",
			Evidence: Evidence{Reason: "access_token:credential"}},
		{ID: "supabase-anon-insert-allowed", Severity: Critical, Resource: "sessions"},
		{ID: "supabase-anon-update-allowed", Severity: Critical, Resource: "sessions"},
		{ID: "supabase-anon-delete-allowed", Severity: Critical, Resource: "sessions"},
		{ID: "supabase-anon-read-exposed", Severity: Medium, Resource: "site_content",
			Evidence: Evidence{Reason: "no column matched the sensitive list"}},
		// Coverage notes carry no SQL and must contribute nothing.
		{ID: "unruly-surface-not-assessed", Severity: Info, Resource: "delete:x"},
		{ID: "unruly-scan-summary", Severity: Info, Resource: "scan"},
	}
}

// Four findings on one relation must produce ONE block, not four repetitions of
// the same ALTER TABLE.
func TestFixPlanConsolidatesPerRelation(t *testing.T) {
	got := FixPlan(planFixture())
	// Counted by the relation's own block marker rather than by the ALTER
	// statement. The statement is now chosen at run time -- a relation may be a
	// view, where enabling row-level security is an error rather than a no-op --
	// so an assertion pinned to the old literal was testing the shape of the SQL
	// instead of the property, which is one block per relation.
	if n := strings.Count(got, "to_regclass('sessions')"); n != 1 {
		t.Errorf("sessions appears %d times; four findings on one relation must "+
			"consolidate into one block", n)
	}
	// And the block must say everything that is open, or consolidating has lost
	// information the four separate blocks carried.
	for _, verb := range []string{"SELECT", "INSERT", "UPDATE", "DELETE"} {
		if !strings.Contains(got, verb) {
			t.Errorf("the plan does not mention %s, which the report proves is open", verb)
		}
	}
	if !strings.Contains(got, "REVOKE ALL ON TABLE sessions FROM anon;") {
		t.Error("row-level security is enabled without revoking the grant, which leaves " +
			"the table open")
	}
}

// Worst first: a reader who applies the first block has fixed the worst thing.
func TestFixPlanIsOrderedWorstFirst(t *testing.T) {
	got := FixPlan(planFixture())
	if strings.Index(got, "sessions") > strings.Index(got, "site_content") {
		t.Error("a medium relation is listed before a critical one")
	}
}

// Every non-SQL line must be a comment. This output is piped into psql by the
// remediation eval on every audit, and by operators for real.
func TestFixPlanIsExecutable(t *testing.T) {
	for _, line := range strings.Split(FixPlan(planFixture()), "\n") {
		s := strings.TrimSpace(line)
		if s == "" || strings.HasPrefix(s, "--") {
			continue
		}
		if !strings.HasSuffix(s, ";") {
			t.Errorf("a line that is neither a comment nor a statement: %q", s)
		}
		// DO is here because the row-level-security statement is now chosen at
		// run time from pg_class: PostgREST exposes tables and views
		// identically, a scan cannot tell them apart from outside, and ALTER
		// TABLE ... ENABLE ROW LEVEL SECURITY fails on a view.
		for _, kw := range []string{"ALTER", "REVOKE", "GRANT", "CREATE", "DROP", "SELECT", "DO"} {
			if strings.HasPrefix(strings.ToUpper(s), kw) {
				goto ok
			}
		}
		t.Errorf("an uncommented line that is not recognisable SQL: %q", s)
	ok:
	}
}

// A reason containing a newline would turn the rest of the sentence into SQL.
func TestFixPlanKeepsReasonsOnOneLine(t *testing.T) {
	got := FixPlan([]Finding{{
		ID: "supabase-anon-read-exposed", Severity: High, Resource: "t",
		Evidence: Evidence{Reason: "line one\nDROP TABLE users;"},
	}})
	if strings.Contains(got, "\nDROP TABLE users;") {
		t.Error("a newline in a reason escaped the comment and became a statement")
	}
}

// Findings that describe the scan have no fix, and inventing one would be worse
// than silence.
func TestFixPlanIgnoresScanCommentary(t *testing.T) {
	got := FixPlan([]Finding{
		{ID: "unruly-scan-summary", Severity: Info, Resource: "scan"},
		{ID: "unruly-surface-not-assessed", Severity: Info, Resource: "write:x"},
	})
	if got != "" {
		t.Errorf("a report with no relational finding produced a plan:\n%s", got)
	}
}
