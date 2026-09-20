package finding

import (
	"strings"
	"testing"
)

// A report with actionable findings must not produce an empty plan.
//
// FixPlan groups remediation so an operator has one thing to read instead of
// four near-identical blocks per relation. It was built for SQL, and its verb
// map lists Supabase ids only, so a Firebase-only report produced a plan of
// exactly zero characters -- measured -- while a single Supabase finding
// produced 814.
//
// The consequence is not in the scan, which is correct on both backends, and
// not in -fix, which prints each finding's own remediation whatever the
// backend. It is in the HTML report, whose "copy all SQL" section is built
// from this function: for a Firebase project with two criticals, the operator
// is handed an empty box.
//
// Empty is the wrong answer for a different reason than "wrong SQL" would be.
// Firebase remediation is not SQL and must never be pasted into psql -- but it
// exists, it is specific, and a plan that silently drops it teaches the reader
// that there is nothing to do.
func TestPlanIsNotEmptyForABackendWithoutSQL(t *testing.T) {
	fb := []Finding{
		{
			ID: "firebase-firestore-anon-read", Severity: Critical, Resource: "user_passwords",
			Name:        "Firestore collection is readable by anyone",
			Remediation: "-- Firestore rules are not SQL; edit firestore.rules and deploy.",
		},
		{
			ID: "firebase-rtdb-anon-read", Severity: Critical, Resource: "/",
			Name:        "Realtime Database is readable by anyone",
			Remediation: "-- Realtime Database rules are JSON, not SQL; edit database.rules.json.",
		},
	}

	plan := FixPlan(fb)
	if strings.TrimSpace(plan) == "" {
		t.Fatal("two critical Firebase findings produced an empty plan; the report's " +
			"remediation section tells an operator with a wide-open database that " +
			"there is nothing to do")
	}
	// It must carry the actual instructions, not merely a header.
	for _, want := range []string{"firestore.rules", "database.rules.json"} {
		if !strings.Contains(plan, want) {
			t.Errorf("the plan does not mention %q, so it is not actionable", want)
		}
	}
	// And it must stay safe to pipe into psql: this output is executed verbatim
	// by the remediation eval and by operators. Every non-SQL line is a comment.
	for _, ln := range strings.Split(plan, "\n") {
		t := strings.TrimSpace(ln)
		if t == "" || strings.HasPrefix(t, "--") {
			continue
		}
		if !strings.ContainsAny(t, ";") {
			// A bare prose line with no statement terminator would be a syntax
			// error the moment somebody pipes this into a database.
			panicOnProse(ln)
		}
	}
}

// panicOnProse is a helper so the failure names the offending line.
func panicOnProse(ln string) {
	panic("non-comment, non-SQL line in a plan piped into psql: " + ln)
}

// The Supabase plan must keep working exactly as before.
func TestPlanStillGroupsSQLForSupabase(t *testing.T) {
	sup := []Finding{
		{ID: "supabase-anon-read-exposed", Severity: Critical, Resource: "users",
			Remediation: "ALTER TABLE users ENABLE ROW LEVEL SECURITY;"},
		{ID: "supabase-anon-delete-allowed", Severity: Critical, Resource: "users",
			Remediation: "REVOKE DELETE ON users FROM anon;"},
	}
	plan := FixPlan(sup)
	if !strings.Contains(plan, "users") || !strings.Contains(plan, "ROW LEVEL SECURITY") {
		t.Errorf("the Supabase plan lost its SQL:\n%s", plan)
	}
	if strings.Count(plan, "ENABLE ROW LEVEL SECURITY") > 1 {
		t.Error("the plan repeats the same statement per verb, which is the " +
			"duplication it exists to remove")
	}
}
