package finding

import (
	"encoding/json"
	"strings"
	"testing"
)

// A reader must be able to tell WHERE a fix is applied.
//
// Every remediation in this report is a block of text beginning with `--`,
// because the output is piped into psql. That convention is right for a
// database and misleading everywhere else: Firestore rules are edited in a
// file and deployed, a signup setting is a toggle in a console, and neither is
// something to paste into a SQL prompt. Rendered identically to SQL, they
// invite exactly that.
//
// The kind is not decoration. It is what lets the fix plan group by destination
// -- run these, edit that file, click this setting -- and what lets a consumer
// of the JSONL route a finding to whoever owns that surface.
func TestRemediationCarriesWhereItIsApplied(t *testing.T) {
	sql := Finding{
		ID: "supabase-anon-read-exposed", Severity: Critical, Resource: "users",
		Remediation: "ALTER TABLE users ENABLE ROW LEVEL SECURITY;",
		FixKind:     FixSQL,
	}
	rules := Finding{
		ID: "firebase-firestore-anon-read", Severity: Critical, Resource: "profiles",
		Remediation: "-- Edit firestore.rules and deploy.",
		FixKind:     FixRulesFile,
	}

	if sql.Where() == rules.Where() {
		t.Fatal("a SQL fix and a rules-file fix describe the same destination, so the " +
			"report cannot tell a reader where to go")
	}
	for _, tc := range []struct {
		f    Finding
		want string
	}{
		{sql, "database"},
		{rules, "rules file"},
	} {
		if !strings.Contains(strings.ToLower(tc.f.Where()), tc.want) {
			t.Errorf("%s: Where() = %q, which does not name %q", tc.f.ID, tc.f.Where(), tc.want)
		}
	}

	// An unset kind must not claim SQL. Most findings predate this field, and a
	// default that guesses "database" would put a console setting in a psql
	// script -- the one place this project has always refused to be sloppy.
	var old Finding
	if strings.Contains(strings.ToLower(old.Where()), "database") {
		t.Errorf("a finding with no declared kind claims a database fix: %q", old.Where())
	}

	// It has to survive into the JSONL, or a consumer routing findings by
	// destination cannot see it.
	b, err := json.Marshal(rules)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "rules-file") {
		t.Errorf("the kind is absent from the JSON: %s", b)
	}
	// And it must be omitted when unset rather than emitted as an empty
	// string, so existing consumers see no new field.
	if b2, _ := json.Marshal(old); strings.Contains(string(b2), "fix_kind") {
		t.Errorf("an unset kind is serialised anyway: %s", b2)
	}
}
