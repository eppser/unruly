package probe

import (
	"strings"
	"testing"

	"github.com/eppser/unruly/internal/classify"
	"github.com/eppser/unruly/internal/finding"
	"github.com/eppser/unruly/internal/postgrest"
)

// A relation whose column names are not English must still be rated by what it
// holds.
//
// This is the case the column-name classifier cannot reach, and it is not an
// edge case: every sensitive pattern in this file is an English word, so a
// German, Spanish or Japanese schema gets no tags at all. Before values were
// inspected, the relation below -- four columns holding a card number, a
// password hash and a customer's address -- was reported as "readable, with
// nothing recognised in it", one severity below the truth.
//
// A scanner whose severity is right only for anglophone projects is not the
// generic tool this one claims to be.
func TestSeverityUsesValuesWhenColumnNamesAreNotEnglish(t *testing.T) {
	rel := Relation{
		Name:    "kunden",
		Read:    postgrest.ReadExposed,
		Rows:    2,
		Columns: []string{"id", "kreditkarte", "passwort", "anschrift"},
		Sample: []map[string]any{{
			"id":          1,
			"kreditkarte": "4111111111111111",
			"passwort":    "$2b$12$" + "abcdefghijklmnopqrstuv" + "ABCDEFGHIJKLMNOPQRSTUVWXYZ01234",
			"anschrift":   "Hauptstrasse 1, Berlin",
		}},
	}
	// The column-name classifier finds nothing here, which is the premise.
	if got := SensitiveColumns(rel.Columns); len(got) > 0 {
		t.Fatalf("premise broken: column names matched %v, so this test no longer "+
			"measures what it claims", got)
	}
	rel.Sensitive = SensitiveColumns(rel.Columns)
	rel.SensitiveValues = classify.Kinds(rel.Sample)

	f := readFinding("http://127.0.0.1/rest/v1", rel, false)
	if f.Severity != finding.Critical {
		t.Errorf("a relation holding a card number and a password hash was rated %v, "+
			"not critical: the severity is one step below the truth for every schema "+
			"whose columns are not named in English", f.Severity)
	}
	if !strings.Contains(f.Evidence.Reason, "financial") ||
		!strings.Contains(f.Evidence.Reason, "credential") {
		t.Errorf("the finding does not say WHAT was found: reason = %q", f.Evidence.Reason)
	}
	// And it must not republish what it found.
	if strings.Contains(f.Evidence.Reason, "4111") {
		t.Error("the reason quotes the card number it is describing")
	}
}
