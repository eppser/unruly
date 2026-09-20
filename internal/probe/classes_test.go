package probe

import (
	"strings"
	"testing"

	"github.com/eppser/unruly/internal/classify"
	"github.com/eppser/unruly/internal/postgrest"
)

// A relation classified by column NAME must not lose what its VALUES said.
//
// The two classifiers answer the same question with different instruments and
// neither subsumes the other: names are English and are read without
// retrieving anything, values carry no language and catch the generic column
// -- notes, payload, data -- that a name rule can never see.
//
// They were combined with an "else if", so any relation with one recognisable
// column name discarded the value findings entirely. The shape that costs is
// ordinary: a users table with an `email` column (pii, by name) and a `notes`
// column holding a service_role key (credential, by value) reported pii and
// said nothing about the credential. The severity is understated and the
// operator is told the wrong thing about what leaked.
func TestNameClassesAndValueClassesAreBothKept(t *testing.T) {
	rel := Relation{
		Name:    "profiles",
		Read:    postgrest.ReadExposed,
		Columns: []string{"id", "email", "notes"},
		Sample: []map[string]any{{
			"id":    1,
			"email": "someone@example.com",
			// A credential no column NAME could betray.
			"notes": "sb_secret_" + strings.Repeat("a", 40),
		}},
	}
	rel.Sensitive = SensitiveColumns(rel.Columns)
	rel.SensitiveValues = classify.Kinds(rel.Sample)

	// Both premises, checked, so a change to either classifier makes this test
	// say so rather than quietly measuring nothing.
	if len(rel.Sensitive) == 0 {
		t.Fatal("premise broken: no column NAME classified, so this cannot test the union")
	}
	if len(rel.SensitiveValues) == 0 {
		t.Fatal("premise broken: no VALUE classified, so this cannot test the union")
	}

	f := readFinding("http://127.0.0.1/rest/v1", rel, false)

	got := map[string]bool{}
	for _, c := range f.Evidence.Classes {
		got[c] = true
	}
	for _, want := range []string{"contact", "credential"} {
		if !got[want] {
			t.Errorf("Evidence.Classes = %v, missing %q; the union of the two classifiers is what the report is meant to carry",
				f.Evidence.Classes, want)
		}
	}
}

// Classes are sorted and deduplicated.
//
// Both classifiers can return the same kind -- a `password` column whose value
// is also a recognisable credential -- and a report that lists "credential"
// twice reads as two findings. Sorted because two scans of an unchanged target
// must produce byte-identical output.
func TestClassesAreSortedAndDeduplicated(t *testing.T) {
	rel := Relation{
		Name:    "creds",
		Read:    postgrest.ReadExposed,
		Columns: []string{"password", "iban"},
		Sample: []map[string]any{{
			"password": "sb_secret_" + strings.Repeat("b", 40),
			"iban":     "GB82WEST12345698765432",
		}},
	}
	rel.Sensitive = SensitiveColumns(rel.Columns)
	rel.SensitiveValues = classify.Kinds(rel.Sample)

	f := readFinding("http://127.0.0.1/rest/v1", rel, false)

	seen := map[string]bool{}
	for i, c := range f.Evidence.Classes {
		if seen[c] {
			t.Errorf("Evidence.Classes = %v repeats %q", f.Evidence.Classes, c)
		}
		seen[c] = true
		if i > 0 && f.Evidence.Classes[i-1] > c {
			t.Errorf("Evidence.Classes = %v is not sorted", f.Evidence.Classes)
		}
	}
	if len(f.Evidence.Classes) == 0 {
		t.Fatal("no classes at all, so this test proved nothing about their order")
	}
}

// Classes never carry a value.
//
// The whole point of reporting a KIND is that the report does not become a
// second copy of the leak. A class list that ever contained the matched text
// would undo -redact as well.
func TestClassesNameKindsAndNeverValues(t *testing.T) {
	const card = "4111111111111111"
	rel := Relation{
		Name:    "orders",
		Read:    postgrest.ReadExposed,
		Columns: []string{"id", "payload"},
		Sample:  []map[string]any{{"id": 1, "payload": card}},
	}
	rel.Sensitive = SensitiveColumns(rel.Columns)
	rel.SensitiveValues = classify.Kinds(rel.Sample)

	f := readFinding("http://127.0.0.1/rest/v1", rel, false)
	for _, c := range f.Evidence.Classes {
		if strings.Contains(c, card) || strings.Contains(c, "4111") {
			t.Errorf("Evidence.Classes = %v quotes the value it is describing", f.Evidence.Classes)
		}
	}
	if len(f.Evidence.Classes) == 0 {
		t.Fatal("nothing classified, so this test proved nothing")
	}
}
