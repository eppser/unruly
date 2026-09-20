package enumerate

import (
	"strings"
	"testing"
)

// A schema that is not in English.
//
// Measured against the benchmark corpus: 10-nonlatin-names scored 7% relation
// recall, one relation of fourteen, while every other project scored between
// 62% and 100%. The cause was one character class. reWord was
// [a-z][a-z0-9_]{2,40}, so a table called 顧客 or contraseñas contains nothing
// it can match, and the application's own bundle -- which names those tables on
// every line -- yielded no seed for any of them.
//
// This is the largest single recall gap the tool has, and it is invisible to
// every English fixture in the repository.
func TestVocabularyHarvestsNamesThatAreNotEnglish(t *testing.T) {
	body := `{"顧客":1,"contraseñas":["x"],"bestellübersicht":2,"данные":3,` +
		`"café_registro":4,"Ünïcödé":true,"ünïcödé":false}`
	got := map[string]bool{}
	addWords(body, got)

	for _, want := range []string{
		"顧客",               // Japanese, two runes, six bytes
		"contraseñas",      // Spanish
		"bestellübersicht", // German
		"данные",           // Cyrillic
		"café_registro",    // accented, with an underscore
	} {
		if !got[want] {
			t.Errorf("%q was not harvested; a scan of an application that names this "+
				"table on every line would still probe the pinned English list and "+
				"report the schema as unreachable", want)
		}
	}
}

// Case is not ours to fold.
//
// Postgres folds an UNQUOTED identifier to lower case, which is why harvesting
// lowercased everything and got away with it for years of ASCII schemas. It
// does NOT fold non-ASCII the same way: the corpus asserts that lower() on a
// catalogue name leaves the umlaut alone unless a collation is named, and it
// holds Ünïcödé and ünïcödé as two different relations to prove the point.
//
// Lowercasing the body before matching collapsed those two into one seed, so
// one of the two tables could never be probed whatever the wordlist contained.
func TestVocabularyKeepsCaseThatPostgresKeeps(t *testing.T) {
	got := map[string]bool{}
	addWords(`{"Ünïcödé":1,"ünïcödé":2}`, got)
	if !got["Ünïcödé"] || !got["ünïcödé"] {
		t.Errorf("harvested %v; these are two different relations and folding them "+
			"together means one of them is never asked about", keys(got))
	}
	// And the ASCII case still yields the folded form, because that IS the
	// name Postgres stores for an unquoted identifier.
	got = map[string]bool{}
	addWords(`{"Customers":1}`, got)
	if !got["customers"] {
		t.Errorf("harvested %v, want customers: an unquoted Customers in a bundle is "+
			"a table called customers in the database", keys(got))
	}
}

// Length is counted in characters, not bytes.
func TestVocabularyMeasuresNamesInCharacters(t *testing.T) {
	// Eight Japanese characters: 24 bytes, comfortably inside the 40-character
	// limit and outside a 40-BYTE one only when the name gets longer -- so the
	// case that matters is the short one, which a byte floor rejects.
	got := map[string]bool{}
	addWords(`{"顧客":1}`, got)
	if !got["顧客"] {
		t.Error("a two-character name was rejected by a three-BYTE floor")
	}
	long := strings.Repeat("客", 41)
	got = map[string]bool{}
	addWords(`{"`+long+`":1}`, got)
	if got[long] {
		t.Error("a 41-character name was accepted; the cap is in characters and " +
			"applies to every alphabet equally")
	}
}

func keys(m map[string]bool) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}
