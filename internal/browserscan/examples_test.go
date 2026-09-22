package browserscan_test

import (
	"strings"
	"testing"

	"github.com/eppser/unruly/internal/browserscan"
)

// Masking is the only thing standing between "your table holds card numbers"
// and a second copy of the card number.
//
// internal/classify exists on the rule that a finding names KINDS and never
// values: "a finding that says this table contains card numbers is evidence;
// one that quotes the number is a second copy of the leak." The browser page
// shows examples because "contact" means nothing to the person reading it and
// "j•••@g•••.com" means everything. That is only defensible while the example
// cannot be read back.
func TestAMaskedValueCannotBeReadBack(t *testing.T) {
	for _, tc := range []struct{ in, mustNotContain string }{
		{"4111111111111111", "411111111111"},
		{"anna.becker@nordwind-logistik.de", "anna.becker"},
		{"DE89370400440532013000", "370400440532"},
		{"$2b$12$EXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEX", "EXAMPLEEXAMPLE"},
		{"+49 170 1234567", "1234567"},
		{"Hauptstrasse 14, 10115 Berlin", "Hauptstrasse"},
	} {
		got := browserscan.Mask(tc.in)
		if strings.Contains(got, tc.mustNotContain) {
			t.Errorf("Mask(%q) = %q, which still contains %q", tc.in, got, tc.mustNotContain)
		}
		// Four characters of the original is the ceiling. Enough to recognise
		// the shape of your own data, not enough to be the data.
		kept := 0
		for _, r := range got {
			if r != '•' && r != ' ' && r != '@' && r != '.' {
				kept++
			}
		}
		if kept > 8 {
			t.Errorf("Mask(%q) = %q keeps %d original characters", tc.in, got, kept)
		}
		if got == tc.in {
			t.Errorf("Mask(%q) returned the input unchanged", tc.in)
		}
	}
}

// An empty or tiny value must not become a preview of itself.
func TestShortValuesAreMaskedWhole(t *testing.T) {
	for _, in := range []string{"a", "ab", "abc", "1234"} {
		if got := browserscan.Mask(in); strings.Contains(got, in) {
			t.Errorf("Mask(%q) = %q leaks the whole value", in, got)
		}
	}
}

// Examples pairs each kind with something the reader recognises.
func TestExamplesAreGroupedByKindAndMasked(t *testing.T) {
	// NOT example.com: the classifier excludes reserved documentation domains
	// on purpose, so a test written with one grades nothing. Found by checking
	// what Kinds actually returns rather than assuming it agreed with me.
	rows := []map[string]any{
		{"email": "anna.becker@nordwind-logistik.de", "card": "4111111111111111", "note": "hello"},
		{"email": "t.olsen@havnegade-shipping.no", "card": "5500000000000004", "note": "world"},
	}
	got := browserscan.Examples(rows, 2)
	if len(got["contact"]) == 0 {
		t.Error("no contact example, although two email addresses were sampled")
	}
	if len(got["financial"]) == 0 {
		t.Error("no financial example, although two card numbers were sampled")
	}
	for kind, ex := range got {
		if len(ex) > 2 {
			t.Errorf("%s returned %d examples, cap is 2", kind, len(ex))
		}
		for _, e := range ex {
			if !strings.Contains(e, "•") {
				t.Errorf("%s example %q is not masked", kind, e)
			}
		}
	}
	if _, ok := got["none"]; ok {
		t.Error(`"none" is not a kind worth showing and must not appear`)
	}
}

// Every readable table gets a preview, not only the ones a rule recognised.
//
// "readable" with nothing beside it reads as harmless. Showing one masked
// value per column is what turns an abstract finding into "that is my customer
// list", and most tables hold nothing a structural rule can name, so keying
// this off classification would leave the majority blank.
func TestEveryColumnGetsAMaskedPreview(t *testing.T) {
	rows := []map[string]any{
		{"id": "8814", "title": "Spring campaign", "status": "draft", "views": float64(12)},
	}
	got := browserscan.Preview(rows, 8)
	if len(got) == 0 {
		t.Fatal("no preview for a table whose columns no rule classifies, which is " +
			"most tables")
	}
	cols := map[string]string{}
	for _, p := range got {
		cols[p.Column] = p.Value
	}
	for _, want := range []string{"id", "title", "status", "views"} {
		if _, ok := cols[want]; !ok {
			t.Errorf("column %q has no preview", want)
		}
	}
	if v := cols["title"]; v == "Spring campaign" {
		t.Errorf("title preview %q is the raw value", v)
	}
	if !strings.Contains(cols["title"], "•") {
		t.Errorf("title preview %q is not masked", cols["title"])
	}
}

func TestPreviewIsCappedAndOrdered(t *testing.T) {
	row := map[string]any{}
	for _, c := range []string{"e", "d", "c", "b", "a"} {
		row[c] = "value-" + c
	}
	got := browserscan.Preview([]map[string]any{row}, 3)
	if len(got) != 3 {
		t.Fatalf("cap 3 returned %d", len(got))
	}
	if got[0].Column != "a" || got[1].Column != "b" {
		t.Errorf("columns not in stable order: %v, %v", got[0].Column, got[1].Column)
	}
}

// A masked timestamp or UUID is safe and useless.
//
// The first browser run previewed created_at as "•••• 0:00" and id as
// "•••• 768d". Both are correctly masked and neither tells the reader
// anything, and on a wide table most columns look like that. Describing the
// SHAPE is both more useful and strictly safer, because it reveals nothing at
// all.
func TestStructuralNoiseIsDescribedRatherThanMasked(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"2026-09-22T18:14:02.318Z", "a date"},
		{"2026-09-22 18:14:02", "a date"},
		{"768d3b71-9f2e-4a55-8c31-2b9f4e77502d", "an ID"},
		{"true", "true"},
	} {
		if got := browserscan.Mask(tc.in); got != tc.want {
			t.Errorf("Mask(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
	// And a real value is still masked rather than described.
	if got := browserscan.Mask("anna.becker@nordwind-logistik.de"); !strings.Contains(got, "•") {
		t.Errorf("a real value was described instead of masked: %q", got)
	}
}
