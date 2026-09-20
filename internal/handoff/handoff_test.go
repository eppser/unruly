package handoff

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTheFileRoundTripsAndIsStable(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "v.json")
	v := NewVocabulary("unruly test", "http://app.example",
		[]string{"orders", "users", "orders", " ", "accounts"},
		[]string{"http://app.example/", "http://app.example/app.js"})
	if err := Write(p, v); err != nil {
		t.Fatalf("write: %v", err)
	}
	got, dropped, err := ReadVocabulary(p)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(dropped) != 0 {
		t.Errorf("dropped %v from a file this package wrote", dropped)
	}
	if want := "accounts,orders,users"; strings.Join(got.Seeds, ",") != want {
		t.Errorf("seeds = %v, want %s sorted and deduplicated", got.Seeds, want)
	}
	if got.Note == "" {
		t.Error("the file carries no note saying what it is for; the reader may be a " +
			"model, and an artifact that does not explain itself gets edited wrongly")
	}

	// Same input, same bytes: an artifact that differs run to run cannot be
	// diffed, and diffing it is the point of handing it to somebody.
	q := filepath.Join(dir, "w.json")
	if err := Write(q, NewVocabulary("unruly test", "http://app.example",
		[]string{"users", "accounts", "orders"},
		[]string{"http://app.example/app.js", "http://app.example/"})); err != nil {
		t.Fatalf("write: %v", err)
	}
	a, _ := os.ReadFile(p)
	b, _ := os.ReadFile(q)
	if string(a) != string(b) {
		t.Error("two files built from the same seeds in a different order differ")
	}
}

func TestASeedThatIsNotAnIdentifierIsDroppedAndReported(t *testing.T) {
	p := filepath.Join(t.TempDir(), "v.json")
	if err := os.WriteFile(p, []byte(`{"schema_version":1,"stage":"vocabulary",
		"seeds":["orders","../../etc/passwd","users?select=*","tab le","Accounts"]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	v, dropped, err := ReadVocabulary(p)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if strings.Join(v.Seeds, ",") != "Accounts,orders" {
		t.Errorf("kept %v; a seed is pasted into a URL path, so only identifiers survive",
			v.Seeds)
	}
	if len(dropped) != 3 {
		t.Errorf("dropped %v, want the traversal, the query string and the space "+
			"reported, not silently enumerated as a shorter list", dropped)
	}
}

func TestAFileFromANewerBuildIsRefused(t *testing.T) {
	p := filepath.Join(t.TempDir(), "v.json")
	if err := os.WriteFile(p, []byte(`{"schema_version":99,"stage":"vocabulary",
		"seeds":["orders"]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ReadVocabulary(p); err == nil {
		t.Error("a schema version this build does not know was accepted; a field it " +
			"cannot see may be the one that changes what a seed means")
	}
}

func TestTheWrongKindOfHandoffIsRefused(t *testing.T) {
	p := filepath.Join(t.TempDir(), "v.json")
	if err := os.WriteFile(p, []byte(`{"schema_version":1,"stage":"findings"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	_, _, err := ReadVocabulary(p)
	if err == nil {
		t.Fatal("a findings artifact was accepted as a vocabulary one, which enumerates nothing")
	}
	if !strings.Contains(err.Error(), "findings") {
		t.Errorf("the error does not say what was supplied instead: %v", err)
	}
}

// A name an agent supplies for a schema that is not in English.
//
// The loader used to require [A-Za-z] and dropped everything else as "not an
// identifier", which is exactly backwards: the supplied-name path exists
// BECAUSE some names cannot be guessed, and a Japanese or Cyrillic table is
// the clearest case of one. On Firestore, where nothing can be enumerated, a
// supplied name is the only route to a collection at all.
func TestSeedsMayBeInAnyAlphabet(t *testing.T) {
	p := filepath.Join(t.TempDir(), "v.json")
	if err := os.WriteFile(p, []byte(`{"schema_version":1,"stage":"vocabulary",
		"seeds":["顧客","contraseñas","данные","Ünïcödé","../etc/passwd"]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	v, dropped, err := ReadVocabulary(p)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	for _, want := range []string{"顧客", "contraseñas", "данные", "Ünïcödé"} {
		if !containsSeed(v.Seeds, want) {
			t.Errorf("%q was dropped as not an identifier; it is a perfectly ordinary "+
				"table name and the whole point of this file is to carry names that "+
				"cannot be guessed", want)
		}
	}
	// The traversal still goes, because a seed is still pasted into a URL.
	if len(dropped) != 1 {
		t.Errorf("dropped %v, want only the traversal", dropped)
	}
}

func containsSeed(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}
