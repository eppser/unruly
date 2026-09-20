package emitsites

import (
	"os"
	"path/filepath"
	"testing"
)

func write(t *testing.T, dir, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

// Both shapes an id can take must be found, and the shape must not depend on
// which backend it belongs to.
//
// The regex this replaced was a list -- supabase|unruly|app -- so the two
// backends added after it was written were invisible to the coverage
// guarantee. A rule that has to be edited whenever somebody adds a provider is
// a rule that gets forgotten.
func TestBothIDShapesAreFoundForAnyBackend(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "literal.go", `package x
func a() Finding {
	return Finding{ID: "pocketbase-anon-read-exposed"}
}
`)
	write(t, dir, "variable.go", `package x
func b() Finding {
	id := "neonbase-something-exposed"
	if cond {
		id = "neonbase-other-exposed"
	}
	return Finding{
		ID:       id,
		Severity: High,
	}
}
`)
	got, err := IDs(dir)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{
		"pocketbase-anon-read-exposed": true,
		"neonbase-something-exposed":   true,
		"neonbase-other-exposed":       true,
	}
	for _, id := range got {
		delete(want, id)
	}
	if len(want) > 0 {
		t.Errorf("these ids were not found: %v (got %v). A backend this extractor "+
			"cannot see is a backend the coverage guarantee does not cover.", want, got)
	}
}

// Test files are not sources of emit sites: a finding constructed only in a
// test is not a finding the tool can emit.
func TestTestFilesAreNotEmitSites(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "thing_test.go", `package x
func c() Finding { return Finding{ID: "unruly-invented-by-a-test"} }
`)
	got, err := IDs(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range got {
		if id == "unruly-invented-by-a-test" {
			t.Error("an id constructed only in a test was reported as an emit site")
		}
	}
}

// Sites names the file and line, because the point of the audit is to send
// somebody to the code rather than to tell them a count.
func TestSitesNameFileAndLine(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "one.go", "package x\n\nfunc d() Finding {\n\treturn Finding{ID: \"unruly-a-thing\"}\n}\n")
	got, err := Sites(dir)
	if err != nil {
		t.Fatal(err)
	}
	s, ok := got["unruly-a-thing"]
	if !ok || len(s) == 0 {
		t.Fatalf("no site recorded: %v", got)
	}
	if s[0].Line != 4 {
		t.Errorf("site line is %d, want 4", s[0].Line)
	}
	if s[0].File == "" {
		t.Error("site has no file")
	}
}
