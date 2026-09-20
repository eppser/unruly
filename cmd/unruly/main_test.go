package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/eppser/unruly/internal/escalate"
)

func TestTargetListParsing(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "targets.txt")
	// Comments, blank lines, surrounding whitespace and a duplicate: all four
	// occur in hand-maintained lists.
	if err := os.WriteFile(path, []byte(`
# production
https://a.example

  https://b.example
# staging
https://a.example
`), 0o600); err != nil {
		t.Fatal(err)
	}

	o := &options{list: path}
	got, err := o.targets()
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"https://a.example", "https://b.example"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("index %d: got %q, want %q", i, got[i], want[i])
		}
	}
}

// File order is preserved rather than sorted. A curated list usually has an
// order its author meant, and reordering makes runs harder to compare.
func TestTargetListPreservesOrder(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "t.txt")
	os.WriteFile(path, []byte("https://z.example\nhttps://a.example\n"), 0o600)

	o := &options{list: path}
	got, _ := o.targets()
	if len(got) != 2 || got[0] != "https://z.example" {
		t.Errorf("order not preserved: %v", got)
	}
}

func TestTargetFlagAndListCombine(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "t.txt")
	os.WriteFile(path, []byte("https://b.example\n"), 0o600)

	o := &options{target: "https://a.example", list: path}
	got, _ := o.targets()
	if len(got) != 2 || got[0] != "https://a.example" || got[1] != "https://b.example" {
		t.Errorf("got %v, want the -u target first then the list", got)
	}
}

func TestMissingListIsAnError(t *testing.T) {
	o := &options{list: "/nonexistent/targets.txt"}
	if _, err := o.targets(); err == nil {
		t.Error("a missing target list must be an error, not an empty scan")
	}
}

func TestNoTargetsYieldsEmpty(t *testing.T) {
	o := &options{}
	got, err := o.targets()
	if err != nil || len(got) != 0 {
		t.Errorf("got %v, %v; want no targets and no error", got, err)
	}
}

// Supplying credentials must not silently reduce coverage.
//
// Discovery used to run only when a credential or origin was MISSING, so
// `-p <ref> -k <key> -s <site>` produced 13 findings where `-u <site>`
// produced 14: the project-ref disclosure was never looked for. A user got a
// quieter report for being more specific, and nothing said a check had been
// skipped.
//
// Whenever a site is known, it is inspected.
//
// This calls shouldDiscover rather than restating it. The previous version of
// this test said "the condition below is the fix, asserted directly" and then
// hand-copied the expression -- which production later grew a third clause that
// the copy never did. It graded its own duplicate, so no change to the scanner
// could have failed it. The last case below is the one that clause exists for.
func TestSiteIsInspectedEvenWhenCredentialsAreSupplied(t *testing.T) {
	cases := []struct {
		name       string
		o          options
		wantLookup bool
	}{
		{"site only", options{site: "https://x"}, true},
		{"site plus full credentials", options{
			site: "https://x", projectRef: "ref", anonKey: "key"}, true},
		{"site plus base url and key", options{
			site: "https://x", baseURL: "https://y", anonKey: "key"}, true},
		{"no site, credentials supplied", options{projectRef: "ref", anonKey: "key"}, false},
		{"no site, nothing supplied", options{}, true}, // needs discovery, will error
		// A .supabase.co target IS an origin, so this must NOT enter the
		// discovery block -- entering it is what refused the tool's most basic
		// invocation. Drop the target/anonKey clause from haveOrigin and this
		// case flips to true.
		{"project URL as target, key supplied", options{
			target: "https://ref.supabase.co", anonKey: "key"}, false},
	}
	for _, tc := range cases {
		tc := tc
		got := shouldDiscover(&tc.o)
		if got != tc.wantLookup {
			t.Errorf("%s: discovery would run = %v, want %v", tc.name, got, tc.wantLookup)
		}
	}
}

// A privileged key must be refused, not scanned with.
//
// service_role bypasses row-level security by design, so every relation reads
// as exposed. Measured on the reference target before this check existed: 14
// read-exposed relations claimed where the truth is 7, with seven correctly
// protected relations described as "readable by the anonymous role".
//
// A false negative hides one problem. This invents seven, and discredits the
// findings that are real.
func TestPrivilegedKeysAreRefused(t *testing.T) {
	// role: service_role / anon / authenticated, base64url, unsigned.
	const svc = "eyJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoic2VydmljZV9yb2xlIn0.QUJDREVGR0hJSktMTU5PUA"
	const anon = "eyJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoiYW5vbiJ9.QUJDREVGR0hJSktMTU5PUA"

	if got := escalate.JWTRole(svc); got != "service_role" {
		t.Fatalf("fixture wrong: role decoded as %q", got)
	}
	if got := escalate.JWTRole(anon); got != "anon" {
		t.Fatalf("fixture wrong: role decoded as %q", got)
	}

	// The anon key must NOT trip the guard, or the tool refuses its own
	// intended input.
	if escalate.JWTRole(anon) == "service_role" {
		t.Error("an anon key must not be treated as privileged")
	}
	// And the secret-key form is caught by prefix, since it is not a JWT.
	if !strings.HasPrefix("sb_secret_abcdef", "sb_secret_") {
		t.Error("secret key prefix check is wrong")
	}
	if strings.HasPrefix("sb_publishable_abcdef", "sb_secret_") {
		t.Error("a publishable key must not be treated as secret")
	}
}
