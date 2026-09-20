package eval_test

// A test a document cites must actually run.
//
// docs/exploitability.md classifies supabase-realtime-anon-subscription as
// impossible to demonstrate and names the live test that would fail if the
// platform ever made it possible. No make target's -run pattern matched that
// test. The row cited a tripwire that could never fire, and the claim resting
// on it was false from the moment it was written.
//
// The first version of this check asserted something broader -- that EVERY
// live test is run by a target -- and it was wrong. Several are deliberately
// manual: eval-determinism names its two offline tests precisely to avoid
// matching TestLiveDeterminism, which scans a cloud project, because that
// target is part of `make ci` and must not depend on somebody else's project
// being reachable. Each such test documents its own command in its header.
// Forcing them into targets would be worse than leaving them.
//
// What is NOT allowed is a document naming a test as evidence when nothing
// runs it. That is the narrow, true invariant, and the one this repo broke.

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

func TestEveryTestCitedByADocumentIsActuallyRun(t *testing.T) {
	root := filepath.Join("..", "..")

	// -run patterns the Makefile hands to ./internal/eval. Recipes wrap with
	// backslash continuations, so the file is unwrapped first: a line-based
	// scan misses `-run X` and `./internal/eval` sitting on separate lines,
	// which is how the first draft of this check produced four false alarms.
	mk, err := os.ReadFile(filepath.Join(root, "Makefile"))
	if err != nil {
		t.Fatalf("Makefile: %v", err)
	}
	unwrapped := strings.ReplaceAll(string(mk), "\\\n", " ")
	var patterns []*regexp.Regexp
	runRe := regexp.MustCompile(`-run '([^']+)'|-run ([A-Za-z0-9_|]+)`)
	for _, line := range strings.Split(unwrapped, "\n") {
		if !strings.Contains(line, "./internal/eval") {
			continue
		}
		for _, m := range runRe.FindAllStringSubmatch(line, -1) {
			pat := m[1]
			if pat == "" {
				pat = m[2]
			}
			re, err := regexp.Compile(pat)
			if err != nil {
				t.Errorf("Makefile -run %q does not compile: %v", pat, err)
				continue
			}
			patterns = append(patterns, re)
		}
	}
	if len(patterns) == 0 {
		t.Fatal("no -run patterns found for ./internal/eval; this check would pass " +
			"against a Makefile that runs nothing")
	}

	// Tests in this package that gate themselves on UNRULY_LIVE.
	live := map[string]bool{}
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	testRe := regexp.MustCompile(`(?m)^func (Test\w+)\(t \*testing\.T\) \{`)
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		b, err := os.ReadFile(e.Name())
		if err != nil {
			t.Fatal(err)
		}
		src := string(b)
		for _, m := range testRe.FindAllStringSubmatchIndex(src, -1) {
			name := src[m[2]:m[3]]
			body := src[m[1]:]
			if end := strings.Index(body, "\nfunc "); end >= 0 {
				body = body[:end]
			}
			// The gate itself, not the words. This file mentions UNRULY_LIVE
			// throughout and gates on nothing.
			if strings.Contains(body, `Getenv("UNRULY_LIVE")`) {
				live[name] = true
			}
		}
	}
	if len(live) == 0 {
		t.Fatal("no live-gated tests found; the comparison below would be vacuous")
	}

	// Every test name a document cites.
	docs, err := filepath.Glob(filepath.Join(root, "docs", "*.md"))
	if err != nil {
		t.Fatal(err)
	}
	nameRe := regexp.MustCompile(`\bTest[A-Z]\w+`)
	cited := map[string][]string{}
	for _, d := range docs {
		b, err := os.ReadFile(d)
		if err != nil {
			t.Fatal(err)
		}
		for _, n := range nameRe.FindAllString(string(b), -1) {
			cited[n] = append(cited[n], filepath.Base(d))
		}
	}

	var broken []string
	for name, where := range cited {
		if !live[name] {
			continue // not live-gated: `go test ./...` runs it
		}
		matched := false
		for _, re := range patterns {
			if re.MatchString(name) {
				matched = true
				break
			}
		}
		if !matched {
			broken = append(broken, name+" (cited by "+strings.Join(where, ", ")+")")
		}
	}
	sort.Strings(broken)
	for _, b := range broken {
		t.Errorf("%s is cited by a document as evidence, gates itself on UNRULY_LIVE, "+
			"and no Makefile -run pattern matches it -- so it never executes and the "+
			"claim resting on it is unbacked.", b)
	}
}
