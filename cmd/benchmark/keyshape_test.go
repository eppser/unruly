package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A key this runner cannot grade must be refused, not scored as empty.
//
// The grader reads expect.relations. 14-firebase states its ground truth as
// expect.checks -- HTTP method, path and status, measured against the running
// emulator -- because Firestore has collections, not relations. Given an empty
// relations list the grader has nothing to compare, and every dimension came
// out 100% recall and 100% precision on a denominator of ZERO.
//
// A Firebase project on the scoreboard with full marks, having graded nothing.
// That is a worse answer than the validation error it replaced, and it is the
// exact shape this repo spends its time removing: a check that could not look,
// rendered identically to one that looked and found everything correct.
//
// The first version of this refusal keyed on "has expect.checks and no
// expect.relations". 05-empty-project and 06-unreachable share that shape
// legitimately -- an empty project HAS no relations, and "nothing expected,
// nothing found" is a real result for it -- so the rule dropped two Supabase
// projects and moved three denominators. The backend is what decides whether
// this runner can grade a target, so the backend is what it asks, and the
// third case below is the one that would have caught it.
func TestAKeyWhoseExpectationsAreNotGradedIsRefused(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}

	// A Supabase project with nothing to find is still scored: its zero
	// relations are a measurement, not an absence of one.
	supabaseChecksOnly := write("empty.yaml", `name: empty
project_ref: r
anon_key_env: SOME_KEY
expect:
  checks:
    - name: the project answers
      method: GET
      path: /
      expect_status: 200
`)
	if _, err := loadCorpusTarget(supabaseChecksOnly); err != nil {
		t.Errorf("a Supabase project whose ground truth is checks was refused: %v.\n"+
			"05-empty-project and 06-unreachable are exactly this shape, and dropping "+
			"them moved three denominators on the scoreboard.", err)
	}

	checksOnly := write("checks.yaml", `name: x
backend: firebase
project_ref: r
expect:
  checks:
    - name: a collection is readable
      method: GET
      path: user_profiles
      expect_status: 200
`)
	if _, err := loadCorpusTarget(checksOnly); err == nil {
		t.Error("a key whose only expectations are expect.checks was accepted; the " +
			"grader reads expect.relations, so every dimension would score 100% on a " +
			"denominator of zero")
	} else if !strings.Contains(err.Error(), "100%") {
		t.Errorf("the refusal does not say what would go wrong: %v", err)
	}

	// The converse: a key this runner DOES grade must still load. Refusing
	// everything would satisfy the assertion above and score no corpus at all.
	relations := write("relations.yaml", `name: y
project_ref: r
anon_key_env: SOME_KEY
expect:
  relations:
    - name: t
      rows: 1
      read_exposed: true
`)
	if _, err := loadCorpusTarget(relations); err != nil {
		t.Errorf("an ordinary relation-based key no longer loads: %v", err)
	}

	// And a key with BOTH is graded on its relations rather than refused: the
	// checks are extra ground truth, not a reason to drop the project.
	both := write("both.yaml", `name: z
project_ref: r
anon_key_env: SOME_KEY
expect:
  checks:
    - name: c
      method: GET
      path: p
      expect_status: 200
  relations:
    - name: t
      rows: 1
      read_exposed: true
`)
	if _, err := loadCorpusTarget(both); err != nil {
		t.Errorf("a key carrying both kinds of expectation was refused: %v", err)
	}
}
