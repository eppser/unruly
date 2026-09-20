package eval_test

// A target that has no anon JWT must not be rejected for lacking one.
//
// Target.Validate required anon_key_env unconditionally, with the message
// "credentials must never be committed". That rule is right for Supabase,
// where the anon key is a JWT and committing one would publish a credential.
// Firebase has no such key: its web API key is documented by Google as public
// and its Firestore REST surface is reached unauthenticated.
//
// The consequence was silent and expensive. benchmark/corpus/14-firebase is
// the only Firebase project in the corpus, fully built -- emulator, rules,
// setup, and ground truth measured against the running suite with curl -- and
// it was dropped from every scoreboard by a validation error. RESULTS.md's
// "Not scored" line quotes that error verbatim, so the reason reads like a
// decision somebody made rather than a Supabase assumption in shared code.
//
// The mission this repo is under is "not just Supabase". A validator that
// rejects the one Firebase corpus project for being Firebase-shaped is that
// problem in one line.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/eppser/unruly/internal/eval"
	"gopkg.in/yaml.v3"
)

func TestAFirebaseCorpusTargetValidates(t *testing.T) {
	path := filepath.Join("..", "..", "benchmark", "corpus", "14-firebase", "answer-key.yaml")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var tgt eval.Target
	if err := yaml.Unmarshal(b, &tgt); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if tgt.AnonKeyEnv != "" {
		t.Fatalf("this target now declares anon_key_env=%q, so it no longer exercises "+
			"the case this test exists for", tgt.AnonKeyEnv)
	}
	if err := tgt.Validate(); err != nil {
		t.Errorf("the only Firebase project in the corpus does not validate: %v.\n"+
			"It has no anon JWT to name, because Firebase does not have one. Rejecting "+
			"it drops it from every scoreboard while RESULTS.md prints the validation "+
			"error as though it were a considered exclusion.", err)
	}
}

// The rule it replaces must keep holding: a Supabase target still may not
// carry a committed key, and still must name the variable holding it.
func TestASupabaseTargetStillNeedsItsKeyFromTheEnvironment(t *testing.T) {
	base := eval.Target{Name: "t", ProjectRef: "ref", AnonKeyEnv: "SOME_KEY"}
	if err := base.Validate(); err != nil {
		t.Fatalf("a well-formed Supabase target must validate: %v", err)
	}
	missing := eval.Target{Name: "t", ProjectRef: "ref"}
	err := missing.Validate()
	if err == nil {
		t.Fatal("a Supabase target with no anon_key_env was accepted; the key would " +
			"then have to be committed, which is what that rule prevents")
	}
	if !strings.Contains(err.Error(), "anon_key_env") {
		t.Errorf("the refusal does not name the missing field: %v", err)
	}
}
