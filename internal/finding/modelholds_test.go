package finding

import (
	"strings"
	"testing"

	"github.com/eppser/unruly/internal/semantic"
)

// What the model found has to reach the reader.
//
// From a real scan with -classifier auto -classifier-model qwen3.5:4b: one
// relation showed a class in HOLDS and twelve showed nothing, including a
// leaders table of 66 rows of names and biographies. The model had been asked
// and had answered; kindsOf simply never read ModelClasses, so every answer
// was computed and then dropped at render time. The operator paid 340ms a
// column for a field nothing printed.
func TestModelClassesReachTheHoldsColumn(t *testing.T) {
	f := Finding{
		ID: "supabase-anon-read-exposed",
		Evidence: Evidence{
			Classes:      []string{"contact"},
			ModelClasses: []string{"pii"},
		},
	}
	got := kindsOf(f)
	joined := strings.Join(got, " | ")
	if !strings.Contains(joined, "email") {
		t.Errorf("the rules' own class vanished: %q", joined)
	}
	if !strings.Contains(joined, "names") {
		t.Errorf("the model's class never reached the reader: %q -- it was computed, "+
			"then dropped", joined)
	}
}

// A model class must be marked as one. A reader who cannot tell a mod-97 check
// from a model's opinion will treat both as proven, and the two measure 0.4%
// and 16% false positives.
func TestAModelClassIsMarkedAsAnOpinion(t *testing.T) {
	proven := kindsOf(Finding{Evidence: Evidence{Classes: []string{"pii"}}})
	guessed := kindsOf(Finding{Evidence: Evidence{ModelClasses: []string{"pii"}}})
	if len(proven) != 1 || len(guessed) != 1 {
		t.Fatalf("proven=%v guessed=%v", proven, guessed)
	}
	if proven[0] == guessed[0] {
		t.Errorf("both render as %q; nothing distinguishes a proof from an opinion", proven[0])
	}
	if !strings.Contains(guessed[0], "?") {
		t.Errorf("model phrase %q carries no uncertainty marker", guessed[0])
	}
}

// Every class the model can return needs a phrase, or it is silently dropped.
//
// The renderer knew seven classes; the model can answer with fifteen. Eight of
// them -- communications, device-id, behavioural, media-file, employment,
// education, biometric, criminal -- had nowhere to land, so even after
// ModelClasses was wired in, most of what the model found would still have
// disappeared without a word.
func TestEveryModelClassHasAPhrase(t *testing.T) {
	have := map[string]bool{}
	for _, p := range plainData {
		have[p.tag] = true
	}
	for _, c := range semantic.Classes() {
		if c.Name == "none" {
			continue
		}
		if !have[c.Name] {
			t.Errorf("the model can answer %q and the renderer has no phrase for it, "+
				"so that answer is dropped with no trace", c.Name)
		}
	}
}
