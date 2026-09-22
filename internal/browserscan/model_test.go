package browserscan_test

import (
	"math"
	"strings"
	"testing"

	"github.com/eppser/unruly/internal/browserscan"
)

// FIVE classes, because the browser runtime returns five logprobs.
//
// The CLI declares sixteen and renormalises the model's probability over all
// of them. WebLLM enforces top_logprobs <= 5 (config.ts throws a RangeError
// above it), so a sixteen-class prompt would be scored on whichever five slots
// happened to surface: the denominator would be short, every surviving class
// would look more confident than it is, and the 0.80 gate -- the only thing
// holding the model's false-positive rate down -- would quietly loosen.
//
// Declaring five makes the arithmetic correct at the constraint instead of
// approximate despite it. It is a coarser answer, not a wronger one.
func TestTheBrowserTaxonomyFitsWhatTheRuntimeReturns(t *testing.T) {
	c := browserscan.ModelClasses()
	if len(c) != 5 {
		t.Fatalf("%d classes declared; the browser runtime returns 5 logprobs, so "+
			"anything else is scored on a partial denominator", len(c))
	}
	seen := map[string]bool{}
	for _, cl := range c {
		if len(cl.Slot) != 1 {
			t.Errorf("slot %q is not a single token", cl.Slot)
		}
		if seen[cl.Slot] {
			t.Errorf("slot %q declared twice", cl.Slot)
		}
		seen[cl.Slot] = true
		if cl.Description == "" {
			t.Errorf("class %q has no description; the model is asked to choose "+
				"between labels it cannot read", cl.Name)
		}
	}
}

// The prompt has to end where the answer goes, and forbid prose.
//
// Measured on the CLI: without "one letter and nothing else" the top token for
// a column called national_id was "The", the correct class ranked second, and
// renormalised to 0.649 against a 0.80 gate. That single sentence was most of
// a twenty point recall gap.
func TestThePromptEndsAtTheAnswerAndForbidsProse(t *testing.T) {
	p := browserscan.ModelPrompt("kreditkarte", []string{"4111 1111 1111 1111"})
	if !strings.Contains(p, "one letter") {
		t.Error("the prompt does not demand a bare letter, so the model will open a sentence")
	}
	if !strings.HasSuffix(strings.TrimRight(p, " "), "Answer:") {
		t.Errorf("the prompt does not end at the answer slot; it ends %q",
			p[max(0, len(p)-24):])
	}
	for _, c := range browserscan.ModelClasses() {
		if !strings.Contains(p, c.Slot+". ") {
			t.Errorf("class %s is missing from the prompt", c.Slot)
		}
	}
}

// Renormalising over DECLARED slots is the whole readout.
func TestPickRenormalisesOverDeclaredSlotsOnly(t *testing.T) {
	ln := func(p float64) float64 { return math.Log(p) }
	// "The" holds most of the mass and is not an answer. Ignoring it must not
	// change which class wins, and must not let a weak winner through.
	w := map[string]float64{
		"The": math.Exp(ln(0.70)), "A": math.Exp(ln(0.06)), "B": math.Exp(ln(0.24)),
	}
	name, p := browserscan.PickClass(w, 0.80)
	if name == "" {
		t.Fatal("nothing picked although two declared slots had mass")
	}
	if p < 0.79 || p > 0.81 {
		t.Errorf("p = %.3f; 0.24 of 0.30 declared mass is 0.80", p)
	}
}

// Below the gate is silence, not a quiet guess.
func TestTheGateRefusesAWeakAnswer(t *testing.T) {
	w := map[string]float64{"A": 0.5, "B": 0.5}
	if name, p := browserscan.PickClass(w, 0.80); name != "" {
		t.Errorf("returned %q at p=%.2f; an even split is not an answer", name, p)
	}
}

// No declared slot came back at all: that is "no opinion", never a class.
func TestNoDeclaredSlotMeansNoAnswer(t *testing.T) {
	if name, _ := browserscan.PickClass(map[string]float64{"The": 0.9, "zzz": 0.1}, 0.80); name != "" {
		t.Errorf("returned %q from a distribution with no declared slot", name)
	}
	if name, _ := browserscan.PickClass(nil, 0.80); name != "" {
		t.Errorf("returned %q from an empty distribution", name)
	}
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
