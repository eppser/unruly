package browserscan_test

import (
	"math"
	"strings"
	"testing"

	"github.com/eppser/unruly/internal/browserscan"
)

// FOUR classes now, and never more than five, because the runtime returns five.
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
	if len(c) > 5 {
		t.Fatalf("%d classes declared; the browser runtime returns 5 logprobs, so "+
			"anything more is scored on a partial denominator", len(c))
	}
	// And no catch-all. "sensitive" covered health, politics, biometrics and
	// criminal records, and against a real application it fired on nearly
	// every text column: a class broad enough to absorb every uncertain answer
	// carries no information, and it filled the report with noise.
	for _, cl := range c {
		if cl.Name == "sensitive" {
			t.Error("the catch-all class is back; it fires on almost everything and " +
				"tells the reader nothing")
		}
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

// The prompt must fit the window the runtime actually gives us.
//
// Measured failure, in a browser: "Prompt tokens exceed context window size:
// number of prompt tokens: 5080; context window size: 4096". The values were
// passed through whole, and one long bio column is enough to blow a 4k window.
//
// Truncating here rather than raising the window is deliberate. A bigger
// window costs VRAM on a machine that already has to hold the model, and the
// classifier does not need the whole value: it is deciding what KIND of thing
// this is, and the first eighty characters of an address say that as well as
// four hundred do.
func TestThePromptStaysInsideTheContextWindow(t *testing.T) {
	long := strings.Repeat("Lorem ipsum dolor sit amet, consectetur adipiscing elit. ", 200)
	p := browserscan.ModelPrompt("biography", []string{long, long, long})
	// ~4 characters per token is the usual rule of thumb; 4096 tokens is
	// therefore around 16k characters. Half of that leaves generous headroom
	// for a tokenizer that disagrees with the rule of thumb.
	if len(p) > 8000 {
		t.Errorf("prompt is %d characters, which will not fit a 4096 token window", len(p))
	}
	if !strings.Contains(p, "Lorem ipsum") {
		t.Error("the value was dropped entirely; the model needs something to read")
	}
}

func TestEveryValueContributesSomething(t *testing.T) {
	p := browserscan.ModelPrompt("c", []string{
		strings.Repeat("a", 500), "distinctive-second-value", strings.Repeat("b", 500)})
	if !strings.Contains(p, "distinctive-second-value") {
		t.Error("a short value was lost because a long one before it used the budget")
	}
}

// WHY THE BROWSER MODEL IS OFF, recorded so it is not re-enabled on the
// assumption I made.
//
// The readout needs a probability distribution over the declared slots. It
// renormalises across them and refuses anything under 0.80, and that gate is
// the only thing keeping a model's false positives out of a security report.
//
// WebLLM does not provide one. Measured in Chrome against
// Qwen2.5-0.5B-Instruct-q4f16_1 at temperature 0, asking for top_logprobs 5:
//
//	slug            [" A":1.000 "!":0.000 "\"":0.000 "#":0.000 "$":0.000]
//	label_en        [" A":1.000 ...]
//	sort_order      [" A":1.000 ...]
//	email           [" A":1.000 ...]
//	password_hash   [" D":1.000 ...]
//
// Three separate faults:
//
//  1. There is no distribution. The argmax comes back at 1.000 and the
//     remaining four entries are '!', '"', '#', '$' -- sequential ASCII at
//     zero, not alternatives.
//  2. So the gate is inert. Nothing arriving at 1.000 can ever be rejected,
//     and a threshold that cannot reject is not a threshold.
//  3. The answers are not answers. slug, label_en, sort_order and email all
//     return A, and password_hash returns D, a slot that no longer exists.
//
// On a real application this reported "Passwords or keys" on 10 of 13 tables,
// at full confidence, for columns holding article slugs and sort orders.
// "This table contains passwords" is the most alarming sentence this page can
// produce, and producing it for news_categories would rightly cost the reader
// their trust in every other finding.
//
// The Go side stays: ModelClasses, ModelPrompt and PickClass are correct and
// tested, and PickClass did the right thing with the garbage it was handed --
// it refused password_hash because D was not declared. What is missing is a
// runtime that returns real logprobs. Re-enabling means measuring that first,
// with something like the table above.
func TestTheGateIsUselessWithoutADistribution(t *testing.T) {
	// What WebLLM actually returns: everything on one slot, nothing anywhere
	// else. Whatever that slot is, it passes a 0.80 gate.
	saturated := map[string]float64{" A": 1.0, "!": 0.0, "\"": 0.0}
	name, p := browserscan.PickClass(saturated, 0.80)
	if name != "credential" || p < 0.999 {
		t.Fatalf("got %q at %.3f; this documents the observed behaviour, so if it "+
			"changes the comment above is stale", name, p)
	}
	// The point: the same call with a real distribution is refused. The gate
	// works. It was never given anything to work on.
	if n, _ := browserscan.PickClass(map[string]float64{"A": 0.5, "B": 0.5}, 0.80); n != "" {
		t.Errorf("an even split returned %q", n)
	}
}
