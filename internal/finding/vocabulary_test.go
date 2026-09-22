package finding

import (
	"testing"

	"github.com/eppser/unruly/internal/classify"
	"github.com/eppser/unruly/internal/semantic"
)

// Every phrase this package can print must name a class something can produce,
// and every class something can produce must have a phrase.
//
// Both directions, because each failure is silent in its own way and both had
// happened. The renderer offered phrases for "contact", "location" and
// "health" and NO classifier has ever emitted any of the three -- dead
// vocabulary that reads, to anyone maintaining this, like coverage that
// exists. In the other direction a class added to the classifier with no
// phrase here is simply dropped from the report: found, and then not
// mentioned, which is worse than not looking.
//
// This is a structural guard rather than a list, so it keeps working as the
// vocabulary grows. It is the check that makes "what classes does this tool
// report" a question with one answer instead of two that disagree.
func TestEveryClassHasAPhraseAndEveryPhraseHasAClass(t *testing.T) {
	// TWO producers, not one. The structural rules in internal/classify are
	// the first; the optional model in internal/semantic is the second, and it
	// can answer with eight classes no checksum can prove -- private messages,
	// device identifiers, what somebody did. Checking only the rules called
	// those phrases dead vocabulary, which would have forced them out of the
	// renderer and left every model answer dropped with no trace.
	producible := map[string]bool{}
	for _, c := range classify.Vocabulary() {
		producible[c] = true
	}
	ruleOnly := len(producible)
	for _, c := range semantic.Classes() {
		if c.Name != "none" { // "none" is the model declining, not a class
			producible[c.Name] = true
		}
	}
	if ruleOnly == 0 {
		t.Fatal("classify.Vocabulary() is empty, so this test cannot check anything")
	}
	if len(producible) == ruleOnly {
		t.Error("semantic.Classes() added nothing to the producible set; either it is " +
			"empty or it has silently converged on the rule vocabulary, and this guard " +
			"has stopped covering the model")
	}

	rendered := map[string]bool{}
	for _, p := range plainData {
		rendered[p.tag] = true
		if !producible[p.tag] {
			t.Errorf("the report can print a phrase for %q, which no classifier can produce: "+
				"dead vocabulary that reads as coverage", p.tag)
		}
		if p.phrase == "" {
			t.Errorf("class %q has an empty phrase", p.tag)
		}
	}

	for c := range producible {
		if !rendered[c] {
			t.Errorf("classifiers can produce %q and this package has no phrase for it, "+
				"so it is found and then never mentioned", c)
		}
	}
}
