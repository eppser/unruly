package semantic_test

import (
	"reflect"
	"testing"

	"github.com/eppser/unruly/internal/semantic"
)

// The adapter between what a probe holds and what Augment needs.
//
// A relation carries sampled rows and the rules' "column:class" pairs. Getting
// this conversion wrong is silent: a column whose rule class is dropped here
// would be sent to the model despite already being proven, which is exactly
// the precedence the feature promises not to break.
func TestSampleAndRulePairsBecomeAugmentInputs(t *testing.T) {
	sample := []map[string]any{
		{"email": "ada@lovelace.test", "anschrift": "Hauptstrasse 14", "n": 1},
		{"email": "grace@hopper.test", "anschrift": "Lindenweg 3a", "n": 2},
	}
	pairs := []string{"email:contact"}

	cols, vals, rules := semantic.FromSample(sample, pairs)

	if !reflect.DeepEqual(cols, []string{"anschrift", "email", "n"}) {
		t.Errorf("columns %v; sorted order is what makes the request sequence "+
			"the same on every run", cols)
	}
	if !reflect.DeepEqual(rules["email"], []string{"contact"}) {
		t.Errorf("rule classes for email = %v, want [contact]. A dropped pair means "+
			"a proven column gets sent to the model anyway", rules["email"])
	}
	if len(rules["anschrift"]) != 0 {
		t.Errorf("anschrift has rule classes %v; the rules do not read it, which is "+
			"the whole reason the model is asked", rules["anschrift"])
	}
	if !reflect.DeepEqual(vals["anschrift"], []string{"Hauptstrasse 14", "Lindenweg 3a"}) {
		t.Errorf("values %v; every sampled row contributes, in row order", vals["anschrift"])
	}
	if !reflect.DeepEqual(vals["n"], []string{"1", "2"}) {
		t.Errorf("non-string values %v must be rendered, not skipped: a JSONB or numeric "+
			"column is still a column", vals["n"])
	}
}

func TestAColumnMissingFromSomeRowsStillContributesTheValuesItHas(t *testing.T) {
	_, vals, _ := semantic.FromSample([]map[string]any{
		{"a": "x"}, {"b": "y"}, {"a": "z"},
	}, nil)
	if !reflect.DeepEqual(vals["a"], []string{"x", "z"}) {
		t.Errorf("a = %v, want [x z]: a sparse column is normal in JSON rows", vals["a"])
	}
}

func TestNilValuesAreSkippedRatherThanRenderedAsTheWordNull(t *testing.T) {
	_, vals, _ := semantic.FromSample([]map[string]any{
		{"a": nil}, {"a": "real"},
	}, nil)
	if !reflect.DeepEqual(vals["a"], []string{"real"}) {
		t.Errorf("a = %v; sending <nil> to the model describes the encoding, not the data", vals["a"])
	}
}

func TestAPairWithNoColonIsIgnoredRatherThanMisread(t *testing.T) {
	_, _, rules := semantic.FromSample([]map[string]any{{"a": "x"}}, []string{"malformed"})
	if len(rules) != 0 {
		t.Errorf("rules = %v from a pair with no separator; guessing at the format is "+
			"how a column silently loses its proof", rules)
	}
}
