package probe

import (
	"context"
	"testing"

	"github.com/eppser/unruly/internal/semantic"
)

type stubAsker struct {
	answer map[string]string
	asked  []string
}

func (s *stubAsker) Enabled() bool { return true }
func (s *stubAsker) Classify(_ context.Context, col string, _ []string) (semantic.Result, error) {
	s.asked = append(s.asked, col)
	if c, ok := s.answer[col]; ok {
		return semantic.Result{Class: c, P: 0.95}, nil
	}
	return semantic.Result{}, nil
}

// A relation carries model classes only where the rules were silent, and the
// rules' own classes are untouched.
func TestRelationCarriesModelClassesSeparately(t *testing.T) {
	rel := Relation{
		Name:            "kunden",
		Sample:          []map[string]any{{"email": "ada@lovelace.test", "anschrift": "Hauptstrasse 14"}},
		Sensitive:       []string{"email:contact"},
		SensitiveValues: []string{"contact"},
	}
	s := &stubAsker{answer: map[string]string{"anschrift": "location", "email": "pii"}}

	classifyWithModel(context.Background(), s, &rel)

	for _, c := range s.asked {
		if c == "email" {
			t.Error("the model was asked about a column the rules classified")
		}
	}
	if got := classesOf(rel); len(got) != 1 || got[0] != "contact" {
		t.Errorf("rule classes = %v, want [contact]: the model must not change them", got)
	}
	if len(rel.ModelClasses) != 1 || rel.ModelClasses[0] != "location" {
		t.Errorf("model classes = %v, want [location]", rel.ModelClasses)
	}
}

// With no classifier the relation is untouched, which is what keeps rule-only
// output byte-identical.
func TestNoClassifierLeavesTheRelationAlone(t *testing.T) {
	rel := Relation{Sample: []map[string]any{{"anschrift": "Hauptstrasse 14"}}}
	classifyWithModel(context.Background(), nil, &rel)
	if rel.ModelClasses != nil {
		t.Errorf("model classes = %v with no classifier", rel.ModelClasses)
	}
	disabled, _ := semantic.New(semantic.Options{})
	classifyWithModel(context.Background(), disabled, &rel)
	if rel.ModelClasses != nil {
		t.Errorf("model classes = %v from a disabled classifier", rel.ModelClasses)
	}
}

// A relation with nothing sampled is not worth a request.
func TestARelationWithNoSampleIsNotSentToTheModel(t *testing.T) {
	rel := Relation{Name: "leer"}
	s := &stubAsker{answer: map[string]string{"x": "pii"}}
	classifyWithModel(context.Background(), s, &rel)
	if len(s.asked) != 0 {
		t.Errorf("asked about %v with no rows sampled; there is nothing to classify "+
			"and the request would be spent on an empty relation", s.asked)
	}
}
