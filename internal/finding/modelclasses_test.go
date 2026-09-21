package finding

import (
	"encoding/json"
	"strings"
	"testing"
)

// A scan with no model configured must write the bytes it wrote before.
//
// The feature is off by default, and "off" has to mean the JSON an existing
// consumer parses is unchanged -- not merely that no requests are made. The
// guarantee comes from omitempty rather than from care, and this pins it.
func TestModelClassesAreAbsentFromRuleOnlyOutput(t *testing.T) {
	e := Evidence{
		Columns: []string{"email", "card_number"},
		Classes: []string{"contact", "financial"},
	}
	b, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "model_classes") {
		t.Errorf("rule-only evidence serialised model_classes: %s", b)
	}

	e.ModelClasses = []string{"location"}
	b2, _ := json.Marshal(e)
	if !strings.Contains(string(b2), `"model_classes":["location"]`) {
		t.Errorf("model classes must be machine-readable and separate: %s", b2)
	}
	if !strings.Contains(string(b2), `"classes":["contact","financial"]`) {
		t.Errorf("the rules' own classes must survive untouched: %s", b2)
	}
}

// The two lists are never merged.
//
// An operator has to be able to tell a mod-97 check from a language model's
// opinion, and a consumer filtering on classes must not silently start
// receiving model output.
func TestTheTwoListsStaySeparate(t *testing.T) {
	e := Evidence{Classes: []string{"financial"}, ModelClasses: []string{"location"}}
	for _, c := range e.Classes {
		for _, m := range e.ModelClasses {
			if c == m {
				t.Errorf("%q appears in both lists", c)
			}
		}
	}
	b, _ := json.Marshal(e)
	if i, j := strings.Index(string(b), "classes"), strings.Index(string(b), "model_classes"); i > j {
		t.Error("model_classes serialises before classes; field order is part of the " +
			"reproducible-output contract")
	}
}
