package semantic_test

import (
	"context"
	"reflect"
	"sync"
	"testing"

	"github.com/eppser/unruly/internal/semantic"
)

// fakeClassifier answers from a table, so the merge rules can be graded
// without a model and without HTTP.
//
// Locked, because Augment asks about the columns of one relation concurrently.
// The order of `asked` is therefore not the order of the columns -- only its
// contents mean anything, and every assertion here is a membership test.
type fakeClassifier struct {
	byColumn map[string]semantic.Result
	mu       sync.Mutex
	asked    []string
}

func (f *fakeClassifier) Enabled() bool { return true }
func (f *fakeClassifier) Classify(_ context.Context, col string, _ []string) (semantic.Result, error) {
	f.mu.Lock()
	f.asked = append(f.asked, col)
	f.mu.Unlock()
	return f.byColumn[col], nil
}

// The rules win. Always, and without asking.
//
// This is the whole safety argument for the feature: the rules are measured at
// 0.4% false positives across 500 negatives and the best model tested at 12%.
// A design where the model can overwrite a proof trades the number that is
// trustworthy for the one that is not.
func TestAColumnTheRulesClassifiedIsNeverSentToTheModel(t *testing.T) {
	f := &fakeClassifier{byColumn: map[string]semantic.Result{
		"kreditkarte": {Class: "pii", P: 0.99}, // wrong, and must never be reached
		"anschrift":   {Class: "location", P: 0.95},
	}}
	got, err := semantic.Augment(context.Background(), f,
		[]string{"kreditkarte", "anschrift"},
		map[string][]string{"kreditkarte": {"4111111111111111"}, "anschrift": {"Hauptstrasse 14"}},
		map[string][]string{"kreditkarte": {"financial"}}, // what the rules found
	)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range f.asked {
		if c == "kreditkarte" {
			t.Error("the model was asked about a column the rules already classified; " +
				"a proof must not be put up for a second opinion")
		}
	}
	if !reflect.DeepEqual(got, []string{"location"}) {
		t.Errorf("model classes %v, want [location]", got)
	}
}

func TestNothingIsReturnedWhenTheRulesCoveredEverything(t *testing.T) {
	f := &fakeClassifier{byColumn: map[string]semantic.Result{"x": {Class: "pii", P: 0.99}}}
	got, err := semantic.Augment(context.Background(), f, []string{"x"},
		map[string][]string{"x": {"v"}}, map[string][]string{"x": {"credential"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Errorf("got %v; with every column already classified there is nothing to add "+
			"and no request to make", got)
	}
	if len(f.asked) != 0 {
		t.Errorf("asked about %v anyway", f.asked)
	}
}

func TestAClassTheRulesAlreadyFoundIsNotRepeatedAsAModelClass(t *testing.T) {
	// The model may land on a class the rules found on a DIFFERENT column.
	// Reporting it twice, once as proof and once as opinion, would make the
	// report argue with itself.
	f := &fakeClassifier{byColumn: map[string]semantic.Result{"notiz": {Class: "financial", P: 0.99}}}
	got, err := semantic.Augment(context.Background(), f, []string{"iban", "notiz"},
		map[string][]string{"iban": {"GB82WEST12345698765432"}, "notiz": {"zahlung erhalten"}},
		map[string][]string{"iban": {"financial"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Errorf("got %v; financial was already established by a mod-97 check on another "+
			"column, so the model adds nothing and saying it twice weakens the first", got)
	}
}

func TestTheResultIsSortedAndDeduplicated(t *testing.T) {
	f := &fakeClassifier{byColumn: map[string]semantic.Result{
		"a": {Class: "pii", P: 0.9}, "b": {Class: "location", P: 0.9},
		"c": {Class: "pii", P: 0.9},
	}}
	got, err := semantic.Augment(context.Background(), f, []string{"c", "a", "b"},
		map[string][]string{"a": {"1"}, "b": {"2"}, "c": {"3"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, []string{"location", "pii"}) {
		t.Errorf("got %v, want [location pii]: unsorted or duplicated output makes two "+
			"runs of the same scan differ", got)
	}
}

func TestADisabledClassifierIsANoOpAndCostsNothing(t *testing.T) {
	c, _ := semantic.New(semantic.Options{})
	got, err := semantic.Augment(context.Background(), c, []string{"anschrift"},
		map[string][]string{"anschrift": {"Hauptstrasse 14"}}, nil)
	if err != nil {
		t.Fatalf("a disabled classifier must not error: %v", err)
	}
	if got != nil {
		t.Errorf("got %v, want nil: the field is omitempty and a non-nil empty slice "+
			"would still change the JSON", got)
	}
}
