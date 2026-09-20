package eval

import (
	"strings"
	"testing"
)

// Classification is scored, and it is scored per relation.
//
// Every other dimension asks whether a relation was FOUND. This one asks what
// the report said was IN it, which is a separate failure with a separate cost:
// a scan can have perfect recall on reachability and still describe a table of
// diagnoses and national identifiers as data with nothing recognised in it.
// Nothing graded that until corpus project 16, so the whole classifier -- both
// halves of it, and every class in the vocabulary -- sat outside the benchmark.
//
// Pairs of relation:class, so a class found on the WRONG relation is a false
// positive and a false negative rather than a silent wash.
func TestClassificationIsScoredPerRelation(t *testing.T) {
	target := &Target{
		Name: "t",
		Expect: Expectation{
			Relations: []Relation{
				{Name: "employees", ReadExposed: true, Classes: []string{"contact", "pii"}},
				{Name: "absence_records", ReadExposed: true, Classes: []string{"health"}},
			},
		},
	}

	got := Grade(target, Observation{
		Relations:   []string{"employees", "absence_records"},
		ReadExposed: []string{"employees", "absence_records"},
		Classes:     []string{"employees:contact", "employees:pii", "absence_records:health"},
	})

	s := dimension(t, got, "data-classification")
	if s.Recall() != 1 || s.Precision() != 1 {
		t.Errorf("a perfectly classified target scored recall %.0f%% precision %.0f%%; missed %v, false %v",
			s.Recall()*100, s.Precision()*100, s.FalseNeg, s.FalsePos)
	}
}

// A class the scan did not report is a false negative.
//
// This is the German-column case that corpus project 16 exists for: the
// relation is found and read, and the classifier that would have named what is
// in it never ran or never saw the values.
func TestAClassThatWasNotReportedIsAMiss(t *testing.T) {
	target := &Target{
		Name: "t",
		Expect: Expectation{Relations: []Relation{
			{Name: "gehaltsdaten", ReadExposed: true, Classes: []string{"contact", "financial"}},
		}},
	}

	got := Grade(target, Observation{
		Relations:   []string{"gehaltsdaten"},
		ReadExposed: []string{"gehaltsdaten"},
		Classes:     []string{}, // found the table, said nothing about its contents
	})

	s := dimension(t, got, "data-classification")
	if s.Recall() != 0 {
		t.Errorf("recall %.0f%% for a relation whose two classes were both missed", s.Recall()*100)
	}
	if len(s.FalseNeg) != 2 {
		t.Errorf("FalseNeg = %v, want both classes named", s.FalseNeg)
	}
}

// A class reported on a relation that has none is a false alarm.
//
// The lookalike tables. Without this half, "comprehensive" would be satisfied
// by a classifier that labels everything, and the class column would stop
// being worth reading.
func TestAClassOnALookalikeRelationIsAFalseAlarm(t *testing.T) {
	target := &Target{
		Name: "t",
		Expect: Expectation{Relations: []Relation{
			{Name: "payout_methods", ReadExposed: true, Classes: []string{}},
		}},
	}

	got := Grade(target, Observation{
		Relations:   []string{"payout_methods"},
		ReadExposed: []string{"payout_methods"},
		Classes:     []string{"payout_methods:location"}, // ip_address read as an address
	})

	s := dimension(t, got, "data-classification")
	if s.Precision() != 0 {
		t.Errorf("precision %.0f%% when the only class reported was wrong", s.Precision()*100)
	}
	if len(s.FalsePos) != 1 || !strings.Contains(s.FalsePos[0], "payout_methods") {
		t.Errorf("FalsePos = %v, want the lookalike relation named", s.FalsePos)
	}
}

// A target that declares no classes is not scored on classification.
//
// Fifteen of the sixteen corpus projects say nothing about classes, and their
// scans DO report sensitive columns. Scoring them against an empty expectation
// would turn every correct classification into a false positive and drop the
// corpus-wide precision for a dimension those projects never claimed to
// measure. Same rule as every other optional dimension here: absent is not
// zero.
func TestATargetThatDeclaresNoClassesIsNotScoredOnClassification(t *testing.T) {
	target := &Target{
		Name: "t",
		Expect: Expectation{Relations: []Relation{
			{Name: "sessions", ReadExposed: true, SensitiveColumns: []string{"access_token"}},
		}},
	}

	got := Grade(target, Observation{
		Relations:   []string{"sessions"},
		ReadExposed: []string{"sessions"},
		Classes:     []string{"sessions:credential"},
	})

	for _, s := range got.Scores {
		if s.Dimension == "data-classification" {
			t.Errorf("a target declaring no classes was scored on classification: %+v", s)
		}
	}
}

// dimension finds one scored dimension, and fails loudly when it is absent.
func dimension(t *testing.T, r Result, name string) Score {
	t.Helper()
	for _, s := range r.Scores {
		if s.Dimension == name {
			return s
		}
	}
	var have []string
	for _, s := range r.Scores {
		have = append(have, s.Dimension)
	}
	t.Fatalf("no %q dimension was scored; got %v", name, have)
	return Score{}
}
