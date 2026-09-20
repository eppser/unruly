package parity

import (
	"strings"
	"testing"

	"github.com/eppser/unruly/internal/finding"
)

func f(id, res string, sev finding.Severity) finding.Finding {
	return finding.Finding{ID: id, Resource: res, Severity: sev, Protocol: "postgrest",
		Matched: "http://h/rest/v1", Evidence: finding.Evidence{Reason: "because"}}
}

// Two runs that found the same things compare equal.
func TestIdenticalFindingsProduceNoDifference(t *testing.T) {
	a := []finding.Finding{f("read-exposed", "notes", finding.High)}
	b := []finding.Finding{f("read-exposed", "notes", finding.High)}
	if d := Diff(a, b); d != "" {
		t.Errorf("identical inputs differ:\n%s", d)
	}
}

// Order is not a difference. The old code path appends findings in the order
// its sections ran; the pipeline appends in stage order. Those orders are not
// the same and must not be, or every port would look like a regression.
// finding.Sort is the canonical order and parity is measured after it.
func TestOrderIsNotADifference(t *testing.T) {
	a := []finding.Finding{f("a-rule", "x", finding.High), f("b-rule", "y", finding.Low)}
	b := []finding.Finding{f("b-rule", "y", finding.Low), f("a-rule", "x", finding.High)}
	if d := Diff(a, b); d != "" {
		t.Errorf("the same findings in a different order were reported as a difference:\n%s", d)
	}
}

// A finding present on one side only is named, with which side it came from.
// A parity failure that says only "outputs differ" costs the reader the whole
// investigation.
func TestAMissingFindingIsNamed(t *testing.T) {
	a := []finding.Finding{f("read-exposed", "notes", finding.High),
		f("write-exposed", "notes", finding.Critical)}
	b := []finding.Finding{f("read-exposed", "notes", finding.High)}
	d := Diff(a, b)
	if d == "" {
		t.Fatal("a dropped finding was not reported as a difference")
	}
	if !strings.Contains(d, "write-exposed") {
		t.Errorf("the difference does not name the missing finding:\n%s", d)
	}
}

// A changed field is a difference even when the finding is otherwise the same.
// Severity drift is the case that matters: a port that quietly downgrades a
// critical to a medium passes any test that only counts findings.
func TestAChangedSeverityIsADifference(t *testing.T) {
	a := []finding.Finding{f("read-exposed", "notes", finding.Critical)}
	b := []finding.Finding{f("read-exposed", "notes", finding.Medium)}
	d := Diff(a, b)
	if d == "" {
		t.Fatal("a severity change was not reported as a difference")
	}
	if !strings.Contains(d, "read-exposed") {
		t.Errorf("the difference does not name the finding that changed:\n%s", d)
	}
}

// Evidence is compared too. A port that keeps the finding and loses the
// sampled row has broken the proof-carrying guarantee while still producing
// the right count and severity.
func TestLostEvidenceIsADifference(t *testing.T) {
	a := []finding.Finding{f("read-exposed", "notes", finding.High)}
	withRow := f("read-exposed", "notes", finding.High)
	withRow.Evidence.Sample = []map[string]any{{"email": "leaked@example.com"}}
	if d := Diff(a, []finding.Finding{withRow}); d == "" {
		t.Error("a finding that gained a sampled row compared equal to one without: " +
			"evidence is not being compared")
	}
}

// The replayable request is proof and is compared. A port that keeps the
// finding and the sample but drops the curl line has produced something an
// auditor cannot re-run, which this scanner treats as not proven at all.
func TestALostReplayableRequestIsADifference(t *testing.T) {
	a := []finding.Finding{f("read-exposed", "notes", finding.High)}
	withReq := f("read-exposed", "notes", finding.High)
	withReq.Evidence.Request = "curl -sS 'http://h/rest/v1/notes?select=*&limit=1'"
	if d := Diff(a, []finding.Finding{withReq}); d == "" {
		t.Error("a finding that gained a replayable request compared equal to one " +
			"without: the request is not being compared")
	}
}
