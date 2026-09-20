package intent

import (
	"testing"

	"github.com/eppser/unruly/internal/finding"
	"github.com/eppser/unruly/scan"
)

func TestIntentOutcomesBecomeViolationsCoverageAndSummary(t *testing.T) {
	fs := Findings("https://target", []Outcome{
		{Expectation: Expectation{Resource: "invoices", Operation: Read,
			Subject: Anonymous, Result: Deny}, State: Violated, Detail: "anonymous allowed"},
		{Expectation: Expectation{Resource: "profiles", Operation: Read,
			Subject: OtherTenant, Result: Deny}, State: Unverified, Detail: "not measured"},
		{Expectation: Expectation{Resource: "catalog", Operation: Read,
			Subject: Anonymous, Result: Allow}, State: Matched, Detail: "matched"},
	})
	want := map[string]bool{
		"unruly-intent-violation":     false,
		"unruly-surface-not-assessed": false,
		"unruly-intent-summary":       false,
	}
	for _, f := range fs {
		if _, ok := want[f.ID]; ok {
			want[f.ID] = true
		}
		if f.ID == "unruly-intent-violation" && f.Severity != finding.High {
			t.Errorf("an observed allow contradicting an intended deny is %s", f.Severity)
		}
	}
	for id, found := range want {
		if !found {
			t.Errorf("%s was not emitted", id)
		}
	}
}

func TestProviderNeutralObservationPreservesScope(t *testing.T) {
	got := Observations(scan.Access{Observed: []scan.AccessFact{{
		Resource: "invoices", Operation: "read", Subject: "owner",
		Scope: "own", Allowed: true,
	}}})
	if len(got) != 1 || got[0].Scope != ScopeOwn {
		t.Fatalf("ownership scope was dropped at the intent boundary: %+v", got)
	}
}
