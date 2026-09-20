package main

import (
	"testing"

	"github.com/eppser/unruly/scan"
)

// A request sent once must be counted once.
//
// The staged breakdown is a SUBSET of the backend's total, not an addition to
// it. Adding both produced "collections 893, providers 893" for a run that sent
// 893 requests, and a ledger that double-counts sends whoever reads it hunting
// a bottleneck that is not there.
func TestProviderSpendCountsEachRequestOnce(t *testing.T) {
	l := newLedger()
	addProviderSpend(l, 1000, []scan.StageSpend{
		{Stage: "collections", Requests: 600},
		{Stage: "escalation", Requests: 150},
	})
	got := l.summary(10)

	// 1000 total, 750 of it staged, so 250 belongs to no stage.
	for _, want := range []string{"collections 600", "escalation 150", "providers 250"} {
		if !contains(got, want) {
			t.Errorf("ledger %q does not contain %q", got, want)
		}
	}
	if contains(got, "providers 1000") {
		t.Error("the staged requests were counted again under providers")
	}
}

// A backend with no stages keeps its whole total under providers, and one whose
// stages account for everything gets no providers line at all -- an entry
// reading "providers 0" is noise in a summary that exists to point somewhere.
func TestProviderSpendHandlesBothEnds(t *testing.T) {
	l := newLedger()
	addProviderSpend(l, 40, nil)
	if got := l.summary(10); !contains(got, "providers 40") {
		t.Errorf("unstaged backend: %q", got)
	}

	l2 := newLedger()
	addProviderSpend(l2, 60, []scan.StageSpend{{Stage: "collections", Requests: 60}})
	got := l2.summary(10)
	if contains(got, "providers") {
		t.Errorf("every request was attributed to a stage and providers still appears: %q", got)
	}
	if !contains(got, "collections 60") {
		t.Errorf("staged total missing: %q", got)
	}
}

func contains(hay, needle string) bool {
	return len(hay) >= len(needle) && (func() bool {
		for i := 0; i+len(needle) <= len(hay); i++ {
			if hay[i:i+len(needle)] == needle {
				return true
			}
		}
		return false
	})()
}
