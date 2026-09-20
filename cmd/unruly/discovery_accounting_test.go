package main

import "testing"

// Provider-name accounting remains a command-facing summary decision. The
// additive workload/request/access merge formerly tested here moved to
// internal/engine, where the merge now lives.
func TestProviderDenominatorRespectsTheProbeBudget(t *testing.T) {
	if got := boundedCount(2740, 1); got != 1 {
		t.Fatalf("summary says %d provider names were probed under a one-name budget", got)
	}
	if got := boundedCount(12, 0); got != 12 {
		t.Fatalf("an unlimited budget changed %d names to %d", 12, got)
	}
}
