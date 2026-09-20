package scan

import "testing"

// Two stages drawing on one budget must not both spend the same allowance.
//
// This is the first genuinely SHARED MUTABLE thing to cross the stage seam.
// Everything before it was either a value passed down (seeds, flags) or a
// provider-private result handed between stages of one backend. A budget is
// different: the default-schema routine sweep and the per-schema sweeps draw
// on the same allowance, and if each sees the full amount the scan issues
// twice the requests the operator capped it at.
func TestOneBudgetIsNotSpentTwice(t *testing.T) {
	b := NewBudget(100)
	if got := b.Take(60); got != 60 {
		t.Fatalf("first taker got %d of 60", got)
	}
	if got := b.Take(60); got != 40 {
		t.Errorf("second taker got %d, want the 40 that were left: a budget that "+
			"hands the same allowance to every caller is not a budget", got)
	}
	if b.Left() != 0 {
		t.Errorf("%d left after the allowance was exhausted", b.Left())
	}
}

// A taker that is clipped LEARNS it was clipped.
//
// This is the property the schemas block was built around after a real gap:
// "only the default schema's truncation was reported, so a secondary schema
// whose routine sweep ran out said nothing at all -- a silent coverage gap in
// the surface most likely to be forgotten". Take returning less than asked is
// what lets the CONSUMER emit its own truncation finding, rather than the
// runner emitting one global note that names no schema.
func TestAClippedTakerCanTellItWasClipped(t *testing.T) {
	b := NewBudget(10)
	if got := b.Take(4); got != 4 {
		t.Fatalf("unclipped take returned %d", got)
	}
	got := b.Take(25)
	if got == 25 {
		t.Fatal("a take beyond the remaining allowance was granted in full")
	}
	if got != 6 {
		t.Errorf("clipped take granted %d, want the 6 remaining", got)
	}
}

// Exhaustion is visible without taking anything, so a stage can decline
// cleanly rather than performing a zero-sized sweep and reporting it as clean.
func TestExhaustionIsVisibleBeforeTaking(t *testing.T) {
	b := NewBudget(5)
	b.Take(5)
	if b.Left() != 0 {
		t.Errorf("Left()=%d after taking everything", b.Left())
	}
	if !b.Exhausted() {
		t.Error("Exhausted() is false with nothing left, so a stage cannot tell " +
			"'no allowance' from 'allowance of zero requests needed'")
	}
}

// A nil budget means UNCAPPED, not zero.
//
// Every existing stage runs with no budget at all, and the zero value must
// keep them working: a Budget that defaulted to zero would silently reduce
// every unbudgeted sweep to nothing and report the result as clean, which is
// the failure mode this whole project exists to prevent.
func TestANilBudgetIsUncappedNotEmpty(t *testing.T) {
	var b *Budget
	if got := b.Take(1000); got != 1000 {
		t.Errorf("nil budget granted %d of 1000: an absent cap must mean no cap, "+
			"or adding budgets silently truncates every stage that has none", got)
	}
	if b.Exhausted() {
		t.Error("a nil budget reports itself exhausted")
	}
}

// Negative and zero requests are not errors and take nothing.
func TestNonPositiveTakesAreHarmless(t *testing.T) {
	b := NewBudget(10)
	if got := b.Take(0); got != 0 {
		t.Errorf("Take(0) granted %d", got)
	}
	if got := b.Take(-5); got != 0 {
		t.Errorf("Take(-5) granted %d", got)
	}
	if b.Left() != 10 {
		t.Errorf("a non-positive take moved the budget to %d", b.Left())
	}
}
