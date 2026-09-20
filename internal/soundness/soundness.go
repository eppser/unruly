// Package soundness turns this project's one hard rule into a test obligation.
//
// The rule, from CONTRIBUTING.md:
//
//	A probe whose negative result is indistinguishable from "nothing was there"
//	is not a probe. It is a coin flip with a plausible story attached.
//
// It has been broken five times during development, every time by someone who
// had just finished explaining the failure mode:
//
//	zero-match DELETE for write access  16 false positives of 21
//	unknown-column INSERT canary        PGRST204 is raised before any SQL runs
//	Realtime subscription ACK           21 of 21, including 13 protected
//	selfcheck's synthetic hint probe    declared a working oracle broken
//	cleanup verification                RLS-denied DELETE returns 204
//
// Five for five is not carelessness, it is a property of the problem: every one
// of those probes looks obviously correct until you run it against an input
// whose answer you already know. Discipline demonstrably does not catch it, so
// the check is mechanical instead.
//
// Require() takes a probe together with a POSITIVE and a NEGATIVE control —
// inputs whose correct answers are known and opposite — runs both, and fails
// the test when they cannot be told apart. A probe that passes has been shown
// to discriminate on this target. A probe that fails would have shipped as a
// coin flip.
//
// The controls are not hypothetical: fixtures/matrix generates a relation for
// every RLS configuration, so a known-open and a known-protected input exist by
// construction for each probe the scanner makes.
package soundness

import (
	"fmt"
	"testing"
)

// Outcome is whatever a probe concluded, reduced to something comparable.
// Verdict is the classification; Detail is kept for the failure message.
type Outcome struct {
	Verdict string
	Detail  string
}

// Probe is a check under test, with the two controls that prove it works.
type Probe struct {
	// Name identifies the probe in failure output.
	Name string
	// What the probe is supposed to detect, in one clause. Printed on failure
	// so the message explains the stakes rather than just the mismatch.
	Detects string

	// Positive runs the probe against an input KNOWN to exhibit the condition.
	Positive func() Outcome
	// PositiveInput names that input, for the failure message.
	PositiveInput string

	// Negative runs the probe against an input KNOWN NOT to exhibit it.
	// Choosing this well is the whole exercise: it must be the closest
	// plausible case, not an obviously different one. A write probe's negative
	// is an RLS-protected relation, not a nonexistent one.
	Negative func() Outcome
	// NegativeInput names that input.
	NegativeInput string
}

// Require asserts the probe distinguishes its controls, and reports the
// expected verdicts so a mismatch says which side went wrong.
func Require(t *testing.T, p Probe, wantPositive, wantNegative string) {
	t.Helper()
	if p.Positive == nil || p.Negative == nil {
		t.Errorf("%s: both controls are required. A probe with only a positive "+
			"control has never been shown to discriminate: it has only been shown "+
			"to fire on something.", p.Name)
		return
	}

	pos := p.Positive()
	neg := p.Negative()

	if pos.Verdict == neg.Verdict {
		t.Errorf(`%s is UNSOUND: both controls produced %q.

  detects:  %s
  positive: %s -> %q (%s)
  negative: %s -> %q (%s)

The probe cannot tell the condition apart from its absence, so every verdict it
produces is a guess. This is the failure mode described in CONTRIBUTING.md and
it has shipped five times in this project already. Find an input that
discriminates, or report the ambiguity instead of resolving it.`,
			p.Name, pos.Verdict, p.Detects,
			p.PositiveInput, pos.Verdict, pos.Detail,
			p.NegativeInput, neg.Verdict, neg.Detail)
		return
	}

	if pos.Verdict != wantPositive {
		t.Errorf("%s: positive control %s produced %q, want %q (%s)",
			p.Name, p.PositiveInput, pos.Verdict, wantPositive, pos.Detail)
	}
	if neg.Verdict != wantNegative {
		t.Errorf("%s: negative control %s produced %q, want %q (%s)",
			p.Name, p.NegativeInput, neg.Verdict, wantNegative, neg.Detail)
	}
}

// String renders an outcome for logs.
func (o Outcome) String() string {
	if o.Detail == "" {
		return o.Verdict
	}
	return fmt.Sprintf("%s (%s)", o.Verdict, o.Detail)
}
