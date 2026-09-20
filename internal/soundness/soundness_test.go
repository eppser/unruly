package soundness

import "testing"

// The helper must fail an unsound probe. Verified by running it against a
// recorder rather than a real *testing.T, so the failure is observed instead
// of failing this test.
func TestRequireRejectsAnIndistinguishableProbe(t *testing.T) {
	fake := &testing.T{}
	// The zero-match DELETE probe, reproduced: both controls answer 204.
	Require(fake, Probe{
		Name:          "zero-match-delete",
		Detects:       "anonymous write access",
		PositiveInput: "an open relation",
		Positive:      func() Outcome { return Outcome{Verdict: "204", Detail: "no rows matched"} },
		NegativeInput: "an RLS-protected relation",
		Negative:      func() Outcome { return Outcome{Verdict: "204", Detail: "no rows matched"} },
	}, "reached", "blocked")

	if !fake.Failed() {
		t.Error("a probe whose controls are indistinguishable must fail Require()")
	}
}

func TestRequireAcceptsADiscriminatingProbe(t *testing.T) {
	fake := &testing.T{}
	// The INSERT discriminator: the controls answer with different SQLSTATEs.
	Require(fake, Probe{
		Name:          "insert-discriminator",
		Detects:       "anonymous write access",
		PositiveInput: "a relation with an anon INSERT policy",
		Positive:      func() Outcome { return Outcome{Verdict: "reached", Detail: "23502"} },
		NegativeInput: "a relation with RLS and no policy",
		Negative:      func() Outcome { return Outcome{Verdict: "blocked", Detail: "42501"} },
	}, "reached", "blocked")

	if fake.Failed() {
		t.Error("a probe that discriminates must pass Require()")
	}
}

// Distinguishing is necessary but not sufficient: the verdicts must also be
// the RIGHT way round. A probe that reports every open relation as protected
// and every protected one as open discriminates perfectly and is still wrong.
func TestRequireCatchesInvertedVerdicts(t *testing.T) {
	fake := &testing.T{}
	Require(fake, Probe{
		Name:          "inverted",
		Detects:       "anonymous write access",
		PositiveInput: "an open relation",
		Positive:      func() Outcome { return Outcome{Verdict: "blocked"} },
		NegativeInput: "a protected relation",
		Negative:      func() Outcome { return Outcome{Verdict: "reached"} },
	}, "reached", "blocked")

	if !fake.Failed() {
		t.Error("verdicts that discriminate but are inverted must still fail")
	}
}

// A probe supplied with only a positive control has not been shown to
// discriminate; it has only been shown to fire on something.
func TestRequireDemandsBothControls(t *testing.T) {
	fake := &testing.T{}
	Require(fake, Probe{
		Name:     "no-negative",
		Positive: func() Outcome { return Outcome{Verdict: "reached"} },
	}, "reached", "blocked")

	if !fake.Failed() {
		t.Error("a probe with no negative control must not be accepted")
	}
}
