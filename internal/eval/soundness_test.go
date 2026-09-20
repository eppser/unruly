package eval_test

// Soundness tests for the scanner's real probes, using the generated state
// space as controls.
//
// Every probe here is run against an input known to exhibit the condition AND
// one known not to, and must tell them apart. The negative controls are chosen
// to be the CLOSEST plausible case rather than an obviously different one: a
// write probe's negative is an RLS-protected relation, not a nonexistent one,
// because "protected" is exactly what an unsound probe misreports as "open".
//
// The NOT NULL variants (_nn) are used throughout so that no probe row can
// land: these tests must be repeatable without resetting the fixture.

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/eppser/unruly/internal/client"
	"github.com/eppser/unruly/internal/escalate"
	"github.com/eppser/unruly/internal/eval"
	"github.com/eppser/unruly/internal/postgrest"
	"github.com/eppser/unruly/internal/probe"
	"github.com/eppser/unruly/internal/soundness"
	"github.com/eppser/unruly/internal/surface"
)

func matrixClient(t *testing.T) *client.Client {
	t.Helper()
	if os.Getenv("UNRULY_LIVE") != "1" {
		t.Skip("set UNRULY_LIVE=1")
	}
	tgt, err := eval.LoadTarget(filepath.Join("..", "..", "evals", "targets", "matrix-fixture.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	key, err := tgt.AnonKey()
	if err != nil {
		t.Skip(err)
	}
	return client.New(client.Options{
		ProjectRef: tgt.ProjectRef, BaseURL: tgt.BaseURL,
		RestPrefix: tgt.RestPrefix, AnonKey: key, Retries: 1,
	})
}

// readOutcome runs the real read classifier against one relation.
func readOutcome(ctx context.Context, c *client.Client, rel string) soundness.Outcome {
	r := probe.Run(ctx, c, []string{rel}, probe.Options{SampleRows: 1})
	if len(r.Relations) == 0 {
		return soundness.Outcome{Verdict: "error", Detail: "no result"}
	}
	got := r.Relations[0]
	return soundness.Outcome{
		Verdict: got.Read.String(),
		Detail:  "rows=" + itoa(got.Rows),
	}
}

// writeOutcome runs the real write discriminator against one relation.
func writeOutcome(ctx context.Context, c *client.Client, rel string) soundness.Outcome {
	r := probe.Run(ctx, c, []string{rel}, probe.Options{Write: true, SampleRows: 1})
	if len(r.Relations) == 0 {
		return soundness.Outcome{Verdict: "error", Detail: "no result"}
	}
	got := r.Relations[0]
	return soundness.Outcome{Verdict: got.Write.String(), Detail: got.WriteWhy}
}

// TestWriteDiscriminatorIsSound is the one that matters most. The probe it
// replaced — zero-match DELETE — passes every test except this one, because
// this is the only test that asks it to tell an open relation from a protected
// one rather than merely to respond.
func TestWriteDiscriminatorIsSound(t *testing.T) {
	c := matrixClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	soundness.Require(t, soundness.Probe{
		Name:          "insert-write-discriminator",
		Detects:       "whether the anonymous role may INSERT into a relation",
		PositiveInput: "m_rls_selnone_insanon_nn (RLS on, INSERT policy TO anon)",
		Positive:      func() soundness.Outcome { return writeOutcome(ctx, c, "m_rls_selnone_insanon_nn") },
		NegativeInput: "m_rls_selnone_insnone_nn (RLS on, no policy at all)",
		Negative:      func() soundness.Outcome { return writeOutcome(ctx, c, "m_rls_selnone_insnone_nn") },
	}, postgrest.WriteReached.String(), postgrest.WriteBlockedRLS.String())
}

// The read classifier must separate "RLS filtered every row" from "rows are
// readable". Conflating them is how 206 gets read as a miss.
func TestReadClassifierIsSound(t *testing.T) {
	c := matrixClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	soundness.Require(t, soundness.Probe{
		Name:          "read-exposure-classifier",
		Detects:       "whether the anonymous role can read rows from a relation",
		PositiveInput: "m_rls_selanon_insnone_nn (SELECT policy TO anon)",
		Positive:      func() soundness.Outcome { return readOutcome(ctx, c, "m_rls_selanon_insnone_nn") },
		NegativeInput: "m_rls_selnone_insnone_nn (RLS on, no policy)",
		Negative:      func() soundness.Outcome { return readOutcome(ctx, c, "m_rls_selnone_insnone_nn") },
	}, postgrest.ReadExposed.String(), postgrest.ReadEmpty.String())
}

// A policy TO authenticated must not read as anon-exposed. This is the control
// pair a classifier reasoning from "has a policy" would fail.
func TestReadClassifierSeparatesPolicyAudience(t *testing.T) {
	c := matrixClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	soundness.Require(t, soundness.Probe{
		Name:          "read-exposure-policy-audience",
		Detects:       "whether a SELECT policy admits the ANONYMOUS role specifically",
		PositiveInput: "m_rls_selanon_insnone_nn (policy TO anon)",
		Positive:      func() soundness.Outcome { return readOutcome(ctx, c, "m_rls_selanon_insnone_nn") },
		NegativeInput: "m_rls_selauthenticated_insnone_nn (policy TO authenticated)",
		Negative:      func() soundness.Outcome { return readOutcome(ctx, c, "m_rls_selauthenticated_insnone_nn") },
	}, postgrest.ReadExposed.String(), postgrest.ReadEmpty.String())
}

// Relation existence must separate "exists but yields nothing" from "does not
// exist". A tool that conflates them reports 404 as "SECURE", which one
// surveyed scanner does.
func TestExistenceProbeIsSound(t *testing.T) {
	c := matrixClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	soundness.Require(t, soundness.Probe{
		Name:          "relation-existence",
		Detects:       "whether a relation exists at all, independent of readability",
		PositiveInput: "m_rls_selnone_insnone_nn (exists, RLS filters every row)",
		Positive:      func() soundness.Outcome { return readOutcome(ctx, c, "m_rls_selnone_insnone_nn") },
		NegativeInput: "no_such_relation_anywhere (does not exist)",
		Negative:      func() soundness.Outcome { return readOutcome(ctx, c, "no_such_relation_anywhere") },
	}, postgrest.ReadEmpty.String(), postgrest.ReadNotFound.String())
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	if neg {
		return "-" + string(b)
	}
	return string(b)
}

// escalationOutcome runs the real role-delta probe against one relation.
func escalationOutcome(ctx context.Context, c *client.Client, elevated, rel string) soundness.Outcome {
	base := probe.Run(ctx, c, []string{rel}, probe.Options{SampleRows: 1})
	res := escalate.Compare(ctx, c, base, escalate.Options{
		Relations: []string{rel}, ElevatedKey: elevated, SampleRows: 1,
	})
	if len(res.Gains) > 0 {
		return soundness.Outcome{
			Verdict: "gain",
			Detail:  itoa(res.Gains[0].Rows) + " rows visible to " + res.Role + " only",
		}
	}
	return soundness.Outcome{Verdict: "no-gain", Detail: "elevated role sees nothing extra"}
}

// TestEscalationProbeIsSound covers the check most at risk of crying wolf.
//
// The negative control is deliberately the closest plausible case, not an
// obviously different one. Both relations are invisible to anon and both grant
// SELECT to `authenticated`; the only difference is that one policy is
// USING (true) and the other scopes rows to the owning user. A probe that
// reported "has an authenticated policy" rather than measuring what the role
// can actually read would flag both, and would flag every correctly built
// application as escalatable.
func TestEscalationProbeIsSound(t *testing.T) {
	c := matrixClient(t)
	elevated := os.Getenv("UNRULY_MATRIX_AUTHED_KEY")
	if elevated == "" {
		t.Skip("set UNRULY_MATRIX_AUTHED_KEY to run the escalation soundness test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	soundness.Require(t, soundness.Probe{
		Name:          "authenticated-escalation",
		Detects:       "rows an authenticated role can read that anon cannot",
		PositiveInput: "m_rls_selauthenticated_insnone_nn (SELECT TO authenticated USING (true))",
		Positive: func() soundness.Outcome {
			return escalationOutcome(ctx, c, elevated, "m_rls_selauthenticated_insnone_nn")
		},
		NegativeInput: "m_rls_selowner_insnone_nn (SELECT TO authenticated, scoped to the owner)",
		Negative: func() soundness.Outcome {
			return escalationOutcome(ctx, c, elevated, "m_rls_selowner_insnone_nn")
		},
	}, "gain", "no-gain")
}

// routineCallability runs the real callability probe against one routine on
// one fixture.
func routineCallability(ctx context.Context, c *client.Client, routine string) soundness.Outcome {
	sf := surface.Run(ctx, c, surface.Options{
		RoutineSeeds:  []string{routine},
		MaxCandidates: 40,
		AllowInvoke:   true,
	})
	callable, known := sf.Callable[routine]
	if !known {
		// Absent means indeterminate: either the routine was never disclosed,
		// or it takes arguments this scan cannot supply.
		for _, r := range sf.Routines {
			if r == routine {
				return soundness.Outcome{
					Verdict: "unknown",
					Detail:  "disclosed, but callability could not be established",
				}
			}
		}
		return soundness.Outcome{Verdict: "not-disclosed", Detail: routine + " was not found"}
	}
	if callable {
		return soundness.Outcome{Verdict: "callable", Detail: "no privilege refusal"}
	}
	return soundness.Outcome{Verdict: "not-callable", Detail: "permission denied for function"}
}

// TestRoutineCallabilityIsSound separates a name leak from an attack surface.
//
// Both controls are routines that PostgREST discloses by name — the hint is
// built from the schema cache and knows nothing about privileges, so
// disclosure alone cannot distinguish them. Only calling them can. Conflating
// the two would report every correctly locked-down routine as reachable.
//
// The controls live in different fixtures because that is where the two states
// exist: lab grants EXECUTE, hardened revokes it.
func TestRoutineCallabilityIsSound(t *testing.T) {
	if os.Getenv("UNRULY_LIVE") != "1" {
		t.Skip("set UNRULY_LIVE=1")
	}
	labKey := os.Getenv("UNRULY_FIXTURE_KEY")
	hardKey := os.Getenv("UNRULY_HARDENED_KEY")
	if labKey == "" || hardKey == "" {
		t.Skip("both fixture keys are required for this control pair")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	lab := client.New(client.Options{
		ProjectRef: "lab", BaseURL: "http://127.0.0.1:54321",
		RestPrefix: "/", AnonKey: labKey, Retries: 1,
	})
	hardened := client.New(client.Options{
		ProjectRef: "hardened", BaseURL: "http://127.0.0.1:54331",
		RestPrefix: "/", AnonKey: hardKey, Retries: 1,
	})

	soundness.Require(t, soundness.Probe{
		Name:          "routine-callability",
		Detects:       "whether a disclosed routine can actually be invoked by the anonymous role",
		PositiveInput: "lab public_stats_summary() (zero-arg, so a privilege check actually happens)",
		Positive: func() soundness.Outcome {
			return routineCallability(ctx, lab, "public_stats_summary")
		},
		NegativeInput: "hardened internal_recalculate_ledger (EXECUTE revoked, still disclosed)",
		Negative: func() soundness.Outcome {
			return routineCallability(ctx, hardened, "internal_recalculate_ledger")
		},
	}, "callable", "not-callable")
}
