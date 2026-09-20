package eval_test

// The RLS state space, graded. Hand-written fixtures cover states somebody
// thought of; this covers the cross product, and its answer key is derived
// from the same rules that emit the DDL rather than transcribed by hand.
//
//   cd fixtures/matrix && docker compose up -d && python3 mint-jwt.py > anon.jwt
//   export UNRULY_MATRIX_KEY=$(cat anon.jwt)

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/eppser/unruly/internal/client"
	"github.com/eppser/unruly/internal/eval"
	"github.com/eppser/unruly/internal/probe"
)

func TestMatrixFullStateSpace(t *testing.T) {
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
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	c := client.New(client.Options{
		ProjectRef: tgt.ProjectRef, BaseURL: tgt.BaseURL,
		RestPrefix: tgt.RestPrefix, AnonKey: key, Retries: 1,
	})

	// The write probe mutates this fixture by design, so a run against a dirty
	// fixture fails on row counts and reads exactly like a scanner regression.
	// It is not one. Check the baseline first and say which it is — the same
	// distinction this tool draws everywhere else between a wrong answer and
	// an unusable question.
	baseline := probe.Run(ctx, c, tgt.RelationNames(), probe.Options{SampleRows: 1})
	for _, r := range tgt.Expect.Relations {
		if !r.ReadExposed {
			continue
		}
		if got := baseline.Rows()[r.Name]; got != r.Rows {
			t.Skipf("fixture has drifted (%s holds %d rows, seed state is %d): "+
				"a previous write probe left rows behind. Run `make fixtures-reset`. "+
				"This is a dirty fixture, not a scanner failure.", r.Name, got, r.Rows)
		}
	}

	start := time.Now()
	// Residue is allowed here, so write recall is measured at full strength.
	// The probe genuinely mutates this fixture: several states permit INSERT
	// without permitting DELETE, so a probe row cannot be removed by anyone
	// holding only the anon key. That is the tool behaving correctly, and it
	// means the fixture must be RESET before each run — `make fixtures-reset`,
	// which `make eval` calls. Grading write exposure without residue would
	// measure a deliberately degraded mode and report 40% as if it were a bug.
	pr := probe.Run(ctx, c, tgt.RelationNames(),
		probe.Options{Write: true, SampleRows: 2})
	elapsed := time.Since(start)

	graded := eval.Grade(tgt, eval.Observation{
		Relations:       tgt.RelationNames(),
		ReadExposed:     pr.ReadExposed(),
		InsertReachable: pr.InsertReachable(),
		Rows:            pr.Rows(),
	})
	t.Logf("%d states probed in %s (%d requests)",
		len(tgt.RelationNames()), elapsed.Round(time.Millisecond), pr.Requests)
	t.Logf("\n%s", graded)

	for _, s := range graded.Scores {
		switch s.Dimension {
		case "relation-discovery", "read-exposure", "write-exposure", "protected-not-flagged":
			if !s.Perfect() {
				t.Errorf("%s", s)
			}
		}
	}
	if len(graded.RowCountErrors) > 0 {
		t.Errorf("row-count mismatches: %v", graded.RowCountErrors)
	}
	// Rows left behind are expected on states that permit INSERT but not
	// DELETE. What matters is that each one is REPORTED rather than silently
	// accumulated, which is what the verified-cleanup fix guarantees.
	var residue int
	for _, rel := range pr.Relations {
		if rel.CleanupErr != "" {
			residue++
			t.Logf("reported residue in %s: %s", rel.Name, rel.CleanupErr)
		}
	}
	t.Logf("%d probe rows could not be removed, all reported", residue)
}

// The states most likely to be conflated by a classifier reasoning from
// "does it have a policy" rather than "does that policy admit anon".
func TestMatrixDistinguishesPolicyAudience(t *testing.T) {
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
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	c := client.New(client.Options{
		ProjectRef: tgt.ProjectRef, BaseURL: tgt.BaseURL,
		RestPrefix: tgt.RestPrefix, AnonKey: key, Retries: 1,
	})

	cases := []struct {
		relation string
		readable bool
		why      string
	}{
		{"m_rls_selanon_insnone_nn", true,
			"a SELECT policy TO anon does expose the relation"},
		{"m_rls_selauthenticated_insnone_nn", false,
			"a SELECT policy TO authenticated must NOT count as anon-readable"},
		{"m_rls_selowner_insnone_nn", false,
			"an owner-scoped policy admits nobody whose JWT subject fails the predicate"},
		{"m_rls_selnone_insnone_nn", false,
			"RLS with no policy admits nobody"},
	}
	var names []string
	for _, tc := range cases {
		names = append(names, tc.relation)
	}
	pr := probe.Run(ctx, c, names, probe.Options{SampleRows: 1})

	readable := map[string]bool{}
	for _, n := range pr.ReadExposed() {
		readable[n] = true
	}
	for _, tc := range cases {
		if readable[tc.relation] != tc.readable {
			t.Errorf("%s: got readable=%v, want %v — %s",
				tc.relation, readable[tc.relation], tc.readable, tc.why)
		}
	}
}

// TestMatrixCleanupIsVerified pins the fix for a bug the row-count dimension
// caught: an RLS-denied DELETE returns 204 having deleted nothing, so the probe
// believed it had cleaned up while rows accumulated across runs. Cleanup now
// reads the row back.
//
// This state — SELECT and INSERT permitted, DELETE not — is ordinary, not
// exotic, which is why it went unnoticed against three hand-written fixtures.
func TestMatrixCleanupIsVerified(t *testing.T) {
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
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	c := client.New(client.Options{
		ProjectRef: tgt.ProjectRef, BaseURL: tgt.BaseURL,
		RestPrefix: tgt.RestPrefix, AnonKey: key, Retries: 1,
	})

	// Readable, writable, all columns nullable: the probe inserts a real row
	// and must either remove it or say plainly that it could not.
	const rel = "m_rls_selanon_insanon_nul"
	before := probe.Run(ctx, c, []string{rel}, probe.Options{SampleRows: 1})
	start := before.Rows()[rel]

	wr := probe.Run(ctx, c, []string{rel}, probe.Options{Write: true, SampleRows: 1})
	after := probe.Run(ctx, c, []string{rel}, probe.Options{SampleRows: 1})
	end := after.Rows()[rel]

	var cleanupErr string
	for _, r := range wr.Relations {
		cleanupErr = r.CleanupErr
	}

	switch {
	case end == start && cleanupErr == "":
		t.Logf("row removed and verified; count steady at %d", end)
	case end != start && cleanupErr == "":
		t.Errorf("probe added %d row(s) and reported success: cleanup verification is "+
			"not working", end-start)
	default:
		t.Logf("cleanup failed and said so (count %d -> %d): %s", start, end, cleanupErr)
	}
}
