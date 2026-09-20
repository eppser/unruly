package eval_test

// Precision evals against a correctly configured project.
//
//   cd fixtures/hardened && docker compose up -d
//   export UNRULY_HARDENED_KEY=$(cat anon.jwt)
//   UNRULY_LIVE=1 go test ./internal/eval -run Hardened -v

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/eppser/unruly/internal/client"
	"github.com/eppser/unruly/internal/escalate"
	"github.com/eppser/unruly/internal/eval"
	"github.com/eppser/unruly/internal/finding"
	"github.com/eppser/unruly/internal/probe"
	"github.com/eppser/unruly/internal/selfcheck"
	"github.com/eppser/unruly/internal/surface"
	"github.com/eppser/unruly/internal/wordlist"
)

func loadHardened(t *testing.T) (*eval.Target, *client.Client) {
	t.Helper()
	if os.Getenv("UNRULY_LIVE") != "1" {
		t.Skip("set UNRULY_LIVE=1 to run live evals")
	}
	tgt, err := eval.LoadTarget(filepath.Join("..", "..", "evals", "targets", "hardened-fixture.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	key, err := tgt.AnonKey()
	if err != nil {
		t.Skip(err)
	}
	return tgt, client.New(client.Options{
		ProjectRef: tgt.ProjectRef, BaseURL: tgt.BaseURL,
		RestPrefix: tgt.RestPrefix, AnonKey: key, Retries: 1,
	})
}

// TestHardenedNoFalsePositives is the precision check. Four relations hold real
// customer records and API credentials; none may be reported as readable.
func TestHardenedNoFalsePositives(t *testing.T) {
	tgt, c := loadHardened(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	pr := probe.Run(ctx, c, tgt.RelationNames(), probe.Options{Write: true, SampleRows: 3})
	graded := eval.Grade(tgt, eval.Observation{
		Relations:       tgt.RelationNames(),
		ReadExposed:     pr.ReadExposed(),
		InsertReachable: pr.InsertReachable(),
		Rows:            pr.Rows(),
	})
	t.Logf("\n%s", graded)

	if n := len(pr.ReadExposed()); n != 0 {
		t.Errorf("a correctly configured project must leak no rows; got %v", pr.ReadExposed())
	}
	for _, s := range graded.Scores {
		switch s.Dimension {
		case "read-exposure", "write-exposure", "protected-not-flagged", "relation-discovery":
			if !s.Perfect() {
				t.Errorf("%s", s)
			}
		}
	}

	all := pr.Findings(c.RestBase(), false)
	// Info-severity findings describe the SCAN or record what was enumerated;
	// they make no claim about the target and cannot be a false positive on it.
	// The inventory of correctly protected relation names is deliberately one of
	// them. What this fixture exists to prove is that nothing ACTIONABLE is
	// invented, so the count is taken over findings a reader would act on.
	var fs []finding.Finding
	for _, f := range all {
		if f.Severity != finding.Info {
			fs = append(fs, f)
		}
	}
	// Exactly one true positive: the public submission form.
	if len(fs) != 1 {
		t.Errorf("expected exactly 1 actionable finding (the intended public insert), got %d", len(fs))
		for _, f := range all {
			t.Logf("  [%s] %s %s", f.Severity, f.ID, f.Resource)
		}
	}
	if len(fs) == 1 {
		if fs[0].Resource != "contact_requests" {
			t.Errorf("the only finding should be contact_requests, got %s", fs[0].Resource)
		}
		// An insert-only relation the role cannot read is materially less
		// dangerous than one that is also readable, and the severity must say so
		// or the report trains operators to ignore criticals.
		if sev := fs[0].Severity.String(); sev == "critical" {
			t.Errorf("write-only exposure on an unreadable relation should not be critical, got %s", sev)
		}
	}
}

// TestHardenedNoRoutineDisclosure: a SECURITY DEFINER routine exists but
// EXECUTE is revoked, so the hint oracle must stay silent.
func TestHardenedNoRoutineDisclosure(t *testing.T) {
	tgt, c := loadHardened(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	// No cap: capping the candidate list is what made the earlier version of
	// this test pass for the wrong reason.
	sf := surface.Run(ctx, c, surface.Options{
		RoutineSeeds:  wordlist.Routines(),
		MaxCandidates: 4000,
		// This is our own fixture, so invoking is permitted. Against a
		// third party it needs -write: learning whether a routine is
		// callable means calling it, and a callable routine runs.
		AllowInvoke: true,
	})
	score := eval.Compare("routine-discovery", tgt.Routines(), sf.Routines)
	t.Logf("%s", score)
	if !score.Perfect() {
		t.Errorf("routine discovery wrong: %s", score)
	}

	// The routine is disclosed but must NOT be reported as callable: EXECUTE is
	// revoked, and conflating a name leak with an attack surface is what makes
	// a scanner's medium findings worthless.
	for name, callable := range sf.Callable {
		if callable {
			t.Errorf("%s reports as callable, but EXECUTE is revoked from anon", name)
		}
	}
	for _, f := range sf.Findings {
		if f.Severity.String() != "info" {
			t.Errorf("a disclosed-but-uncallable routine should be info, got %s for %s",
				f.Severity, f.Resource)
		}
	}
}

// TestHardenedNoEscalation: policies are scoped to the owning user, so holding
// the authenticated role gains nothing. Reporting a gain here would be the
// false alarm that makes the escalation check untrustworthy.
func TestHardenedNoEscalation(t *testing.T) {
	tgt, c := loadHardened(t)
	elevated := os.Getenv("UNRULY_HARDENED_AUTHED_KEY")
	if elevated == "" {
		t.Skip("set UNRULY_HARDENED_AUTHED_KEY to run the escalation precision check")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	base := probe.Run(ctx, c, tgt.RelationNames(), probe.Options{SampleRows: 2})
	res := escalate.Compare(ctx, c, base, escalate.Options{
		Relations: tgt.RelationNames(), ElevatedKey: elevated, SampleRows: 2,
	})
	if len(res.Gains) != 0 {
		t.Errorf("owner-scoped policies grant an arbitrary authenticated user nothing; got %v",
			res.GainedRelations())
	}
	t.Logf("escalation gains on a correctly configured project: %d", len(res.Gains))
}

// TestHardenedZeroFindingsIsTrustworthy separates the two ways a scan reaches
// zero findings. On this target it must be the good one.
//
// "0 findings" means nothing on its own — it is exactly what every surveyed
// tool prints when its oracle has quietly stopped working. It is only
// meaningful alongside a self-check confirming the scanner could actually see.
// Here the oracles must all report healthy AND the result must be zero.
func TestHardenedZeroFindingsIsTrustworthy(t *testing.T) {
	tgt, c := loadHardened(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	pr := probe.Run(ctx, c, tgt.RelationNames(), probe.Options{SampleRows: 2})
	sc := selfcheck.Run(ctx, c, selfcheck.Evidence{
		HintsObserved:  1, // enumeration on this fixture does draw hints
		RelationsFound: len(tgt.RelationNames()),
	})

	if d := sc.Degraded(); len(d) > 0 {
		t.Fatalf("a zero-finding result is only trustworthy when the scanner could see; "+
			"degraded: %v", d)
	}

	// This assertion used to require auth and storage to be reported as
	// UNASSESSED, because the fixture was bare PostgREST and genuinely had
	// neither. That encoded a deficiency of the fixture as an expectation of
	// the scanner, and it meant this fixture could never demonstrate the thing
	// it exists to demonstrate: a complete clean scan. A gateway now serves
	// the auth, storage and functions endpoints a managed project has, with a
	// correct configuration -- signup closed, no buckets, no functions.
	//
	// So the requirement inverts. Every surface must be ASSESSED, and every
	// one must come back clean. A zero that comes from looking is the claim;
	// a zero that comes from not looking is what this project exists to
	// distinguish it from.
	// Seeds, not an empty Options. This ran with surface.Options{} for a long
	// time, which gave the RPC hint oracle no candidate names to probe -- so it
	// asserted "no routine disclosure" while never asking a single question,
	// and passed. A real scan seeds from harvested vocabulary and DOES disclose
	// this fixture's routine. A test that cannot fail is not evidence.
	sf := surface.Run(ctx, c, surface.Options{
		RoutineSeeds:   []string{"internal", "recalculate", "ledger", "admin", "customers"},
		RoutineGuesses: []string{"internal_recalculate_ledger", "recalculate_ledger"},
	})
	for _, f := range sf.Findings {
		if f.ID == "unruly-surface-not-assessed" {
			t.Errorf("the hardened fixture serves %s, so it must be assessed rather "+
				"than skipped", f.Resource)
			continue
		}
		// One exception, and it is real rather than tolerated noise: PostgREST
		// builds its fuzzy-match hint from the schema cache, which knows nothing
		// about privileges, so an internal routine's NAME leaks to anon even
		// with EXECUTE revoked from PUBLIC. Nothing in the database's
		// configuration can suppress it; the fix is to move the routine to a
		// schema PostgREST does not expose. Reporting it is correct. Reporting
		// it above Low would not be: callability was never established.
		if f.ID == "supabase-rpc-discoverable" && f.Severity == finding.Low {
			t.Logf("expected: the hint leaks %s even with EXECUTE revoked", f.Resource)
			continue
		}
		if f.Severity > finding.Info {
			t.Errorf("unexpected finding on a correctly configured project: [%s] %s %s",
				f.Severity, f.ID, f.Resource)
		}
	}
	if !sf.StorageReachable {
		t.Error("storage is served by the fixture gateway and must be reachable")
	}
	if !sf.Auth.Reachable {
		t.Error("auth is served by the fixture gateway and must be reachable")
	}
	if sf.Auth.SignupOpen() {
		t.Error("the fixture closes signup; reporting it open is a false positive")
	}
	// The whole point of the gateway: a complete scan of a correct project
	// reports no unmeasured surface, which is what makes exit 0 reachable.
	if incomplete, what := finding.CoverageIncomplete(sf.Findings); incomplete {
		t.Errorf("a fully served, correctly configured project must leave nothing "+
			"unmeasured; got %v", what)
	}
	// The claim, stated the same way the README states it: nothing above info.
	// The info entries are not false positives — they record what was NOT
	// assessed, which is the opposite of a false positive and the reason a
	// zero here can be trusted at all.
	for _, f := range pr.Findings(c.RestBase(), false) {
		if f.Severity > finding.Info {
			t.Errorf("a correctly configured project must produce nothing above info; "+
				"got [%s] %s %s", f.Severity, f.ID, f.Resource)
		}
	}
	t.Logf("zero findings, %d capabilities verified healthy", len(sc.Capabilities))
}

// TestBlindScanIsLoud is the counterpart: a target the scanner cannot reach
// must NOT produce a quiet clean report.
func TestBlindScanIsLoud(t *testing.T) {
	if os.Getenv("UNRULY_LIVE") != "1" {
		t.Skip("set UNRULY_LIVE=1")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Nothing listens here.
	dead := client.New(client.Options{
		BaseURL: "http://127.0.0.1:59999", RestPrefix: "/", AnonKey: "dummy", Retries: 0,
	})
	sc := selfcheck.Run(ctx, dead, selfcheck.Evidence{HintsObserved: 0, RelationsFound: 0})

	if len(sc.Degraded()) == 0 {
		t.Fatal("an unreachable target must be reported as degraded, not scanned clean")
	}
	if len(sc.Findings) == 0 {
		t.Fatal("a blind scan must produce a finding saying so")
	}
	t.Logf("blind scan correctly reported %d degraded capabilities", len(sc.Degraded()))
}
