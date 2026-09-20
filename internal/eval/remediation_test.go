package eval_test

// Does the remediation actually remediate?
//
// This is the claim a scanner makes that is easiest to get wrong and hardest to
// notice: -fix emits SQL, the SQL executes cleanly, and nothing changes. That
// happened here. REVOKE EXECUTE ON FUNCTION x FROM anon runs without error and
// is a no-op, because PostgreSQL grants EXECUTE to PUBLIC by default when a
// function is created, so the role still reaches the routine through PUBLIC.
// Every layer reported success and the hole stayed open.
//
// The only way to know is to apply the tool's own output to a database and
// scan it again. That is what this does, so a future edit to any remediation
// string is checked against reality rather than against plausibility.
//
//   make fixtures-reset && UNRULY_LIVE=1 go test ./internal/eval -run Remediation -v

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/eppser/unruly/internal/client"
	"github.com/eppser/unruly/internal/finding"
	"github.com/eppser/unruly/internal/probe"
	"github.com/eppser/unruly/internal/surface"
	"github.com/eppser/unruly/internal/wordlist"
)

// applySQL runs statements against the lab fixture's database.
func applySQL(t *testing.T, sql string) {
	t.Helper()
	cmd := exec.Command("docker", "compose", "exec", "-T", "db",
		"psql", "-U", "postgres", "-d", "fixture", "-v", "ON_ERROR_STOP=1", "-f", "-")
	cmd.Dir = "../../fixtures/lab"
	cmd.Stdin = strings.NewReader(sql)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("remediation SQL failed to execute: %v\n%s\n--- sql ---\n%s", err, out, sql)
	}
}

// executableSQL strips comment and blank lines, leaving statements only.
func executableSQL(remediations []string) string {
	var stmts []string
	seen := map[string]bool{}
	for _, r := range remediations {
		for _, line := range strings.Split(r, "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "--") || strings.HasPrefix(line, "#") {
				continue
			}
			if !seen[line] {
				seen[line] = true
				stmts = append(stmts, line)
			}
		}
	}
	return strings.Join(stmts, "\n")
}

func labClient(t *testing.T) *client.Client {
	t.Helper()
	if os.Getenv("UNRULY_LIVE") != "1" {
		t.Skip("set UNRULY_LIVE=1")
	}
	key := os.Getenv("UNRULY_FIXTURE_KEY")
	if key == "" {
		t.Skip("UNRULY_FIXTURE_KEY required")
	}
	return client.New(client.Options{
		ProjectRef: "lab", BaseURL: "http://127.0.0.1:54321",
		RestPrefix: "/", AnonKey: key, Retries: 1,
	})
}

// TestRemediationClosesTheFindings applies every emitted fix and rescans.
//
// MUTATES the lab fixture. Run `make fixtures-reset` afterwards, which the
// Makefile does before every eval run for exactly this reason.
func TestRemediationClosesTheFindings(t *testing.T) {
	c := labClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	relations := []string{
		"open_no_rls", "open_no_rls_archive", "leaky_credentials",
		"all_defaults_insertable", "read_only_policy", "write_only_policy",
		"protected_rls_no_policy",
	}

	before := probe.Run(ctx, c, relations, probe.Options{Write: true, SampleRows: 2})
	beforeFindings := before.Findings(c.RestBase(), false)
	if len(beforeFindings) == 0 {
		t.Fatal("the vulnerable fixture should report findings before remediation")
	}

	var fixes []string
	for _, f := range beforeFindings {
		if f.Remediation == "" {
			t.Errorf("%s/%s carries no remediation", f.ID, f.Resource)
			continue
		}
		fixes = append(fixes, f.Remediation)
	}
	sql := executableSQL(fixes)
	t.Logf("before: %d findings; applying %d statements",
		len(beforeFindings), len(strings.Split(sql, "\n")))

	applySQL(t, sql)

	after := probe.Run(ctx, c, relations, probe.Options{Write: true, SampleRows: 2})
	afterFindings := after.Findings(c.RestBase(), false)
	t.Logf("after: %d findings", len(afterFindings))

	// Remediation closes exposure. It cannot make relation NAMES stop existing,
	// and it is not supposed to: the inventory finding records relations that
	// answer correctly, which after a successful fix is all of them. Anything
	// above info still standing means the fix did not work.
	for _, f := range afterFindings {
		if f.Severity == finding.Info {
			continue
		}
		t.Errorf("still reported after applying its own fix: [%s] %s %s — %s",
			f.Severity, f.ID, f.Resource, f.Evidence.Reason)
	}
	if n := len(after.ReadExposed()); n != 0 {
		t.Errorf("%d relations still leak rows after remediation: %v", n, after.ReadExposed())
	}
	if n := len(after.InsertReachable()); n != 0 {
		t.Errorf("%d relations still accept anonymous writes: %v", n, after.InsertReachable())
	}
}

// TestRoutineRemediationRevokesFromPublic is the regression for the no-op.
//
// The emitted SQL must revoke from PUBLIC, not only from anon. Asserting on the
// text alone would be weak, so this applies it and confirms the routine can no
// longer be called.
func TestRoutineRemediationRevokesFromPublic(t *testing.T) {
	c := labClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	// public_stats_summary() takes no arguments, so callability is measurable.
	sf := surface.Run(ctx, c, surface.Options{
		RoutineSeeds:  wordlist.Merge([]string{"public_stats_summary"}, nil),
		MaxCandidates: 40,
		AllowInvoke:   true,
	})
	if callable, known := sf.Callable["public_stats_summary"]; !known || !callable {
		t.Skipf("fixture routine is not callable to begin with (known=%v callable=%v); "+
			"run make fixtures-reset", known, callable)
	}

	var fix string
	for _, f := range sf.Findings {
		if f.Resource == "public_stats_summary" {
			fix = f.Remediation
		}
	}
	if !strings.Contains(fix, "FROM PUBLIC") {
		t.Fatalf("remediation must revoke from PUBLIC; PostgreSQL grants EXECUTE to it by "+
			"default, so revoking from anon alone is a no-op:\n%s", fix)
	}
	applySQL(t, executableSQL([]string{fix}))

	after := surface.Run(ctx, c, surface.Options{
		RoutineSeeds:  wordlist.Merge([]string{"public_stats_summary"}, nil),
		MaxCandidates: 40,
		AllowInvoke:   true,
	})
	if callable, known := after.Callable["public_stats_summary"]; known && callable {
		t.Error("the routine is still callable after applying its own remediation")
	} else {
		t.Logf("routine no longer callable after remediation (known=%v)", known)
	}
}

// TestRemediationClosesFindingsInASecondSchema executes the SQL rather than
// reading it.
//
// The schema-qualification fix was verified by asserting that the emitted text
// CONTAINS "reporting.daily_revenue". That is a string check: it would pass for
// SQL that is qualified and still wrong, and it proves nothing about whether
// Postgres accepts it. This applies the tool's own output to the fixture and
// re-probes.
//
// Two layers, and they fail in a deliberate order. Stripping the schema from
// Qualified() trips the text guard below first, which is the clearer message.
// Had it not, application would still have failed: there is no
// public.daily_revenue, so `ALTER TABLE daily_revenue ...` errors under
// ON_ERROR_STOP=1. Verified by running that mutation.
func TestRemediationClosesFindingsInASecondSchema(t *testing.T) {
	c := labClient(t).WithSchema("reporting")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	relations := []string{"daily_revenue", "member_invoices", "revenue_secrets"}

	before := probe.Run(ctx, c, relations, probe.Options{
		Write: true, SampleRows: 2, Schema: "reporting",
	})
	beforeFindings := before.Findings(c.RestBase(), false)
	if len(beforeFindings) == 0 {
		t.Fatal("reporting.daily_revenue is readable by anon, so there must be a finding " +
			"to remediate; with none this test would pass without doing anything")
	}

	var qualified bool
	var fixes []string
	for _, f := range beforeFindings {
		if f.Remediation == "" {
			t.Errorf("%s/%s carries no remediation", f.ID, f.Resource)
			continue
		}
		if strings.Contains(f.Remediation, "reporting.") {
			qualified = true
		}
		fixes = append(fixes, f.Remediation)
	}
	if !qualified {
		t.Fatal("no emitted statement names the schema; applying it would hit whatever " +
			"search_path resolves to")
	}

	sql := executableSQL(fixes)
	t.Logf("before: %d findings in reporting; applying %d statements",
		len(beforeFindings), len(strings.Split(sql, "\n")))
	applySQL(t, sql) // ON_ERROR_STOP=1: unqualified SQL fails here, loudly

	after := probe.Run(ctx, c, relations, probe.Options{
		Write: true, SampleRows: 2, Schema: "reporting",
	})
	// Same rule as the default-schema case: remediation closes exposure, it
	// does not delete relations, so the info-severity inventory of correctly
	// protected names survives a successful fix by design.
	for _, f := range after.Findings(c.RestBase(), false) {
		if f.Severity == finding.Info {
			continue
		}
		t.Errorf("still reported after applying its own fix: [%s] %s %s — %s",
			f.Severity, f.ID, f.Resource, f.Evidence.Reason)
	}
	if n := len(after.ReadExposed()); n != 0 {
		t.Errorf("%d relation(s) in reporting still leak rows: %v", n, after.ReadExposed())
	}
}

// TestRemediationEveryEmittedStatementExecutes runs the SQL the tool actually
// emits, for every finding it can produce against the fixtures.
//
// eval-templates executes the commented WORKED EXAMPLES, and only three
// findings carry one. TestRemediationClosesTheFindings executes the real SQL,
// but only for the relations the probe stage covers. Between them, the
// remediation for routines in a non-default schema had never been run -- and
// it was wrong:
//
//	REVOKE EXECUTE ON FUNCTION public.rebuild_daily_revenue FROM ...
//	ERROR: could not find a function named "public.rebuild_daily_revenue"
//
// The routine lives in reporting. One of the two routine constructors had been
// schema-qualified and the other had not, and the one missed was the CRITICAL
// finding.
//
// Statements are split on the semicolon, not the newline. The first version of
// this sweep split on newlines and reported CREATE POLICY as broken, because a
// policy spans several lines -- a false positive of the harness that would
// have sent me looking for a defect that was not there.
func TestRemediationEveryEmittedStatementExecutes(t *testing.T) {
	c := labClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	var all []finding.Finding
	pr := probe.Run(ctx, c, []string{
		"open_no_rls", "leaky_credentials", "write_only_policy", "tokens",
	}, probe.Options{Write: true, SampleRows: 2})
	all = append(all, pr.Findings(c.RestBase(), false)...)

	sf := surface.Run(ctx, c, surface.Options{
		RoutineSeeds: []string{"admin", "purge", "submissions", "stats"},
		AllowInvoke:  true, Concurrency: 4,
	})
	all = append(all, sf.Findings...)

	// The non-default schema, which is where the defect was.
	rc := c.WithSchema("reporting")
	rp := probe.Run(ctx, rc, []string{"daily_revenue", "revenue_secrets"},
		probe.Options{Write: true, SampleRows: 2, Schema: "reporting"})
	all = append(all, rp.Findings(c.RestBase(), false)...)
	all = append(all, surface.Routines(ctx, rc, surface.Options{
		RoutineGuesses: []string{"rebuild_daily_revenue"},
		AllowInvoke:    true, Concurrency: 4, Schema: "reporting",
	}).Findings...)

	if len(all) == 0 {
		t.Fatal("no findings collected; this test would assert nothing")
	}

	var executed int
	for _, f := range all {
		for _, stmt := range sqlStatements(f.Remediation) {
			executed++
			t.Run(f.ID+"/"+f.Resource, func(t *testing.T) {
				// ROLLBACK so the fixture is untouched: this asks whether the
				// statement RUNS, not whether it should be applied.
				applySQL(t, "BEGIN;\n"+stmt+";\nROLLBACK;\n")
			})
		}
	}
	if executed == 0 {
		t.Fatal("no executable statement was extracted from any remediation; the " +
			"extractor stopped matching and this test is measuring nothing")
	}
	t.Logf("%d emitted statements executed across %d findings", executed, len(all))
}

// sqlStatements pulls runnable statements out of a remediation block: comment
// lines dropped, the rest joined and split on the semicolon so a multi-line
// statement survives intact.
func sqlStatements(remediation string) []string {
	var body []string
	for _, ln := range strings.Split(remediation, "\n") {
		t := strings.TrimSpace(ln)
		if t == "" || strings.HasPrefix(t, "--") || strings.HasPrefix(t, "#") {
			continue
		}
		body = append(body, t)
	}
	var out []string
	for _, stmt := range strings.Split(strings.Join(body, "\n"), ";") {
		s := strings.TrimSpace(stmt)
		if s == "" {
			continue
		}
		// Only things Postgres will accept. Prose and shell commands live in
		// the same block for surfaces whose fix is not SQL at all.
		switch strings.ToUpper(strings.Fields(s)[0]) {
		case "ALTER", "CREATE", "DROP", "REVOKE", "GRANT", "SELECT", "UPDATE",
			"DELETE", "INSERT", "NOTIFY", "COMMENT":
			out = append(out, s)
		}
	}
	return out
}
