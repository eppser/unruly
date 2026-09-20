package neon

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/eppser/unruly/internal/client"
	"github.com/eppser/unruly/internal/exploit"
	"github.com/eppser/unruly/internal/neonauth"
	"github.com/eppser/unruly/internal/neonfixture"
	"github.com/eppser/unruly/scan"
)

// An independent implementation reaches the same rows the scan reports.
//
// backend/neon's offline evals grade RECALL: replaying a recording, does the
// stage name the right tables. They cannot answer the harder question --
// can anybody actually DO the thing the finding claims -- because the recording
// was made by the same kind of code that interprets it.
//
// So two implementations run against the live lab here. internal/exploit
// imports nothing from the scanner and rewrites the Neon Auth sequence from
// scratch; the stage uses internal/neonauth and the shared client. If both
// arrive at the same rows through separately written code, the measurement is
// corroborated rather than repeated.
//
//	set -a && . .secrets/neon.env && set +a
//	UNRULY_LIVE=1 go test ./backend/neon -run CrossCheck -v
func TestCrossCheckAgainstTheLiveLab(t *testing.T) {
	if os.Getenv("UNRULY_LIVE") != "1" {
		t.Skip("set UNRULY_LIVE=1")
	}
	api, auth := os.Getenv("NEON_DATA_API"), os.Getenv("NEON_AUTH_URL")
	if api == "" || auth == "" {
		t.Fatal("NEON_DATA_API and NEON_AUTH_URL must be set; source .secrets/neon.env")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	// Verify the lab is in its known state before grading against it.
	//
	// This eval measures recall and precision against fixtures/neon's answer
	// key. If the lab has drifted -- a probe left a row, a seed row was
	// deleted, a policy changed -- it stops measuring the scanner and starts
	// measuring the laboratory, then reports the difference as a regression.
	// Skipping renders as "not run" in the audit, which is visible; a pass or
	// a failure on drifted ground truth is neither.
	if conn := os.Getenv("NEON_DATABASE_URL"); conn != "" {
		if err := neonfixture.Drift(ctx, conn, "../../fixtures/neon/answer-key.yaml"); err != nil {
			t.Skipf("the Neon lab has drifted from its answer key, so this check "+
				"could not measure what it claims to: %v", err)
		}
	} else {
		t.Log("NEON_DATABASE_URL unset: grading against a lab whose seed counts " +
			"were NOT verified this run")
	}

	const origin = "http://localhost:3000"

	// --- the independent harness -------------------------------------------
	got := exploit.NeonEscalation(ctx, exploit.NeonExploit{
		ID: "rls-disabled-authenticated-read", Table: "rls_disabled",
		Class: "authenticated read of every row", Rows: 3,
		DataAPI: api, AuthURL: auth, Origin: origin,
		Email: "unruly-exploit@example.com", Password: "Correct-Horse-9271",
	})
	if got.Unmeasured {
		t.Fatalf("the harness could not establish the read either way: %s", got.Detail)
	}
	if !got.Succeeded {
		t.Fatalf("the harness read nothing: HTTP %d, %s", got.Status, got.Detail)
	}
	if got.RowsGot != got.RowsWanted {
		t.Errorf("the harness read %d row(s), the answer key expects %d: the lab and "+
			"the key disagree and one of them is wrong", got.RowsGot, got.RowsWanted)
	}
	if got.Sample == "" {
		t.Error("no sampled row: an exploit that retrieves nothing has demonstrated nothing")
	}

	// --- the scanner --------------------------------------------------------
	tok, err := neonauth.New(auth, origin).
		Token(ctx, "unruly-crosscheck@example.com", "Correct-Horse-9271")
	if err != nil {
		t.Fatalf("scanner-side token: %v", err)
	}
	var st scan.State
	stage := EscalationStage{
		Base: api, Tables: allTables, Token: tok,
		Client: client.New(client.Options{
			BaseURL: api, RestPrefix: "/", Timeout: 30 * time.Second,
			UserAgent: "unruly-crosscheck", Limiter: client.NewLimiter(0),
		}),
	}
	if err := stage.Run(ctx, &st); err != nil {
		t.Fatalf("stage: %v", err)
	}

	reported := map[string]bool{}
	for _, f := range st.Findings() {
		reported[f.Resource] = true
	}
	if !reported["rls_disabled"] {
		t.Errorf("an independent implementation read %d row(s) from rls_disabled and "+
			"the scan does not report it. Either the scanner has a recall gap or the "+
			"harness is exploiting something the scanner is right to ignore -- and "+
			"which it is has to be established, not assumed", got.RowsGot)
	}
	// Precision holds on the live lab too, not only against the recording.
	for _, tbl := range wantSilent {
		if reported[tbl] {
			t.Errorf("the scan reports %s against the live lab, and the answer key "+
				"records it as protected", tbl)
		}
	}
	t.Logf("harness: %d rows (%s); scan reports rls_disabled: %v",
		got.RowsGot, got.Sample, reported["rls_disabled"])
}
