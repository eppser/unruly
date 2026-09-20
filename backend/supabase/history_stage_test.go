package supabase

import (
	"context"
	"testing"

	"github.com/eppser/unruly/internal/finding"
	"github.com/eppser/unruly/internal/history"
	"github.com/eppser/unruly/internal/parity"
	"github.com/eppser/unruly/scan"
)

// The stage must report exactly what the code it replaced reported.
//
// oldPath below is a faithful transcription of the
// "// ---- historical exposure ----" section of scanTarget: same options, same
// accounting, same order. history.Run is offline here because ArchiveBase
// points at nothing reachable, which is the honest shape of this test -- the
// question is whether the STAGE wraps the call identically, not whether the
// archive is up.
func TestTheHistoryStageAgreesWithTheCodeItReplaced(t *testing.T) {
	opts := history.Options{
		Site: "https://app.example.invalid", CurrentKey: "k", Redact: false,
		ArchiveBase: "http://127.0.0.1:1",
	}

	// --- the original expression, transcribed ---------------------------
	var old []finding.Finding
	h := history.Run(context.Background(), opts)
	old = append(old, h.Findings...)
	oldRequests := h.Requests

	// --- the same work through the pipeline ------------------------------
	st := &scan.State{Target: opts.Site}
	if _, err := (scan.Pipeline{HistoryStage{Opts: opts}}).
		Run(context.Background(), st); err != nil {
		t.Fatal(err)
	}

	if d := parity.Diff(old, st.Findings()); d != "" {
		t.Errorf("the ported stage disagrees with the code it replaced:\n%s", d)
	}
	if got := st.Attributed(); got != oldRequests {
		t.Errorf("attributed %d requests, the original counted %d", got, oldRequests)
	}
}

// The stage name is part of the output contract: it appears in the spend
// breakdown and in the not-assessed finding the pipeline emits if it fails.
func TestTheHistoryStageHasAStableName(t *testing.T) {
	if got := (HistoryStage{}).Name(); got != "history" {
		t.Errorf("stage name %q, want \"history\"", got)
	}
}

// A scan with no site to look up contributes nothing rather than guessing one.
//
// The original guarded on o.site != "" && o.checkHistory before doing any
// work. The guard has to survive the move, or a scan pointed at a bare
// project ref starts querying a public archive for the empty string.
func TestNoSiteMeansNoArchiveLookup(t *testing.T) {
	st := &scan.State{}
	if _, err := (scan.Pipeline{HistoryStage{Opts: history.Options{Site: ""}}}).
		Run(context.Background(), st); err != nil {
		t.Fatal(err)
	}
	if n := st.Attributed(); n != 0 {
		t.Errorf("issued %d requests with no site to check", n)
	}
	if len(st.Findings()) != 0 {
		t.Errorf("produced findings with no site to check: %+v", st.Findings())
	}
}

// The stage publishes its result so the command can report what it indexed.
//
// The counts the operator sees -- captures indexed, captures fetched,
// credentials recovered -- are an interface concern and stay with the command,
// so the stage hands them back rather than logging them itself. Same optional
// Out seam the probing stage uses: a caller that does not need the result
// leaves it nil and the stage must not panic.
func TestTheHistoryStagePublishesItsResult(t *testing.T) {
	st := &scan.State{}
	stage := HistoryStage{
		Opts: history.Options{Site: "https://app.example.invalid",
			ArchiveBase: "http://127.0.0.1:1"},
	}
	if _, err := (scan.Pipeline{stage}).Run(context.Background(), st); err != nil {
		t.Fatal(err)
	}
	out, ok := scan.Get[history.Result](st)
	if !ok {
		t.Fatal("the history stage published no result")
	}
	// Nothing is reachable, so the counts are zero; what matters is that the
	// destination was written to at all rather than left untouched.
	if out.Requests != st.Attributed() {
		t.Errorf("published Requests=%d but attributed %d", out.Requests, st.Attributed())
	}
}
