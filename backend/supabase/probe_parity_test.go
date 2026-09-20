package supabase

import (
	"context"
	"strings"
	"testing"

	"github.com/eppser/unruly/internal/client"
	"github.com/eppser/unruly/internal/enumerate"
	"github.com/eppser/unruly/internal/finding"
	"github.com/eppser/unruly/internal/parity"
	"github.com/eppser/unruly/internal/probe"
	"github.com/eppser/unruly/scan"
)

// The stage must report exactly what the code it replaced reported.
//
// This is the regression test the port hangs on. The body of oldPath below is
// a faithful transcription of the "// ---- probing ----" section of
// scanTarget() as it stood before the move: same call, same arguments, same
// column-budget follow-up, same order of operations. If ProbeStage ever stops
// agreeing with it, the port changed behaviour -- and a port that changes
// behaviour silently is the thing this harness exists to prevent.
//
// Order is deliberately NOT compared: the old path appended into one growing
// slice and the pipeline appends per stage. parity.Diff canonicalises first,
// so a reordering is not a failure but a lost finding, a drifted severity or a
// dropped sample is.
func TestTheProbeStageAgreesWithTheCodeItReplaced(t *testing.T) {
	names := []string{"public_notes", "profiles"}
	opts := probe.Options{SampleRows: 1, Concurrency: 2}

	// --- the original expression, transcribed ---------------------------
	srvOld := leaky(t, names...)
	cOld := client.New(client.Options{BaseURL: srvOld.URL, AnonKey: "k", RestPrefix: "/"})
	var old []finding.Finding
	pr := probe.Run(context.Background(), cOld, names, opts)
	old = append(old, pr.Findings(cOld.RestBase(), false)...)
	if pr.ColumnBudgetBound {
		old = append(old, probe.ColumnBudgetFinding(cOld.RestBase(), pr.ColumnProbesUsed,
			opts.MaxColumnProbes, pr.ColumnsUnprobedCount))
	}

	// --- the same work through the pipeline ------------------------------
	srvNew := leaky(t, names...)
	cNew := client.New(client.Options{BaseURL: srvNew.URL, AnonKey: "k", RestPrefix: "/"})
	st := &scan.State{Target: srvNew.URL}
	// The relation names the transcribed original probed, published as the
	// enumerate stage now would.
	rels := make([]enumerate.Relation, 0, len(names))
	for _, n := range names {
		rels = append(rels, enumerate.Relation{Name: n})
	}
	scan.Put(st, EnumerateOutcome{Result: enumerate.Result{Relations: rels}})
	if _, err := (scan.Pipeline{ProbeStage{Client: cNew, Opts: opts}}).
		Run(context.Background(), st); err != nil {
		t.Fatal(err)
	}

	// The two servers are distinct instances, so their URLs differ and every
	// Matched field with them. Comparing findings that embed a random port
	// would fail on the port and nothing else, so normalise the origin -- the
	// question this test asks is whether the same exposures were found and
	// described identically, not which ephemeral port served them.
	normalise(old, srvOld.URL, "http://target")
	got := st.Findings()
	normalise(got, srvNew.URL, "http://target")

	if len(old) == 0 {
		t.Fatal("the transcribed original found nothing, so this test would pass vacuously")
	}
	if d := parity.Diff(old, got); d != "" {
		t.Errorf("the ported stage disagrees with the code it replaced:\n%s", d)
	}
}

// normalise rewrites an origin inside the fields that embed it, so two runs
// against different ephemeral ports are comparable.
func normalise(fs []finding.Finding, from, to string) {
	for i := range fs {
		fs[i].Matched = replace(fs[i].Matched, from, to)
		fs[i].Description = replace(fs[i].Description, from, to)
		fs[i].Remediation = replace(fs[i].Remediation, from, to)
		fs[i].Evidence.Reason = replace(fs[i].Evidence.Reason, from, to)
		fs[i].Evidence.Request = replace(fs[i].Evidence.Request, from, to)
	}
}

func replace(s, from, to string) string { return strings.ReplaceAll(s, from, to) }
