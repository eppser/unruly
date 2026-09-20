package supabase

import (
	"context"
	"testing"

	"github.com/eppser/unruly/internal/client"
	"github.com/eppser/unruly/internal/enumerate"
	"github.com/eppser/unruly/internal/finding"
	"github.com/eppser/unruly/internal/parity"
	"github.com/eppser/unruly/internal/probe"
	"github.com/eppser/unruly/internal/realtime"
	"github.com/eppser/unruly/scan"
)

// The stage must report exactly what the code it replaced reported.
//
// oldPath transcribes the "// ---- realtime ----" section of scanTarget: the
// same options, the same per-schema pass with the same schema-qualified
// resources, and the same coverage finding on an unreachable endpoint.
//
// The endpoint is deliberately unreachable. That is not a weaker test: a
// Realtime endpoint that cannot be reached is the case where the scan MUST say
// it could not see, and reporting nothing there is the false negative this
// project exists to eliminate.
func TestTheRealtimeStageAgreesWithTheCodeItReplaced(t *testing.T) {
	c := client.New(client.Options{BaseURL: "http://127.0.0.1:1", AnonKey: "k", RestPrefix: "/"})
	pr := probe.Result{}
	schemas := []SchemaScan{{Name: "reporting", Relations: []string{"daily_revenue"}}}
	rels := []string{"notes"}

	// --- the original expression, transcribed ---------------------------
	var old []finding.Finding
	readExposed := map[string]bool{}
	for _, n := range pr.ReadExposed() {
		readExposed[n] = true
	}
	rtOpts := realtime.Options{
		BaseURL: c.BaseURL(), AnonKey: "k",
		ReadExposed: readExposed,
	}
	rt := realtime.Run(context.Background(), rtOpts)
	oldRequests := rt.Requests
	old = append(old, rt.Findings...)
	for _, ss := range schemas {
		srtOpts := rtOpts
		srtOpts.Schema = ss.Name
		srtOpts.Relations = ss.Relations
		srtReadable := map[string]bool{}
		for _, n := range ss.Result.ReadExposed() {
			srtReadable[n] = true
		}
		srtOpts.ReadExposed = srtReadable
		srt := realtime.Run(context.Background(), srtOpts)
		oldRequests += srt.Requests
		for _, f := range srt.Findings {
			f.Resource = ss.Name + "." + f.Resource
			old = append(old, f)
		}
	}
	if !rt.Reachable {
		if f, ok := rt.CoverageFinding(c.BaseURL()); ok {
			old = append(old, f)
		}
	}

	// --- the same work through the pipeline ------------------------------
	st := &scan.State{Target: c.BaseURL()}
	scan.Put(st, pr)
	scan.Put(st, Schemas{Scans: schemas})
	erels := make([]enumerate.Relation, 0, len(rels))
	for _, n := range rels {
		erels = append(erels, enumerate.Relation{Name: n})
	}
	scan.Put(st, EnumerateOutcome{Result: enumerate.Result{Relations: erels}})
	stage := RealtimeStage{Client: c, AnonKey: "k"}
	if _, err := (scan.Pipeline{stage}).Run(context.Background(), st); err != nil {
		t.Fatal(err)
	}

	if len(old) == 0 {
		t.Fatal("the transcribed original produced nothing, so this test would pass " +
			"vacuously; an unreachable endpoint must yield a coverage finding")
	}
	if d := parity.Diff(old, st.Findings()); d != "" {
		t.Errorf("the ported stage disagrees with the code it replaced:\n%s", d)
	}
	if got := st.Attributed(); got != oldRequests {
		t.Errorf("attributed %d requests, the original counted %d", got, oldRequests)
	}
}

// Findings from a non-default schema stay qualified by that schema.
//
// Without the prefix a fix says CREATE POLICY ... ON daily_revenue for a table
// in another schema, which resolves against search_path and either errors or
// targets a different table entirely.
func TestSchemaFindingsKeepTheirSchemaPrefix(t *testing.T) {
	c := client.New(client.Options{BaseURL: "http://127.0.0.1:1", AnonKey: "k", RestPrefix: "/"})
	st := &scan.State{Target: c.BaseURL()}
	scan.Put(st, probe.Result{})
	scan.Put(st, EnumerateOutcome{})
	scan.Put(st, Schemas{Scans: []SchemaScan{
		{Name: "reporting", Relations: []string{"daily_revenue"}}}})
	stage := RealtimeStage{Client: c, AnonKey: "k"}
	if _, err := (scan.Pipeline{stage}).Run(context.Background(), st); err != nil {
		t.Fatal(err)
	}
	for _, f := range st.Findings() {
		if f.Resource == "daily_revenue" {
			t.Error("a finding from the reporting schema is unqualified, so its fix would " +
				"target whatever search_path resolves daily_revenue to")
		}
	}
}

// -no-residue withdraws the delivery probe rather than silently downgrading it.
//
// Measured on the lab: a -no-residue scan once left one extra row behind
// because the probe stage had been fixed and this had inherited nothing. A
// Realtime change cannot be made residue-free the way an INSERT probe can, so
// the check is declined, and declining must mean no Trigger is installed.
func TestNoResidueDeclinesTheDeliveryProbe(t *testing.T) {
	c := client.New(client.Options{BaseURL: "http://127.0.0.1:1", AnonKey: "k", RestPrefix: "/"})
	stage := RealtimeStage{Client: c, AnonKey: "k",
		Write: true, NoResidue: true}
	if stage.wouldTrigger() {
		t.Error("-no-residue left the delivery trigger installed, so the scan would " +
			"cause a row-creating change the operator declined")
	}
	armed := RealtimeStage{Client: c, AnonKey: "k", Write: true}
	if !armed.wouldTrigger() {
		t.Error("-write without -no-residue did not arm the delivery probe, so delivery " +
			"is never tested and acknowledgements are all that is left")
	}
}
