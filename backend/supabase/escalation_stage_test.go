package supabase

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/eppser/unruly/internal/client"
	"github.com/eppser/unruly/internal/enumerate"
	"github.com/eppser/unruly/internal/escalate"
	"github.com/eppser/unruly/internal/finding"
	"github.com/eppser/unruly/internal/parity"
	"github.com/eppser/unruly/internal/probe"
	"github.com/eppser/unruly/scan"
)

// escalationFixture answers like a PostgREST that lets the elevated role read
// a relation anonymous cannot, so the comparison has something real to find.
func escalationFixture(t *testing.T) *client.Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "Bearer elevated" {
			w.Header().Set("Content-Range", "0-0/1")
			w.WriteHeader(http.StatusPartialContent)
			_, _ = w.Write([]byte(`[{"id":1}]`))
			return
		}
		w.Header().Set("Content-Range", "*/0")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`[]`))
	}))
	t.Cleanup(srv.Close)
	return client.New(client.Options{BaseURL: srv.URL, RestPrefix: "/", AnonKey: "anon", Concurrency: 2})
}

// The stage must report exactly what the code it replaced reported.
//
// The block below is a faithful transcription of the
// "// ---- privilege escalation ----" section of scanTarget: the same
// Compare for the default schema, the same Compare per exposed schema, in
// the same order.
func TestTheEscalationStageAgreesWithTheCodeItReplaced(t *testing.T) {
	ctx := context.Background()
	relations := []string{"orders", "invoices"}
	schemas := []SchemaScan{{Name: "reporting", Relations: []string{"ledger"}}}

	opts := func(schema string, rels []string) escalate.Options {
		return escalate.Options{
			Relations: rels, ElevatedKey: "elevated",
			Concurrency: 2, SampleRows: 1, Redact: false, Measure: false,
			Schema: schema,
		}
	}

	// One fixture for both runs. Two servers differ only by port, and the
	// finding carries the URL, so the diff would be noise about ports rather
	// than a disagreement about behaviour.
	oc := escalationFixture(t)
	var old []finding.Finding
	oldEsc := escalate.Compare(ctx, oc, probe.Result{}, escalate.Options{
		Relations: relations, ElevatedKey: "elevated",
		Concurrency: 2, SampleRows: 1, Redact: false, Measure: false,
	})
	oldRequests := oldEsc.Requests
	old = append(old, oldEsc.Findings...)
	for _, ss := range schemas {
		s := escalate.Compare(ctx, oc.WithSchema(ss.Name), ss.Result, opts(ss.Name, ss.Relations))
		oldRequests += s.Requests
		old = append(old, s.Findings...)
	}

	// --- the same work through the pipeline ------------------------------
	st := &scan.State{Target: "t"}
	// The probe result now travels as a published artifact, so the test
	// publishes what the probing stage would have.
	scan.Put(st, probe.Result{})
	scan.Put(st, Schemas{Scans: schemas})
	rels := make([]enumerate.Relation, 0, len(relations))
	for _, n := range relations {
		rels = append(rels, enumerate.Relation{Name: n})
	}
	scan.Put(st, EnumerateOutcome{Result: enumerate.Result{Relations: rels}})
	stage := EscalationStage{
		Client: oc, ElevatedKey: "elevated",
		Concurrency: 2, SampleRows: 1,
	}
	if _, err := (scan.Pipeline{stage}).Run(ctx, st); err != nil {
		t.Fatal(err)
	}

	if d := parity.Diff(old, st.Findings()); d != "" {
		t.Errorf("the ported stage disagrees with the code it replaced:\n%s", d)
	}
	if got := st.Attributed(); got != oldRequests {
		t.Errorf("attributed %d requests, the original counted %d", got, oldRequests)
	}
}

// This is the point of the port: inline, escalation was the only work in the
// scan that spent requests with NO ledger attribution, so it could be the
// largest spender and never appear in the largest-first breakdown.
func TestTheEscalationStageAttributesItsSpend(t *testing.T) {
	st := &scan.State{Target: "t"}
	// The anonymous probing stage's result is a declared requirement now, so
	// the test publishes what that stage would have.
	scan.Put(st, probe.Result{})
	scan.Put(st, EnumerateOutcome{Result: enumerate.Result{
		Relations: []enumerate.Relation{{Name: "orders"}}}})
	stage := EscalationStage{
		Client:      escalationFixture(t),
		ElevatedKey: "elevated", Concurrency: 2, SampleRows: 1,
	}
	if _, err := (scan.Pipeline{stage}).Run(context.Background(), st); err != nil {
		t.Fatal(err)
	}
	sp := st.Spending()
	if len(sp) != 1 || sp[0].Stage != "escalation" {
		t.Fatalf("escalation must appear in the spend breakdown, got %v", sp)
	}
	if sp[0].Requests == 0 {
		t.Error("attributed zero requests for a pass that probed a relation")
	}
}

// Without a credential there is nothing to compare. Attributing a zero would
// read as "ran and spent nothing", which is a different claim from "never
// signed in".
func TestTheEscalationStageDoesNothingWithoutACredential(t *testing.T) {
	st := &scan.State{Target: "t"}
	stage := EscalationStage{Client: escalationFixture(t)}
	if _, err := (scan.Pipeline{stage}).Run(context.Background(), st); err != nil {
		t.Fatal(err)
	}
	if n := len(st.Findings()); n != 0 {
		t.Errorf("reported %d findings with no elevated credential", n)
	}
	if got := st.Attributed(); got != 0 {
		t.Errorf("spent %d requests with no elevated credential", got)
	}
}

func TestTheEscalationStageHasAStableName(t *testing.T) {
	if got := (EscalationStage{}).Name(); got != "escalation" {
		t.Errorf("stage name %q, want \"escalation\"", got)
	}
}
