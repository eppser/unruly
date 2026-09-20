// An inconclusive write verdict must reach the report and the exit code.
//
// probe.Result.Findings emitted a finding for WriteReached and nothing else, so
// a relation whose write probe declined disappeared entirely: no finding, no
// coverage caveat, no effect on the exit code. The scan reported the relations
// it could test and stayed silent about the one it could not, which reads as
// "tested, safe".
//
// It is reachable on the reference target with the documented safe mode:
//
//	unruly -u https://example-app.test -write -yes-i-own-this -no-residue
//
// cve_articles is INSERT-reachable but not read-exposed, so -no-residue has no
// sampled row to collide with and declines. Four relations get reported, the
// fifth does not, and the scan exits as though the write surface were fully
// assessed.
package eval_test

import (
	"strings"
	"testing"

	"github.com/eppser/unruly/internal/finding"
	"github.com/eppser/unruly/internal/postgrest"
	"github.com/eppser/unruly/internal/probe"
)

func TestInconclusiveWriteIsReportedAndCountsAsBlind(t *testing.T) {
	// Exactly the cve_articles shape: the write probe ran and could not answer.
	res := probe.Result{Relations: []probe.Relation{
		{
			Name:     "cve_articles",
			Read:     postgrest.ReadEmpty,
			Write:    postgrest.WriteInconclusive,
			WriteWhy: "no sampled row to collide with",
		},
	}}

	fs := res.Findings("https://ref.supabase.co/rest/v1", false)
	if len(fs) == 0 {
		t.Fatal("an inconclusive write produced no finding at all: the relation is " +
			"absent from the report, which reads as tested-and-safe")
	}

	var got *finding.Finding
	for i := range fs {
		if strings.HasPrefix(fs[i].Resource, "write:") {
			got = &fs[i]
		}
	}
	if got == nil {
		t.Fatalf("no finding describes the unassessed write; got resources %v",
			resources(fs))
	}
	if !strings.Contains(got.Resource, "cve_articles") {
		t.Errorf("finding does not name the relation: resource %q", got.Resource)
	}
	// The reason must survive into the report. "Could not assess" without
	// saying why sends the reader to the source to find out.
	if !strings.Contains(got.Evidence.Reason, "collide") {
		t.Errorf("the reason the probe declined was dropped: evidence %q",
			got.Evidence.Reason)
	}

	// And it must drive the exit code, not merely appear in the output. This is
	// the half that makes CI see it.
	incomplete, what := finding.CoverageIncomplete(fs)
	if !incomplete {
		t.Fatal("an unassessed write does not count as incomplete coverage, so the " +
			"scan exits 0 while a relation went untested")
	}
	if !strings.Contains(strings.Join(what, ","), "cve_articles") {
		t.Errorf("the exit-3 message does not name the relation: %v", what)
	}
}

// A write verdict that WAS reached must not be dragged into the blind set by
// the change above -- otherwise every successful write probe would also push
// the scan to exit 3 and the code would stop meaning anything.
func TestReachedWriteIsNotBlind(t *testing.T) {
	res := probe.Result{Relations: []probe.Relation{
		{Name: "agent_runs", Read: postgrest.ReadExposed, Rows: 465,
			Write: postgrest.WriteReached, WriteWhy: "passed RLS, rejected by not-null"},
	}}
	fs := res.Findings("https://ref.supabase.co/rest/v1", false)
	if incomplete, what := finding.CoverageIncomplete(fs); incomplete {
		t.Errorf("a relation whose write access was PROVEN counts as unassessed: %v", what)
	}
}

func resources(fs []finding.Finding) []string {
	out := make([]string, 0, len(fs))
	for _, f := range fs {
		out = append(out, f.Resource)
	}
	return out
}
