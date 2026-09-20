// UPDATE and DELETE must be graded in BOTH directions.
//
// The zero-match PATCH probe every other scanner uses reports "writable" for
// every relation it sees, and passes any test that only checks it fires on an
// open table. What kills that design is a readable table whose policy grants
// SELECT and nothing else: the probe must stay silent there. fixtures/lab
// carries verb_read_only for exactly that, and this file grades against it.
//
// The answer key is fixtures/lab/schema/04_verbs.sql.
package eval_test

import (
	"context"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/eppser/unruly/internal/client"
	"github.com/eppser/unruly/internal/finding"
	"github.com/eppser/unruly/internal/postgrest"
	"github.com/eppser/unruly/internal/probe"
	"github.com/eppser/unruly/internal/surface"
)

// verbCase is one row of the answer key.
type verbCase struct {
	rel        string
	wantUpdate postgrest.WriteState
	wantDelete postgrest.WriteState
	why        string
}

var verbAnswerKey = []verbCase{
	{"verb_update_open", postgrest.WriteReached, postgrest.WriteInconclusive,
		"SELECT+UPDATE to anon. UPDATE is open; DELETE cannot be probed because " +
			"INSERT is closed, so the scan can create no row of its own to delete"},
	{"verb_read_only", postgrest.WriteBlockedRLS, postgrest.WriteInconclusive,
		"SELECT only. This is the false-positive control: a scanner that reports " +
			"either verb here is guessing from a 204"},
	{"verb_delete_open", postgrest.WriteBlockedRLS, postgrest.WriteReached,
		"SELECT+INSERT+DELETE. The scan inserts a row of its own and deletes it, " +
			"which proves DELETE without touching the fixture's rows"},
	{"verb_all_open", postgrest.WriteReached, postgrest.WriteReached,
		"FOR ALL grants every verb at once -- the usual way a table becomes " +
			"deletable by strangers"},
	{"verb_update_noinsert", postgrest.WriteReached, postgrest.WriteInconclusive,
		"SELECT+UPDATE, INSERT closed: UPDATE must be established against a row " +
			"belonging to the fixture, without altering it"},
	{"verb_identity_key", postgrest.WriteReached, postgrest.WriteInconclusive,
		"identity key. The no-op probe still answers because it writes a non-key " +
			"column back unchanged"},
}

func TestVerbProbesGradeBothDirections(t *testing.T) {
	_, c := loadFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	names := make([]string, 0, len(verbAnswerKey))
	for _, k := range verbAnswerKey {
		names = append(names, k.rel)
	}
	before := rowCounts(ctx, t, c, names)

	pr := probe.Run(ctx, c, names, probe.Options{Write: true, SampleRows: 2})
	got := map[string]probe.Relation{}
	for _, rel := range pr.Relations {
		got[rel.Name] = rel
	}

	for _, k := range verbAnswerKey {
		rel, ok := got[k.rel]
		if !ok {
			t.Errorf("%s: not probed at all", k.rel)
			continue
		}
		if rel.Update != k.wantUpdate {
			t.Errorf("%s UPDATE: want %v, got %v (%s)\n  key: %s",
				k.rel, k.wantUpdate, rel.Update, rel.UpdateWhy, k.why)
		}
		if rel.Delete != k.wantDelete {
			t.Errorf("%s DELETE: want %v, got %v (%s)\n  key: %s",
				k.rel, k.wantDelete, rel.Delete, rel.DeleteWhy, k.why)
		}
	}

	// The probes must not change the database. An UPDATE probe that alters a
	// value, or a DELETE probe that removes one of the fixture's rows, is a
	// scanner damaging what it was pointed at -- worse than a missed finding.
	after := rowCounts(ctx, t, c, names)
	for _, n := range names {
		if before[n] != after[n] {
			t.Errorf("%s: the probes changed the row count, %d -> %d",
				n, before[n], after[n])
		}
	}
}

// TestReadOnlyRelationYieldsNoVerbFinding is the same control stated as the
// output the operator sees. The state assertion above can hold while the
// finding layer still emits something, and a false positive in a report is
// what an operator actually acts on.
func TestReadOnlyRelationYieldsNoVerbFinding(t *testing.T) {
	_, c := loadFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	pr := probe.Run(ctx, c, []string{"verb_read_only"}, probe.Options{Write: true, SampleRows: 2})
	for _, f := range pr.Findings("http://127.0.0.1/rest/v1", false) {
		switch f.ID {
		case "supabase-anon-update-allowed", "supabase-anon-delete-allowed",
			"supabase-anon-insert-allowed":
			t.Errorf("false positive on a SELECT-only relation: %s (%s)",
				f.ID, f.Evidence.Reason)
		}
	}
}

func rowCounts(ctx context.Context, t *testing.T, c *client.Client, names []string) map[string]int {
	t.Helper()
	out := map[string]int{}
	r := probe.Run(ctx, c, names, probe.Options{SampleRows: 1})
	for _, rel := range r.Relations {
		out[rel.Name] = rel.Rows
	}
	return out
}

// Nested personal data must raise severity, against a real PostgREST.
//
// The unit test for this works on Go maps. This one goes through the wire
// format: PostgREST returns jsonb as nested JSON and a text column as a string,
// and the classifier has to reach into both. A relation whose only sensitive
// material is inside app_state was graded high -- "readable" -- when the
// correct grade is critical, "readable and carries credentials".
func TestNestedJSONRaisesSeverityAgainstPostgREST(t *testing.T) {
	_, c := loadFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	pr := probe.Run(ctx, c, []string{"nested_payloads"}, probe.Options{SampleRows: 2})
	if len(pr.Relations) != 1 || pr.Relations[0].Read != postgrest.ReadExposed {
		t.Fatalf("fixture not readable; this test would assert nothing: %+v", pr.Relations)
	}
	rel := pr.Relations[0]

	for _, want := range []string{
		"app_state.user.access_token", "app_state.user.email", "raw.payment.card_number",
	} {
		if !slices.Contains(rel.Columns, want) {
			t.Errorf("path %q not recovered from the wire format\n  got: %v", want, rel.Columns)
		}
	}
	if len(rel.Sensitive) == 0 {
		t.Fatal("nothing classified as sensitive, so severity cannot rise")
	}

	fs := pr.Findings("http://127.0.0.1/rest/v1", false)
	if len(fs) == 0 {
		t.Fatal("no findings")
	}
	if fs[0].Severity != finding.Critical {
		t.Errorf("severity %s; a readable relation carrying an access_token inside a "+
			"jsonb column is critical, and grading only the outer column name is what "+
			"made it high\n  sensitive: %v", fs[0].Severity, rel.Sensitive)
	}
}

// "Can a stranger drop my database?" is a question about routines, not tables.
//
// PostgREST exposes no DDL endpoint, so the only route from an anon key to DROP
// is a routine that takes SQL and runs it. fixtures/lab carries both halves:
// exec_sql, granted to anon, and run_sql -- same shape, same name family, no
// grant. A scanner that reports run_sql is guessing from the name.
func TestArbitrarySQLExecutionIsProvenNotGuessed(t *testing.T) {
	_, c := loadFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	res := surface.Routines(ctx, c, surface.Options{Concurrency: 4})

	var got *finding.Finding
	for i := range res.Findings {
		f := res.Findings[i]
		if f.ID != "supabase-anon-arbitrary-sql" {
			continue
		}
		if strings.Contains(f.Resource, "run_sql") {
			t.Errorf("false positive: run_sql has no EXECUTE grant for anon and answers "+
				"42501, so reporting it means the name alone was enough — %s",
				f.Evidence.Reason)
		}
		if strings.Contains(f.Resource, "exec_sql") {
			got = &res.Findings[i]
		}
	}
	if got == nil {
		t.Fatal("exec_sql executes caller SQL as the owner and was not reported; this is " +
			"the finding that answers whether an anonymous caller can drop the database")
	}
	if got.Severity != finding.Critical {
		t.Errorf("severity %s; arbitrary SQL execution as the function owner is critical",
			got.Severity)
	}
	// The proof must be the computed answer, not a 200.
	if !strings.Contains(got.Evidence.Response, "42") {
		t.Errorf("evidence does not carry the computed value, so the finding cannot be "+
			"told apart from a routine that echoed its argument: %q", got.Evidence.Response)
	}
	// And it must say what it did NOT do, since the description raises DROP.
	if !strings.Contains(got.Description, "did NOT attempt") {
		t.Error("the finding raises DROP without stating that nothing destructive was sent")
	}
	if !strings.Contains(got.Remediation, "REVOKE EXECUTE") {
		t.Errorf("remediation does not revoke the grant:\n%s", got.Remediation)
	}
}
