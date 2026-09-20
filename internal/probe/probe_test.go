package probe

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"runtime"
	"slices"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/eppser/unruly/internal/client"

	"github.com/eppser/unruly/internal/finding"
	"github.com/eppser/unruly/internal/postgrest"
)

func TestSensitiveColumns(t *testing.T) {
	cases := []struct {
		cols []string
		want []string
	}{
		// The real columns of the reference target's `sessions` relation.
		{[]string{"id", "code", "title", "is_active", "created_at", "access_token"},
			[]string{"access_token:credential"}},
		{[]string{"id", "name", "title", "quote", "status"}, nil},
		{[]string{"email", "password_hash"},
			[]string{"email:contact", "password_hash:credential"}},
		{[]string{"api_key", "refresh_token", "credit_card_number"},
			[]string{"api_key:credential", "credit_card_number:financial", "refresh_token:credential"}},
		{[]string{"user_email", "phone_number", "date_of_birth"},
			[]string{"date_of_birth:pii", "phone_number:contact", "user_email:contact"}},
	}
	for _, tc := range cases {
		got := SensitiveColumns(tc.cols)
		if len(got) != len(tc.want) {
			t.Errorf("SensitiveColumns(%v) = %v, want %v", tc.cols, got, tc.want)
			continue
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Errorf("SensitiveColumns(%v)[%d] = %q, want %q", tc.cols, i, got[i], tc.want[i])
			}
		}
	}
}

// A relation holding credentials must outrank one holding ordinary data, so
// operators triage the token leak before the public endorsement list.
func TestSensitiveColumnsRaiseSeverity(t *testing.T) {
	res := Result{Relations: []Relation{
		{Name: "sessions", Read: postgrest.ReadExposed, Rows: 17,
			Columns:   []string{"id", "access_token"},
			Sensitive: SensitiveColumns([]string{"id", "access_token"}),
			Sample:    []map[string]any{{"id": 1, "access_token": "4cc276"}}},
		{Name: "signatory_submissions", Read: postgrest.ReadExposed, Rows: 124,
			Columns: []string{"id", "name", "quote"},
			Sample:  []map[string]any{{"id": 204, "name": "A"}}},
	}}
	fs := res.Findings("https://ref.supabase.co/rest/v1", false)
	if len(fs) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(fs))
	}
	// Sorted most-severe first.
	if fs[0].Resource != "sessions" || fs[0].Severity != finding.Critical {
		t.Errorf("expected sessions/critical first, got %s/%s", fs[0].Resource, fs[0].Severity)
	}
	if fs[1].Severity != finding.High {
		t.Errorf("expected the non-sensitive relation to be high, got %s", fs[1].Severity)
	}
}

// Every finding must carry proof. A boolean claim is exactly what makes the
// surveyed tools untrustworthy.
func TestFindingsCarryProof(t *testing.T) {
	res := Result{Relations: []Relation{
		{Name: "sessions", Read: postgrest.ReadExposed, Rows: 17,
			Columns: []string{"id", "access_token"},
			Sample:  []map[string]any{{"id": 1, "access_token": "4cc276"}}},
	}}
	f := res.Findings("https://ref.supabase.co/rest/v1", false)[0]
	if f.Evidence.Rows != 17 {
		t.Error("evidence must carry the observed row count")
	}
	if len(f.Evidence.Sample) == 0 {
		t.Error("evidence must carry real sampled rows")
	}
	if f.Evidence.Request == "" {
		t.Error("evidence must carry a replayable request")
	}
	if f.Remediation == "" {
		t.Error("every finding must carry remediation")
	}
	if strings.Contains(f.Evidence.Request, "eyJ") {
		t.Error("the replayable request must not embed a real credential")
	}
}

func TestRedactDropsSamplesOnly(t *testing.T) {
	res := Result{Relations: []Relation{
		{Name: "sessions", Read: postgrest.ReadExposed, Rows: 17,
			Columns: []string{"access_token"},
			Sample:  []map[string]any{{"access_token": "4cc276"}}},
	}}
	f := res.Findings("https://ref.supabase.co/rest/v1", true)[0]
	if len(f.Evidence.Sample) != 0 {
		t.Error("redact must drop sampled rows")
	}
	if f.Evidence.Rows != 17 {
		t.Error("redact must keep the row count")
	}
}

func TestRemediationIsDeterministicAndTargeted(t *testing.T) {
	a := readRemediation("sessions", "sessions")
	b := readRemediation("sessions", "sessions")
	if a != b {
		t.Error("remediation must be byte-identical across calls")
	}
	if !strings.Contains(a, "ALTER TABLE sessions ENABLE ROW LEVEL SECURITY") {
		t.Error("remediation must name the affected relation")
	}
	// RLS alone leaves the GRANT in place; the fix must say so.
	if !strings.Contains(a, "REVOKE ALL ON TABLE sessions FROM anon") {
		t.Error("remediation must also revoke the grant")
	}
	w := writeRemediation("agent_runs", "agent_runs")
	if !strings.Contains(w, "REVOKE INSERT, UPDATE, DELETE ON TABLE agent_runs FROM anon") {
		t.Error("write remediation must revoke write grants")
	}
}

// Protected relations must produce no finding that CLAIMS anything about them.
//
// The rule used to be "no findings at all". It is now "nothing above info, and
// no exposure claim", because the inventory finding records protected relation
// names deliberately: enumeration recovers them at real cost and dropping them
// discarded most of the scan's product. What must never happen is a protected
// relation appearing as exposure, which is the false positive this test exists
// to prevent, and which no info-severity inventory line can cause -- a reader
// filtering for things to fix never sees it.
func TestProtectedRelationsProduceNoExposureFindings(t *testing.T) {
	res := Result{Relations: []Relation{
		{Name: "cves", Read: postgrest.ReadEmpty, Write: postgrest.WriteBlockedRLS},
		{Name: "exploits", Read: postgrest.ReadEmpty, Write: postgrest.WriteBlockedRLS},
	}}
	fs := res.Findings("https://ref.supabase.co/rest/v1", false)
	for _, f := range fs {
		if f.Severity != finding.Info {
			t.Errorf("protected relation produced a %s finding: %s %s",
				f.Severity, f.ID, f.Resource)
		}
		// The rule is the one stated above -- info, and no exposure claim --
		// not a fixed list of one id. It was relaxed once already for the
		// inventory, and relaxed again here for the statement that UPDATE and
		// DELETE were never established on relations this scan cannot read:
		// that is a fact about the examination, and on a fully hardened
		// project it is the only thing standing between "0 exposures" and a
		// reader believing the write verbs were checked.
		switch f.ID {
		case "unruly-relations-protected", "unruly-surface-not-assessed":
		default:
			t.Errorf("unexpected finding for a protected relation: %s %s",
				f.ID, f.Resource)
		}
	}
	// And the names must actually be carried, or the findings are just noise.
	var inventory *finding.Finding
	for i := range fs {
		if fs[i].ID == "unruly-relations-protected" {
			inventory = &fs[i]
		}
	}
	if inventory == nil {
		t.Fatalf("no inventory finding among %d", len(fs))
	}
	fs = []finding.Finding{*inventory}
	for _, want := range []string{"cves", "exploits"} {
		if !strings.Contains(fs[0].Description, want) {
			t.Errorf("inventory does not name %q", want)
		}
	}
}

// A probe row we failed to remove is itself reportable: the operator has to
// know we left something behind.
func TestCleanupFailureIsReported(t *testing.T) {
	res := Result{Relations: []Relation{
		{Name: "open_table", Write: postgrest.WriteReached,
			CleanupErr: "cleanup DELETE returned HTTP 401; manual cleanup required"},
	}}
	fs := res.Findings("https://ref.supabase.co/rest/v1", false)
	var found bool
	for _, f := range fs {
		if f.ID == "unruly-probe-row-left-behind" {
			found = true
		}
	}
	if !found {
		t.Error("a failed cleanup must surface as its own finding")
	}
}

// Write severity must distinguish a blind write from a compounding one. Rating
// every anon-writable relation critical inflates the count on correctly built
// projects — a public submission form is insert-only by design — and an
// inflated critical count is how a report stops being read.
func TestWriteSeverityDependsOnReadability(t *testing.T) {
	blind := Result{Relations: []Relation{
		{Name: "contact_requests", Read: postgrest.ReadEmpty, Write: postgrest.WriteReached},
	}}.Findings("https://x/rest/v1", false)
	blindWrite := findingByID(blind, "supabase-anon-insert-allowed")
	if blindWrite == nil {
		t.Fatalf("expected an insert finding, got %d findings", len(blind))
	}
	if blindWrite.Severity != finding.High {
		t.Errorf("blind write should be high, got %s", blindWrite.Severity)
	}

	compounding := Result{Relations: []Relation{
		{Name: "sessions", Read: postgrest.ReadExposed, Rows: 17,
			Columns: []string{"id"}, Sample: []map[string]any{{"id": 1}},
			Write: postgrest.WriteReached},
	}}.Findings("https://x/rest/v1", false)
	var w *finding.Finding
	for i := range compounding {
		if compounding[i].ID == "supabase-anon-insert-allowed" {
			w = &compounding[i]
		}
	}
	if w == nil {
		t.Fatal("expected a write finding")
	}
	if w.Severity != finding.Critical {
		t.Errorf("readable AND writable should be critical, got %s", w.Severity)
	}
}

// Remediation for a relation outside the default schema must name it the way
// SQL has to.
//
// It did not. The fix read:
//
//	ALTER TABLE daily_revenue ENABLE ROW LEVEL SECURITY;
//
// for a table in the reporting schema. Pasted into a SQL editor that resolves
// against public via search_path, that either errors or alters a DIFFERENT
// table of the same name -- leaving the real exposure open while the operator
// believes it is closed. A fix that silently targets the wrong object is worse
// than no fix at all.
func TestRemediationIsSchemaQualifiedOutsideTheDefaultSchema(t *testing.T) {
	rel := Relation{
		Name: "daily_revenue", Schema: "reporting",
		Read: postgrest.ReadExposed, Rows: 14,
		Columns: []string{"id", "customer_email"},
	}
	f := readFinding("http://x/rest/v1", rel, false)

	if f.Resource != "reporting.daily_revenue" {
		t.Errorf("resource %q must be schema-qualified", f.Resource)
	}
	if !strings.Contains(f.Remediation, "ALTER TABLE reporting.daily_revenue") {
		t.Errorf("the SQL must name the schema, or it hits whatever search_path "+
			"resolves to:\n%s", f.Remediation)
	}
	if strings.Contains(f.Remediation, "ALTER TABLE daily_revenue ") {
		t.Error("an unqualified ALTER TABLE is the bug this test exists for")
	}
	// The policy IDENTIFIER should not carry the dot; the object it is ON must.
	if strings.Contains(f.Remediation, `"reporting.daily_revenue_owner_read"`) {
		t.Error("the policy name should be the bare relation; only the object needs qualifying")
	}
	// The URL addresses PostgREST, which takes the relation by bare name and
	// the schema from a header. A qualified path is a 404.
	if strings.Contains(f.Matched, "reporting.daily_revenue") {
		t.Errorf("the URL must use the bare name, got %q", f.Matched)
	}
	if !strings.Contains(f.Evidence.Request, "Accept-Profile: reporting") {
		t.Errorf("evidence that omits the schema header does not reproduce: %q",
			f.Evidence.Request)
	}
}

// And nothing changes for the default schema.
func TestRemediationIsUnqualifiedInTheDefaultSchema(t *testing.T) {
	rel := Relation{Name: "sessions", Read: postgrest.ReadExposed, Rows: 17}
	f := readFinding("http://x/rest/v1", rel, false)
	if f.Resource != "sessions" {
		t.Errorf("resource %q", f.Resource)
	}
	if strings.Contains(f.Remediation, ".sessions") {
		t.Errorf("the default schema must not be spelled out:\n%s", f.Remediation)
	}
	if strings.Contains(f.Evidence.Request, "Accept-Profile") {
		t.Error("no profile header belongs on a default-schema request")
	}
}

// The sensitive-column classifier decides whether a read exposure is high or
// CRITICAL, so a gap in it understates a credential leak rather than missing
// it outright -- which is harder to notice.
//
// The token rule was a fixed prefix list and missed every token Supabase's own
// auth schema uses. Both directions are asserted, because the obvious fix
// (flag anything containing "token") is wrong in a way that matters here: the
// reference target is an LLM-adjacent database full of token COUNTS.
func TestSensitiveColumnsCoverCredentialsWithoutFlaggingCounts(t *testing.T) {
	mustFlag := map[string]string{
		// Supabase auth uses these names verbatim.
		"confirmation_token": "credential",
		"recovery_token":     "credential",
		"email_change_token": "credential",
		// and the shapes every hand-rolled auth grows.
		"reset_token":        "credential",
		"verification_token": "credential",
		"invite_token":       "credential",
		"magic_token":        "credential",
		"token":              "credential",
		"jwt":                "credential",
		"signing_key":        "credential",
		"encryption_key":     "credential",
		"otp_code":           "credential",
		"recovery_code":      "credential",
		"backup_code":        "credential",
		"password_hash":      "credential",
		"bank_account":       "financial",
		"routing_number":     "financial",
		"sort_code":          "financial",
		"national_id":        "government-id",
		"drivers_license":    "government-id",
	}
	for col, class := range mustFlag {
		got := SensitiveColumns([]string{col})
		if len(got) == 0 {
			t.Errorf("%q is not flagged; a relation exposing it would be reported high "+
				"rather than critical", col)
			continue
		}
		if !strings.HasSuffix(got[0], ":"+class) {
			t.Errorf("%q classified %q, want class %q", col, got[0], class)
		}
	}

	// Counts, not secrets. Flagging these would put a critical on ordinary
	// usage tables, and this project's own reference target is full of them.
	for _, col := range []string{
		"max_tokens", "total_tokens", "prompt_tokens", "completion_tokens",
		"token_count", "tokens_used", "created_at", "title", "is_active",
		"run_id", "status", "model",
	} {
		if got := SensitiveColumns([]string{col}); len(got) > 0 {
			t.Errorf("%q flagged as %v: it is a count or an ordinary field, and a false "+
				"critical is how a scanner loses the reader's trust", col, got)
		}
	}
}

// The write finding's reproduction command must send JSON.
//
// Without Content-Type, curl sends application/x-www-form-urlencoded and
// PostgREST reads the body as a column list, answering PGRST204 "Could not
// find the '{}' column" -- so the finding's own proof denies the finding.
// Found by running every emitted evidence command instead of reading them.
func TestWriteEvidenceCommandSendsJSON(t *testing.T) {
	rel := Relation{Name: "open_no_rls", Write: postgrest.WriteReached, WriteWhy: "reached"}
	f := writeFinding("http://x/rest/v1", rel)
	req := f.Evidence.Request

	if !strings.Contains(req, "Content-Type: application/json") {
		t.Errorf("the command must declare JSON or PostgREST parses the body as columns:\n  %s", req)
	}
	if !strings.Contains(req, "-d '{}'") {
		t.Errorf("the command must send the same empty object the probe sent:\n  %s", req)
	}
}

// Probing must cost one request per relation and hold nothing per relation
// that grows faster than the list.
//
// Measured against the fixture at 300 relations: 32ms, 300 requests, 3MB of
// heap, and rendering the findings with -fix took 7ms. Scale is not a problem
// today, which is exactly when the invariant is cheap to pin -- an extra probe
// per relation, or an accumulator that keeps every response, would not show up
// on a ten-table fixture and would be very visible on somebody's real project.
func TestProbingCostsOneRequestPerRelation(t *testing.T) {
	var served atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		served.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"code":"PGRST205","message":"not found"}`))
	}))
	defer srv.Close()

	const n = 300
	names := make([]string, n)
	for i := range names {
		names[i] = fmt.Sprintf("relation_%03d", i)
	}

	c := client.New(client.Options{BaseURL: srv.URL, AnonKey: "k", RestPrefix: "/", Concurrency: 32})

	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	res := Run(context.Background(), c, names, Options{SampleRows: 3, Concurrency: 32})
	runtime.ReadMemStats(&after)

	// One request per relation, PLUS ONE for the control.
	//
	// The control asks for a name that cannot exist, and its answer decides
	// whether any of the others carry information. It is a real request to
	// somebody's server and is counted as one: a scan that spent it silently
	// would under-report its own traffic, which this project treats as a claim
	// about another person's machine that happens to be wrong.
	//
	// The shape is the point -- n+1, not "about n". Anything that multiplies
	// per relation still fails, which is what this test has always been for.
	const withControl = n + 1
	if got := served.Load(); got != withControl {
		t.Errorf("%d requests for %d relations: read probing must be one request each "+
			"plus a single control, and anything else multiplies on a project with "+
			"hundreds of tables", got, n)
	}
	if res.Requests != withControl {
		t.Errorf("Result.Requests says %d, the server counted %d; the number the report "+
			"shows an operator must be the number sent", res.Requests, served.Load())
	}
	if grown := int64(after.TotalAlloc-before.TotalAlloc) >> 20; grown > 64 {
		t.Errorf("heap grew %d MB probing %d absent relations; nothing per-relation should "+
			"be retained", grown, n)
	}
}

// Personal data in Supabase schemas is very often inside a jsonb column whose
// own name says nothing: app_state, preferences, payload, metadata. Grading
// only the outer name grades the half the developer chose and ignores the half
// the framework filled in, which under-reported a relation holding session
// tokens from critical to high on a real target.
func TestNestedJSONColumnsAreClassified(t *testing.T) {
	rows := []map[string]any{{
		"id": 1,
		"app_state": map[string]any{
			"user": map[string]any{
				"email":        "person@example.invalid",
				"access_token": "sk_live_...",
			},
			"theme": "dark",
		},
		// A text column holding JSON is the same disclosure as a jsonb one.
		"raw": `{"payment":{"card_number":"4111111111111111"}}`,
		// An array contributes one path, not one per element.
		"members": []any{
			map[string]any{"email": "a@example.invalid"},
			map[string]any{"email": "b@example.invalid"},
		},
	}}

	cols := columnsOf(rows)
	for _, want := range []string{
		"app_state", "app_state.user.email", "app_state.user.access_token",
		"app_state.theme", "raw.payment.card_number", "members[].email",
	} {
		if !slices.Contains(cols, want) {
			t.Errorf("columnsOf did not surface %q\n  got: %v", want, cols)
		}
	}
	if n := strings.Count(strings.Join(cols, " "), "members[].email"); n != 1 {
		t.Errorf("array produced %d paths for the same key; the name set must not "+
			"grow with row count", n)
	}

	sens := SensitiveColumns(cols)
	for _, want := range []string{
		"app_state.user.access_token:credential",
		"raw.payment.card_number:financial",
	} {
		if !slices.Contains(sens, want) {
			t.Errorf("nested %q not classified as sensitive\n  got: %v", want, sens)
		}
	}
	// The outer name is not itself sensitive, which is the whole point: before
	// this, that was the only name the classifier ever saw.
	for _, s := range sens {
		if s == "app_state:credential" {
			t.Error("app_state itself should not classify; the leaf is what matters")
		}
	}
}

// The anchors in sensitivePatterns are written against bare column names.
// Matching them against a dotted path breaks them silently.
func TestNestedClassificationMatchesOnTheLeaf(t *testing.T) {
	for _, path := range []string{"profile.jwt", "session.access_token", "a.b.c.password"} {
		if got := SensitiveColumns([]string{path}); len(got) == 0 {
			t.Errorf("%q was not classified; the pattern is anchored and must be "+
				"applied to the last path segment, not the whole path", path)
		}
	}
	// And a leaf that merely CONTAINS a sensitive word stays unflagged, so the
	// path change did not loosen the rules.
	for _, path := range []string{"usage.total_tokens", "limits.max_tokens"} {
		if got := SensitiveColumns([]string{path}); len(got) > 0 {
			t.Errorf("%q classified as %v; counts are not credentials", path, got)
		}
	}
}

// A pathological document must not turn one sampled row into thousands of
// names to match, since this runs for every exposed relation.
func TestNestedJSONIsBounded(t *testing.T) {
	deep := map[string]any{"email": "x@example.invalid"}
	for i := 0; i < 40; i++ {
		deep = map[string]any{"n": deep}
	}
	wide := map[string]any{}
	for i := 0; i < 5000; i++ {
		wide[fmt.Sprintf("k%04d", i)] = i
	}
	cols := columnsOf([]map[string]any{{"deep": deep, "wide": wide}})
	if len(cols) > maxJSONPaths+len(wide) {
		t.Errorf("unbounded: %d names", len(cols))
	}
	for _, c := range cols {
		if strings.Count(c, ".") > maxJSONDepth {
			t.Errorf("path %q exceeds the depth bound", c)
		}
	}
}

func findingByID(fs []finding.Finding, id string) *finding.Finding {
	for i := range fs {
		if fs[i].ID == id {
			return &fs[i]
		}
	}
	return nil
}

// The UPDATE and DELETE findings must be built by the OFFLINE suite.
//
// The live evals in internal/eval exercise them against a real PostgREST, but
// they skip without Docker, so the coverage check -- which requires every
// finding id to have an emit site a test actually executes -- counted both as
// named-but-never-built. A finding that only runs under a fixture is a finding
// CI cannot protect.
func TestVerbFindingsAreBuiltOffline(t *testing.T) {
	res := Result{Relations: []Relation{{
		Name:      "api_tokens",
		Read:      postgrest.ReadExposed,
		Rows:      12,
		Columns:   []string{"id", "token"},
		Sensitive: SensitiveColumns([]string{"id", "token"}),
		Update:    postgrest.WriteReached,
		UpdateWhy: "no-op UPDATE probe: the statement affected 1 row(s)",
		Delete:    postgrest.WriteReached,
		DeleteWhy: "a row this scan created was deleted anonymously and verified gone",
	}}}
	fs := res.Findings("https://ref.supabase.co/rest/v1", false)

	for _, id := range []string{"supabase-anon-update-allowed", "supabase-anon-delete-allowed"} {
		f := findingByID(fs, id)
		if f == nil {
			t.Fatalf("%s was not emitted", id)
		}
		// Readable and writable is the compounding case.
		if f.Severity != finding.Critical {
			t.Errorf("%s on a readable relation should be critical, got %s", id, f.Severity)
		}
		if f.Resource != "api_tokens" {
			t.Errorf("%s names %q", id, f.Resource)
		}
		if f.Evidence.Reason == "" {
			t.Errorf("%s carries no reason, so the report asserts without showing", id)
		}
		if !strings.Contains(f.Remediation, "REVOKE") {
			t.Errorf("%s remediation does not revoke anything:\n%s", id, f.Remediation)
		}
	}

	// A blind relation is materially less dangerous and must rate lower.
	blind := Result{Relations: []Relation{{
		Name: "queue", Read: postgrest.ReadEmpty,
		Delete: postgrest.WriteReached, DeleteWhy: "verified gone",
	}}}.Findings("https://ref.supabase.co/rest/v1", false)
	if f := findingByID(blind, "supabase-anon-delete-allowed"); f == nil {
		t.Error("blind delete not reported")
	} else if f.Severity != finding.High {
		t.Errorf("blind delete should be high, got %s", f.Severity)
	}
}
