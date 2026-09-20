package neon

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/eppser/unruly/internal/client"
	"github.com/eppser/unruly/scan"
)

type writeRecorder struct {
	mu      sync.Mutex
	bodies  []string
	prefers []string
	status  int
	reply   string
}

func (w *writeRecorder) prefer() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	if len(w.prefers) == 0 {
		return ""
	}
	return w.prefers[0]
}

func (w *writeRecorder) handler() http.HandlerFunc {
	return func(rw http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		w.mu.Lock()
		w.bodies = append(w.bodies, string(b))
		w.prefers = append(w.prefers, r.Header.Get("Prefer"))
		w.mu.Unlock()
		rw.WriteHeader(w.status)
		_, _ = io.WriteString(rw, w.reply)
	}
}

func (w *writeRecorder) sent() []string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]string(nil), w.bodies...)
}

func neonWriteStage(t *testing.T, url string, tables []string) WriteStage {
	t.Helper()
	return WriteStage{
		Base: url, Tables: tables, Token: "tok", Consent: true,
		Client: client.New(client.Options{
			BaseURL: url, RestPrefix: "/", Timeout: 5 * time.Second,
			UserAgent: "unruly-test", Limiter: client.NewLimiter(0), Retries: 0,
		}),
	}
}

// The probe must not invent a column name.
//
// It sent {"body": "..."} -- a column called `body`, chosen because the lab's
// open_guestbook happens to have one. Every other table in that same lab
// answered 400 PGRST204 `column "body" does not exist`, which is not 201, so
// the stage reported nothing and the write tier went unmeasured on five of six
// tables while looking like a clean result.
//
// On a project whose schema has no `body` anywhere, that is every table. The
// standing constraint is that this tool works against ANY project without
// hardcoding, and a column name picked from one fixture is exactly that.
//
// An empty object needs no schema knowledge: PostgREST hands it to Postgres,
// and the privilege check happens before any column is considered. Measured
// against the live lab on 2026-08-22 -- 42501 on four tables with no INSERT
// grant, 201 on the one that has it.
func TestNeonWriteProbeInventsNoColumn(t *testing.T) {
	rec := &writeRecorder{status: http.StatusForbidden,
		reply: `{"code":"42501","message":"permission denied for table t"}`}
	srv := httptest.NewServer(rec.handler())
	defer srv.Close()

	var st scan.State
	if err := neonWriteStage(t, srv.URL, []string{"t"}).Run(context.Background(), &st); err != nil {
		t.Fatalf("stage: %v", err)
	}
	sent := rec.sent()
	if len(sent) != 1 {
		t.Fatalf("%d request(s), want 1", len(sent))
	}
	var payload map[string]any
	if err := json.Unmarshal([]byte(sent[0]), &payload); err != nil {
		t.Fatalf("the probe body is not JSON: %q", sent[0])
	}
	if len(payload) != 0 {
		t.Errorf("the probe sent %q, naming column(s) it cannot know exist. A table "+
			"without them answers 400 PGRST204, which is not 201, so the write tier "+
			"goes unmeasured and reports nothing", sent[0])
	}
}

// A constraint violation is the STRONGEST evidence this probe can get: the
// security layer let the insert through and a NOT NULL check stopped it, so
// the write is permitted AND no row was created.
func TestNeonWriteCountsAConstraintViolationAsPermitted(t *testing.T) {
	rec := &writeRecorder{status: http.StatusBadRequest,
		reply: `{"code":"23502","message":"null value in column \"title\" violates not-null constraint"}`}
	srv := httptest.NewServer(rec.handler())
	defer srv.Close()

	var st scan.State
	if err := neonWriteStage(t, srv.URL, []string{"posts"}).Run(context.Background(), &st); err != nil {
		t.Fatalf("stage: %v", err)
	}
	var reported bool
	for _, f := range st.Findings() {
		if strings.Contains(f.ID, "write") && f.Resource == "posts" {
			reported = true
			if !strings.Contains(f.Description, "23502") {
				t.Errorf("the finding does not quote the code that proves it: %q", f.Description)
			}
		}
	}
	if !reported {
		t.Error("23502 means the insert passed the privilege check and died on a column " +
			"constraint -- the write is permitted and nothing was stored, which is proof " +
			"without residue. It was reported as nothing")
	}
}

// And a denial stays a denial.
func TestNeonWriteReportsNothingOnADenial(t *testing.T) {
	rec := &writeRecorder{status: http.StatusForbidden,
		reply: `{"code":"42501","message":"permission denied for table locked"}`}
	srv := httptest.NewServer(rec.handler())
	defer srv.Close()

	var st scan.State
	if err := neonWriteStage(t, srv.URL, []string{"locked"}).Run(context.Background(), &st); err != nil {
		t.Fatalf("stage: %v", err)
	}
	for _, f := range st.Findings() {
		if strings.Contains(f.ID, "write-allowed") {
			t.Errorf("42501 is the security layer refusing before the table is consulted, "+
				"and it was reported as %s", f.ID)
		}
	}
}

// The finding must describe the row it actually created.
//
// Changing the probe to {} broke this and the break was invisible until the
// BINARY was run and its output read: the description still claimed "the row
// carries the value unruly_write_probe" and the remediation still emitted
// DELETE ... WHERE body = 'unruly_write_probe'. Neither was true any more. The
// row carries defaults, so that DELETE removes nothing -- and on a table with
// no `body` column it is not even valid SQL.
//
// A finding that misreports what it did is worse than the hardcoded column it
// replaced: the operator is told a row exists, given a statement that will not
// remove it, and left with residue they believe they have cleaned up.
//
// Prefer: return=representation makes the server hand back what it stored, so
// the primary key is known and the DELETE can name it.
func TestAcceptedWriteQuotesTheRowItCreated(t *testing.T) {
	rec := &writeRecorder{status: http.StatusCreated,
		reply: `[{"id":42,"body":null,"created_at":"2026-08-22T00:00:00Z"}]`}
	srv := httptest.NewServer(rec.handler())
	defer srv.Close()

	var st scan.State
	if err := neonWriteStage(t, srv.URL, []string{"open_guestbook"}).Run(context.Background(), &st); err != nil {
		t.Fatalf("stage: %v", err)
	}
	var f *findingLike
	for _, got := range st.Findings() {
		if got.ID == "neon-authenticated-write-allowed" {
			f = &findingLike{Description: got.Description, Remediation: got.Remediation}
		}
	}
	if f == nil {
		t.Fatal("the accepted write was not reported")
	}
	if strings.Contains(f.Description, "unruly_write_probe") ||
		strings.Contains(f.Remediation, "unruly_write_probe") {
		t.Errorf("the finding still claims the row carries a marker the probe no longer "+
			"sends.\n  description: %s\n  remediation: %s", f.Description, f.Remediation)
	}
	if !strings.Contains(f.Remediation, "id = 42") {
		t.Errorf("the remediation does not name the row that was created, so an operator "+
			"following it leaves the row behind:\n%s", f.Remediation)
	}
	if !strings.Contains(f.Description, "42") {
		t.Errorf("the description does not quote the row the server returned: %s", f.Description)
	}
	// And the probe must ASK for the row back, or there is nothing to quote.
	if got := rec.sent(); len(got) != 1 {
		t.Fatalf("%d request(s)", len(got))
	}
	if p := rec.prefer(); !strings.Contains(p, "representation") {
		t.Errorf("Prefer = %q; without it PostgREST returns an empty body and the row's "+
			"identity is unknown, so no exact DELETE can be offered", p)
	}
}

type findingLike struct{ Description, Remediation string }

// The replayable request must replay what was actually sent.
//
// It carried -d '{"body":"unruly_write_probe"}' after the probe had stopped
// sending that, and omitted the Prefer header the result depends on. Running it
// against a table with no `body` column returns 400 PGRST204 rather than the
// 201 the finding reports, so an operator checking the tool's own evidence
// would conclude the tool was wrong. Proof-carrying means the command in the
// report reproduces the observation in the report.
func TestTheReplayableRequestIsTheRequestWeSent(t *testing.T) {
	rec := &writeRecorder{status: http.StatusCreated, reply: `[{"id":7}]`}
	srv := httptest.NewServer(rec.handler())
	defer srv.Close()

	var st scan.State
	if err := neonWriteStage(t, srv.URL, []string{"t"}).Run(context.Background(), &st); err != nil {
		t.Fatalf("stage: %v", err)
	}
	for _, f := range st.Findings() {
		if f.ID != "neon-authenticated-write-allowed" {
			continue
		}
		req := f.Evidence.Request
		if strings.Contains(req, "unruly_write_probe") {
			t.Errorf("the replayable request sends a payload the probe does not: %s", req)
		}
		if !strings.Contains(req, writeProbePayload) {
			t.Errorf("the replayable request does not carry the payload that was sent: %s", req)
		}
		if !strings.Contains(req, "Prefer") {
			t.Errorf("the replayable request omits the header the result depends on, so "+
				"replaying it returns an empty body and the row cannot be seen: %s", req)
		}
		return
	}
	t.Fatal("no write finding")
}
