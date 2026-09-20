package neon

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"time"

	"github.com/eppser/unruly/internal/client"
	"strings"
	"testing"

	"github.com/eppser/unruly/internal/finding"
	"github.com/eppser/unruly/internal/transcript"
	"github.com/eppser/unruly/scan"
)

// The tables the recorded fixture covers, and what the answer key says about
// each one. Kept here rather than read from YAML so a drifting parser cannot
// quietly turn this into a test of nothing.
const secretToken = "replayed-secret-bearer-value"

var (
	wantReported = []string{"open_guestbook", "rls_disabled"}
	wantSilent   = []string{"anon_readable", "owner_only", "rls_enforced", "rls_no_policy"}
	allTables    = append(append([]string{}, wantReported...), wantSilent...)
)

// Escalation is measured, and measured precisely.
//
// Replays the transcript recorded off the live Neon lab. Two claims are
// graded, and the second matters more than the first:
//
//   - RECALL: rls_disabled has RLS switched off and a GRANT to authenticated,
//     so an account that signed itself up seconds ago reads every row --
//     including other users' card_last4. That must be reported.
//   - PRECISION: owner_only must NOT be reported. Neon's own console warns
//     that it "has RLS disabled -- all authenticated users can view all rows",
//     which is false: there is no GRANT, so it answers 403/42501. A scanner
//     that reasons from RLS state alone repeats the vendor's mistake.
//
// rls_enforced and rls_no_policy both answer 200 with an empty array and must
// stay silent too; an empty read is not an exposure.
func TestEscalationIsMeasuredAndDoesNotRepeatTheConsolesMistake(t *testing.T) {
	tr, err := transcript.Load("../../fixtures/neon/transcript.json")
	if err != nil {
		t.Fatalf("loading the recorded lab transcript: %v", err)
	}
	srv := tr.Server(func(msg string) {
		t.Errorf("the stage made a request the lab recording does not cover: %s", msg)
	})
	defer srv.Close()

	var st scan.State
	stage := EscalationStage{Base: srv.URL, Tables: allTables, Token: "replayed.token.value", Client: testClient(srv.URL)}
	if err := stage.Run(context.Background(), &st); err != nil {
		t.Fatalf("stage: %v", err)
	}

	got := map[string]bool{}
	for _, f := range st.Findings() {
		got[f.Resource] = true
	}

	for _, tbl := range wantReported {
		if !got[tbl] {
			t.Errorf("%s was not reported: an account that signed itself up read "+
				"rows from it, which is the escalation this backend exists to find", tbl)
		}
	}
	for _, tbl := range wantSilent {
		if got[tbl] {
			t.Errorf("%s was reported but is protected: it answers 403 or an empty "+
				"array to an authenticated caller. Reporting owner_only in "+
				"particular repeats the false positive in Neon's own console", tbl)
		}
	}
}

// The finding carries the rows it claims, not a boolean.
func TestEscalationFindingCarriesTheRowsItClaims(t *testing.T) {
	tr, err := transcript.Load("../../fixtures/neon/transcript.json")
	if err != nil {
		t.Fatal(err)
	}
	srv := tr.Server(func(msg string) { t.Errorf("unrecorded request: %s", msg) })
	defer srv.Close()

	var st scan.State
	if err := (EscalationStage{Base: srv.URL, Tables: allTables, Token: secretToken, Client: testClient(srv.URL)}).
		Run(context.Background(), &st); err != nil {
		t.Fatal(err)
	}

	var f, ok = findingFor(st, "rls_disabled")
	if !ok {
		t.Fatal("no finding for rls_disabled; nothing to check evidence on")
	}
	if len(f.Evidence.Sample) == 0 {
		t.Error("the finding carries no sampled rows: a report that says " +
			"'escalation possible' without the rows is the boolean this scanner refuses")
	}
	if f.Evidence.Request == "" {
		t.Error("no replayable request on the finding")
	}
	if !strings.Contains(f.Evidence.Request, "Authorization") {
		t.Error("the replayable request omits the Authorization header; pasting it " +
			"would reproduce the anonymous refusal, not the escalation it documents")
	}
	// card_last4 belongs to other users. Naming the sensitive columns is what
	// makes a redacted report still actionable.
	if len(f.Evidence.Columns) == 0 {
		t.Error("no columns recorded on the evidence")
	}
	// A report is a document that gets forwarded. A credential pasted into one
	// is a second incident, so the request references the token by environment
	// variable rather than embedding it.
	if strings.Contains(f.Evidence.Request, secretToken) {
		t.Errorf("the replayable request embeds the bearer token: %q", f.Evidence.Request)
	}
}

func findingFor(st scan.State, resource string) (f finding.Finding, ok bool) {
	for _, x := range st.Findings() {
		if x.Resource == resource {
			return x, true
		}
	}
	return f, false
}

// testClient forwards every control the operator would, which is the whole
// point of the stage refusing to build its own.
func testClient(base string) *client.Client {
	return client.New(client.Options{
		BaseURL:    base,
		RestPrefix: "/",
		Timeout:    5 * time.Second,
		UserAgent:  "unruly-test",
		Limiter:    client.NewLimiter(0),
	})
}

// The anonymous observation is taken ONCE, not once per table.
//
// It is the same response every time -- that is the measured fact this backend
// is built on: a Neon Data API refuses an unauthenticated caller before it
// looks at the table, so the answer carries no information about which table
// was asked for. Taking it per candidate doubles the traffic and learns
// nothing the first one did not say.
//
// That is not a tuning detail. Names come from the application's vocabulary
// because Neon exposes no enumeration oracle, so a real scan carries hundreds
// of candidates; against the lab this stage was issuing roughly seventeen
// hundred requests, and a scan is not free for the person being scanned.
func TestTheAnonymousObservationIsTakenOnce(t *testing.T) {
	tr, err := transcript.Load("../../fixtures/neon/transcript.json")
	if err != nil {
		t.Fatal(err)
	}
	srv := tr.Server(func(msg string) {
		t.Errorf("the stage made a request the lab recording does not cover: %s", msg)
	})
	defer srv.Close()

	c := testClient(srv.URL)
	var st scan.State
	stage := EscalationStage{Base: srv.URL, Tables: allTables, Token: secretToken, Client: c}
	if err := stage.Run(context.Background(), &st); err != nil {
		t.Fatalf("stage: %v", err)
	}

	sent, _ := c.Stats()
	want := int64(len(allTables)) + 1 // one read per candidate, plus one control
	if sent > want {
		t.Errorf("the stage sent %d requests for %d candidates; %d is enough -- one "+
			"authenticated read each, and a single anonymous observation whose "+
			"answer is identical for every name", sent, len(allTables), want)
	}
}

// Candidates are probed concurrently, and the report is still deterministic.
//
// The stage looped serially, one blocking round trip at a time. Against a real
// target that is not a tuning detail: Neon offers no enumeration oracle, so
// candidates come from the application's vocabulary and a scan carries
// hundreds, and at a quarter-second each the run stops being one an operator
// waits for. Measured against the lab, the binary had not finished after
// several minutes.
//
// Order is asserted alongside speed because concurrency is how a report stops
// being byte-identical between runs, which eval-determinism grades.
func TestCandidatesAreProbedConcurrentlyAndOutputStaysOrdered(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(20 * time.Millisecond)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[{"id":1,"card_last4":"0000"}]`))
	}))
	defer srv.Close()

	names := make([]string, 40)
	for i := range names {
		names[i] = fmt.Sprintf("t_%02d", i)
	}

	var st scan.State
	start := time.Now()
	stage := EscalationStage{
		Base: srv.URL, Tables: names, Token: secretToken, Client: testClient(srv.URL),
	}
	if err := stage.Run(context.Background(), &st); err != nil {
		t.Fatalf("stage: %v", err)
	}
	elapsed := time.Since(start)

	// Serial would be at least 40 x 20ms = 800ms. The margin is wide on
	// purpose: this asserts "not serial", not a particular pool size.
	if elapsed > 400*time.Millisecond {
		t.Errorf("probing %d candidates took %v; serially that is unavoidable and "+
			"concurrently it is not, and a real scan carries hundreds of names",
			len(names), elapsed)
	}

	var got []string
	for _, f := range st.Findings() {
		got = append(got, f.Resource)
	}
	if !sort.StringsAreSorted(got) {
		t.Errorf("findings came back in %v: concurrency reordered the report, and "+
			"byte-identical output between runs is graded", got)
	}
}
