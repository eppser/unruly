package neon

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/eppser/unruly/internal/client"
	"github.com/eppser/unruly/internal/transcript"
	"github.com/eppser/unruly/scan"
)

// Without consent the stage sends NOTHING.
//
// This is the assertion that matters most in the file, and it is about
// requests rather than about findings. A stage that probed first and discarded
// the result would satisfy any check on its output while still having written
// a row into somebody's database -- which is the thing -write exists to
// prevent. So the client's own request counter is what is graded.
func TestWithoutConsentNoRequestIsSent(t *testing.T) {
	srv, c := writeHarness(t)
	var st scan.State
	stage := WriteStage{Base: srv.URL, Tables: allTables, Token: secretToken, Client: c}
	if err := stage.Run(context.Background(), &st); err != nil {
		t.Fatalf("stage: %v", err)
	}
	if sent, _ := c.Stats(); sent != 0 {
		t.Errorf("the stage sent %d request(s) with no consent given. Writes are opt-in "+
			"because they change somebody's data, and a probe whose result is "+
			"discarded has still been performed", sent)
	}
	// Silence is not acceptable either: the operator has to learn the surface
	// was not assessed, or an unmeasured tier reads as a clean one.
	var said bool
	for _, f := range st.Findings() {
		if strings.Contains(strings.ToLower(f.Description), "write") {
			said = true
		}
	}
	if !said {
		t.Error("nothing in the report says the write tier was not assessed; an " +
			"unmeasured surface that reports nothing is indistinguishable from a safe one")
	}
}

// With consent, the table that accepts an INSERT is reported and the one that
// refuses is not.
//
// 201 is acceptance. 403/42501 is a denial, and reporting it would be the same
// error as reporting a table whose RLS returns no rows: reasoning from the
// existence of an endpoint rather than from what it did.
func TestWithConsentTheAcceptedInsertIsReported(t *testing.T) {
	srv, c := writeHarness(t)
	var st scan.State
	stage := WriteStage{
		Base: srv.URL, Tables: allTables, Token: secretToken, Consent: true, Client: c,
	}
	if err := stage.Run(context.Background(), &st); err != nil {
		t.Fatalf("stage: %v", err)
	}
	got := map[string]bool{}
	for _, f := range st.Findings() {
		if f.Resource != "" {
			got[f.Resource] = true
		}
	}
	if !got["open_guestbook"] {
		t.Error("open_guestbook accepted an INSERT (201) and was not reported")
	}
	if got["owner_only"] {
		t.Error("owner_only answered 403/42501 to the INSERT and was reported anyway: " +
			"a refusal is not an exposure")
	}
}

func writeHarness(t *testing.T) (*httptest.Server, *client.Client) {
	t.Helper()
	tr, err := transcript.Load("../../fixtures/neon/transcript.json")
	if err != nil {
		t.Fatalf("loading the recorded lab transcript: %v", err)
	}
	s := tr.Server(func(msg string) {
		t.Errorf("the stage made a request the lab recording does not cover: %s", msg)
	})
	t.Cleanup(s.Close)
	return s, testClient(s.URL)
}

// Write probes are bounded and concurrent too, and stay ordered.
//
// The same defect as the read path, and it matters more here rather than less:
// this stage only runs when an operator has consented, which means they are
// waiting for it, and a serial loop over hundreds of candidates is minutes of
// that wait.
func TestWriteProbesAreConcurrentAndOrdered(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(20 * time.Millisecond)
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()

	names := make([]string, 40)
	for i := range names {
		names[i] = fmt.Sprintf("t_%02d", i)
	}

	var st scan.State
	start := time.Now()
	stage := WriteStage{
		Base: srv.URL, Tables: names, Token: secretToken,
		Consent: true, Client: testClient(srv.URL),
	}
	if err := stage.Run(context.Background(), &st); err != nil {
		t.Fatalf("stage: %v", err)
	}
	if elapsed := time.Since(start); elapsed > 400*time.Millisecond {
		t.Errorf("probing %d candidates took %v; serially that is unavoidable and "+
			"concurrently it is not", len(names), elapsed)
	}

	var got []string
	for _, f := range st.Findings() {
		got = append(got, f.Resource)
	}
	if len(got) != len(names) {
		t.Fatalf("reported %d of %d accepted writes", len(got), len(names))
	}
	if !sort.StringsAreSorted(got) {
		t.Errorf("findings came back in %v: concurrency reordered the report", got)
	}
}
