package neon

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/eppser/unruly/internal/client"
	"github.com/eppser/unruly/scan"
)

// A token nobody accepted must not read as a project with nothing exposed.
//
// EscalationStage reports a table only when rows actually came back, which is
// right: a 403 is a denial and a 200 with an empty array is a filtered or
// deny-all result, and neither is an exposure. That is the distinction Neon's
// own console gets wrong on owner_only.
//
// But the same silence covers a case that is not a result at all. If the token
// has expired, or was minted for another project, or the endpoint is rate
// limiting, then EVERY table answers 401/403/429 and the stage reports nothing
// -- identical output to a project where every table is correctly protected.
// Escalation is the headline finding on this backend, so a stale token turns
// the one check that matters into a clean bill of health.
//
// The stage already has what it needs: observation carries status and err. It
// simply never said so.
func TestEscalationSaysWhenEveryTableRefusedTheToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"message":"JWT expired"}`))
	}))
	defer srv.Close()

	var st scan.State
	stage := EscalationStage{
		Base: srv.URL, Tables: []string{"rls_disabled", "owner_only", "open_guestbook"},
		Token: "stale-token",
		Client: client.New(client.Options{
			BaseURL: srv.URL, RestPrefix: "/", Timeout: 5 * time.Second,
			UserAgent: "unruly-test", Limiter: client.NewLimiter(0), Retries: 0,
		}),
	}
	if err := stage.Run(context.Background(), &st); err != nil {
		t.Fatalf("stage: %v", err)
	}
	var said bool
	for _, f := range st.Findings() {
		if strings.Contains(strings.ToLower(f.Description), "token") ||
			strings.Contains(f.ID, "not-assessed") {
			said = true
		}
	}
	if !said {
		var ids []string
		for _, f := range st.Findings() {
			ids = append(ids, f.ID)
		}
		t.Errorf("every table refused the token and the stage reported %v. A project "+
			"whose tables are all correctly protected produces exactly this, so the "+
			"headline Neon finding is indistinguishable from an expired credential", ids)
	}
}

// And a project that really is protected must stay quiet: 200 with an empty
// array is a measurement, and a warning on every clean scan is one people learn
// to skip.
func TestEscalationIsQuietWhenTablesAnswerAndAreEmpty(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`[]`))
	}))
	defer srv.Close()

	var st scan.State
	stage := EscalationStage{
		Base: srv.URL, Tables: []string{"rls_enforced", "rls_no_policy"}, Token: "good-token",
		Client: client.New(client.Options{
			BaseURL: srv.URL, RestPrefix: "/", Timeout: 5 * time.Second,
			UserAgent: "unruly-test", Limiter: client.NewLimiter(0), Retries: 0,
		}),
	}
	if err := stage.Run(context.Background(), &st); err != nil {
		t.Fatalf("stage: %v", err)
	}
	if n := len(st.Findings()); n != 0 {
		var ids []string
		for _, f := range st.Findings() {
			ids = append(ids, f.ID)
		}
		t.Errorf("every table answered 200 with no rows -- a result, not a gap -- and "+
			"the stage reported %v", ids)
	}
}
