package neon

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/eppser/unruly/internal/client"
	"github.com/eppser/unruly/internal/testrec"
	"github.com/eppser/unruly/scan"
)

// Neon's Data API leaks table names through PostgREST's hint oracle.
//
// internal/provider/neon.go declared CapListing unavailable on the grounds that
// the OpenAPI root is not served -- which is true, measured, and the wrong
// conclusion. The OpenAPI root is not the only enumeration oracle: PostgREST
// answers a near-miss name with PGRST205 and a hint naming the real one, and
// internal/enumerate has exploited that against Supabase for this project's
// whole existence. Measured against the live lab on 2026-08-22:
//
//	GET /rls_disable    -> PGRST205  hint "Perhaps you meant the table 'public.rls_disabled'"
//	GET /anon_readabl   -> PGRST205  hint "Perhaps you meant the table 'public.anon_readable'"
//	GET /totally_unrelated_xyz -> PGRST205  hint null
//
// The last line is what makes it an oracle rather than noise: an unrelated name
// draws nothing, so a hint is evidence about THIS schema.
//
// The stage must reuse internal/enumerate rather than reimplement it. That
// reuse is the abstraction test the mission names, and if a Neon-specific
// oracle turns out to be necessary then the shared package is not shared.
func TestEnumerateRecoversNamesFromHints(t *testing.T) {
	var seen testrec.Log
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := strings.TrimPrefix(strings.SplitN(r.URL.Path, "?", 2)[0], "/")
		seen.Add(name)
		w.Header().Set("Content-Type", "application/json")
		switch name {
		case "rls_disabled":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`[{"id":1,"card_last4":"0000"}]`))
		case "rls_disable":
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, `{"code":"PGRST205","hint":"Perhaps you meant the table 'public.rls_disabled'",`+
				`"message":"Could not find the table 'public.rls_disable' in the schema cache"}`)
		default:
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, `{"code":"PGRST205","hint":null,`+
				`"message":"Could not find the table in the schema cache"}`)
		}
	}))
	defer srv.Close()

	var st scan.State
	stage := EnumerateStage{
		Base: srv.URL, Seeds: []string{"rls_disable", "totally_unrelated_xyz"},
		Token: "tok",
		// The client is based somewhere ELSE, exactly as it is in a real scan:
		// the scan-wide client points at the target root and carries the REST
		// prefix, while the stage's Base is the Data API root. internal/enumerate
		// probes c.RestURL(name), so a stage that hands over this client
		// unchanged asks a path that does not exist -- and then reports that the
		// API volunteered nothing, which is true of the URL and false of the API.
		//
		// The first version of this test based the client at srv.URL, so the
		// rebasing was a no-op and the mutation that removes it survived. A
		// fixture that cannot tell the bug from the fix is not a fixture.
		Client: client.New(client.Options{
			BaseURL: srv.URL + "/some/other/root", RestPrefix: "/rest/v1",
			Timeout: 5 * time.Second, UserAgent: "unruly-test",
			Limiter: client.NewLimiter(0), Retries: 0,
		}),
	}
	if err := stage.Run(context.Background(), &st); err != nil {
		t.Fatalf("stage: %v", err)
	}

	var reported bool
	for _, f := range st.Findings() {
		if strings.Contains(f.Description, "rls_disabled") || f.Resource == "rls_disabled" {
			reported = true
		}
	}
	if !reported {
		var ids []string
		for _, f := range st.Findings() {
			ids = append(ids, f.ID+"/"+f.Resource)
		}
		t.Errorf("the server volunteered the name rls_disabled and the scan reported %v. "+
			"A name the TARGET disclosed is the finding; without it a Neon scan can only "+
			"probe what the operator already knew to ask for", ids)
	}
	// The probe must have actually asked, and must have followed the hint.
	if seen.Len() < 2 {
		t.Errorf("only %d name(s) probed: %v", seen.Len(), seen.Entries())
	}
}

// A token is required, and its absence must be reported rather than returned as
// an empty result.
//
// On Neon a headerless request is refused identically for every name, so an
// unauthenticated oracle draws no hints at all -- enumeration would report
// nothing and look exactly like a project with no tables. That is the
// non-discriminating case the whole backend is built around.
func TestEnumerateWithoutATokenSaysSoRatherThanReportingNothing(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"message":"missing authentication credentials"}`))
	}))
	defer srv.Close()

	var st scan.State
	stage := EnumerateStage{
		Base: srv.URL, Seeds: []string{"rls_disable"}, Token: "",
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
		if strings.Contains(f.ID, "not-assessed") || strings.Contains(f.ID, "not-discriminating") {
			said = true
		}
	}
	if !said {
		t.Error("enumeration ran without a token, drew no hints, and reported nothing. " +
			"That is indistinguishable from a project with no tables, which is the " +
			"confusion this backend exists to refuse")
	}
}
