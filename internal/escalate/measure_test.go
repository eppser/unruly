package escalate

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/eppser/unruly/internal/client"
	"github.com/eppser/unruly/internal/probe"
	"github.com/eppser/unruly/internal/testrec"
)

// -measure must hold through the escalation compare.
//
// The flag promises exposure is established WITHOUT transferring any data.
// The compare re-reads every relation with the elevated credential, and it was
// building probe.Options without Measure -- so a scan run in -measure mode
// retrieved rows here anyway, which is the single thing that mode exists to
// make impossible.
//
// The structural guard that was supposed to catch this only ever read
// main.go, so this call site was never checked. Found while porting the probe
// stage, when the guard had to be generalised to follow the moved code.
func TestTheEscalationCompareHonoursMeasure(t *testing.T) {
	var sampled testrec.Log
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// A request that asks for rows is the leak: -measure establishes
		// exposure with limit=0 and reads the count, never the contents.
		if lim := r.URL.Query().Get("limit"); lim != "" && lim != "0" {
			sampled.Add(r.URL.RequestURI())
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Range", "0-0/1")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`[{"id":1,"secret":"do-not-transfer"}]`))
	}))
	defer srv.Close()

	c := client.New(client.Options{BaseURL: srv.URL, AnonKey: "anon", RestPrefix: "/"})
	Compare(context.Background(), c, probe.Result{}, Options{
		Relations:   []string{"invoices"},
		ElevatedKey: "elevated",
		SampleRows:  3,
		Concurrency: 2,
		Measure:     true,
	})

	if sampled.Len() > 0 {
		t.Errorf("the escalation compare requested rows while -measure was set: the mode "+
			"promises exposure is established without transferring any data, and this "+
			"path transferred it: %v", sampled.Entries())
	}
}
