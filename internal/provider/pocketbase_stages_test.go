package provider

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/eppser/unruly/scan"
)

// A detected PocketBase instance contributes stages that produce a report.
//
// This is the end of the seam: detection alone identifies a backend, and
// Staged is what turns that identification into work the pipeline can run
// without main knowing anything about PocketBase.
func TestADetectedPocketBaseContributesAWorkingStage(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(r.URL.Path, "/leaky/") {
			_, _ = w.Write([]byte(`{"items":[{"id":"a1","card":"4111111111111111"}],"totalItems":1}`))
			return
		}
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"message":"Only superusers can perform this action.","status":403}`))
	}))
	defer srv.Close()

	d := Detection{Provider: "pocketbase", Project: srv.URL}
	stages := StagesFor(d, scan.Inputs{Seeds: []string{"leaky", "locked"}, Client: testSeamClient(srv.URL)})
	if len(stages) == 0 {
		t.Fatal("a detected PocketBase contributed no stages, so a scan of it would " +
			"identify the backend and then say nothing about it")
	}

	st := &scan.State{Target: srv.URL}
	if _, err := scan.Pipeline(stages).Run(context.Background(), st); err != nil {
		t.Fatal(err)
	}

	var found bool
	for _, f := range st.Findings() {
		if f.ID == "pocketbase-anon-read-exposed" && f.Resource == "leaky" {
			found = true
			if len(f.Evidence.Sample) == 0 {
				t.Error("the finding carries no rows")
			}
		}
	}
	if !found {
		t.Errorf("the contributed stage found nothing against a leaking collection: %+v",
			st.Findings())
	}
}

// The operator's choices reach the stage.
//
// Stages(Detection) alone could only build stages that need nothing but the
// identification, which is true of no real stage: every one of them needs the
// candidate names discovered upstream and the flags the operator set. A seam
// that cannot carry those forces each provider to reach around it, which is
// how the orchestration ended up in main the first time.
func TestTheOperatorsInputsReachTheContributedStage(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"items":[{"id":"a1","card":"4111111111111111"}],"totalItems":1}`))
	}))
	defer srv.Close()

	d := Detection{Provider: "pocketbase", Project: srv.URL}
	st := &scan.State{Target: srv.URL}
	stages := StagesFor(d, scan.Inputs{Seeds: []string{"anything"}, Redact: true, Client: testSeamClient(srv.URL)})
	if _, err := scan.Pipeline(stages).Run(context.Background(), st); err != nil {
		t.Fatal(err)
	}
	for _, f := range st.Findings() {
		if len(f.Evidence.Sample) != 0 {
			t.Errorf("-redact was set and the finding still carries sampled values: %v",
				f.Evidence.Sample)
		}
		if f.ID == "pocketbase-anon-read-exposed" &&
			!strings.Contains(f.Evidence.Reason, "card") {
			t.Errorf("redaction removed the values AND the column names, leaving a "+
				"finding a reader cannot act on: %q", f.Evidence.Reason)
		}
	}
}

// A provider with no seeds to work from still contributes, and says nothing
// rather than inventing names.
func TestNoSeedsMeansNoClaims(t *testing.T) {
	d := Detection{Provider: "pocketbase", Project: "http://127.0.0.1:1"}
	st := &scan.State{Target: d.Project}
	stages := StagesFor(d, scan.Inputs{Client: testSeamClient(d.Project)})
	if _, err := scan.Pipeline(stages).Run(context.Background(), st); err != nil {
		t.Fatal(err)
	}
	for _, f := range st.Findings() {
		if f.ID == "pocketbase-anon-read-exposed" {
			t.Errorf("claimed an exposure with no candidates supplied: %+v", f)
		}
	}
}
