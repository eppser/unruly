package provider

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/eppser/unruly/internal/client"
)

// The budget must not silently eat the names the operator asked for.
//
// Found the hard way. The Firebase lab deploys publicEcho and privateControl;
// the cross-check supplied both and the scan reported only the second. Nothing
// was broken in the probe: functionCandidates sorts and truncates at
// maxFunctionProbes, the vocabulary harvested from the page contributed thirty
// tokens of config-key noise (apiKey, apikey, doctype, juw, the API key
// itself), privateControl landed at position 25 and publicEcho at 28. One
// survived the cut by a single position and the other did not.
//
// A dropped name is indistinguishable from a function that is not deployed,
// because both produce no finding. So the cap turned a live, world-callable
// function into silence -- the exact failure this scanner exists to refuse,
// arriving through a budget rather than through a bug.
func TestSuppliedFunctionNamesOutrankHarvestedNoise(t *testing.T) {
	// More harvested noise than the budget allows, all sorting before the
	// supplied name, exactly as real config-key tokens did.
	var noise []string
	for i := 0; i < maxFunctionProbes+10; i++ {
		noise = append(noise, fmt.Sprintf("aaa%02d", i))
	}
	got, dropped := functionCandidates([]string{"publicEcho"}, noise)
	if len(got) > maxFunctionProbes {
		t.Fatalf("%d candidates exceeds the budget of %d", len(got), maxFunctionProbes)
	}
	var found bool
	for _, g := range got {
		if g == "publicEcho" {
			found = true
		}
	}
	if !found {
		t.Errorf("the operator supplied publicEcho and the budget dropped it for harvested "+
			"noise (%v). A name an operator asserts is not a guess, and a dropped name "+
			"looks exactly like a function that is not deployed", got)
	}
	if dropped == 0 {
		t.Errorf("%d name(s) were cut and the count came back 0, so nothing downstream "+
			"can report the bound", len(noise)+1-len(got))
	}
}

// A bounded search must say it was bounded.
//
// The repo's rule everywhere else: absence of a finding is only evidence when
// the scan could see. A cap that trims candidates without a word makes a
// partial scan read as a complete one.
func TestFunctionBudgetReportsWhatItCouldNotCall(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	functionHostOverride = srv.URL
	t.Cleanup(func() { functionHostOverride = "" })

	var many []string
	for i := 0; i < maxFunctionProbes+7; i++ {
		many = append(many, fmt.Sprintf("fn%02d", i))
	}
	fs := functionFindings(context.Background(),
		Detection{Provider: "firebase", Project: "p"},
		ScanOptions{
			Client:    client.New(client.Options{BaseURL: srv.URL, Retries: 0}),
			Harvested: many, Invoke: true,
		})
	var said bool
	for _, f := range fs {
		if strings.Contains(f.Description, "7") && strings.Contains(strings.ToLower(f.Description), "budget") {
			said = true
		}
	}
	if !said {
		var ids []string
		for _, f := range fs {
			ids = append(ids, f.ID+":"+f.Resource)
		}
		t.Errorf("the scan called %d of %d names and reported no bound (%v). A silent cap "+
			"makes a partial answer look like a whole one", maxFunctionProbes, len(many), ids)
	}
}
