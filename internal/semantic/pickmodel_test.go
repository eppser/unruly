package semantic_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/eppser/unruly/internal/semantic"
	"github.com/eppser/unruly/internal/testrec"
)

// tagsServer answers the model listing and the calibration probes, with each
// named model answering correctly or not.
func tagsServer(t *testing.T, models map[string]bool, sizes map[string]string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/tags" {
			var list []any
			for n := range models {
				list = append(list, map[string]any{"name": n,
					"details": map[string]any{"parameter_size": sizes[n]}})
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"models": list})
			return
		}
		var req struct {
			Model  string `json:"model"`
			Prompt string `json:"prompt"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		slot := "Z"
		if models[req.Model] {
			slot = semantic.SlotFor(semantic.ProbeAnswer(req.Prompt))
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"logprobs": []any{map[string]any{
			"top_logprobs": []any{map[string]any{"token": slot, "logprob": -0.01}}}}})
	}))
	t.Cleanup(srv.Close)
	return srv
}

// Size does not decide, and it used to.
//
// This file previously asserted "largest installed model wins", generalising
// from a size ladder measured WITHIN one family to a rule about size in
// general. Measured across families it is false:
//
//	qwen3.5:4b     4.7B   100.0% recall   332ms
//	glimmer-eval  27.9B     0.0% recall  2124ms
//
// Those assertions are deleted rather than adjusted, because the rule they
// pinned was wrong, not miscalibrated. What replaces them is a measurement.
func TestTheModelThatAnswersCorrectlyWinsRegardlessOfSize(t *testing.T) {
	srv := tagsServer(t,
		map[string]bool{"huge-but-useless:30b": false, "small-but-good:4b": true},
		map[string]string{"huge-but-useless:30b": "30B", "small-but-good:4b": "4B"})
	got, warn := semantic.PickModel(srv.URL, 5*time.Second)
	if got != "small-but-good:4b" {
		t.Errorf("picked %q; the 30B model answers \"none\" to every probe, which is "+
			"how an unsuitable model fails here, and every size rule prefers it", got)
	}
	if warn != "" {
		t.Errorf("warned %q about a model that answered every probe", warn)
	}
}

func TestNoUsableModelIsReportedRatherThanHidden(t *testing.T) {
	srv := tagsServer(t, map[string]bool{"useless:7b": false}, map[string]string{"useless:7b": "7B"})
	_, warn := semantic.PickModel(srv.URL, 5*time.Second)
	if warn == "" {
		t.Fatal("no warning when every candidate failed; the operator gets an empty " +
			"model_classes and no reason for it")
	}
	if !strings.Contains(warn, "useless:7b") {
		t.Errorf("warning %q does not name what was tried", warn)
	}
}

func TestAServerThatListsNoModelsSaysSo(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"models": []any{}})
	}))
	defer srv.Close()
	got, warn := semantic.PickModel(srv.URL, 2*time.Second)
	if got != "" {
		t.Errorf("picked %q from an empty server", got)
	}
	if warn == "" {
		t.Error("llama.cpp serves one model and needs no name, so an empty pick is not " +
			"always an error -- the caller has to be able to tell the cases apart")
	}
}

func TestParameterSizeOnlyOrdersTheSearch(t *testing.T) {
	// Both models work, so the first tried stands and nothing else is loaded.
	// That is the smallest above the floor: equal capability, a fraction of
	// the per-column cost, and no reason to pay for a 30B load.
	srv := tagsServer(t,
		map[string]bool{"big:30b": true, "small:4b": true},
		map[string]string{"big:30b": "30B", "small:4b": "4B"})
	if got, _ := semantic.PickModel(srv.URL, 5*time.Second); got != "small:4b" {
		t.Errorf("picked %q; with both passing, the cheapest that works should stand", got)
	}
}

// Candidates are tried SMALLEST first that still clears the floor.
//
// Largest-first was the first ordering and it is expensive in the wrong place.
// Measured on this machine: calibrating largest-first took 54 seconds, most of
// it loading a 17GB model, and chose one that runs at 2712ms per column
// against 332ms for a 4.7B that scores the same:
//
//	qwen3.5:4b     4.7B   100.0% recall  10.0% FP   332ms
//	qwen-eval     27.3B    97.5% recall   7.5% FP  2712ms
//
// The big model is marginally more precise and eight times slower, and a scan
// pays that per column while calibration is paid once. Smallest-first finds a
// working model sooner, loads faster, and leaves the fast one selected.
//
// The floor still applies: below about 4B the readout stops working at all, so
// those are tried last rather than first.
func TestCandidatesAreTriedSmallestFirstAboveTheFloor(t *testing.T) {
	// internal/testrec, not a bare slice: httptest serves each connection on
	// its own goroutine, so a handler appending to a captured slice is a data
	// race -- which the repo's handler audit catches, and did.
	var order testrec.Log
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/tags" {
			_ = json.NewEncoder(w).Encode(map[string]any{"models": []any{
				map[string]any{"name": "huge:30b", "details": map[string]any{"parameter_size": "30B"}},
				map[string]any{"name": "tiny:1b", "details": map[string]any{"parameter_size": "1B"}},
				map[string]any{"name": "right:4b", "details": map[string]any{"parameter_size": "4B"}},
			}})
			return
		}
		var req struct {
			Model, Prompt string
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		if order.Last() != req.Model {
			order.Add(req.Model)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"logprobs": []any{map[string]any{
			"top_logprobs": []any{map[string]any{
				"token": semantic.SlotFor(semantic.ProbeAnswer(req.Prompt)), "logprob": -0.01}}}}})
	}))
	defer srv.Close()

	got, _ := semantic.PickModel(srv.URL, 5*time.Second)
	if got != "right:4b" {
		t.Errorf("picked %q, want right:4b -- the smallest model above the floor, and "+
			"the cheapest per column of the three", got)
	}
	tried := order.Entries()
	if len(tried) == 0 || tried[0] != "right:4b" {
		t.Errorf("tried %v first; the smallest model above the floor loads fastest and "+
			"is usually enough, so paying a 17GB load first is cost in the wrong place", tried)
	}
	for _, m := range tried {
		if m == "tiny:1b" {
			t.Error("tried tiny:1b; below the floor a model cannot decline and is not " +
				"a candidate worth a load")
		}
	}
}
