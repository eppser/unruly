package semantic_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/eppser/unruly/internal/semantic"
)

// auto picks the model that WORKS, measured on the spot.
//
// The first two attempts both guessed. "Largest wins" chose a 27.9B fine-tune
// that scored 0% recall over a 4.7B model that scored 100%. An allowlist of
// families I happened to test is worse: it is overfit to one laptop, and on a
// machine running mistral or llama it flags everything as unknown and helps
// nobody.
//
// Neither is automatic. A handful of probes with known answers is: it costs a
// few seconds once, works for any model on any machine, and needs no list to
// stay current.
func TestCalibrationPicksTheModelThatAnswersCorrectly(t *testing.T) {
	// good answers the probes; lazy says "none" to everything, which is how a
	// model that cannot do this task actually fails.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/tags" {
			_ = json.NewEncoder(w).Encode(map[string]any{"models": []any{
				map[string]any{"name": "lazy:30b", "details": map[string]any{"parameter_size": "30B"}},
				map[string]any{"name": "good:4b", "details": map[string]any{"parameter_size": "4B"}},
			}})
			return
		}
		var req struct {
			Model  string `json:"model"`
			Prompt string `json:"prompt"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		slot := "Z"
		if req.Model == "good:4b" {
			slot = semantic.SlotFor(semantic.ProbeAnswer(req.Prompt))
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"logprobs": []any{map[string]any{
			"top_logprobs": []any{map[string]any{"token": slot, "logprob": -0.01}}}}})
	}))
	defer srv.Close()

	got, warn := semantic.PickModel(srv.URL, 10*time.Second)
	if got != "good:4b" {
		t.Errorf("picked %q, want good:4b. The 30B model answers \"none\" to every "+
			"probe, which is exactly how an unsuitable model fails here -- and it is "+
			"six times larger, so any size rule picks it", got)
	}
	if warn != "" {
		t.Errorf("warned %q about a model that passed calibration", warn)
	}
}

// When nothing passes, say so rather than returning a model that will report
// nothing and leave the operator wondering.
func TestCalibrationWarnsWhenNoModelCanDoIt(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/tags" {
			_ = json.NewEncoder(w).Encode(map[string]any{"models": []any{
				map[string]any{"name": "useless:7b", "details": map[string]any{"parameter_size": "7B"}}}})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"logprobs": []any{map[string]any{
			"top_logprobs": []any{map[string]any{"token": "Z", "logprob": -0.01}}}}})
	}))
	defer srv.Close()
	got, warn := semantic.PickModel(srv.URL, 10*time.Second)
	if warn == "" {
		t.Error("no warning when every model failed calibration; the operator would " +
			"get an empty model_classes and no reason for it")
	}
	if !strings.Contains(warn, "useless:7b") {
		t.Errorf("warning %q does not name what was tried", warn)
	}
	_ = got
}

// The probe set has to contain both, or a model that says "none" to everything
// scores perfectly on positives-only and a model that says "pii" to everything
// scores perfectly on negatives-only.
func TestTheProbeSetContainsPositivesAndNegatives(t *testing.T) {
	var pos, neg int
	for _, p := range semantic.Probes() {
		if p.Want == "" {
			neg++
		} else {
			pos++
		}
	}
	if pos < 2 || neg < 2 {
		t.Errorf("%d positives and %d negatives; both halves are needed or a model "+
			"that answers the same thing every time passes", pos, neg)
	}
}
