package semantic_test

import (
	"context"
	"encoding/json"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/eppser/unruly/internal/semantic"
)

// Three servers, three response shapes, one readout.
//
// Measured against a real Ollama 0.34.2 on this machine: its OpenAI-compatible
// /v1/completions accepts `logprobs` and returns none, so a client that only
// knew that shape would gate on nothing -- which means running the model
// ungated, at the 12-22% false-positive rate the gate exists to prevent. Its
// native /api/generate does return them, under a different key.
func TestEveryDialectYieldsTheSameDistribution(t *testing.T) {
	ln := func(p float64) float64 { return math.Log(p) }
	for _, tc := range []struct {
		name string
		body map[string]any
	}{
		{"openai completions", map[string]any{"choices": []any{map[string]any{
			"logprobs": map[string]any{"top_logprobs": []any{
				map[string]float64{"B": ln(0.9), "Z": ln(0.1)}}}}}}},
		{"ollama native", map[string]any{"logprobs": []any{map[string]any{
			"top_logprobs": []any{
				map[string]any{"token": "B", "logprob": ln(0.9)},
				map[string]any{"token": "Z", "logprob": ln(0.1)}}}}}},
		{"llama.cpp native", map[string]any{"completion_probabilities": []any{map[string]any{
			"probs": []any{
				map[string]any{"tok_str": "B", "prob": 0.9},
				map[string]any{"tok_str": "Z", "prob": 0.1}}}}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_ = json.NewEncoder(w).Encode(tc.body)
			}))
			defer srv.Close()
			c, err := semantic.New(semantic.Options{Endpoint: srv.URL, Threshold: 0.8})
			if err != nil {
				t.Fatal(err)
			}
			got, err := c.Classify(context.Background(), "anschrift", []string{"Hauptstrasse 14"})
			if err != nil {
				t.Fatalf("%s: %v", tc.name, err)
			}
			if got.Class != "location" {
				t.Errorf("%s gave %q, want location", tc.name, got.Class)
			}
			if got.P < 0.89 || got.P > 0.91 {
				t.Errorf("%s gave p=%v, want ~0.9: the dialects must agree on the "+
					"number the gate is applied to", tc.name, got.P)
			}
		})
	}
}

// A server that returns a choice but no distribution must be REFUSED, not
// trusted.
//
// This is the failure Ollama's OpenAI endpoint actually produces: a letter
// arrives and no probability does. Taking the letter would run the model
// ungated, which on the measured benchmark means tagging 12% of ordinary
// columns as sensitive. Refusing is the only safe reading, and the message
// has to say what to do about it.
func TestAServerThatReturnsNoProbabilitiesIsRefused(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Exactly what Ollama 0.34.2 answers on /v1/completions.
		_ = json.NewEncoder(w).Encode(map[string]any{
			"choices": []any{map[string]any{"text": "B", "finish_reason": "length"}}})
	}))
	defer srv.Close()
	c, _ := semantic.New(semantic.Options{Endpoint: srv.URL, Threshold: 0.8})
	got, err := c.Classify(context.Background(), "anschrift", []string{"Hauptstrasse 14"})
	if err == nil {
		t.Fatal("a server with no logprobs was accepted; without a distribution the " +
			"gate cannot fire and the model runs unguarded")
	}
	if got.Class != "" {
		t.Errorf("classified %q with no probability behind it", got.Class)
	}
	for _, want := range []string{"logprob", "/api/generate"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %q; an operator hitting this needs to "+
				"know which endpoint to point at instead", err, want)
		}
	}
}

// The request body is chosen from the endpoint PATH, not sent in every shape
// at once.
//
// The first attempt sent all the dialects' knobs together, which cannot work:
// OpenAI's `logprobs` is how MANY to return and Ollama's is WHETHER to, so the
// same key is an integer in one dialect and a boolean in the other. A real
// Ollama answered `json: cannot unmarshal number into ... logprobs of type
// bool` and the unit tests did not notice, because the stubs decoded into
// permissive structs. The URL already names the server.
func TestTheRequestShapeFollowsTheEndpointPath(t *testing.T) {
	for _, tc := range []struct {
		name, path string
		check      func(t *testing.T, body map[string]any)
	}{
		{"openai", "/v1/completions", func(t *testing.T, b map[string]any) {
			if _, ok := b["logprobs"].(float64); !ok {
				t.Errorf("logprobs = %#v, want a number: OpenAI takes a count", b["logprobs"])
			}
			if b["max_tokens"] != float64(1) {
				t.Errorf("max_tokens = %v, want 1", b["max_tokens"])
			}
		}},
		{"ollama", "/api/generate", func(t *testing.T, b map[string]any) {
			if b["logprobs"] != true {
				t.Errorf("logprobs = %#v, want true: Ollama takes a boolean and 400s on a number", b["logprobs"])
			}
			if _, ok := b["top_logprobs"].(float64); !ok {
				t.Errorf("top_logprobs = %#v, want a number", b["top_logprobs"])
			}
			o, _ := b["options"].(map[string]any)
			if o == nil || o["num_predict"] != float64(1) {
				t.Errorf("options.num_predict = %#v, want 1: Ollama takes the limit there", o)
			}
		}},
		{"llama.cpp", "/completion", func(t *testing.T, b map[string]any) {
			if _, ok := b["n_probs"].(float64); !ok {
				t.Errorf("n_probs = %#v, want a number", b["n_probs"])
			}
			if b["n_predict"] != float64(1) {
				t.Errorf("n_predict = %v, want 1", b["n_predict"])
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var seen map[string]any
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_ = json.NewDecoder(r.Body).Decode(&seen)
				_ = json.NewEncoder(w).Encode(map[string]any{"choices": []any{map[string]any{
					"logprobs": map[string]any{"top_logprobs": []any{
						map[string]float64{"Z": math.Log(0.99)}}}}}})
			}))
			defer srv.Close()
			c, _ := semantic.New(semantic.Options{Endpoint: srv.URL + tc.path})
			if _, err := c.Classify(context.Background(), "x", []string{"y"}); err != nil {
				t.Fatal(err)
			}
			if seen == nil {
				t.Fatal("no request body captured")
			}
			tc.check(t, seen)
			if seen["temperature"] != float64(0) {
				if o, _ := seen["options"].(map[string]any); o == nil || o["temperature"] != float64(0) {
					t.Errorf("temperature is not zero in either place; sampling would make "+
						"the same column classify differently between runs: %#v", seen)
				}
			}
		})
	}
}

// Reasoning models must be told not to reason.
//
// Measured against Qwen3.5-4B on Ollama, which is the configuration this
// feature was built for. Without the flag the top token at the answer
// position is "Thinking" or "<think>" and the answer slots never appear at
// all: 5.3% recall and 96.2% false positives, against 90.2% and 12% for the
// same model read correctly. The readout depends on the next token BEING the
// answer, so a model that opens with a reasoning block has nothing to read.
//
// SemIf does this through the tokenizer -- apply_chat_template(...,
// enable_thinking=False) -- which is not reachable over HTTP. Ollama exposes
// it as `think`, and a server that does not know the field ignores it.
func TestReasoningIsDisabledForServersThatSupportIt(t *testing.T) {
	var seen map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&seen)
		_ = json.NewEncoder(w).Encode(map[string]any{"logprobs": []any{map[string]any{
			"top_logprobs": []any{map[string]any{"token": "Z", "logprob": -0.01}}}}})
	}))
	defer srv.Close()
	c, _ := semantic.New(semantic.Options{Endpoint: srv.URL + "/api/generate"})
	if _, err := c.Classify(context.Background(), "x", []string{"y"}); err != nil {
		t.Fatal(err)
	}
	if seen["think"] != false {
		t.Errorf("think = %#v, want false. A reasoning model emits a thinking block "+
			"where the answer should be, and the readout reads that block's first "+
			"token instead of a class", seen["think"])
	}
	// The chat template must still be applied: raw:true skips it, and then the
	// prompt does not end at the assistant turn, so the next token is a
	// newline rather than an answer.
	if seen["raw"] == true {
		t.Error("raw is true; without the chat template the next token is whitespace, " +
			"not the answer slot")
	}
}
