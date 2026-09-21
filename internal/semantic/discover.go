package semantic

import (
	"context"
	"net/http"
	"time"
)

// probes are the ways a local model server identifies itself, and the
// completion endpoint each one wants afterwards.
//
// The pairing matters more than the detection. Ollama answers on both
// /api/generate and an OpenAI-compatible /v1/completions, and only the first
// returns logprobs -- the second accepts the parameter and silently drops it,
// which would leave the confidence gate with nothing to gate on. Discovering
// the server and then guessing its endpoint would find the wrong one.
var probes = []struct {
	path, completion string
}{
	{"/api/version", "/api/generate"}, // Ollama
	{"/health", "/completion"},        // llama.cpp server
	{"/v1/models", "/v1/completions"}, // LM Studio, vLLM, anything OpenAI-shaped
}

// DefaultHosts are the addresses a local model server listens on, in the order
// they are tried. Loopback only: this looks for something the operator is
// already running, and probing anything else would be a port scan of their
// network.
func DefaultHosts() []string {
	return []string{
		"http://127.0.0.1:11434", // Ollama
		"http://127.0.0.1:8080",  // llama.cpp server
		"http://127.0.0.1:1234",  // LM Studio
		"http://127.0.0.1:8000",  // vLLM
	}
}

// Discover returns the completion endpoint of the first local model server
// that answers, or "" when none does.
//
// Never called unless an operator asks for it. A scanner that started using a
// model because one happened to be listening would put statements in a report
// that nobody requested, and this feature's whole safety argument is that its
// output is separable from the proofs.
//
// Ordered rather than concurrent, and the order is the answer, so two machines
// running the same software make the same choice.
func Discover(hosts []string, timeout time.Duration) string {
	c := &http.Client{Timeout: timeout}
	for _, host := range hosts {
		for _, p := range probes {
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, host+p.path, nil)
			if err != nil {
				cancel()
				continue
			}
			resp, err := c.Do(req)
			if err != nil {
				cancel()
				continue
			}
			code := resp.StatusCode
			resp.Body.Close()
			cancel()
			if code == http.StatusOK {
				return host + p.completion
			}
		}
	}
	return ""
}
