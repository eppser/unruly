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

// Discovery runs only when asked for, and names the endpoint it found.
//
// "Off by default" has to survive this feature: a scanner that starts talking
// to a model because one happened to be listening would be a surprise, and the
// surprise would land in a report. So -classifier auto is a request, not a
// default, and nothing probes until an operator types it.
func TestDiscoveryFindsEachServerAtItsOwnEndpoint(t *testing.T) {
	for _, tc := range []struct {
		name, probe, want string
		body              any
	}{
		{"ollama", "/api/version", "/api/generate", map[string]string{"version": "0.34.2"}},
		{"llama.cpp", "/health", "/completion", map[string]string{"status": "ok"}},
		{"openai-compatible", "/v1/models", "/v1/completions",
			map[string]any{"data": []any{map[string]string{"id": "qwen"}}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != tc.probe {
					http.NotFound(w, r)
					return
				}
				_ = json.NewEncoder(w).Encode(tc.body)
			}))
			defer srv.Close()
			got := semantic.Discover([]string{srv.URL}, 2*time.Second)
			if got == "" {
				t.Fatalf("%s server at %s was not found", tc.name, srv.URL)
			}
			if !strings.HasSuffix(got, tc.want) {
				t.Errorf("found %q, want an endpoint ending %q -- the completion path "+
					"differs per server and the wrong one returns no logprobs", got, tc.want)
			}
		})
	}
}

func TestDiscoveryReturnsNothingWhenNoServerIsListening(t *testing.T) {
	// A closed port, not a slow one: discovery must not become a delay an
	// operator pays for on every scan.
	start := time.Now()
	got := semantic.Discover([]string{"http://127.0.0.1:1"}, 500*time.Millisecond)
	if got != "" {
		t.Errorf("found %q with nothing listening", got)
	}
	if el := time.Since(start); el > 3*time.Second {
		t.Errorf("took %v to give up on one dead host", el)
	}
}

func TestDiscoveryPrefersTheEarlierCandidate(t *testing.T) {
	// Two servers, both valid. The order of DefaultHosts is the answer, so two
	// machines with the same software make the same choice.
	mk := func() *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/api/version" {
				_ = json.NewEncoder(w).Encode(map[string]string{"version": "x"})
				return
			}
			http.NotFound(w, r)
		}))
	}
	a, b := mk(), mk()
	defer a.Close()
	defer b.Close()
	if got := semantic.Discover([]string{a.URL, b.URL}, time.Second); !strings.HasPrefix(got, a.URL) {
		t.Errorf("got %q, want the first candidate %q", got, a.URL)
	}
}

func TestTheDefaultHostListCoversTheCommonServers(t *testing.T) {
	want := map[string]bool{"11434": false, "8080": false, "1234": false, "8000": false}
	for _, h := range semantic.DefaultHosts() {
		for p := range want {
			if strings.Contains(h, p) {
				want[p] = true
			}
		}
	}
	for p, ok := range want {
		if !ok {
			t.Errorf("port %s is not probed; that is where one of Ollama, llama.cpp, "+
				"LM Studio or vLLM listens by default", p)
		}
	}
}
