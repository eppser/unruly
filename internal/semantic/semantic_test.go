package semantic_test

import (
	"context"
	"encoding/json"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/eppser/unruly/internal/semantic"
)

// A stub model server speaking the completions shape unruly asks for.
//
// It returns the probability the test names, at the answer slot the test names,
// so the gating and merge rules can be graded without a model on the machine.
func stubModel(t *testing.T, letter string, p float64) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			MaxTokens   int     `json:"max_tokens"`
			Temperature float64 `json:"temperature"`
			Logprobs    int     `json:"logprobs"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		// The readout is the whole technique: exactly one token, no sampling.
		// A server asked to generate prose would make the result a parse.
		if req.MaxTokens != 1 {
			t.Errorf("max_tokens %d, want 1: this reads a logit, it does not generate", req.MaxTokens)
		}
		if req.Temperature != 0 {
			t.Errorf("temperature %v, want 0: sampling makes the same column classify differently between runs", req.Temperature)
		}
		if req.Logprobs < 2 {
			t.Errorf("logprobs %d: without the distribution there is nothing to gate on", req.Logprobs)
		}
		// All remaining mass goes to a DECLARED slot. The classifier
		// renormalises over the declared slots -- SemIf's technique, and the
		// reason the number means "among these options" -- so a stub that
		// parked mass on an undeclared letter would inflate the answer's
		// probability and make the gate look broken. It did, on the first run:
		// 0.79 came back as 0.85 and cleared a 0.80 gate.
		_ = json.NewEncoder(w).Encode(map[string]any{"choices": []any{map[string]any{
			"logprobs": map[string]any{"top_logprobs": []any{map[string]float64{
				letter: lnf(p), "Z": lnf(1 - p),
			}}},
		}}})
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestTheModelIsOffUnlessAnEndpointIsGiven(t *testing.T) {
	c, err := semantic.New(semantic.Options{})
	if err != nil {
		t.Fatalf("an unconfigured classifier must construct, not fail: %v", err)
	}
	if c.Enabled() {
		t.Error("enabled with no endpoint configured; this feature is off by default " +
			"and a scan that silently started calling a model would be a surprise")
	}
	got, err := c.Classify(context.Background(), "anschrift", []string{"Hauptstrasse 14, Berlin"})
	if err != nil {
		t.Errorf("a disabled classifier must be a no-op, not an error: %v", err)
	}
	if got.Class != "" {
		t.Errorf("disabled classifier returned %q", got.Class)
	}
}

func TestTheGateIsAppliedToTheModelsOwnProbability(t *testing.T) {
	for _, tc := range []struct {
		name      string
		p, thresh float64
		want      string
	}{
		{"clearly above the gate", 0.95, 0.80, "location"},
		{"exactly at the gate", 0.80, 0.80, "location"},
		{"below the gate", 0.79, 0.80, ""},
		{"far below", 0.20, 0.80, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// "location" is slot B in the declared order.
			srv := stubModel(t, "B", tc.p)
			c, err := semantic.New(semantic.Options{Endpoint: srv.URL, Threshold: tc.thresh})
			if err != nil {
				t.Fatal(err)
			}
			got, err := c.Classify(context.Background(), "anschrift", []string{"Hauptstrasse 14"})
			if err != nil {
				t.Fatal(err)
			}
			if got.Class != tc.want {
				t.Errorf("p=%v threshold=%v gave %q, want %q. The gate is the only thing "+
					"between a 12%% false-positive rate and a severity column nobody trusts",
					tc.p, tc.thresh, got.Class, tc.want)
			}
		})
	}
}

func TestAnUnreachableModelDoesNotFailTheScan(t *testing.T) {
	c, err := semantic.New(semantic.Options{Endpoint: "http://127.0.0.1:1", Timeout: 200 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	got, err := c.Classify(context.Background(), "anschrift", []string{"x"})
	if err == nil {
		t.Error("a dead endpoint must report an error so the scan can say the surface " +
			"was not assessed, rather than reporting it as clean")
	}
	if got.Class != "" {
		t.Errorf("classified %q from an unreachable model", got.Class)
	}
}

func TestTheSameColumnClassifiesIdenticallyTwice(t *testing.T) {
	srv := stubModel(t, "B", 0.91)
	c, _ := semantic.New(semantic.Options{Endpoint: srv.URL, Threshold: 0.8})
	a, _ := c.Classify(context.Background(), "anschrift", []string{"Hauptstrasse 14"})
	b, _ := c.Classify(context.Background(), "anschrift", []string{"Hauptstrasse 14"})
	if a != b {
		t.Errorf("two runs gave %+v and %+v; byte-identical output between runs is a "+
			"published property of this scanner and the model path must not cost it", a, b)
	}
}

func TestEveryClassInTheTaxonomyGetsItsOwnSlot(t *testing.T) {
	// A prompt that declares fewer slots than the taxonomy has classes silently
	// makes some classes unreachable, which is the SemIf 16-option ceiling
	// arriving by the back door.
	if n := len(semantic.Classes()); n < 7 {
		t.Fatalf("%d classes declared; the rule taxonomy alone has seven", n)
	}
	seen := map[string]bool{}
	for _, c := range semantic.Classes() {
		if seen[c.Slot] {
			t.Errorf("slot %q is used twice; two classes reading the same logit cannot be told apart", c.Slot)
		}
		seen[c.Slot] = true
		if len(c.Slot) != 1 {
			t.Errorf("slot %q is not a single token", c.Slot)
		}
		if strings.TrimSpace(c.Description) == "" {
			t.Errorf("class %q has no criteria text; the model is asked to choose between labels it cannot read", c.Name)
		}
	}
}

// lnf is the natural log, for building stub logprobs from probabilities.
func lnf(p float64) float64 {
	if p <= 0 {
		return -100
	}
	return math.Log(p)
}

// The prompt must demand a bare letter, or probability leaks to prose.
//
// Measured against Qwen3.5-4B. Without the instruction the top token for a
// column called national_id is "The" -- the model starting a sentence -- with
// the correct slot second. Renormalised over the declared slots that is 0.649,
// under the 0.80 gate, so a correct answer is discarded as unconfident. With
// the instruction the same column reads 0.978.
//
// This is what the 20-point gap against the reference implementation turned
// out to be: not quantization, not the criteria text, but a prompt that let
// the model answer in prose.
func TestThePromptDemandsABareLetter(t *testing.T) {
	c, err := semantic.New(semantic.Options{Endpoint: "http://example.invalid/v1/completions"})
	if err != nil {
		t.Fatal(err)
	}
	body := c.Request("anschrift", []string{"Hauptstrasse 14"})
	p, _ := body["prompt"].(string)
	if p == "" {
		t.Fatal("no prompt in the request body")
	}
	low := strings.ToLower(p)
	if !strings.Contains(low, "one letter") {
		t.Errorf("the prompt does not ask for one letter, so the model answers in prose "+
			"and the correct slot loses the mass that would clear the gate:\n%s", p)
	}
	if !strings.Contains(low, "nothing else") {
		t.Errorf("the prompt does not forbid anything but the letter:\n%s", p)
	}
}
