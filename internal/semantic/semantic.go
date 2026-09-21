// Package semantic asks a local model about the columns the rules cannot read.
//
// internal/classify is structural: a card number must pass Luhn and carry a
// real issuer prefix, an IBAN must satisfy mod-97. That design is why it works
// in twenty-five languages without reading a single column name, and it is also
// why it is blind to a street address, a diagnosis or a private message, which
// carry nothing checkable. Measured against a 550-case set across 22 data
// classes, the rules recover 14.9% and never once tag an ordinary column.
//
// This package closes part of that gap WITHOUT touching the part that works.
// Three rules govern it, and each is enforced by a test rather than by care:
//
//  1. The rules are authoritative. A class the rules produced is never removed
//     or overridden. The model is consulted only where they said nothing.
//  2. A class arrives only above a probability gate. Ungated, the best model
//     measured tags 12% of ordinary columns as sensitive.
//  3. Everything it produces is marked model-derived, so an operator can tell
//     a proof from an opinion.
//
// WHY HTTP AND NOT AN EMBEDDED MODEL. unruly is one static binary, built with
// CGO_ENABLED=0 for five platforms, and release-check fails the build if a
// binary comes out dynamically linked. llama.cpp and onnxruntime both need cgo,
// which would end cross-compilation; a 4B transformer in pure Go is not
// realistic. So the model runs where the user already runs models, and this
// speaks the OpenAI completions shape that llama.cpp's server, Ollama, LM
// Studio and vLLM all answer. Nothing is downloaded, nothing is vendored, and
// the feature is off until an endpoint is configured.
//
// THE READOUT. One forward pass, one token, no sampling. The prompt ends at an
// answer slot, each class owns a single-token letter, and the probabilities
// come from the logits at that one position. No answer sentence is generated
// and nothing is parsed out of prose, which is what makes the result
// reproducible and what makes the gate mean something.
package semantic

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"sort"
	"strings"
	"time"
)

// Class is one answer slot: a taxonomy name, the single token that stands for
// it, and the criteria the model is given.
type Class struct {
	Name        string
	Slot        string
	Description string
}

// classes are ordered, and the order is the slot assignment. Adding one in the
// middle would renumber the rest, so new classes go on the end.
var classes = []Class{
	{"credential", "A", "secret material: password, password hash, API key, access token, private key, recovery code"},
	{"location", "B", "where a person is or lives: street address, postal address, coordinates"},
	{"health", "C", "medical or biological data: diagnosis, medication, allergy, blood type, genetic result"},
	{"pii", "D", "a personal attribute of an identifiable person: full name, date of birth, gender, nationality, ethnicity, religion, political affiliation, union membership, sexual orientation"},
	{"contact", "E", "a way to reach a person: email address, phone number, messaging handle"},
	{"financial", "F", "payment instrument or bank account: card number, IBAN, account number, salary amount"},
	{"government-id", "G", "state-issued identifier or status: national ID, passport, tax ID, social security number, visa"},
	{"communications", "H", "the content of private correspondence: message body, chat text, direct message, private note"},
	{"device-id", "I", "an identifier for a device or session: IP address, device ID, advertising ID, cookie ID, user agent"},
	{"behavioural", "J", "a record of what a person did: search query, page view, watch history, purchase history"},
	{"media-file", "K", "a reference to a file a person uploaded: avatar path, document URL, photo key, attachment name"},
	{"employment", "L", "the employment relationship: job title, employer, performance review, disciplinary record"},
	{"education", "M", "educational record: school, degree, grade, transcript, enrolment status"},
	{"biometric", "N", "a biological measurement used to identify someone: fingerprint template, face embedding, voiceprint"},
	{"criminal", "O", "criminal convictions, offences, charges, or background-check results"},
	{"none", "Z", "ordinary application data with nothing personal or secret in it: product text, order references, prices, status values, timestamps, technical identifiers, logs"},
}

// Classes returns the declared answer slots.
func Classes() []Class { return classes }

// Result is what the model said, and how strongly.
type Result struct {
	Class string
	P     float64
}

// Options configure the classifier. A zero Options is a disabled classifier,
// which is the default and must stay a working no-op.
type Options struct {
	Endpoint  string        // e.g. http://127.0.0.1:8080/v1/completions
	Model     string        // passed through; llama.cpp ignores it, Ollama needs it
	Threshold float64       // minimum probability for a class to be reported
	Timeout   time.Duration // per request
	Client    *http.Client
}

// DefaultThreshold is where the measured false-positive rate stops being worth
// the recall. On the 22-class benchmark the best model tested tagged 12% of
// ordinary columns ungated; the gate is what buys that back.
const DefaultThreshold = 0.80

// Classifier asks the model, or declines to.
type Classifier struct {
	opt    Options
	prompt string
}

// New builds a classifier. An empty Endpoint is not an error: it is the off
// switch, and every caller has to work without a model anyway.
func New(opt Options) (*Classifier, error) {
	if opt.Threshold == 0 {
		opt.Threshold = DefaultThreshold
	}
	if opt.Timeout == 0 {
		opt.Timeout = 20 * time.Second
	}
	if opt.Client == nil {
		opt.Client = &http.Client{Timeout: opt.Timeout}
	}
	if opt.Endpoint != "" && !strings.HasPrefix(opt.Endpoint, "http") {
		return nil, fmt.Errorf("endpoint %q is not an http url", opt.Endpoint)
	}
	var b strings.Builder
	b.WriteString("A column was read from a database table. Given its name and the " +
		"values sampled from it, choose the single class of sensitive data it holds.\n\n")
	for _, c := range classes {
		fmt.Fprintf(&b, "%s. %s\n", c.Slot, c.Description)
	}
	return &Classifier{opt: opt, prompt: b.String()}, nil
}

// Enabled reports whether a model will actually be asked.
func (c *Classifier) Enabled() bool { return c.opt.Endpoint != "" }

// apiResponse covers the three shapes a local model server actually answers
// with. Measured rather than assumed, on this machine:
//
//	OpenAI /v1/completions   choices[0].logprobs.top_logprobs[0]  map of token->logprob
//	                         vLLM and LM Studio return this. Ollama ACCEPTS the
//	                         logprobs parameter on this endpoint and returns
//	                         none, which is the failure this struct exists to
//	                         notice rather than to paper over.
//	Ollama /api/generate     logprobs[0].top_logprobs[]           list of {token, logprob}
//	llama.cpp /completion    completion_probabilities[0].probs[]  list of {tok_str, prob}
//
// A server that answers in none of these shapes has given us a letter with no
// probability behind it, and the gate is the only thing making this feature
// safe to run.
type apiResponse struct {
	// OpenAI
	Choices []struct {
		Logprobs struct {
			TopLogprobs []map[string]float64 `json:"top_logprobs"`
		} `json:"logprobs"`
	} `json:"choices"`
	// Ollama native
	Logprobs []struct {
		TopLogprobs []struct {
			Token   string  `json:"token"`
			Logprob float64 `json:"logprob"`
		} `json:"top_logprobs"`
	} `json:"logprobs"`
	// llama.cpp native
	CompletionProbabilities []struct {
		Probs []struct {
			TokStr string  `json:"tok_str"`
			Prob   float64 `json:"prob"`
		} `json:"probs"`
	} `json:"completion_probabilities"`
}

// weights returns token -> unnormalised weight, in whichever dialect the
// server answered, or nil when it gave no distribution at all.
func (r apiResponse) weights() map[string]float64 {
	out := map[string]float64{}
	if len(r.Choices) > 0 && len(r.Choices[0].Logprobs.TopLogprobs) > 0 {
		for tok, lp := range r.Choices[0].Logprobs.TopLogprobs[0] {
			out[tok] = math.Exp(lp)
		}
	}
	if len(out) == 0 && len(r.Logprobs) > 0 {
		for _, e := range r.Logprobs[0].TopLogprobs {
			out[e.Token] = math.Exp(e.Logprob)
		}
	}
	if len(out) == 0 && len(r.CompletionProbabilities) > 0 {
		for _, e := range r.CompletionProbabilities[0].Probs {
			out[e.TokStr] = e.Prob
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// Classify returns the model's class for one column, or an empty Result when
// it is disabled, declines, or falls below the gate.
func (c *Classifier) Classify(ctx context.Context, column string, values []string) (Result, error) {
	if !c.Enabled() {
		return Result{}, nil
	}
	body, err := json.Marshal(c.request(column, values))
	if err != nil {
		return Result{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.opt.Endpoint, bytes.NewReader(body))
	if err != nil {
		return Result{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.opt.Client.Do(req)
	if err != nil {
		return Result{}, fmt.Errorf("classifier endpoint: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return Result{}, fmt.Errorf("classifier endpoint: HTTP %d", resp.StatusCode)
	}
	var out apiResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return Result{}, fmt.Errorf("classifier endpoint: %w", err)
	}
	w := out.weights()
	if w == nil {
		return Result{}, fmt.Errorf("classifier endpoint returned a token but no logprobs, " +
			"so the confidence gate cannot be applied and the model would run unguarded. " +
			"Ollama's OpenAI-compatible /v1/completions accepts the parameter and returns " +
			"nothing: point -classifier at its native /api/generate instead, or use " +
			"llama.cpp's server")
	}
	return c.pick(w), nil
}

// request builds the body for the dialect the endpoint PATH names.
//
// Sending every dialect's knobs together was the first attempt and cannot
// work: OpenAI's `logprobs` is how MANY logprobs to return and Ollama's is
// WHETHER to return them, so the same key is a number in one dialect and a
// boolean in the other. A real Ollama answered
//
//	json: cannot unmarshal number into Go struct field GenerateRequest.logprobs of type bool
//
// and no unit test caught it, because stubs decode into permissive structs.
// The URL already says which server this is, so it chooses.
//
// Temperature is zero in whichever place the dialect reads it. Sampling would
// make the same column classify differently between runs, and byte-identical
// output is a published property of this scanner.
func (c *Classifier) request(column string, values []string) map[string]any {
	prompt := c.render(column, values)
	n := len(classes)
	switch {
	case strings.Contains(c.opt.Endpoint, "/api/generate"):
		return map[string]any{
			"model": c.opt.Model, "prompt": prompt, "stream": false,
			"logprobs": true, "top_logprobs": n,
			// Reasoning off. Measured against Qwen3.5-4B: with it on, the top
			// token at the answer position is "Thinking" and no answer slot
			// appears -- 5.3% recall and 96.2% false positives, against 90.2%
			// and 12% for the same model read correctly. The readout depends
			// on the next token BEING the answer, and a model that opens with
			// a reasoning block has nothing there to read.
			//
			// Not raw: the chat template has to be applied, because it is what
			// ends the prompt at the assistant turn. Without it the next token
			// is a newline.
			"think":   false,
			"options": map[string]any{"num_predict": 1, "temperature": 0},
		}
	case strings.Contains(c.opt.Endpoint, "/completion") &&
		!strings.Contains(c.opt.Endpoint, "/v1/"):
		return map[string]any{
			"prompt": prompt, "n_predict": 1, "n_probs": n,
			"temperature": 0, "stream": false,
		}
	default: // OpenAI: vLLM, LM Studio, llama.cpp's compatibility endpoint
		return map[string]any{
			"model": c.opt.Model, "prompt": prompt, "stream": false,
			"max_tokens": 1, "temperature": 0, "logprobs": n,
		}
	}
}

// pick softmaxes over the DECLARED slots only.
//
// Renormalising over the answer slots rather than the whole vocabulary is the
// point: it asks what the model would choose among these options, not how much
// of its probability mass went to unrelated tokens. Slots the server did not
// return are absent rather than zero, which keeps the comparison between the
// ones it did return honest.
func (c *Classifier) pick(top map[string]float64) Result {
	sum, best, bestP := 0.0, "", 0.0
	weights := make(map[string]float64, len(classes))
	for _, cl := range classes {
		w, ok := top[cl.Slot]
		if !ok {
			// Some tokenizers emit the leading space as part of the token.
			if w, ok = top[" "+cl.Slot]; !ok {
				continue
			}
		}
		weights[cl.Name] = w
		sum += w
	}
	if sum == 0 {
		return Result{}
	}
	names := make([]string, 0, len(weights))
	for n := range weights {
		names = append(names, n)
	}
	// Sorted, so a tie resolves the same way on every run and on every machine.
	sort.Strings(names)
	for _, n := range names {
		if p := weights[n] / sum; p > bestP {
			best, bestP = n, p
		}
	}
	if best == "none" || bestP < c.opt.Threshold {
		return Result{}
	}
	return Result{Class: best, P: bestP}
}

func (c *Classifier) render(column string, values []string) string {
	var b strings.Builder
	b.WriteString(c.prompt)
	fmt.Fprintf(&b, "\ncolumn name: %s\nsampled values: %s\n\nAnswer:",
		column, strings.Join(values, " | "))
	return b.String()
}
