package semantic_test

import (
	"strings"
	"testing"

	"github.com/eppser/unruly/internal/semantic"
)

// The shared block goes FIRST. This is a performance contract, not a style
// choice, and nothing else in the package protects it.
//
// Every request carries the same ~1.4kB of class descriptions and differs only
// in the trailing column name and values. A server that reuses a cached prefix
// -- llama.cpp with cache_prompt -- then re-reads only the tail: measured on
// this machine, 259ms/column falls to 36ms, 7.2x, on a varying suffix.
//
// That reuse is prefix-only. SemIf, the reference implementation, builds its
// payload as {evidence, criterion, options} with the per-row evidence FIRST,
// so its shared portion is a SUFFIX and prefix reuse cannot engage: its
// "serial" mode measured 484ms/case against 508ms for a cold direct call, a
// 5% gain rather than the order of magnitude the ordering here buys.
//
// Reordering render() to put the column at the top reads better and silently
// costs the whole thing.
func TestTheSharedBlockIsAPrefixNotASuffix(t *testing.T) {
	c, err := semantic.New(semantic.Options{Endpoint: "http://127.0.0.1:8080/completion"})
	if err != nil {
		t.Fatal(err)
	}
	a, _ := c.Request("kreditkarte", []string{"4111111111111111"})["prompt"].(string)
	b, _ := c.Request("wohnort", []string{"Hauptstrasse 14", "Mainz"})["prompt"].(string)
	if a == "" || b == "" {
		t.Fatal("no prompt in the request body")
	}

	shared := 0
	for shared < len(a) && shared < len(b) && a[shared] == b[shared] {
		shared++
	}
	// Every declared slot has to sit inside the shared head, or the part a
	// server can cache is only a fraction of what it could be.
	head := a[:shared]
	for _, cl := range semantic.Classes() {
		if !strings.Contains(head, cl.Slot+". ") {
			t.Fatalf("class %q (slot %s) is outside the shared prefix; the column was "+
				"moved above the class list and prefix reuse is dead", cl.Name, cl.Slot)
		}
	}
	// And the differing tail has to be short. Anything long here means
	// per-column text crept in above the shared block.
	if tail := len(a) - shared; tail > 200 {
		t.Errorf("the varying tail is %d bytes; the shared prefix is %d. Per-column "+
			"text belongs after the class list, not before it", tail, shared)
	}
	if shared < 1000 {
		t.Errorf("only %d bytes are shared between two requests; the class block is "+
			"~1.4kB and should be nearly all of it", shared)
	}
}

// Ask llama.cpp to keep the prefix. One field, an order of magnitude.
//
// Sent only on llama.cpp's native endpoint. Ollama has no such parameter -- it
// reuses a cache only for a byte-identical repeat, measured 394ms varied
// against 35ms identical -- and vLLM's OpenAI server rejects unknown fields,
// so sending it there would turn a speedup into a 400.
func TestCachePromptIsSentToLlamaCppAndNowhereElse(t *testing.T) {
	for _, tc := range []struct {
		name     string
		endpoint string
		want     bool
	}{
		{"llama.cpp native", "http://127.0.0.1:8080/completion", true},
		{"ollama native", "http://127.0.0.1:11434/api/generate", false},
		{"openai compatible", "http://127.0.0.1:8000/v1/completions", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, err := semantic.New(semantic.Options{Endpoint: tc.endpoint, Model: "m"})
			if err != nil {
				t.Fatal(err)
			}
			got, present := c.Request("email", []string{"a@b.de"})["cache_prompt"]
			if tc.want && got != true {
				t.Errorf("cache_prompt is %v (present=%v); llama.cpp re-reads the whole "+
					"1.4kB class block on every column without it", got, present)
			}
			if !tc.want && present {
				t.Errorf("cache_prompt sent to %s, which does not take it", tc.endpoint)
			}
		})
	}
}
