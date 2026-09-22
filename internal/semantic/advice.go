package semantic

import (
	"fmt"
	"strings"
)

// RecommendedModel is what to install, named rather than left to the reader.
//
// Qwen3.5 4B, quantised, about 2.5GB. It is the model this classifier's
// numbers come from: 88.0% recall at 16% false positives over 550 columns
// across 22 data classes and 25 languages, and in a browser over 22 labelled
// columns it reported eight findings at the 0.80 gate with none of them wrong.
//
// A recommendation has to be ONE thing. "Any model above 4B" is true and
// useless to someone who has never pulled one; a reader with a list of
// hundreds and no name does not have a recommendation, they have homework.
const RecommendedModel = "qwen3.5:4b"

// recommendedSize is stated because it decides whether someone bothers, and
// they find out at the download either way.
const recommendedSize = "2.5GB"

// SetupAdvice is what to print when no local model server answers.
//
// The message this replaced said "Start one (ollama serve, or llama-server
// --port 8080)". That is correct and insufficient: someone who has Ollama
// installed and no model follows it exactly and still gets nothing, because
// the missing piece was never the server. So the advice names a model, says
// what it costs, and is copy-pasteable.
func SetupAdvice() string {
	return fmt.Sprintf(`-classifier auto found no local model server on loopback, so the scan
  continued with the deterministic rules only. The rules prove what they find;
  what they cannot read is addresses, names and diagnoses, which have no
  structure to check.

  To add that, install a model once:

      ollama pull %s     # %s, one time
      ollama serve                 # if it is not already running

  Then re-run with -classifier auto. Anything above 4B parameters works and
  unruly measures whichever it finds before trusting it; %s is what
  the published accuracy numbers were produced with.

  llama.cpp works too, and is faster: llama-server -m <model.gguf> --port 8080`,
		RecommendedModel, recommendedSize, RecommendedModel)
}

// NoUsableModelAdvice is what to print when a server answers but holds nothing
// worth asking.
//
// It names what WAS found, because the first question a reader has is whether
// unruly looked at the right server at all, and a bare "no usable model" does
// not answer it.
func NoUsableModelAdvice(endpoint string, found []string) string {
	have := "no models at all"
	if len(found) > 0 {
		have = strings.Join(found, ", ")
	}
	return fmt.Sprintf(`a model server answered at %s but none of its models is usable for
  classification. It holds: %s.

  Below about 4B parameters the failure is not a weaker classifier, it is a
  different one: a 2B tagged 499 of 500 ordinary columns as sensitive. Install
  one that works:

      ollama pull %s     # %s, one time`,
		endpoint, have, RecommendedModel, recommendedSize)
}
