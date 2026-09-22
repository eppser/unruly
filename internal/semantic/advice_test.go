package semantic_test

import (
	"strings"
	"testing"

	"github.com/eppser/unruly/internal/semantic"
)

// Telling someone to start a server is not telling them what to run.
//
// The old message said "Start one (ollama serve, or llama-server --port
// 8080)". Someone who has Ollama installed and no model follows that exactly
// and still gets nothing, because the missing piece was never the server. The
// advice has to name a model that works and be copy-pasteable.
func TestTheAdviceNamesAModelAndIsCopyPasteable(t *testing.T) {
	a := semantic.SetupAdvice()
	if !strings.Contains(a, "ollama pull") {
		t.Error("the advice does not say how to GET a model, only how to run a server")
	}
	if !strings.Contains(a, semantic.RecommendedModel) {
		t.Errorf("the advice does not name %s, so the reader still has to choose one "+
			"from a list of hundreds", semantic.RecommendedModel)
	}
	// The size matters more than the name to someone deciding whether to
	// bother, and they will find out anyway when the download starts.
	if !strings.Contains(a, "GB") {
		t.Error("the advice does not say how big the download is")
	}
}

// The recommended model is the one that was measured, not the newest one.
func TestTheRecommendationIsAboveTheFloorThatWasMeasured(t *testing.T) {
	if semantic.MinParameters < 4.0 {
		t.Errorf("the parameter floor is %v; measured behaviour below 4B is not a "+
			"weaker classifier, it is a different failure: a 2B tagged 499 of 500 "+
			"ordinary columns as sensitive", semantic.MinParameters)
	}
	if !strings.Contains(semantic.RecommendedModel, "4b") &&
		!strings.Contains(semantic.RecommendedModel, "4B") {
		t.Errorf("recommended model %q is not the size that was measured",
			semantic.RecommendedModel)
	}
}

// And when a server IS running but holds nothing usable, say which model to
// add rather than reporting a bare failure.
func TestTheNoUsableModelMessageSaysWhatToInstall(t *testing.T) {
	m := semantic.NoUsableModelAdvice("http://127.0.0.1:11434/api/generate", []string{"llama3.2:1b", "phi3:mini"})
	if !strings.Contains(m, "llama3.2:1b") {
		t.Error("the message does not say what it DID find, so the reader cannot tell " +
			"whether unruly looked at the right server")
	}
	if !strings.Contains(m, semantic.RecommendedModel) {
		t.Error("the message does not name a model that would work")
	}
}
