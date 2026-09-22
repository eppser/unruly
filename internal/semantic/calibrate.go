package semantic

import (
	"context"
	"strings"
	"time"
)

// Probe is one calibration case with a known answer.
type Probe struct {
	Column string
	Values []string
	Want   string // "" means the correct answer is none
}

// probes are deliberately small, deliberately obvious, and deliberately
// include both halves.
//
// A model that answers "none" to everything scores perfectly on positives-only
// and is useless; a model that answers "pii" to everything scores perfectly on
// negatives-only and is worse. Both halves are how a model that cannot do this
// actually fails -- the 27.9B fine-tune that prompted this code answered "none"
// to all of them.
//
// English, because these test whether the readout works at all, not whether
// the model is multilingual. A model that cannot classify a plain English
// street address will not do better in Telugu.
var probes = []Probe{
	{"home_address", []string{"221B Baker Street, London NW1 6XE"}, "location"},
	{"diagnosis_note", []string{"Type 2 diabetes, metformin 500mg twice daily"}, "health"},
	{"message_body", []string{"Hi, can we move tomorrow's call to 3pm?"}, "communications"},
	{"order_ref", []string{"ORD-100234", "ORD-100235"}, ""},
	{"currency_code", []string{"EUR", "USD"}, ""},
	{"http_status", []string{"200", "404"}, ""},
}

// Probes returns the calibration set.
func Probes() []Probe { return probes }

// SlotFor returns the answer slot for a class name, for tests and tooling.
func SlotFor(class string) string {
	for _, c := range classes {
		if c.Name == class {
			return c.Slot
		}
	}
	return "Z"
}

// ProbeAnswer returns the class a rendered prompt is asking about, by matching
// the column name it carries. Exported so a stub server can answer correctly
// without reimplementing the prompt format.
func ProbeAnswer(prompt string) string {
	for _, p := range probes {
		if strings.Contains(prompt, "column name: "+p.Column) {
			return p.Want
		}
	}
	return "none"
}

// calibrate scores one model against the probe set.
//
// Returns the number correct. A wrong class and a missing one count the same:
// both leave the operator without the classification they asked for, and
// neither is worth paying seconds per column for.
func calibrate(ctx context.Context, endpoint, model string, timeout time.Duration) int {
	c, err := New(Options{
		Endpoint: endpoint, Model: model,
		// Calibration is graded on whether the model can answer at all, not on
		// whether it clears the reporting gate. A model that is right but
		// unconfident is still a model that understands the task.
		Threshold: 0.30, Timeout: timeout,
	})
	if err != nil {
		return 0
	}
	score := 0
	for _, p := range probes {
		r, err := c.Classify(ctx, p.Column, p.Values)
		if err != nil {
			return 0
		}
		if r.Class == p.Want {
			score++
		}
	}
	return score
}
