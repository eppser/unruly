package escalate

import (
	"strings"
	"testing"

	"github.com/eppser/unruly/internal/client"
	"github.com/eppser/unruly/internal/finding"
)

// The authenticated path must rate data the same way the anonymous path does.
//
// A relation that only a logged-in user can read is not less serious than one
// anyone can read -- where signup is open, which is the default, the set of
// logged-in users is everyone. So the same two questions apply: what are the
// columns called, and what is actually in them.
//
// The second was missing here. This finding carries sampled rows and rated
// them by column NAME alone, so the German-schema blind spot fixed for the
// anonymous path was still open one layer up: an escalation gain holding card
// numbers under columns called kreditkarte read as "readable by any logged-in
// user" at high, one step below the truth.
func TestEscalationSeverityUsesValuesAsWellAsColumnNames(t *testing.T) {
	c := client.New(client.Options{BaseURL: "http://127.0.0.1:1", RestPrefix: "/"})

	g := Gain{
		Relation: "kunden",
		Rows:     3,
		Columns:  []string{"id", "kreditkarte", "anschrift"},
		Sample: []map[string]any{{
			"id":          1,
			"kreditkarte": "4111111111111111",
			"anschrift":   "Hauptstrasse 1",
		}},
	}
	f := gainFinding(c, "authenticated", g, "")
	if f.Severity != finding.Critical {
		t.Errorf("an escalation gain holding a card number was rated %v: the anonymous "+
			"path rates the same rows critical, and a logged-in user is everyone where "+
			"signup is open", f.Severity)
	}
	if !strings.Contains(f.Evidence.Reason, "financial") {
		t.Errorf("the finding does not say what was found: reason = %q", f.Evidence.Reason)
	}
	if strings.Contains(f.Evidence.Reason, "4111") {
		t.Error("the reason quotes the card number it describes")
	}

	// And an ordinary gain must stay high, or the rating says nothing.
	plain := Gain{
		Relation: "beitraege",
		Rows:     2,
		Columns:  []string{"id", "titel", "text"},
		Sample:   []map[string]any{{"id": 1, "titel": "Hallo", "text": "Willkommen."}},
	}
	if f := gainFinding(c, "authenticated", plain, ""); f.Severity != finding.High {
		t.Errorf("an ordinary escalation gain was rated %v, not high", f.Severity)
	}
}
