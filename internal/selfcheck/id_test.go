package selfcheck

import (
	"strings"
	"testing"

	"github.com/eppser/unruly/internal/client"
)

// The degraded-capability finding is how a scan admits it was partly blind.
// Every other tool surveyed reports "no findings" when its enumerator returns
// nothing, with no way to tell that from a clean project; this finding is the
// difference. If it stops being emitted, unruly silently joins them.
func TestCapabilityDegradedFindingID(t *testing.T) {
	c := client.New(client.Options{ProjectRef: "x", BaseURL: "http://x", AnonKey: "k"})
	f := degradedFinding(c, Capability{
		Name:    "postgrest-relation-hints",
		Working: false,
		Detail:  "a deliberate near-miss returned no hint",
		Impact:  "relation discovery falls back to the wordlist and recall drops",
	})
	if f.ID != "unruly-capability-degraded" {
		t.Errorf("ID changed to %q; consumers filter on it", f.ID)
	}
	if f.Resource != "postgrest-relation-hints" {
		t.Errorf("the capability must be the resource, got %q", f.Resource)
	}
	// The impact is the whole point: "a check did not run" is only actionable
	// if the reader is told what the scan therefore cannot say.
	if !strings.Contains(f.Description, "recall drops") {
		t.Errorf("the stated impact must reach the reader, got: %s", f.Description)
	}
}
