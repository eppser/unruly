package main

import (
	"strings"
	"testing"
)

// The two ways a scan goes blind must not be reported as each other.
//
// Both end in the same silence and the same refusal to claim the target is
// clean. They differ entirely in what the operator should do next: get a
// working key, or stop hammering a host that is refusing everything. This
// branch lived inside scanTarget and was reachable only by driving a real
// client into its breaker, so nothing graded which finding came out of it.
func TestGaveUpFindingSeparatesRejectedKeyFromRefusingHost(t *testing.T) {
	rejected := gaveUpFinding("https://x/rest/v1", 40, true, "anon", "-k")
	refused := gaveUpFinding("https://x/rest/v1", 40, false, "anon", "-k")

	if rejected.ID == refused.ID {
		t.Fatalf("both outcomes report %q, so a report cannot say whether the key "+
			"was wrong or the host was hostile", rejected.ID)
	}
	if rejected.ID != "unruly-credential-rejected" {
		t.Errorf("a rejected credential reports %q", rejected.ID)
	}
	if refused.ID != "unruly-target-refused" {
		t.Errorf("a refusing host reports %q", refused.ID)
	}
	// The remediation is the part the operator acts on, so it is the part that
	// must not be interchangeable.
	if rejected.Remediation == refused.Remediation {
		t.Error("both outcomes carry the same remediation, which is the whole cost " +
			"of confusing them: one is fixed with a key, the other is not")
	}
}

// The refusing-host branch must say what it observed, not merely that it
// failed: "429, 5xx or nothing at all" is the evidence that distinguishes a
// rate limit from an outage, and it is the only evidence the operator gets.
func TestGaveUpFindingCitesWhatTheHostDid(t *testing.T) {
	refused := gaveUpFinding("https://x/rest/v1", 40, false, "anon", "-k")
	body := refused.Description + " " + refused.Remediation
	for _, want := range []string{"429", "5xx"} {
		if !strings.Contains(body, want) {
			t.Errorf("the refusal finding never mentions %q, so nothing tells the "+
				"operator what the host actually answered", want)
		}
	}
}
