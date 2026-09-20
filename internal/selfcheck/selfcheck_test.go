package selfcheck

import (
	"strings"
	"testing"

	"github.com/eppser/unruly/internal/client"
	"github.com/eppser/unruly/internal/finding"
)

// The point of this package is that a degraded scan is louder than a quiet
// one. These assertions pin that: a broken oracle must surface as a finding
// whose text says the results are incomplete.
func TestDegradedCapabilityBecomesAFinding(t *testing.T) {
	c := client.New(client.Options{BaseURL: "https://ref.supabase.co", AnonKey: "k"})
	f := degradedFinding(c, Capability{
		Name:    "postgrest-relation-hints",
		Working: false,
		Detail:  "server returned 404 without a relation hint",
		Impact:  "Relation discovery falls back to the pinned wordlist alone.",
	})
	// Info, deliberately. Severity ranks how bad something is on the TARGET,
	// and this finding is about the scan rather than the target: a reader
	// filtering severity >= medium for things to fix must not be handed a
	// scanner diagnostic. Scanning four hosts that are not Supabase produced
	// no vulnerability findings and three to four Mediums each, all of them
	// this one. What must not change is that the finding exists and says what
	// the scan therefore cannot claim.
	if f.Severity != finding.Info {
		t.Errorf("a scanner diagnostic is not a target severity, got %s", f.Severity)
	}
	if !strings.Contains(f.Description, "absence of findings below is not evidence") {
		t.Error("the finding must warn that an empty result is not a clean result")
	}
	if !strings.Contains(f.Description, "server returned 404 without a relation hint") {
		t.Error("the finding must quote what was actually observed")
	}
	if f.Remediation == "" {
		t.Error("a degraded scan needs an operator action")
	}
}

func TestDegradedListsOnlyBrokenCapabilities(t *testing.T) {
	r := Result{Capabilities: []Capability{
		{Name: "b", Working: false},
		{Name: "a", Working: true},
		{Name: "c", Working: false},
	}}
	got := r.Degraded()
	if len(got) != 2 || got[0] != "b" || got[1] != "c" {
		t.Errorf("Degraded() = %v, want [b c]", got)
	}
}

// A working oracle must produce no noise at all: this check runs on every scan
// and must stay silent on healthy targets or it becomes wallpaper.
func TestHealthyCapabilitiesProduceNoFindings(t *testing.T) {
	r := Result{Capabilities: []Capability{
		{Name: "postgrest-relation-hints", Working: true},
		{Name: "postgrest-routine-hints", Working: true},
		{Name: "postgrest-error-codes", Working: true},
	}}
	if len(r.Findings) != 0 || len(r.Degraded()) != 0 {
		t.Error("healthy capabilities must produce nothing")
	}
}

// TestPartialTransportFailureIsReported is the case a total outage hides.
//
// When everything fails, every oracle fails and the scan is unmistakably loud.
// When a handful of requests out of thousands are lost, the oracles still work,
// the self-check still passes, and the relations behind those requests are
// simply absent — indistinguishable from relations that never existed. Nothing
// else in this tool would notice, which is why the transport is a capability.
func TestPartialTransportFailureIsReported(t *testing.T) {
	healthy := checkTransport(Evidence{RequestsSent: 2000, RequestsFailed: 0})
	if !healthy.Working {
		t.Error("a scan that lost nothing must not be reported as degraded")
	}

	partial := checkTransport(Evidence{RequestsSent: 2000, RequestsFailed: 5})
	if partial.Working {
		t.Error("losing 5 requests of 2000 must be reported: those gaps look like absence")
	}
	if !strings.Contains(partial.Detail, "5 of 2000") {
		t.Errorf("the detail must quantify the loss, got %q", partial.Detail)
	}
	if !strings.Contains(partial.Impact, "look identical to absence") {
		t.Error("the impact must say WHY a lost request matters, not just that it happened")
	}

	idle := checkTransport(Evidence{})
	if !idle.Working {
		t.Error("a scan that issued no requests has lost nothing")
	}
}
