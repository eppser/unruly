package provider

import (
	"fmt"
	"sort"
	"strings"

	"github.com/eppser/unruly/internal/finding"
)

// Capability names one thing a scan can measure about a backend.
//
// The list is deliberately short and outcome-shaped rather than
// implementation-shaped: it answers "what could an attacker do", which is the
// question the threat model asks, and not "which endpoint did we call", which
// changes with every product release.
type Capability string

const (
	CapRead     Capability = "anonymous read"
	CapWrite    Capability = "anonymous write"
	CapEscalate Capability = "what a signed-up user gains"
	CapStorage  Capability = "stored files"
	CapExecute  Capability = "callable code"
	CapRealtime Capability = "live subscriptions"
	CapListing  Capability = "enumerating what exists"
)

var allCapabilities = []Capability{
	CapRead, CapWrite, CapEscalate, CapStorage, CapExecute, CapRealtime, CapListing,
}

// Limited is the mandatory capability manifest. A capability in Measures is
// assessed; one in Cannot is not; one in both is only partially assessed and
// the Cannot reason states the boundary. Every known capability must appear in
// at least one side.
//
// It exists because of an asymmetry in how the two halves of this scanner
// fail. The Supabase pass emits a coverage finding wherever a stage cannot
// run, and the audit checks it does. A provider is trusted to remember -- and
// the surface a contributor did not implement is precisely the surface they
// will not think to mention, so the silence lands exactly where the report is
// least able to warn anyone.
//
// Declaring is one line. Remembering is every release.
type Limited interface {
	Measures() []Capability
	// Cannot maps each unmeasurable capability to the reason, phrased for a
	// reader of the report rather than for a maintainer.
	Cannot() map[Capability]string
}

func validateCapabilities(d Detector) error {
	seen := map[Capability]bool{}
	for _, c := range d.Measures() {
		if !knownCapability(c) {
			return fmt.Errorf("provider %q declares unknown measured capability %q", d.Name(), c)
		}
		if seen[c] {
			return fmt.Errorf("provider %q declares measured capability %q twice", d.Name(), c)
		}
		seen[c] = true
	}
	for c, why := range d.Cannot() {
		if !knownCapability(c) {
			return fmt.Errorf("provider %q declares unknown limitation %q", d.Name(), c)
		}
		if strings.TrimSpace(why) == "" {
			return fmt.Errorf("provider %q gives no reason for limitation %q", d.Name(), c)
		}
		seen[c] = true
	}
	for _, c := range allCapabilities {
		if !seen[c] {
			return fmt.Errorf("provider %q does not declare capability %q as measured or limited", d.Name(), c)
		}
	}
	return nil
}

func knownCapability(want Capability) bool {
	for _, c := range allCapabilities {
		if c == want {
			return true
		}
	}
	return false
}

// NotMeasured returns the coverage findings a provider's declaration implies.
//
// One finding per declared limit, sorted so two scans of an unchanged project
// produce identical bytes.
func NotMeasured(d Detector, det Detection) []finding.Finding {
	cannot := d.Cannot()
	if len(cannot) == 0 {
		return nil
	}
	caps := make([]string, 0, len(cannot))
	for c := range cannot {
		caps = append(caps, string(c))
	}
	sort.Strings(caps)

	where := det.Project
	if where == "" {
		where = d.Name()
	}
	out := make([]finding.Finding, 0, len(caps))
	for _, c := range caps {
		why := strings.TrimSpace(cannot[Capability(c)])
		out = append(out, finding.Finding{
			ID:   "unruly-surface-not-assessed",
			Name: "Not measurable on this backend — " + c,
			// Info, always. This is a statement about the scan, not about the
			// target, and a reader filtering for things to fix must never be
			// handed a scanner diagnostic.
			Severity: finding.Info,
			Protocol: "unruly",
			Matched:  where,
			Resource: c,
			Description: "The " + d.Name() + " provider reports that it cannot measure " +
				c + " on this backend: " + why + ". This is a limit of the scan rather " +
				"than a property of the project, and it is stated because a report that " +
				"is silent about a surface reads exactly like a report that found it " +
				"clean.",
			Remediation: "-- Nothing to fix on the target. To cover this surface, inspect " +
				"it from inside the project's own console or with an administrative\n" +
				"-- credential, which a public scan does not have.",
			Evidence: finding.Evidence{
				Reason: "declared unmeasurable by the " + d.Name() + " provider",
			},
		})
	}
	return out
}

// NotMeasuredFor looks up the registered provider for a detection and returns
// its declared limits.
//
// The caller has a Detection rather than a Detector, so the lookup belongs
// here beside the registry rather than in main.
func NotMeasuredFor(d Detection) []finding.Finding {
	mu.RLock()
	defer mu.RUnlock()
	for _, det := range detectors {
		if det.Name() == d.Provider {
			return NotMeasured(det, d)
		}
	}
	return nil
}
