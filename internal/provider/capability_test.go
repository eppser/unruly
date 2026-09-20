package provider

import (
	"strings"
	"testing"

	"github.com/eppser/unruly/scan"

	"github.com/eppser/unruly/internal/finding"
)

// A backend that cannot measure something must say so, without being asked.
//
// This project's central rule is that absence of a finding is only evidence
// when the scan could see. The Supabase pass honours it by construction --
// every stage that cannot run emits a coverage finding. A provider is trusted
// to remember, and a contributor who forgets produces a report that looks
// clean on a surface nobody looked at.
//
// Forgetting is the expected failure, not a hypothetical one: the thing you do
// not implement is the thing you do not think to mention.
//
// So a provider declares what it structurally cannot measure, and the core
// emits the coverage findings itself. Declaring is one line; remembering is
// every release.
type limitedBackend struct{}

func (limitedBackend) Stages(Detection, scan.Inputs) []scan.Stage { return nil }

func (limitedBackend) Name() string { return "limited" }
func (limitedBackend) Detect(Surface) (Detection, bool) {
	return Detection{Provider: "limited", Project: "p"}, true
}
func (limitedBackend) Cannot() map[Capability]string {
	return map[Capability]string{
		CapWrite: "this backend has no sound write probe: its API returns the same " +
			"status for a refused write and an accepted one",
	}
}
func (limitedBackend) Measures() []Capability {
	return []Capability{CapRead, CapEscalate, CapStorage, CapExecute, CapRealtime, CapListing}
}

type completeBackend struct{}

func (completeBackend) Stages(Detection, scan.Inputs) []scan.Stage { return nil }

func (completeBackend) Name() string { return "complete" }
func (completeBackend) Detect(Surface) (Detection, bool) {
	return Detection{Provider: "complete", Project: "p"}, true
}
func (completeBackend) Measures() []Capability        { return append([]Capability(nil), allCapabilities...) }
func (completeBackend) Cannot() map[Capability]string { return nil }

func TestADeclaredLimitIsReportedWithoutTheProviderRememberingTo(t *testing.T) {
	d := Detection{Provider: "limited", Project: "p"}
	fs := NotMeasured(limitedBackend{}, d)

	if len(fs) == 0 {
		t.Fatal("a provider that declared it cannot probe writes produced no coverage " +
			"finding, so the report is silent about a surface nobody looked at")
	}
	f := fs[0]
	if f.ID != "unruly-surface-not-assessed" {
		t.Errorf("id is %q; a limit is a statement about the SCAN and must reuse the id "+
			"the exit code already treats as blindness", f.ID)
	}
	if f.Severity != finding.Info {
		t.Errorf("severity is %v; a scanner diagnostic must never be handed to a reader "+
			"filtering for things to fix", f.Severity)
	}
	// The reason the provider gave must survive into the report. Without it the
	// reader is told a surface was skipped and cannot judge whether that
	// matters.
	if !strings.Contains(f.Description, "no sound write probe") {
		t.Errorf("the declared reason is missing from the finding: %q", f.Description)
	}
	if !strings.Contains(strings.ToLower(f.Resource+f.Description), "write") {
		t.Errorf("the finding does not name WHICH capability was not measured: %+v", f)
	}
}

func TestAProviderWithNoLimitsEmitsNothing(t *testing.T) {
	if fs := NotMeasured(completeBackend{}, Detection{Provider: "complete"}); len(fs) != 0 {
		t.Errorf("a provider with full declared coverage produced %d limit findings", len(fs))
	}
}

type incompleteBackend struct{ completeBackend }

func (incompleteBackend) Name() string           { return "incomplete" }
func (incompleteBackend) Measures() []Capability { return []Capability{CapRead} }

func TestRegistrationRejectsAnIncompleteCapabilityManifest(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("provider registration accepted six silent capability gaps")
		}
	}()
	Register(incompleteBackend{})
}
