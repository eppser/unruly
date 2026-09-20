package provider

import (
	"context"
	"testing"

	"github.com/eppser/unruly/internal/finding"
	"github.com/eppser/unruly/scan"
)

// namedStage records that it ran, under a name.
type namedStage struct {
	name string
	ran  *[]string
}

func (n namedStage) Name() string { return n.name }

func (n namedStage) Describe() scan.StageDescriptor {
	return scan.StageDescriptor{ID: n.name}
}

func (n namedStage) Run(_ context.Context, st *scan.State) error {
	*n.ran = append(*n.ran, n.name)
	st.Add(finding.Finding{ID: "x-" + n.name, Resource: n.name, Severity: finding.Info})
	return nil
}

// stagedDetector is a provider that expresses its scan as pipeline stages.
type stagedDetector struct {
	name   string
	stages []scan.Stage
}

func (s stagedDetector) Name() string { return s.name }

func (s stagedDetector) Measures() []Capability        { return append([]Capability(nil), allCapabilities...) }
func (s stagedDetector) Cannot() map[Capability]string { return nil }

func (s stagedDetector) Detect(Surface) (Detection, bool) {
	return Detection{Provider: s.name}, true
}

func (s stagedDetector) Stages(Detection, scan.Inputs) []scan.Stage { return s.stages }

// A provider contributes the stages its scan is made of.
//
// This is the seam the rebuild exists to create. Today a backend declares what
// it can measure (Capability) and what it structurally cannot (Limited), but
// the orchestration that actually measures it lives in main -- 1,390 lines of
// it for Supabase. A provider that can hand back its own stages is a provider
// whose scan can be run, and tested, without main being involved at all.
func TestAProviderContributesItsOwnStages(t *testing.T) {
	var ran []string
	p := stagedDetector{name: "teststaged", stages: []scan.Stage{
		namedStage{name: "discover", ran: &ran},
		namedStage{name: "probe", ran: &ran},
	}}
	Register(p)
	t.Cleanup(func() { unregister("teststaged") })

	got := StagesFor(Detection{Provider: "teststaged"}, scan.Inputs{})
	if len(got) != 2 {
		t.Fatalf("provider contributed %d stages, want 2", len(got))
	}
	if _, err := (scan.Pipeline(got)).Run(context.Background(), &scan.State{}); err != nil {
		t.Fatal(err)
	}
	if len(ran) != 2 || ran[0] != "discover" || ran[1] != "probe" {
		t.Errorf("stages ran %v, want [discover probe] -- the provider's declared order "+
			"is part of its contract, not a detail of the runner", ran)
	}
}

// A provider may explicitly return no stages for a detection it cannot plan.
// The method itself is mandatory, so there is no second Assess execution path;
// the engine turns the empty plan into a visible coverage failure.
func TestAProviderThatDeclaresNoStagesContributesNone(t *testing.T) {
	Register(plainDetector{name: "testplain"})
	t.Cleanup(func() { unregister("testplain") })

	if got := StagesFor(Detection{Provider: "testplain"}, scan.Inputs{}); len(got) != 0 {
		t.Errorf("a provider with no Stages() contributed %d stages", len(got))
	}
}

// An unknown provider contributes nothing rather than panicking. A detection
// naming a backend nobody registered is a bug elsewhere, and the runner has to
// survive it well enough to report the rest of the scan.
func TestAnUnregisteredProviderContributesNoStages(t *testing.T) {
	if got := StagesFor(Detection{Provider: "no-such-backend"}, scan.Inputs{}); got != nil {
		t.Errorf("an unregistered provider produced stages: %v", got)
	}
}

type plainDetector struct{ name string }

func (p plainDetector) Name() string { return p.name }

func (p plainDetector) Measures() []Capability        { return append([]Capability(nil), allCapabilities...) }
func (p plainDetector) Cannot() map[Capability]string { return nil }

func (p plainDetector) Detect(Surface) (Detection, bool) {
	return Detection{Provider: p.name}, true
}

func (p plainDetector) Stages(Detection, scan.Inputs) []scan.Stage { return nil }
