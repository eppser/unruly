package scan

import (
	"context"
	"strings"
	"testing"
)

// A stage the operator turned OFF is not a stage that could not be assessed.
//
// Both are "did not run", and this project's whole argument is that different
// kinds of not-knowing are different results. "Could not be assessed" means the
// scan tried and the surface refused, and it drives exit 3 -- correctly,
// because an unexamined surface must not pass for a clean one. "The operator
// did not ask for this" means the scan was told not to look, and reporting
// that as a failure tells somebody to fix a cause that is their own flag.
//
// Found by measuring rather than by reasoning: running the provider's full
// stage list added two findings for -history and -subdomains, and both landed
// in the id that drives exit 3, with remediation reading "re-run the scan once
// the cause above is resolved".
func TestADeliberateSkipIsNotReportedAsAFailureToAssess(t *testing.T) {
	st := &State{Target: "t"}
	_, _ = Pipeline{Skip(failing{name: "history"}, "-history was not set")}.
		Run(context.Background(), st)

	fs := st.Findings()
	if len(fs) != 1 {
		t.Fatalf("a skipped stage produced %d findings, want exactly one saying it was "+
			"skipped", len(fs))
	}
	f := fs[0]
	if f.ID == "unruly-surface-not-assessed" {
		t.Errorf("a stage the operator turned off is reported as %q, which is the id "+
			"that drives exit 3 and whose remediation says to re-run once the cause is "+
			"resolved. The cause is the operator's own flag.", f.ID)
	}
	if !strings.Contains(f.Description, "-history") {
		t.Errorf("the finding does not name what would enable the stage: %q", f.Description)
	}
}

// A stage that genuinely FAILED still reports as not assessed.
//
// The distinction only means something if the other half survives: a surface
// the scan tried to reach and could not must keep driving exit 3.
func TestAStageThatFailedIsStillReportedAsNotAssessed(t *testing.T) {
	st := &State{Target: "t"}
	_, _ = Pipeline{failing{name: "realtime"}}.Run(context.Background(), st)

	fs := st.Findings()
	if len(fs) != 1 {
		t.Fatalf("a failing stage produced %d findings, want one", len(fs))
	}
	if fs[0].ID != "unruly-surface-not-assessed" {
		t.Errorf("a stage that tried and failed is reported as %q; an unexamined "+
			"surface must not stop driving exit 3", fs[0].ID)
	}
}

type failing struct{ name string }

func (f failing) Name() string { return f.name }
func (f failing) Run(context.Context, *State) error {
	return errUnreachable
}

var errUnreachable = &staticErr{"the endpoint could not be reached"}

type staticErr struct{ s string }

func (e *staticErr) Error() string { return e.s }
