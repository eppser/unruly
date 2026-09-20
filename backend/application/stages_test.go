package application

import (
	"context"
	"strings"
	"testing"

	"github.com/eppser/unruly/scan"
)

// A disabled application check is REPORTED, not absent.
//
// The same rule the rest of the scan follows: a row marked "not run" is not a
// pass. Moved here with the stage -- it used to be asserted against the
// Supabase plan, which is where routes wrongly lived.
func TestADisabledRoutesPassIsSkippedRatherThanDropped(t *testing.T) {
	full := Stages(Config{Site: "https://app.example.invalid"})
	off := Stages(Config{Site: "https://app.example.invalid", SkipRoutes: true})

	if len(full) != len(off) {
		t.Fatalf("turning routes off changed the plan from %d to %d entries; a "+
			"disabled check must still appear and report itself", len(full), len(off))
	}
	err := off[0].Run(context.Background(), &scan.State{Target: "t"})
	if err == nil || !strings.Contains(err.Error(), "not run") {
		t.Errorf("a disabled routes pass returned %v; it must report itself as not "+
			"run, or the operator's flag turns the check off in name only", err)
	}
}

// The application plan needs no backend at all.
//
// This is the property the move exists for. If Config ever grows a project
// reference or an anon key, the plan stops being runnable for a target whose
// backend is unknown -- which is exactly the target whose routes matter most.
func TestTheApplicationPlanIsRunnableWithNoBackend(t *testing.T) {
	s := Stages(Config{Site: "https://app.example.invalid"})
	if len(s) == 0 {
		t.Fatal("no application stages were produced")
	}
	if err := scan.Validate(s); err != nil {
		t.Errorf("the application plan does not validate on its own: %v", err)
	}
}
