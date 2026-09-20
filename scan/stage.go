// Package scan is the provider-agnostic pipeline that runs a posture scan.
//
// It exists to break up scanTarget(), a single 1,390-line function that
// carried the whole Supabase scan. That function had 12 author-marked stage
// boundaries and roughly 30 variables crossing them, and it is the mechanical
// reason Supabase could not sit behind the same provider seam Firebase already
// uses: there was no boundary to lift. The stages below are those same 12
// boundaries, made into things that can be run -- and therefore tested -- one
// at a time.
package scan

import (
	"context"
	"fmt"

	"github.com/eppser/unruly/internal/finding"
)

// A Stage is one step of a scan.
//
// The interface is deliberately tiny. Anything a stage needs comes from State,
// and everything it learns goes back into State, because the alternative --
// stages that accept and return bespoke tuples -- is how the original function
// grew 30 variables of shared scope in the first place.
type Stage interface {
	// Name is stable and appears in coverage reporting, so it is part of the
	// output contract, not a debug label.
	Name() string
	// Run performs the step. Returning an error means "this surface could not
	// be assessed", not "the scan failed": see Pipeline.Run.
	Run(ctx context.Context, st *State) error
}

// Pipeline is an ordered list of stages.
type Pipeline []Stage

// Run executes every stage in order and returns everything they found.
//
// A stage that fails does NOT abort the run. In the single-function version an
// error returned from scanTarget and every remaining surface -- realtime,
// storage, historical exposure -- went unexamined while the report said
// nothing about them. Stopping at the first refusal and reporting whatever was
// reached before it is precisely the false-negative this project exists to
// eliminate.
//
// Continuing is only honest because the failure is recorded: each error
// becomes a not-assessed finding carrying the id the exit code already keys
// on, so an unexamined surface drives exit 3 rather than passing for a clean
// one.
func (p Pipeline) Run(ctx context.Context, st *State) ([]finding.Finding, error) {
	for _, s := range p {
		// A cancelled scan has not assessed the stages it never reached, and
		// saying so is the difference between a short scan and a short scan
		// nobody noticed.
		if err := ctx.Err(); err != nil {
			st.Add(finding.NotAssessedStage(st.Target, s.Name(), "the scan was cancelled before "+
				"this stage ran: "+err.Error()))
			continue
		}
		// The stage's own Name() attributes anything it says, so no stage
		// has to repeat its name and none can misspell it. The ledger learned
		// this the hard way: runStage takes the spend label from Name() for
		// exactly the same reason.
		st.Stage = s.Name()
		if err := s.Run(ctx, st); err != nil {
			// A stage the OPERATOR turned off is reported as skipped, not as a
			// surface that could not be assessed. Both are "did not run" and
			// they are different results: one drives exit 3 because the scan
			// tried and could not see, the other is the scan being told not to
			// look. Conflating them tells somebody to fix their own flag.
			if nr, ok := err.(notRun); ok {
				st.Add(finding.SkippedStage(st.Target, s.Name(), nr.reason))
				continue
			}
			st.Add(finding.NotAssessedStage(st.Target, s.Name(), err.Error()))
		}
		if err := validateRuntimeArtifacts(s, st); err != nil {
			st.Stage = ""
			return st.Findings(), err
		}
		st.Stage = ""
	}
	return st.Findings(), nil
}

// validateRuntimeArtifacts checks the part of a stage contract only execution
// can prove: what the stage actually published. Plan validation proves order;
// this proves the running code did not write around that plan.
func validateRuntimeArtifacts(s Stage, st *State) error {
	d, ok := s.(Describer)
	if !ok {
		// Pipeline is also a small execution primitive used in unit tests. A
		// production plan is rejected by Validate before it reaches Run; keeping
		// runtime checking conditional here preserves that primitive while every
		// validated engine workload remains strict.
		return nil
	}
	desc := d.Describe()
	declared := make(map[ArtifactType]bool, len(desc.Produces))
	for _, a := range desc.Produces {
		declared[a] = true
	}
	for a := range st.artifactWrites[s.Name()] {
		if !declared[a] {
			return fmt.Errorf("stage %q published undeclared artifact %q", s.Name(), a)
		}
	}
	readable := make(map[ArtifactType]bool, len(desc.Requires)+len(desc.Optional))
	for _, a := range desc.Requires {
		readable[a] = true
	}
	for _, a := range desc.Optional {
		readable[a] = true
	}
	for a := range st.artifactReads[s.Name()] {
		if !readable[a] {
			return fmt.Errorf("stage %q read undeclared artifact %q", s.Name(), a)
		}
	}
	return nil
}

// Skip wraps a stage the operator turned off, or that a declared limit rules
// out, so that it does not run and is still reported.
//
// The rule is the one the audit applies to its own checks: a row marked "not
// run" is not a pass. Two flags once disabled a check AND suppressed any note
// that it had been disabled, so a scan with them read exactly like a scan
// where those surfaces came back clean.
func Skip(s Stage, reason string) Stage { return skipped{s: s, reason: reason} }

type skipped struct {
	s      Stage
	reason string
}

// NOTE: skipped deliberately does NOT implement Describer.
//
// That is not an omission. A stage that will not run produces nothing and asks
// for nothing, and the invisibility gives exactly those semantics: a live
// consumer requiring what a skipped stage would have produced fails validation
// -- correctly, because at run time it would find nothing and report its
// surface as empty -- while the skipped stage's own inputs are not held
// against it.
//
// Forwarding Describe from the inner stage would be the obvious "fix" and it
// would be wrong in the dangerous direction: the plan would believe the
// artifact is published, validate cleanly, and produce the empty surface
// anyway. Pinned by TestASkippedProducerLeavesItsConsumerUnsatisfiable.

func (k skipped) Name() string { return k.s.Name() }

func (k skipped) Run(context.Context, *State) error { return notRun{k.reason} }

type notRun struct{ reason string }

func (n notRun) Error() string { return "not run: " + n.reason }
