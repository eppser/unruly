package scan

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/eppser/unruly/internal/finding"
)

// stub is a stage that records that it ran and emits one finding.
type stub struct {
	name string
	err  error
	ran  *[]string
}

func (s stub) Name() string { return s.name }

func (s stub) Run(_ context.Context, st *State) error {
	*s.ran = append(*s.ran, s.name)
	if s.err != nil {
		return s.err
	}
	st.Add(finding.Finding{ID: "x-" + s.name, Resource: s.name, Severity: finding.Info})
	return nil
}

// Stages run in the order they were declared.
//
// The order is not cosmetic: discovery feeds enumeration feeds probing, and a
// pipeline that reordered them would produce a scan that probes names it has
// not yet found. The old scanTarget got this right by being one straight-line
// function; a staged pipeline has to state it as a property and test it.
func TestStagesRunInTheOrderTheyWereDeclared(t *testing.T) {
	var ran []string
	p := Pipeline{stub{name: "discover", ran: &ran}, stub{name: "enumerate", ran: &ran},
		stub{name: "probe", ran: &ran}}
	if _, err := p.Run(context.Background(), &State{}); err != nil {
		t.Fatalf("run: %v", err)
	}
	if want := []string{"discover", "enumerate", "probe"}; !reflect.DeepEqual(ran, want) {
		t.Errorf("stages ran %v, want %v", ran, want)
	}
}

// One stage failing must not silence the stages after it.
//
// This is the whole reason the pipeline exists. In the single-function version
// an early error returned from scanTarget and the entire remaining scan --
// realtime, storage, historical exposure -- was never attempted, and the report
// said nothing about them. A scan that stops at the first refusal and reports
// what it happened to reach before that is the false-negative class this
// project exists to eliminate.
func TestAFailingStageDoesNotSilenceTheStagesAfterIt(t *testing.T) {
	var ran []string
	p := Pipeline{
		stub{name: "discover", ran: &ran},
		stub{name: "realtime", ran: &ran, err: errors.New("connection refused")},
		stub{name: "storage", ran: &ran},
	}
	st := &State{}
	if _, err := p.Run(context.Background(), st); err != nil {
		t.Fatalf("a stage error must not abort the pipeline, got: %v", err)
	}
	if want := []string{"discover", "realtime", "storage"}; !reflect.DeepEqual(ran, want) {
		t.Errorf("stages ran %v, want %v -- a refusal in one surface hid the others", ran, want)
	}
}

// And the failure is RECORDED, not swallowed.
//
// Continuing past an error is only honest if the report says the surface was
// not assessed. Silently continuing would turn "realtime refused the
// connection" into "realtime is clean", which is worse than aborting.
func TestAFailedStageIsRecordedAsSomethingTheScanCouldNotSee(t *testing.T) {
	var ran []string
	st := &State{}
	p := Pipeline{stub{name: "realtime", ran: &ran, err: errors.New("connection refused")}}
	if _, err := p.Run(context.Background(), st); err != nil {
		t.Fatalf("run: %v", err)
	}
	blind, what := finding.CoverageIncomplete(st.Findings())
	if !blind {
		t.Fatalf("a stage that errored left the report claiming full coverage: %v", what)
	}
	var saw bool
	for _, f := range st.Findings() {
		if f.Resource == "realtime" && f.ID == "unruly-surface-not-assessed" {
			saw = true
			if f.Evidence.Reason == "" {
				t.Error("the not-assessed finding does not carry the reason it failed")
			}
		}
	}
	if !saw {
		t.Errorf("no not-assessed finding names the stage that failed: %+v", st.Findings())
	}
}

// Repeated runs of the same pipeline produce the same findings in the same
// order. Determinism is graded byte-for-byte by eval-determinism, and it has to
// hold at this layer or nothing above it can be stable.
func TestTheSamePipelineProducesTheSameOrderEveryRun(t *testing.T) {
	build := func() (Pipeline, *[]string) {
		var ran []string
		return Pipeline{stub{name: "a", ran: &ran}, stub{name: "b", ran: &ran},
			stub{name: "c", ran: &ran}}, &ran
	}
	first, _ := build()
	s1 := &State{}
	if _, err := first.Run(context.Background(), s1); err != nil {
		t.Fatal(err)
	}
	second, _ := build()
	s2 := &State{}
	if _, err := second.Run(context.Background(), s2); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(s1.Findings(), s2.Findings()) {
		t.Errorf("two identical runs disagree:\n%+v\n%+v", s1.Findings(), s2.Findings())
	}
}

// A stage may be skipped by the operator or by a declared limit. A skipped
// stage must not run, and must still be visible -- the same rule the audit
// applies to its own checks: a row marked "not run" is not a pass.
func TestASkippedStageDoesNotRunAndIsStillReported(t *testing.T) {
	var ran []string
	p := Pipeline{Skip(stub{name: "realtime", ran: &ran}, "disabled with -no-realtime")}
	st := &State{}
	if _, err := p.Run(context.Background(), st); err != nil {
		t.Fatal(err)
	}
	if len(ran) != 0 {
		t.Errorf("a skipped stage ran anyway: %v", ran)
	}
	// REPORTED, and reported as skipped rather than as unassessable.
	//
	// This used to assert that a skip made coverage incomplete, i.e. drove
	// exit 3. That contradicted the rule the coverage set already states in
	// its own comment: "unruly-checks-skipped is deliberately absent. It fires
	// whenever -write is not passed, which is the default and a decision the
	// operator made; if it counted here, almost every scan would report
	// incomplete coverage and the signal would mean nothing."
	//
	// The same reasoning applies to a stage the operator turned off, and two
	// mechanisms disagreeing about one question was the real defect: Supabase
	// skips went through skippedChecks and did not drive exit 3, while
	// PocketBase and Neon skips went through Skip and did. Now both say the
	// same thing.
	fs := st.Findings()
	if len(fs) != 1 || fs[0].ID != "unruly-stage-skipped" {
		t.Fatalf("a skipped stage produced %v; it must be reported, and reported as "+
			"skipped: a check that did not run is not a check that passed", ids(fs))
	}
	if !strings.Contains(fs[0].Description, "-no-realtime") {
		t.Errorf("the finding does not name what would enable the stage: %q",
			fs[0].Description)
	}
	if blind, _ := finding.CoverageIncomplete(fs); blind {
		t.Error("a stage the operator turned off drove exit 3, so a scan narrowed by " +
			"its own flags reports itself as blind and the signal stops meaning anything")
	}
}

func ids(fs []finding.Finding) []string {
	out := make([]string, 0, len(fs))
	for _, f := range fs {
		out = append(out, f.ID)
	}
	return out
}
