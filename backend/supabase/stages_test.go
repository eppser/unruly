package supabase

import (
	"context"
	"strings"
	"testing"

	"github.com/eppser/unruly/scan"
)

// The stage list, its order, and what the flags do to it.
//
// This is the boundary. main is not meant to know what a Supabase scan is made
// of: it parses flags, discovers targets, builds shared clients, runs
// providers and renders results. Which stages exist and in what order is the
// provider's own business, and until now it was thirteen inline constructions
// in scanTarget.
//
// ORDER IS LOAD-BEARING, not cosmetic. Stages hand each other typed artifacts,
// so probing before enumeration produces no relations to probe and the
// escalation compare before probing has nothing to compare against. Two scans
// of an unchanged project also have to produce identical bytes, and stage
// order fixes finding order.
func TestStagesRunInTheOrderTheirArtifactsRequire(t *testing.T) {
	got := names(Stages(Config{}))

	// Ordering constraints, each one a real dependency rather than a
	// preference. Written as pairs so a future insertion cannot silently
	// break one: adding a stage between two of these leaves the pair intact.
	for _, dep := range []struct{ first, then, why string }{
		{"vocabulary", "relations", "enumeration probes the candidate names the vocabulary stage merges"},
		{"relations", "probe", "probing needs the relations enumeration found"},
		{"relations", "selfcheck", "the oracles are judged on what enumeration observed"},
		{"probe", "schemas", "the per-schema pass mirrors what the default-schema probe established"},
		{"probe", "graphql", "a GraphQL read is only a BYPASS if REST could not read it"},
		{"probe", "realtime", "realtime steers on which relations are readable and writable"},
		{"schemas", "realtime", "a publication is not limited to the default schema"},
		{"probe", "escalation", "the elevated pass is a comparison against what anon got"},
		{"schemas", "escalation", "the elevated pass covers every schema the anonymous pass did"},
	} {
		i, j := indexOf(got, dep.first), indexOf(got, dep.then)
		if i < 0 || j < 0 {
			t.Errorf("stage %q or %q is missing from %v", dep.first, dep.then, got)
			continue
		}
		if i > j {
			t.Errorf("%q runs after %q, but %s", dep.first, dep.then, dep.why)
		}
	}
}

// A stage the operator turned off is REPORTED, not absent.
//
// The rule this project applies to its own checks: a row marked "not run" is
// not a pass. If -no-realtime simply dropped the stage from the list, a scan
// with that flag would read exactly like a scan whose realtime surface came
// back clean -- and two flags once did precisely that here.
func TestDisabledStagesAreSkippedRatherThanDropped(t *testing.T) {
	full := names(Stages(Config{Site: "https://app.example.invalid"}))
	off := Stages(Config{
		Site:         "https://app.example.invalid",
		SkipRealtime: true,
	})

	if len(full) != len(off) {
		t.Fatalf("turning two checks off changed the stage list from %d to %d entries.\n"+
			"A disabled stage must still appear, wrapped so it reports itself as not run: "+
			"a scan that silently omits a surface reads like a scan that found it clean.\n"+
			"full: %v\noff:  %v", len(full), len(off), full, names(off))
	}

	// AND IT MUST ACTUALLY BE WRAPPED. Counting entries is not enough, which
	// was measured rather than assumed: a break returning the real stage
	// instead of the skipped one kept the list exactly the same length and
	// SURVIVED this test, while turning -no-realtime into "run realtime
	// anyway". Length showed the stage was present; it could not show it was
	// disabled.
	//
	// A skipped stage returns a not-run error, which the pipeline turns into a
	// not-assessed finding. That is the observable difference, so that is what
	// is asserted.
	// "routes" was here too. It moved to backend/application: probing an
	// application's own endpoints is not a Supabase surface, and keeping it in
	// this plan meant a project with another backend never had it probed. The
	// same assertion now lives beside the stage.
	for _, name := range []string{"realtime"} {
		st := findStage(off, name)
		if st == nil {
			t.Errorf("stage %q vanished when it was disabled", name)
			continue
		}
		err := st.Run(context.Background(), &scan.State{Target: "t"})
		if err == nil {
			t.Errorf("disabled stage %q ran and reported success, so the operator's "+
				"flag turned the check off in name only", name)
			continue
		}
		if !strings.Contains(err.Error(), "not run") {
			t.Errorf("disabled stage %q failed with %q rather than reporting itself as "+
				"not run; the report cannot tell a skipped surface from a broken one",
				name, err)
		}
	}
}

func findStage(ss []scan.Stage, name string) scan.Stage {
	for _, s := range ss {
		if s.Name() == name {
			return s
		}
	}
	return nil
}

// Every stage in the list can be built from the config alone.
//
// The whole point of the sequence that led here. If any stage needed an
// earlier stage's RESULT to be constructed, this function could not exist:
// the list would have to be built lazily, mid-scan, by whoever was holding
// the intermediate values -- which is what main was doing.
func TestStagesNeedsNothingButItsConfig(t *testing.T) {
	s := Stages(Config{})
	if len(s) == 0 {
		t.Fatal("no stages were produced, so this test asserts nothing")
	}
	for _, st := range s {
		if strings.TrimSpace(st.Name()) == "" {
			t.Error("a stage has no name; the name appears in the spend breakdown and " +
				"in the not-assessed finding, so it is part of the output contract")
		}
	}
}

func names(ss []scan.Stage) []string {
	out := make([]string, 0, len(ss))
	for _, s := range ss {
		out = append(out, s.Name())
	}
	return out
}

func indexOf(ss []string, name string) int {
	for i, s := range ss {
		if s == name {
			return i
		}
	}
	return -1
}
