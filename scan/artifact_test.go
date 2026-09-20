package scan

import "testing"

type probeish struct {
	Names []string
}

type surfaceish struct {
	Buckets int
}

// A stage hands a typed value to a later stage through State.
//
// This replaces the Out pointer. Today a Supabase stage writes its result
// through `Out *probe.Result`, and the variable that pointer refers to is
// declared in scanTarget -- so main owns the wiring between two Supabase
// stages, and reordering them, removing one or handing one off means editing
// main. That is the 30-variables-of-shared-scope problem wearing a struct
// field.
func TestAStageCanHandATypedValueToALaterStage(t *testing.T) {
	st := &State{}
	Put(st, probeish{Names: []string{"employees", "payslips"}})

	got, ok := Get[probeish](st)
	if !ok {
		t.Fatal("the value a stage put was not there for the next stage")
	}
	if len(got.Names) != 2 || got.Names[0] != "employees" {
		t.Errorf("got %+v, want the value that was put", got)
	}
}

// ABSENT IS NOT ZERO. The whole project in one method signature.
//
// A stage that did not run leaves nothing behind, and a consumer must be able
// to tell that from a stage that ran and found nothing. With a bare `Get[T]`
// returning only T, the two are the same empty struct -- which is exactly how
// "the probe stage was skipped" would come to read as "the probe found no
// relations", in a tool whose entire argument is that those are different.
func TestAnAbsentArtifactIsDistinguishableFromAnEmptyOne(t *testing.T) {
	st := &State{}

	if _, ok := Get[probeish](st); ok {
		t.Error("an artifact nobody put reported as present on a fresh State")
	}

	// AND on a State that other stages have already written to. This second
	// check is the one that matters and it was missing: a fresh State has a
	// nil map, so the lookup short-circuits before the miss path is ever
	// reached, and a Get that reported every miss as a hit passed this test.
	// Measured by breaking it on purpose -- the mid-pipeline case, where some
	// stages have run and the one you are asking about has not, is the only
	// case that exercises the lookup at all, and it is also the only case that
	// happens in a real scan.
	Put(st, surfaceish{Buckets: 1})
	if _, ok := Get[probeish](st); ok {
		t.Error("a stage that never ran reported as present once ANOTHER stage had run; " +
			"this is the shape a real pipeline is in, and the shape that makes " +
			"\"skipped\" read as \"found nothing\"")
	}

	// Put an EMPTY one: the stage ran, and found nothing.
	Put(st, probeish{})
	got, ok := Get[probeish](st)
	if !ok {
		t.Fatal("an empty artifact that was put reported as absent; a stage that ran and " +
			"found nothing is not a stage that did not run")
	}
	if got.Names != nil {
		t.Errorf("got %+v, want the empty value that was put", got)
	}
}

// Artifacts are keyed by TYPE, so two stages cannot disagree about a name.
//
// A string-keyed bag is a contract two packages must agree on out of band, and
// a typo in either one is silent: the producer writes "probe-result", the
// consumer reads "probe_result", and the consumer sees a stage that never ran.
// A type is checked by the compiler.
func TestDifferentArtifactTypesDoNotCollide(t *testing.T) {
	st := &State{}
	Put(st, probeish{Names: []string{"a"}})
	Put(st, surfaceish{Buckets: 3})

	p, okP := Get[probeish](st)
	s, okS := Get[surfaceish](st)
	if !okP || !okS {
		t.Fatalf("one type displaced the other: probe ok=%v surface ok=%v", okP, okS)
	}
	if len(p.Names) != 1 || s.Buckets != 3 {
		t.Errorf("values crossed: probe=%+v surface=%+v", p, s)
	}
}

// The last writer wins, and says so.
//
// Not a deep merge and not an append. A stage that runs twice in one scan
// replaces its own artifact, because the alternative -- silently accumulating
// -- would make the result depend on how many times the pipeline was built.
func TestPuttingAnArtifactTwiceReplacesIt(t *testing.T) {
	st := &State{}
	Put(st, probeish{Names: []string{"first"}})
	Put(st, probeish{Names: []string{"second"}})

	got, _ := Get[probeish](st)
	if len(got.Names) != 1 || got.Names[0] != "second" {
		t.Errorf("got %+v, want the second value", got)
	}
}

// The zero State is usable, like the rest of this package.
//
// A stage must not have to know whether somebody remembered to call a
// constructor. scan.State is built in three places already and a nil map
// panics on write, which would turn a missing initialiser into a crash in the
// middle of somebody's scan rather than a compile error.
func TestTheZeroStateAcceptsArtifacts(t *testing.T) {
	var st State
	Put(&st, probeish{Names: []string{"x"}})
	if _, ok := Get[probeish](&st); !ok {
		t.Error("the zero State dropped an artifact")
	}
}
