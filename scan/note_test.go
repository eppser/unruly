package scan

import (
	"context"
	"testing"
)

// Stages narrate; the command renders.
//
// main currently reads twelve Supabase-specific artifacts for one reason: to
// print the operator-facing lines between stages -- "3 relations, 2 readable",
// "retried with N near-miss candidates", "self-check ok". Those sentences are
// the only thing keeping cmd/unruly importing backend/supabase types, and they
// are why the provider boundary is closed for construction and open for
// execution.
//
// A stage knows what its own result means. The command knows whether the
// operator asked for quiet, and in what order to print. Notes split those two
// jobs at the right seam: the provider produces the sentence, the command
// decides whether it is seen.
func TestAStageCanNarrateWithoutTheCommandReadingItsArtifacts(t *testing.T) {
	st := &State{}
	st.Note(Info, "%d relation(s), %d readable", 3, 2)
	st.Note(Warn, "the application could not be read")

	ns := st.Notes()
	if len(ns) != 2 {
		t.Fatalf("recorded %d notes, want 2", len(ns))
	}
	if ns[0].Text != "3 relation(s), 2 readable" {
		t.Errorf("note text = %q, want the formatted sentence", ns[0].Text)
	}
	if ns[0].Level != Info || ns[1].Level != Warn {
		t.Errorf("levels = %v, %v; a warning that renders as info loses the distinction "+
			"between a choice and a loss", ns[0].Level, ns[1].Level)
	}
}

// Order is preserved, because the operator reads it as a narrative.
//
// The lines describe a scan unfolding: what was harvested, then what was
// enumerated, then what was probed. Sorted or grouped output would still
// contain every fact and would stop being a description of what happened.
func TestNotesKeepTheOrderTheyWereMade(t *testing.T) {
	st := &State{}
	for _, s := range []string{"first", "second", "third"} {
		st.Note(Info, "%s", s)
	}
	for i, want := range []string{"first", "second", "third"} {
		if got := st.Notes()[i].Text; got != want {
			t.Errorf("note %d = %q, want %q", i, got, want)
		}
	}
}

// Notes are attributed to the stage that made them.
//
// Without this the command can print them but cannot group, filter or
// attribute them -- and an agent-facing renderer cannot say which stage was
// talking, which is the whole point of making them structured rather than
// letting stages call a logger directly.
func TestANoteRecordsWhichStageMadeIt(t *testing.T) {
	st := &State{}
	st.Stage = "relations"
	st.Note(Info, "enumerating")
	st.Stage = "probe"
	st.Note(Info, "probing")

	if got := st.Notes()[0].Stage; got != "relations" {
		t.Errorf("first note attributed to %q, want relations", got)
	}
	if got := st.Notes()[1].Stage; got != "probe" {
		t.Errorf("second note attributed to %q, want probe", got)
	}
}

// The zero State narrates, like the rest of this package.
func TestTheZeroStateAcceptsNotes(t *testing.T) {
	var st State
	st.Note(Info, "x")
	if len(st.Notes()) != 1 {
		t.Error("the zero State dropped a note")
	}
}

// The PIPELINE attributes notes, not the stage.
//
// A stage that had to set st.Stage itself would eventually set it to the wrong
// name, or forget, and the ledger has already taught this repository what a
// hand-written label costs: runStage takes the spend label from the stage's own
// Name() precisely so no spelling exists to get wrong. Same rule here.
func TestThePipelineAttributesNotesToTheRunningStage(t *testing.T) {
	st := &State{}
	_, _ = Pipeline{noting{name: "alpha"}, noting{name: "beta"}}.Run(t.Context(), st)

	ns := st.Notes()
	if len(ns) != 2 {
		t.Fatalf("got %d notes, want one per stage", len(ns))
	}
	if ns[0].Stage != "alpha" || ns[1].Stage != "beta" {
		t.Errorf("notes attributed to %q and %q; the pipeline is not naming the stage "+
			"that made them", ns[0].Stage, ns[1].Stage)
	}
}

type noting struct{ name string }

func (n noting) Name() string { return n.name }
func (n noting) Run(_ context.Context, st *State) error {
	// Deliberately does NOT set st.Stage: that is the pipeline's job.
	st.Note(Info, "ran")
	return nil
}

// Notes reach the renderer AS THEY ARE MADE.
//
// The first version collected notes and rendered them after each stage
// finished, which is fine for a verdict and wrong for progress. "enumerating
// relations via the PostgREST hint oracle" printed after enumeration had
// already happened, so a long stage ran in silence and then announced that it
// was about to start.
//
// That is why those lines were still in the command: a stage could not say
// them at a useful moment. With a live hook it can, and the last narration
// leaves main.
func TestNotesReachTheRendererWhileTheStageIsStillRunning(t *testing.T) {
	var seen []string
	st := &State{}
	st.OnNote = func(n Note) { seen = append(seen, n.Text) }

	st.Note(Info, "starting")
	if len(seen) != 1 || seen[0] != "starting" {
		t.Fatalf("renderer saw %v after the first note; a progress line delivered at the "+
			"end of the stage announces work that has already finished", seen)
	}
	st.Note(Info, "done")
	if len(seen) != 2 {
		t.Errorf("renderer saw %v, want both notes in order", seen)
	}
}

// And they are still recorded, so a non-streaming consumer sees them too.
//
// The hook is for a terminal watching a scan happen. An agent reading the run
// afterwards, or a test, gets the same notes from Notes() -- one source of
// truth, two ways to reach it.
func TestNotesAreRecordedEvenWhenSomethingIsWatching(t *testing.T) {
	st := &State{}
	st.OnNote = func(Note) {}
	st.Note(Info, "x")
	if len(st.Notes()) != 1 {
		t.Error("a note delivered to the hook was not also recorded, so anything reading " +
			"the run afterwards would miss it")
	}
}
