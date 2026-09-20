package scan

import "fmt"

// Notes are what a stage tells the operator.
//
// They exist to close the provider boundary on its EXECUTION side. main
// stopped constructing Supabase stages, and still read twelve Supabase-specific
// artifacts -- Vocabulary, EnumerateOutcome, Schemas, Escalation and the rest --
// for one reason: to print the sentences between stages. "3 relations, 2
// readable". "retried with 40 near-miss candidates". Those lines were the last
// thing making cmd/unruly import a backend's types.
//
// The seam is: A STAGE KNOWS WHAT ITS RESULT MEANS, AND THE COMMAND KNOWS
// WHETHER THE OPERATOR WANTS TO HEAR IT. So the stage produces the sentence and
// the command decides whether it is printed, at what verbosity, and in what
// format. A stage that called a logger directly would take that decision away
// from the command and make -silent a property of thirteen scattered call
// sites.
//
// Structured rather than pre-formatted strings, because an agent-facing
// renderer needs to say which stage was talking and at what level, and a
// human-facing one needs to colour warnings differently from progress.

// NoteLevel separates progress from loss.
//
// The distinction is load-bearing and this project has already got it wrong
// once: falling back to the pinned wordlist is a CHOICE when there is no site
// and a LOSS when there is one, and printing both as info told operators
// nothing had gone wrong when their recall had just dropped.
type NoteLevel int

const (
	// Info is the scan describing what it is doing.
	Info NoteLevel = iota
	// Warn is the scan describing something that reduces what it can find.
	Warn
	// Error is the scan saying its own results cannot be relied on.
	//
	// Distinct from Warn because the consequence is different in kind. A
	// warning says recall dropped; an error says the measurement itself is
	// untrustworthy, which is what a failed control probe means -- read and
	// write classification both start from the discovered set, so nothing
	// downstream of it can be believed.
	Error
)

func (l NoteLevel) String() string {
	switch l {
	case Warn:
		return "warn"
	case Error:
		return "error"
	}
	return "info"
}

// A Note is one operator-facing sentence from one stage.
type Note struct {
	Stage string
	Level NoteLevel
	Text  string
}

// Note records a sentence for the command to render.
//
// Formatted here rather than by the caller so that the stage's own
// vocabulary -- counts, names, reasons -- stays with the stage, and so a
// renderer never receives a half-built string it has to finish.
func (s *State) Note(level NoteLevel, format string, args ...any) {
	n := Note{Stage: s.Stage, Level: level, Text: fmt.Sprintf(format, args...)}
	s.notes = append(s.notes, n)
	// Recorded first, delivered second: a hook that panics or is slow must not
	// cost the run the note itself.
	if s.OnNote != nil {
		s.OnNote(n)
	}
}

// Notes returns everything stages have said, in the order they said it.
//
// Order is the point: the lines describe a scan unfolding, and sorting or
// grouping them would keep every fact while ceasing to be a description of
// what happened.
func (s *State) Notes() []Note { return s.notes }
