package eval

import (
	"fmt"
	"sort"
	"strings"
)

// Score is precision/recall for one dimension of a scan.
//
// Both halves matter and they fail in opposite directions. Recall catches the
// bug that breaks every surveyed tool: silently reporting a vulnerable
// database as clean. Precision catches the opposite temptation — flagging
// every relation so recall looks perfect — which produces a scanner nobody
// trusts. A dimension only passes when both hold.
type Score struct {
	Dimension string
	TruePos   []string
	FalsePos  []string
	FalseNeg  []string
	// Sampled marks a dimension whose answer key lists a SAMPLE of the target
	// rather than all of it. Recall still means something -- everything named
	// must be found -- and precision does not, because a name the key omits
	// may be a correct find rather than an invention. Reported so a reader
	// never sees a precision figure that could not have been computed.
	Sampled bool
	// Unstable carries the key's own reason when WHICH items answer changes
	// between identical runs. A number computed over a fixed list there is a
	// measurement of the target's rate limiter, and quoting it would be worse
	// than reporting nothing.
	Unstable string
}

func (s Score) Recall() float64 {
	d := len(s.TruePos) + len(s.FalseNeg)
	if d == 0 {
		return 1
	}
	return float64(len(s.TruePos)) / float64(d)
}

func (s Score) Precision() float64 {
	d := len(s.TruePos) + len(s.FalsePos)
	if d == 0 {
		return 1
	}
	return float64(len(s.TruePos)) / float64(d)
}

// Perfect reports whether the dimension has no misses and no false alarms.
func (s Score) Perfect() bool { return len(s.FalsePos) == 0 && len(s.FalseNeg) == 0 }

func (s Score) String() string {
	var b strings.Builder
	status := "FAIL"
	if s.Perfect() {
		status = "PASS"
	}
	fmt.Fprintf(&b, "%-22s %s  recall %5.1f%%  precision %5.1f%%  (tp=%d fp=%d fn=%d)",
		s.Dimension, status, s.Recall()*100, s.Precision()*100,
		len(s.TruePos), len(s.FalsePos), len(s.FalseNeg))
	if len(s.FalseNeg) > 0 {
		fmt.Fprintf(&b, "\n    MISSED:      %s", strings.Join(s.FalseNeg, ", "))
	}
	if len(s.FalsePos) > 0 {
		fmt.Fprintf(&b, "\n    FALSE ALARM: %s", strings.Join(s.FalsePos, ", "))
	}
	return b.String()
}

// Compare scores an actual set against an expected set.
func Compare(dimension string, expected, actual []string) Score {
	exp := toSet(expected)
	act := toSet(actual)
	s := Score{Dimension: dimension}
	for name := range exp {
		if act[name] {
			s.TruePos = append(s.TruePos, name)
		} else {
			s.FalseNeg = append(s.FalseNeg, name)
		}
	}
	for name := range act {
		if !exp[name] {
			s.FalsePos = append(s.FalsePos, name)
		}
	}
	sort.Strings(s.TruePos)
	sort.Strings(s.FalsePos)
	sort.Strings(s.FalseNeg)
	return s
}

// Result aggregates every dimension for one target.
type Result struct {
	Target string
	Scores []Score
	// RowCountErrors records relations where the scanner reported the wrong
	// number of rows. Getting the count wrong means the evidence is wrong,
	// even when the boolean verdict is right.
	RowCountErrors []string
}

func (r Result) Passed() bool {
	if len(r.RowCountErrors) > 0 {
		return false
	}
	for _, s := range r.Scores {
		if !s.Perfect() {
			return false
		}
	}
	return true
}

func (r Result) String() string {
	var b strings.Builder
	verdict := "FAIL"
	if r.Passed() {
		verdict = "PASS"
	}
	fmt.Fprintf(&b, "target %s: %s\n", r.Target, verdict)
	for _, s := range r.Scores {
		fmt.Fprintf(&b, "  %s\n", s.String())
	}
	if len(r.RowCountErrors) > 0 {
		fmt.Fprintf(&b, "  row-count mismatches: %s\n", strings.Join(r.RowCountErrors, ", "))
	}
	return b.String()
}

// Observation is what a scan actually found, in the shape the scorer needs.
// The scanner produces this; the scorer never imports the scanner, so evals
// stay usable for grading third-party tools too.
//
// NIL AND EMPTY MEAN DIFFERENT THINGS on the optional dimensions. A nil slice
// says "this stage did not run"; an empty non-nil slice says "it ran and found
// nothing". Conflating them is the same mistake this tool exists to correct,
// and it had leaked into the tool's own eval output: a probe-only test scored
// routine-discovery at 0% recall and printed "target lab-fixture: FAIL" while
// passing, because the target declares routines and the observation left them
// nil. Reports that print FAIL next to a passing result teach people to stop
// reading FAIL.
type Observation struct {
	Relations       []string
	ReadExposed     []string
	InsertReachable []string
	Rows            map[string]int
	Routines        []string
	EscalationGains []string
	// Classes are the relation:class pairs the scan reported.
	//
	// Nil means the observation makes no statement -- a probe-only run, or a
	// backend whose findings carry no classes -- and the dimension is skipped.
	Classes []string
}

// Grade scores an observation against a target.
func Grade(t *Target, o Observation) Result {
	res := Result{Target: t.Name}
	res.Scores = append(res.Scores,
		Compare("relation-discovery", t.RelationNames(), o.Relations),
		Compare("read-exposure", t.ReadExposed(), o.ReadExposed),
		Compare("write-exposure", t.InsertReachable(), o.InsertReachable),
	)

	// Classification: what the report says is IN the data, not whether it
	// found it. Scored only where the key claims it, because a target that
	// makes no claim is not a target that claims "nothing" -- and fifteen of
	// the sixteen corpus projects make none while their scans do report
	// sensitive columns.
	if t.ClaimsClasses() && o.Classes != nil {
		res.Scores = append(res.Scores,
			Compare("data-classification", t.ExpectedClasses(), o.Classes))
	}

	// A protected relation reported as exposed is a false alarm; scoring it
	// explicitly makes the "flag everything" strategy fail loudly.
	exposed := toSet(o.ReadExposed)
	var wronglyFlagged []string
	for _, name := range t.Protected() {
		if exposed[name] {
			wronglyFlagged = append(wronglyFlagged, name)
		}
	}
	sort.Strings(wronglyFlagged)
	res.Scores = append(res.Scores, Score{
		Dimension: "protected-not-flagged",
		TruePos:   diff(t.Protected(), wronglyFlagged),
		FalsePos:  wronglyFlagged,
	})

	// Scored only when the target declares routines AND the caller measured
	// them. A nil observation means the stage did not run, which is not a
	// finding of zero.
	if len(t.Expect.Routines) > 0 && o.Routines != nil {
		res.Scores = append(res.Scores,
			Compare("routine-discovery", t.Routines(), o.Routines))
	}

	if len(t.Expect.EscalationGains) > 0 && o.EscalationGains != nil {
		res.Scores = append(res.Scores,
			Compare("escalation-gains", t.EscalationGains(), o.EscalationGains))
	}

	if o.Rows != nil {
		for _, r := range t.Expect.Relations {
			if !r.ReadExposed {
				continue
			}
			got, ok := o.Rows[r.Name]
			if !ok {
				continue // already counted as a recall miss
			}
			if got != r.Rows {
				res.RowCountErrors = append(res.RowCountErrors,
					fmt.Sprintf("%s(want %d, got %d)", r.Name, r.Rows, got))
			}
		}
		sort.Strings(res.RowCountErrors)
	}
	return res
}

func toSet(xs []string) map[string]bool {
	m := make(map[string]bool, len(xs))
	for _, x := range xs {
		m[x] = true
	}
	return m
}

func diff(all, remove []string) []string {
	rm := toSet(remove)
	var out []string
	for _, x := range all {
		if !rm[x] {
			out = append(out, x)
		}
	}
	return out
}
