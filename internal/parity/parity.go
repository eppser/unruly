// Package parity compares the output of two code paths that are supposed to
// agree.
//
// It exists for the port. Supabase's scan is moving out of a single 1,390-line
// function into pipeline stages, and the only way to move code that large
// without silently changing what it reports is to compare the two outputs on
// every step. The comparison has to be strict about what matters and blind to
// what does not: the old path appends findings in the order its sections ran
// and the pipeline appends in stage order, so ORDER is not a difference, but a
// severity that drifted or a sampled row that went missing is.
//
// Build-time only. Nothing in the shipped scan path imports this.
package parity

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/eppser/unruly/internal/finding"
)

// Canonical renders findings in a stable, comparable form.
//
// finding.Sort supplies the canonical order -- the same order the report uses
// -- so two paths that found the same things serialise identically regardless
// of the sequence in which they found them.
func Canonical(fs []finding.Finding) []string {
	cp := append([]finding.Finding(nil), fs...)
	finding.Sort(cp)
	out := make([]string, 0, len(cp))
	for _, f := range cp {
		out = append(out, line(f))
	}
	return out
}

// line is the comparable projection of one finding.
//
// Everything a reader acts on is included: the rule, how bad it is, what it is
// about, and the proof. Evidence is part of the comparison because a port that
// keeps the finding and loses the sampled row has broken the proof-carrying
// guarantee while still producing the right count and severity -- which is
// exactly the regression a count-based check waves through. The replayable
// request is compared for the same reason: a finding an auditor cannot re-run
// is a claim, and this scanner does not ship claims.
func line(f finding.Finding) string {
	sample, _ := json.Marshal(f.Evidence.Sample)
	return strings.Join([]string{
		f.ID, f.Severity.String(), f.Protocol, f.Matched, f.Resource,
		f.Description, f.Remediation, f.Evidence.Reason, f.Evidence.Request, string(sample),
	}, "\x00")
}

// Diff reports how two sets of findings differ, or "" when they agree.
//
// The message names the findings involved. A parity failure that says only
// "outputs differ" hands the reader the whole investigation, and the point of
// this harness is to make a drift during the port cheap to diagnose.
func Diff(want, got []finding.Finding) string {
	w, g := index(want), index(got)
	var b strings.Builder
	for _, k := range sortedKeys(w) {
		switch {
		case g[k] == "":
			fmt.Fprintf(&b, "only in the first: %s\n", k)
		case g[k] != w[k]:
			fmt.Fprintf(&b, "differs: %s\n  first:  %s\n  second: %s\n",
				k, show(w[k]), show(g[k]))
		}
	}
	for _, k := range sortedKeys(g) {
		if w[k] == "" {
			fmt.Fprintf(&b, "only in the second: %s\n", k)
		}
	}
	return b.String()
}

// index keys findings by rule and resource, which is what identifies "the same
// finding" across two implementations, and keeps the full line as the value so
// a changed field inside an otherwise-matching finding is still caught.
func index(fs []finding.Finding) map[string]string {
	out := map[string]string{}
	for _, f := range fs {
		out[f.ID+" ["+f.Resource+"]"] = line(f)
	}
	return out
}

func sortedKeys(m map[string]string) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}

// show makes a NUL-joined line readable in test output.
func show(s string) string { return strings.ReplaceAll(s, "\x00", " | ") }
