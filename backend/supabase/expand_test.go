package supabase

import "testing"

// The near-miss expansion costs ~13,000 probes and buys a lot when it runs:
// 2 of 7 relations became 7 of 7 on one project, 19 of 21 became 21 of 21 on
// another. It must run whenever it can help and must not run when it cannot.
func TestExpansionRunsWhenTheCheapAttemptProducedNothing(t *testing.T) {
	// No vocabulary harvested: the pinned list has to reach the schema alone.
	if !shouldExpand(true, 12, 0, 3) {
		t.Error("no vocabulary was harvested and the expansion was skipped; the pinned " +
			"list alone reached 2 of 7 relations on the reference project")
	}
	// Vocabulary harvested but no relation found: plenty of words, none of
	// them schema names. Replacing this trigger with the other one took the
	// reference lab from 7 of 7 back to 2 of 7.
	if !shouldExpand(true, 12, 40, 0) {
		t.Error("the first pass found no relations and the expansion was skipped")
	}
}

// It must NOT run when the first pass already worked: an application's own
// vocabulary beats any expansion of a generic list.
func TestExpansionIsSkippedWhenTheFirstPassWorked(t *testing.T) {
	if shouldExpand(true, 12, 40, 7) {
		t.Error("the first pass harvested vocabulary and found relations, and the " +
			"expansion ran anyway, spending 13,000 probes to improve on a result that " +
			"was already better than it can produce")
	}
}

// And it must not run when the ORACLE ITSELF produced nothing.
//
// This is the condition that was missing, measured on a PocketBase host: the
// scan spent 15,001 retry probes against /rest/v1/ paths on a server that is
// not PostgREST, and its own self-check reported postgrest-relation-hints as
// degraded in the same report. The expansion works by generating near misses
// and reading the names back out of the hint oracle; with no hint observed in
// the first pass there is no oracle to read, and the second pass cannot
// discriminate anything the first could not.
//
// Safe by measurement rather than by hope: on the lab fixture, a real
// PostgREST target, the scan reports ZERO degraded capabilities and finds 19
// read-exposed relations, so hints are observed there and this condition never
// fires. It fires only where the oracle is already known dead.
func TestExpansionIsSkippedWhenTheOracleProducedNoHints(t *testing.T) {
	if shouldExpand(true, 0, 0, 0) {
		t.Error("the hint oracle produced nothing in the first pass and the expansion " +
			"ran anyway; it derives near misses and reads the answer out of that same " +
			"oracle, so 13,000 further probes cannot discriminate what the first pass " +
			"could not")
	}
}

// A non-discriminating control probe already skipped the expansion, and still
// must: if a relation that cannot exist answers as though it does, no answer
// distinguishes anything.
func TestExpansionIsSkippedWhenTheControlProbeIsUseless(t *testing.T) {
	if shouldExpand(false, 12, 0, 0) {
		t.Error("the control probe was answered as though a relation that cannot exist " +
			"does, and the expansion ran anyway")
	}
}
