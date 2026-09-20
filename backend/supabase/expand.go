package supabase

// shouldExpand decides whether to spend ~13,000 probes on near-miss candidates
// derived from the seed list.
//
// The expansion buys a lot when it runs -- 2 of 7 relations became 7 of 7 on
// one project, 19 of 21 became 21 of 21 on another -- and it must not run when
// the first pass already worked, because an application's own vocabulary beats
// any expansion of a generic list.
//
// discriminating is whether the control probe distinguished anything at all.
// hints is how many hints the oracle produced in the first pass. harvested and
// found are the sizes of the harvested vocabulary and the relations recovered.
func shouldExpand(discriminating bool, hints, harvested, found int) bool {
	// A control probe that answers as though a relation which cannot exist
	// does means no answer distinguishes anything.
	if !discriminating {
		return false
	}
	// THE ORACLE MUST HAVE SPOKEN AT LEAST ONCE.
	//
	// The expansion generates near misses and reads the real names back out of
	// the hint oracle. With no hint observed in the first pass there is no
	// oracle to read, and a second pass cannot discriminate what the first
	// could not.
	//
	// Measured, on a PocketBase host reached through its own app bundle: the
	// scan spent 15,001 retry probes against /rest/v1/ paths on a server that
	// is not PostgREST at all, and reported postgrest-relation-hints as
	// degraded in the very same report. It had already established the oracle
	// was dead and kept paying for it.
	//
	// Safe by measurement rather than by hope. On the lab fixture -- a real
	// PostgREST target -- the scan reports ZERO degraded capabilities and
	// finds 19 read-exposed relations, so hints are observed and this never
	// fires there. An earlier early-stop was tried in this project and
	// WITHDRAWN because it cut the exploit lab from 7 relations to 2; that one
	// stopped on a heuristic about diminishing returns, which fires on healthy
	// targets. This stops only where the oracle is already known dead.
	if hints == 0 {
		return false
	}
	// Two triggers, and replacing the first with the second made things worse
	// before it was measured: switching to "the first pass found nothing"
	// alone took the reference lab from 7 of 7 back to 2 of 7, because that
	// pass found two relations and so never retried. Two is not nothing and it
	// is not success either.
	return harvested == 0 || found == 0
}
