package scan

import "sort"

// Access is what the scan ESTABLISHED about who may do what.
//
// It is the neutral half of intent verification. The measurements live in a
// backend's own artifacts -- a probe result knows which relations anon could
// read, an escalation result knows what a signed-in role gained -- and the
// command must not read those. So the provider translates, exactly as it does
// for Coverage.
//
// ONLY MEASURED FACTS BELONG HERE. A relation nobody probed produces no fact,
// and an expectation about it is therefore unverified rather than satisfied.
// Filling this in optimistically -- assuming a relation that was never
// enumerated is denied -- would turn a manifest of intentions into a clean
// report from a scan that tested none of them.
type Access struct {
	Observed []AccessFact
}

// An AccessFact is one measured (resource, operation, subject) outcome.
//
// The fields are strings rather than typed enums because this is the boundary:
// intent's vocabulary and a backend's vocabulary meet here, and a type shared
// between them would make the pipeline import one of the two.
type AccessFact struct {
	Resource  string
	Operation string
	Subject   string
	// Scope is empty when the probe did not distinguish ownership. "own" and
	// "all" are carried without importing the intent package.
	Scope string
	// Allowed is what happened, not what should have.
	Allowed bool
}

// MergeAccess combines provider-neutral measurements without interpreting
// them. Exact duplicates are removed and output order is stable.
func MergeAccess(parts ...Access) Access {
	seen := map[AccessFact]bool{}
	var out Access
	for _, part := range parts {
		for _, fact := range part.Observed {
			if seen[fact] {
				continue
			}
			seen[fact] = true
			out.Observed = append(out.Observed, fact)
		}
	}
	sort.Slice(out.Observed, func(i, j int) bool {
		a, b := out.Observed[i], out.Observed[j]
		ak := a.Resource + "\x00" + a.Operation + "\x00" + a.Subject + "\x00" + a.Scope
		bk := b.Resource + "\x00" + b.Operation + "\x00" + b.Subject + "\x00" + b.Scope
		if ak != bk {
			return ak < bk
		}
		return !a.Allowed && b.Allowed
	})
	return out
}
