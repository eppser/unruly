package scan

// Budget is an allowance several stages draw on.
//
// It is the first genuinely SHARED MUTABLE thing to cross the stage seam.
// Everything before it was either a value passed down (seeds, flags) or a
// provider-private result handed between stages of one backend. A budget is
// different: on Supabase the default-schema routine sweep and every
// per-schema sweep draw on one allowance, and if each sees the full amount the
// scan issues several times the requests the operator capped it at.
//
// It lives here rather than in a provider package because every backend has a
// request budget -- the rule already in force is that things EVERY backend has
// belong to the shared core, and things one backend has stay in its own
// package.
type Budget struct{ left int }

// NewBudget returns an allowance of n requests.
func NewBudget(n int) *Budget {
	if n < 0 {
		n = 0
	}
	return &Budget{left: n}
}

// Take grants up to n and returns how much was actually granted.
//
// Returning the GRANTED amount rather than a boolean is what lets the caller
// report its own truncation. The schemas pass was built around this after a
// real gap: "previously only the default schema's truncation was reported, so
// a secondary schema whose routine sweep ran out said nothing at all -- a
// silent coverage gap in the surface most likely to be forgotten". A single
// global note that names no schema does not close that; the consumer has to
// know it personally was clipped.
//
// A nil Budget is UNCAPPED and grants everything asked. That is deliberate and
// load-bearing: every stage written before this type existed runs with no
// budget, and a zero value that meant "nothing" would silently reduce each of
// them to zero work and report the result as clean -- the exact false negative
// this scanner exists to refuse.
func (b *Budget) Take(n int) int {
	if n <= 0 {
		return 0
	}
	if b == nil {
		return n
	}
	if n > b.left {
		n = b.left
	}
	b.left -= n
	return n
}

// Left is how much of the allowance remains. A nil Budget never runs out.
func (b *Budget) Left() int {
	if b == nil {
		return int(^uint(0) >> 1)
	}
	return b.left
}

// Exhausted reports whether nothing remains, so a stage can decline cleanly
// rather than perform a zero-sized sweep and report it as a clean one.
func (b *Budget) Exhausted() bool { return b != nil && b.left == 0 }
