// Package sample decides WHICH items a budget keeps.
//
// Every probe list in this scanner is bounded, because probing is requests and
// requests are somebody else's server. The bounds are not the problem and are
// reported honestly wherever they bind. What was wrong is how they chose.
//
// Each list was sorted and then cut at the limit, which is stable, obvious, and
// biased: the survivors are the alphabetically first ones. Measured, both of
// these were live on the reference project rather than hypothetical:
//
//   - the harvested vocabulary yields 4,112 tokens and the cap keeps 2,000, so
//     half the words the application uses about itself were discarded before
//     any probe was sent, upstream of relation AND routine discovery;
//   - the RPC budget binds at 1,200 of 7,547, and on a vocabulary spanning 25
//     name prefixes it reached 10 of them and stopped at "import".
//
// Alphabetical position says nothing about whether a name is worth probing, so
// the old sample was arbitrary and biased. A stride is arbitrary in the same
// way, deterministic in the same way, and unbiased with respect to the name
// space. That matters more than it sounds: a report can say "1200 of 7547
// probed" and an operator can reason about a lower bound, but nobody can
// correct for a bias that was never stated.
package sample

// Strided reorders xs so that any prefix of the result spans the whole list
// rather than its opening pages.
//
// It is a permutation: every element appears exactly once, nothing is dropped
// here, and the caller's budget alone decides what is reached. Deterministic by
// construction -- same input, same order, every run -- which the byte-identical
// report guarantee depends on.
//
// budget is how many items the caller can afford. When the list already fits,
// it is returned untouched, so an unbudgeted scan probes in plain sorted order.
func Strided(xs []string, budget int) []string {
	if budget <= 0 || len(xs) <= budget {
		return xs
	}
	stride := (len(xs) + budget - 1) / budget
	out := make([]string, 0, len(xs))
	for off := 0; off < stride; off++ {
		for i := off; i < len(xs); i += stride {
			out = append(out, xs[i])
		}
	}
	return out
}

// Take keeps at most n items, spread across the whole list.
//
// This is the form a hard cut wants: xs[:n] keeps the front, Take(xs, n) keeps
// n items sampled across all of it.
func Take(xs []string, n int) []string {
	if n <= 0 || len(xs) <= n {
		return xs
	}
	return Strided(xs, n)[:n]
}
