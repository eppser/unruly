package semantic

import (
	"context"
	"sort"
	"sync"
)

// augmentWorkers is how many columns of one relation are in flight at once.
//
// Four. What this is worth depends entirely on whether the server reuses the
// prompt prefix, and the measurement is worth stating because the obvious
// guess is wrong. With a 1.9kB prompt and no prefix reuse, concurrency buys
// NOTHING -- Ollama measured 340ms per request at concurrency 1, 2, 4 and 8,
// and llama.cpp with cache_prompt off measured 203ms, equally flat. The GPU is
// already saturated processing the prompt, and concurrency cannot overlap work
// that is compute-bound.
//
// Once caching removes that work the remaining cost is overhead, and overhead
// overlaps: llama.cpp with cache_prompt measured 33ms at one worker and 17ms
// at four. End to end over sixteen columns, 31ms per column serial against
// 15ms parallel.
//
// So the pool is not the lever -- it is what makes the lever pay. Four,
// because that is where it stopped improving; extra requests queue server-side
// rather than erroring, so overshooting is cheap and undershooting is not.
const augmentWorkers = 4

// Asker is the part of a Classifier that Augment needs. An interface rather
// than the concrete type so the merge rules can be tested without a model.
type Asker interface {
	Enabled() bool
	Classify(ctx context.Context, column string, values []string) (Result, error)
}

// Augment returns classes a model found for columns the RULES could not read.
//
// The precedence is the safety argument for the whole feature, so it is
// enforced here rather than left to callers:
//
//   - A column the rules classified is never sent to the model. The rules
//     measure 0.4% false positives across 500 negatives; the best model tested
//     measures 12%. Putting a proof up for a second opinion trades the number
//     that is trustworthy for the one that is not, and it costs a request.
//   - A class the rules already established anywhere on this relation is not
//     repeated as a model class. A report that states the same fact once as
//     proof and once as opinion argues with itself.
//   - A model that cannot be reached is not an error here. The caller decides
//     whether an unassessed surface is worth a finding; losing the whole scan
//     because a sidecar is down is not a trade this tool makes.
//
// values is keyed by column. ruleClasses is what internal/classify produced,
// also keyed by column; a column present there is considered covered.
//
// Returns nil -- not an empty slice -- when there is nothing to add, because
// the field it feeds is omitempty and a non-nil empty slice still changes the
// JSON a rule-only scan writes.
func Augment(ctx context.Context, c Asker, columns []string,
	values map[string][]string, ruleClasses map[string][]string) ([]string, error) {

	if c == nil || !c.Enabled() {
		return nil, nil
	}
	established := map[string]bool{}
	for _, cs := range ruleClasses {
		for _, cl := range cs {
			established[cl] = true
		}
	}
	// Sorted, so the set of columns asked about -- and which error is reported
	// when several fail -- is the same on every run.
	cols := make([]string, 0, len(columns))
	for _, col := range columns {
		if len(ruleClasses[col]) == 0 {
			cols = append(cols, col)
		}
	}
	sort.Strings(cols)

	// Asked in parallel, merged in sorted order. See augmentWorkers for what
	// that is worth and when.
	//
	// Every result lands in its own slot and nothing is read until all of them
	// are back, so which request wins the race changes neither the classes
	// returned nor the error reported. Byte-identical output across runs is a
	// published property of this scanner and concurrency must not spend it.
	type outcome struct {
		res Result
		err error
	}
	out := make([]outcome, len(cols))
	work := make(chan int)
	var wg sync.WaitGroup
	for w := 0; w < augmentWorkers && w < len(cols); w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range work {
				out[i].res, out[i].err = c.Classify(ctx, cols[i], values[cols[i]])
			}
		}()
	}
	for i := range cols {
		work <- i
	}
	close(work)
	wg.Wait()

	found := map[string]bool{}
	var firstErr error
	for _, o := range out {
		if o.err != nil {
			if firstErr == nil {
				firstErr = o.err
			}
			continue
		}
		if o.res.Class == "" || established[o.res.Class] {
			continue
		}
		found[o.res.Class] = true
	}
	if len(found) == 0 {
		return nil, firstErr
	}
	classes := make([]string, 0, len(found))
	for cl := range found {
		classes = append(classes, cl)
	}
	sort.Strings(classes)
	return classes, firstErr
}
