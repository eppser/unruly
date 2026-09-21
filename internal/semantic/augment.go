package semantic

import (
	"context"
	"sort"
)

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
	found := map[string]bool{}
	var firstErr error
	// Sorted, so the request order -- and so any partial result after an error
	// -- is the same on every run.
	cols := append([]string(nil), columns...)
	sort.Strings(cols)
	for _, col := range cols {
		if len(ruleClasses[col]) > 0 {
			continue
		}
		r, err := c.Classify(ctx, col, values[col])
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		if r.Class == "" || established[r.Class] {
			continue
		}
		found[r.Class] = true
	}
	if len(found) == 0 {
		return nil, firstErr
	}
	out := make([]string, 0, len(found))
	for cl := range found {
		out = append(out, cl)
	}
	sort.Strings(out)
	return out, firstErr
}
