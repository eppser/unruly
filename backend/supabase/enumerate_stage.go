package supabase

import (
	"context"
	"errors"

	"github.com/eppser/unruly/internal/client"
	"github.com/eppser/unruly/internal/enumerate"
	"github.com/eppser/unruly/internal/wordlist"
	"github.com/eppser/unruly/scan"
)

// EnumerateStage recovers relation names, and retries once with near-miss
// candidates when the first pass came back empty.
//
// Ported from the "// ---- vocabulary + enumeration ----" section of
// scanTarget. This is the Enumerate phase of the provider contract: it decides
// what EXISTS, not whether it is exposed.
//
// TWO LEDGER LABELS, DELIBERATELY. The first pass attributes under "relations"
// and the retry under "relations-retry", exactly as the inline code did.
// Folding them into one would erase what the retry cost -- and the retry only
// runs when the first pass found nothing, so an operator reading a large
// "relations" figure needs to know whether that was one sweep or two.
// runStage folds State.Spending() rather than Name() precisely so a stage can
// attribute under several labels.
//
// THE STAGE DOES NOT LOG. No ported stage does: operator-facing messages stay
// in the command, where -silent governs them and their order is one person's
// decision. The retry's message needs facts only this stage has, so they come
// back in the outcome rather than a logger coming in.
type EnumerateStage struct {
	Client      *client.Client
	MaxRelation int
	Concurrency int
}

// EnumerateOutcome is what was found, plus what the command needs to say.
type EnumerateOutcome struct {
	Result enumerate.Result
	// Retried is false when there was no second pass, which is NOT the same as
	// a second pass that found nothing.
	Retried bool
	// Why is the operator-facing cause, decided here because only this stage
	// knows which condition fired.
	Why        string
	Candidates int
}

func (EnumerateStage) Name() string { return "relations" }

func (s EnumerateStage) Run(ctx context.Context, st *scan.State) error {
	st.Note(scan.Info, "enumerating relations via the PostgREST hint oracle")

	// Seeds come from the published vocabulary. HarvestedCount too: zero is the
	// difference between "the application told us nothing" and "it told us
	// names that turned out not to exist", and the vocabulary stage is what
	// knows which happened.
	vocab, ok := scan.Get[Vocabulary](st)
	if !ok {
		return errors.New("no vocabulary was published, so there is nothing to " +
			"enumerate with: this surface was not assessed")
	}
	en := enumerate.Run(ctx, s.Client, enumerate.Options{
		Seeds: vocab.Seeds, Concurrency: s.Concurrency})
	st.Attribute("relations", en.Requests)

	out := EnumerateOutcome{Result: en}
	if shouldExpand(en.Discriminating, en.HintsObserved, vocab.Origins.Harvested, len(en.Relations)) {
		expanded := wordlist.RelationCandidatesFrom(vocab.Seeds, en.Names(), s.MaxRelation)
		why := "the first pass found no relations"
		if vocab.Origins.Harvested == 0 {
			why = "no vocabulary could be harvested from the target"
		}
		retry := enumerate.Run(ctx, s.Client, enumerate.Options{
			Seeds: expanded, Concurrency: s.Concurrency})
		st.Attribute("relations-retry", retry.Requests)
		// Past tense, deliberately: the retry has already run by the time
		// anyone hears about it. "retrying" would announce finished work.
		st.Note(scan.Info, "%s; retried with %d near-miss candidates derived from "+
			"the seed list", why, len(expanded))
		out = EnumerateOutcome{
			Result:     en.Merge(retry),
			Retried:    true,
			Why:        why,
			Candidates: len(expanded),
		}
	}
	// Published, not written through a caller's pointer. Probing, realtime and
	// escalation all steer on this outcome, and every one of those hand-offs
	// used to be a variable in scanTarget.
	scan.Put(st, out)

	// --- what this measurement is worth ---------------------------------
	//
	// Three findings and three sentences that used to sit in scanTarget. Every
	// one is derived from the result this stage just produced, and holding
	// that result to derive them was one of main's reasons to know what a
	// Supabase scan is made of.
	res := out.Result

	// The candidate list was truncated: the scan asked about fewer names than
	// the seeds could generate, so the relation list is bounded by a budget
	// rather than by the target.
	if out.Retried {
		// The untruncated size, without asking for a slice the size of a small
		// country: the generator cannot produce more than one stem plus one
		// compound per modifier per seed.
		uncapped := len(vocab.Seeds) * (wordlist.RelationModifierCount() + 1)
		if full := wordlist.RelationCandidates(vocab.Seeds, uncapped); len(full) > out.Candidates {
			st.Add(enumerate.BudgetFinding(s.Client.RestBase(), out.Candidates, len(full)))
		}
	}

	// The control probe could not tell an absent relation from a present one,
	// so NOTHING downstream of enumeration can be trusted: read and write
	// classification both start from the discovered set. Reported as a finding
	// rather than left as an empty result, because an empty result reads as a
	// clean project.
	if !res.Discriminating {
		st.Note(scan.Error, "relation discovery is not trustworthy against this "+
			"target: %s", res.ControlDetail)
		if f, ok := res.ControlFinding(s.Client.RestBase()); ok {
			st.Add(f)
		}
	}

	// Probes that never got a readable answer, usually rate limiting. The
	// relation list is then a LOWER BOUND, and saying so is the difference
	// between a short list and a short list nobody questioned.
	if f, ok := res.UnresolvedFinding(s.Client.RestBase(), res.SeedCount); ok {
		st.Add(f)
		st.Note(scan.Warn, "%d of %d relation probes never got a readable answer "+
			"(usually rate limiting); the relations below are a lower bound",
			res.Unresolved, res.SeedCount)
	}
	st.Note(scan.Info, "%d relations discovered", len(res.Relations))
	return nil
}
