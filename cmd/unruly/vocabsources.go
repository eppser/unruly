package main

import (
	"context"

	"github.com/eppser/unruly/internal/client"
	"github.com/eppser/unruly/internal/wordlist"
	"github.com/eppser/unruly/scan"
)

// vocabularySources decides what the scan is allowed to guess.
//
// -vocab-only exists because every Firestore probe is a metered read on
// SOMEBODY ELSE'S project: the pinned list is 884 names, and an operator who
// already knows their own schema should not have to buy 884 guesses to have
// the four collections they named checked.
//
// It is deliberately not spelled -max-collections. That bound samples ACROSS
// the merged vocabulary, so it can drop the very names the operator supplied
// -- silently turning "check these four" into "check some four of everything".
// Restricting the SOURCES is the honest lever; sampling is a budget, not a
// selection.
func vocabularySources(o *options, harvested, advertised, supplied []string) scan.SeedSet {
	if o.vocabOnly {
		// Harvested and advertised names are dropped too. "Only" has to mean
		// only, or the flag's cost promise is not one.
		return scan.SeedSet{Supplied: supplied}
	}
	return scan.SeedSet{
		Pinned:     wordlist.Relations(),
		Harvested:  harvested,
		Advertised: advertised,
		Supplied:   supplied,
	}
}

// firebaseCandidates decides what the Firestore probe is allowed to guess.
//
// Firestore is built from a SEPARATE candidate list than the PostgREST path --
// Collections merged with Relations, not the VocabularyStage's seeds -- so
// restricting the Supabase sources alone would have left this path probing the
// full list while the flag claimed otherwise. Found by checking rather than
// assuming: the two paths do not share a vocabulary.
//
// This is where -vocab-only actually saves the project's owner money, because
// Firestore has no discovery oracle: every candidate is a metered read, billed
// whether the collection exists or not.
//
// With the flag off this is exactly what the call site did before, including
// the fact that harvestFor already folds in the supplied names.
func firebaseCandidates(ctx context.Context, o *options, limiter *client.Limiter) []string {
	return firebaseCandidatesFrom(o, harvestFor(ctx, o, limiter))
}

// firebaseCandidatesFrom is the pure half, shared with the engine hand-off so
// application vocabulary is harvested once and every provider receives the
// same snapshot.
func firebaseCandidatesFrom(o *options, harvested []string) []string {
	if o.vocabOnly {
		return suppliedVocabulary(o)
	}
	return wordlist.Merge(harvested,
		wordlist.Merge(wordlist.Collections(), wordlist.Relations()))
}

// keyChoice is which credential the scan will use, and why.
//
// Returned rather than logged so the decision can be tested without capturing
// log output. The message is part of the contract: an operator whose ambient
// key was overruled has to be told, or the scan silently used a credential
// they never named.
type keyChoice struct {
	Key        string
	FromEnv    bool
	Discovered bool
	// Warn is empty when nothing surprising happened.
	Warn string
}

// chooseKey decides between the credential already in hand and the one the
// target ships.
//
// THE BUG THIS ENCODES A FIX FOR: preferring the target's key used to require
// that BOTH project references were known and differed, which quietly meant
// "managed projects only". A self-hosted deployment has no reference, so the
// ambient SUPABASE_ANON_KEY was kept, every request was answered 401, and the
// scan reported 0 relations on a target where the discovered key finds 21.
// The references are now used ONLY to word the warning, never to decide.
//
// An explicitly supplied -k is not overruled: naming a credential is an
// instruction, an exported shell variable is ambience.
//
// Extracted from scanTarget so the decision is testable without a network, a
// fixture or Docker. Its one recorded failure produced a report that looked
// clean, which is the shape this project cares most about.
func chooseKey(current string, fromEnv bool, discovered, discoveredRef, currentRef string) keyChoice {
	switch {
	case current == "":
		return keyChoice{Key: discovered, Discovered: discovered != ""}
	case fromEnv && discovered != "" && discovered != current:
		warn := "SUPABASE_ANON_KEY does not match the key this target ships; using the " +
			"discovered one, which is the credential that belongs to this project"
		if currentRef != "" && discoveredRef != "" {
			warn = "SUPABASE_ANON_KEY belongs to project " + currentRef +
				" but this target is " + discoveredRef +
				"; using the key discovered on the target instead"
		}
		return keyChoice{Key: discovered, Discovered: true, Warn: warn}
	}
	return keyChoice{Key: current, FromEnv: fromEnv}
}
