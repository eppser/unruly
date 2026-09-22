// Package browserscan holds the decisions the WebAssembly build makes, in a
// place a test can reach them.
//
// cmd/unruly-wasm is tagged `js && wasm`, so nothing in it compiles on a
// developer machine or in CI, and nothing in it can be tested there either.
// The first version of that file built its candidate list inline with
// wordlist.RelationCandidates(nil, 240) -- a function that expands SEEDS and
// returns an empty slice when given none. The browser therefore probed zero
// names and reported "Nothing readable was found" for a project the CLI finds
// 23 relations on.
//
// A wrong answer is bad. A wrong answer that looks like a clean bill of health
// is the specific thing this scanner refuses to produce, and it shipped
// because the decision lived where no test could see it. That is why this
// package exists.
package browserscan

import (
	"regexp"
	"sort"
	"strings"

	"github.com/eppser/unruly/internal/wordlist"
)

// reWord picks identifiers out of minified JavaScript.
//
// Lower-case, at least four characters, which is the same floor
// wordlist.RelationCandidates applies. Minified code is mostly one and two
// letter locals, so the floor removes nearly all of the noise without a
// language-aware parse.
var reWord = regexp.MustCompile(`[a-z][a-z0-9_]{3,47}`)

// reCall matches the supabase-js calls that NAME a table or routine outright.
//
// This is the whole ballgame, and generic word harvesting is not close. On a
// real application bundle, `.from("...")` yielded the 22 tables the app uses
// and `.rpc("...")` the 13 routines: together, essentially its entire schema,
// read straight out of the code rather than guessed. Alphabetically sorted
// word harvesting over the same bundle reached 3 of 18 known tables at a
// budget of 240, because the budget filled up with words starting "a".
//
// Quoting varies with the bundler, so all three forms are matched.
var reCall = regexp.MustCompile(`\.(?:from|rpc)\(\s*["'` + "`" + `]([A-Za-z0-9_]{2,63})["'` + "`" + `]`)

// stop holds words that appear in every bundle and name no table.
//
// Deliberately short. A long list would start encoding the schemas seen during
// development, which is how a scanner comes to look accurate on its author's
// projects and blind everywhere else.
var stop = map[string]bool{
	"function": true, "return": true, "const": true, "await": true, "async": true,
	"import": true, "export": true, "default": true, "window": true, "document": true,
	"length": true, "string": true, "number": true, "object": true, "value": true,
	"true": true, "false": true, "null": true, "undefined": true, "select": true,
	"from": true, "where": true, "insert": true, "update": true, "delete": true,
	"https": true, "http": true, "supabase": true, "react": true, "className": true,
	"module": true, "require": true, "prototype": true, "constructor": true,
}

// Candidates returns the relation names a browser scan should ask about,
// highest value first, capped at max.
//
// Names harvested from the application's own code come FIRST. A vibe-coded
// schema is named after its domain rather than after conventions, so the
// pinned list alone reaches very little of it, and the budget here is small
// enough that order decides what actually gets probed.
//
// With no harvested text this still returns the pinned list. Returning nothing
// would make a scan that looked at nothing indistinguishable from one that
// found nothing.
func Candidates(bundleText string, max int) []string {
	if max <= 0 {
		return nil
	}
	pinned := wordlist.Merge(wordlist.Collections(), wordlist.Relations())
	named := Named(bundleText)
	harvested := Harvest(bundleText)

	out := make([]string, 0, max)
	seen := map[string]bool{}
	add := func(names []string) {
		for _, n := range names {
			if len(out) >= max || seen[n] {
				continue
			}
			seen[n] = true
			out = append(out, n)
		}
	}
	// Names the code states outright, then the app's other words, then what
	// those expand to, then convention. Order is the whole design: the budget
	// is small and it is spent from the top.
	add(named)
	add(harvested)
	add(wordlist.RelationCandidates(harvested, max))
	add(pinned)
	return out
}

// Named returns the tables and routines the application's own code names in a
// supabase-js call. These are not guesses; they are the schema.
func Named(text string) []string {
	if text == "" {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, m := range reCall.FindAllStringSubmatch(text, -1) {
		if n := m[1]; !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	// Sorted, because two runs against the same app must probe in the same
	// order. The CLI publishes byte-identical output and this build does not
	// get to be the exception.
	sort.Strings(out)
	return out
}

// Harvest pulls plausible relation names out of a page or a bundle.
func Harvest(text string) []string {
	if text == "" {
		return nil
	}
	seen := map[string]bool{}
	for _, w := range reWord.FindAllString(text, -1) {
		w = strings.ToLower(w)
		if stop[w] || seen[w] {
			continue
		}
		seen[w] = true
	}
	out := make([]string, 0, len(seen))
	for w := range seen {
		out = append(out, w)
	}
	// Sorted, so two runs against the same app probe in the same order and the
	// browser build keeps the determinism the CLI promises.
	sort.Strings(out)
	return out
}
