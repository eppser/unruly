// Package handoff carries one stage's result out of the scan and back into it.
//
// The scan path is deterministic and stays that way: the same inputs produce
// the same report, and no model runs inside it. That rule constrains the
// ANALYSIS, not the INPUTS. Enumeration is seeded with candidate names, and
// where those names come from has never been part of the determinism claim --
// the pinned wordlist is one source, the application's own bundles are
// another.
//
// This package makes that seam a file. `-emit-vocab` writes what the harvest
// found and stops; `-vocab` reads a file back and enumerates from it. Between
// the two, anything may edit the list: an operator who knows the schema, a
// model reading the marketing copy, or a tool that unruly cannot parse at all
// -- an APK, an Electron bundle, a decompiled binary. unruly then tests every
// name the same deterministic way, and the evidence in the report is a real
// response either way.
//
// A file an agent wrote is untrusted input. Seeds land in URL paths, so
// ReadVocabulary drops anything that is not an identifier and says how many it
// dropped rather than quietly enumerating a shorter list.
package handoff

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
)

// SchemaVersion is the version of the artifact this build writes. A reader
// refuses a NEWER file: a field it does not understand may be the one that
// changes what a seed means.
const SchemaVersion = 1

// VocabularyStage names the stage this artifact belongs to. Checked on read,
// so feeding the wrong file to -vocab is an error rather than an empty scan.
const VocabularyStage = "vocabulary"

// Note travels inside the file. The reader is as likely to be a model as a
// person, and an artifact that does not say what it is for gets edited wrongly.
const Note = "Seeds are candidate relation and routine names. unruly tests each one " +
	"against the target's own error responses and reports only what it can prove. " +
	"Add names you believe exist -- from the application's copy, its API, a mobile " +
	"bundle, or knowledge of the schema -- one per entry, lowercase, letters digits " +
	"and underscore. Nothing here is a finding; every name is a guess until measured."

// Vocabulary is the enumeration stage's input, in file form.
type Vocabulary struct {
	SchemaVersion int    `json:"schema_version"`
	Stage         string `json:"stage"`
	Tool          string `json:"tool"`
	// Site is where the seeds were harvested, when they were harvested.
	// Empty when the file was written by hand.
	Site string `json:"site,omitempty"`
	Note string `json:"note"`
	// Sources are the URLs that contributed, kept so a reader can tell a
	// harvest that read the whole application from one that read a 404 page.
	Sources []string `json:"sources"`
	Seeds   []string `json:"seeds"`
}

// NewVocabulary builds the artifact. Seeds and sources are sorted and
// deduplicated here, so the file is byte-identical for identical input.
func NewVocabulary(tool, site string, seeds, sources []string) Vocabulary {
	return Vocabulary{
		SchemaVersion: SchemaVersion,
		Stage:         VocabularyStage,
		Tool:          tool,
		Site:          site,
		Note:          Note,
		Sources:       normalise(sources),
		Seeds:         normalise(seeds),
	}
}

// Write encodes v to path.
func Write(path string, v Vocabulary) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o644)
}

// reSeed is what a seed may look like. A hand-written file may propose a
// CamelCase relation, which PostgreSQL allows, so the reader is the more
// permissive of the two. Everything outside it -- a path traversal, a query
// string, a shell metacharacter -- is dropped, because a seed is pasted into
// a URL.
//
// Any alphabet. The first version was [A-Za-z][A-Za-z0-9_]{0,62}, which threw
// away every name an agent supplied for a schema that is not in English --
// and Firestore, where a supplied name is the ONLY way to reach a collection,
// is exactly where that mattered most. The same ASCII assumption cost the
// harvester 93% of its recall on the corpus project built to measure it.
var reSeed = regexp.MustCompile(`^[\p{L}][\p{L}\p{N}_]{0,62}$`)

// ReadVocabulary loads path. Seeds that are not identifiers are dropped and
// returned separately: silently enumerating a shorter list than the file asks
// for is the failure this scanner exists to refuse.
func ReadVocabulary(path string) (v Vocabulary, dropped []string, err error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return v, nil, err
	}
	if err := json.Unmarshal(b, &v); err != nil {
		return v, nil, fmt.Errorf("%s is not a vocabulary handoff file: %w", path, err)
	}
	if v.Stage != VocabularyStage {
		return v, nil, fmt.Errorf("%s is a %q handoff, not %q", path,
			or(v.Stage, "(unnamed)"), VocabularyStage)
	}
	if v.SchemaVersion > SchemaVersion {
		return v, nil, fmt.Errorf("%s is schema version %d and this build reads %d: "+
			"upgrade unruly rather than enumerating a file it may misread",
			path, v.SchemaVersion, SchemaVersion)
	}
	kept := make([]string, 0, len(v.Seeds))
	for _, s := range v.Seeds {
		if reSeed.MatchString(s) {
			kept = append(kept, s)
			continue
		}
		dropped = append(dropped, s)
	}
	v.Seeds = normalise(kept)
	sort.Strings(dropped)
	return v, dropped, nil
}

// normalise lowercases nothing and changes nothing: it sorts, deduplicates and
// drops blanks, so two runs that harvested the same tokens write the same
// bytes.
func normalise(xs []string) []string {
	seen := make(map[string]bool, len(xs))
	out := make([]string, 0, len(xs))
	for _, x := range xs {
		x = strings.TrimSpace(x)
		if x == "" || seen[x] {
			continue
		}
		seen[x] = true
		out = append(out, x)
	}
	sort.Strings(out)
	return out
}

func or(s, alt string) string {
	if s == "" {
		return alt
	}
	return s
}
