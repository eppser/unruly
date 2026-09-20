// Package emitsites finds where each finding id is constructed.
//
// Two things need this list and they used to disagree about how to get it.
// cmd/coveraudit walked the source and matched the two shapes an id can take;
// the exploitability ledger's test read docs/checks.md instead, which meant a
// finding missing from the documentation was invisible to the one check that
// records whether a serious claim has anything behind it. Two safety nets, the
// same hole -- and it was live: PocketBase shipped two high-severity findings
// that appeared in neither.
//
// So the extraction lives here once and both callers import it. Duplicating
// the regexes into a test would have reproduced the defect this repository
// keeps finding: a check that grades its own copy of the rule cannot fail for
// a reason the real rule would.
package emitsites

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

var (
	// An id in the field literal. The shape is deliberately generic rather
	// than a list of providers: a rule that has to be edited whenever somebody
	// adds a backend is a rule that will be forgotten by the person least
	// likely to know it exists.
	reEmit = regexp.MustCompile(`ID:\s*"([a-z][a-z0-9]*(?:-[a-z0-9]+)+)"`)
	// `ID: id`, where the id was chosen further up the function.
	reEmitVar = regexp.MustCompile(`ID:\s*[a-zA-Z_][a-zA-Z0-9_]*\s*,`)
	// Any id-shaped literal, used to attribute the form above. Same shape as
	// reEmit for the same reason.
	reIDConst = regexp.MustCompile(`"([a-z][a-z0-9]*(?:-[a-z0-9]+)+)"`)
)

// Site is one place a finding is constructed.
type Site struct {
	File string
	Line int
}

// Sites maps finding id to every place it is constructed under root.
//
// Matching broadly over-reports, which is the safe direction: an over-report
// demands coverage that probably exists, an under-report hides a check nobody
// tests.
func Sites(root string) (map[string][]Site, error) {
	out := map[string][]Site{}
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(path, ".go") ||
			strings.HasSuffix(path, "_test.go") {
			return err
		}
		b, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		rel := strings.TrimPrefix(filepath.ToSlash(path), "./")
		lines := strings.Split(string(b), "\n")
		for n, line := range lines {
			if m := reEmit.FindStringSubmatch(line); m != nil {
				out[m[1]] = append(out[m[1]], Site{File: rel, Line: n + 1})
				continue
			}
			// The id is chosen above the literal. Attribute the site to every
			// finding id named in the enclosing function.
			if reEmitVar.MatchString(line) {
				for _, id := range enclosingIDs(lines, n) {
					out[id] = append(out[id], Site{File: rel, Line: n + 1})
				}
			}
		}
		return nil
	})
	return out, err
}

// IDs is every finding id constructed under any of the roots, sorted.
func IDs(roots ...string) ([]string, error) {
	seen := map[string]bool{}
	for _, r := range roots {
		s, err := Sites(r)
		if err != nil {
			return nil, err
		}
		for id := range s {
			seen[id] = true
		}
	}
	out := make([]string, 0, len(seen))
	for id := range seen {
		out = append(out, id)
	}
	sort.Strings(out)
	return out, nil
}

// enclosingIDs returns the finding ids named inside the function containing
// the given line.
func enclosingIDs(lines []string, at int) []string {
	start := 0
	for i := at; i >= 0; i-- {
		if strings.HasPrefix(lines[i], "func ") {
			start = i
			break
		}
	}
	end := len(lines)
	for i := at + 1; i < len(lines); i++ {
		if strings.HasPrefix(lines[i], "func ") {
			end = i
			break
		}
	}
	seen := map[string]bool{}
	var out []string
	for _, l := range lines[start:end] {
		for _, m := range reIDConst.FindAllStringSubmatch(l, -1) {
			if !seen[m[1]] {
				seen[m[1]] = true
				out = append(out, m[1])
			}
		}
	}
	return out
}
