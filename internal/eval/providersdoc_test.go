package eval

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// docs/providers.md must name every core concept a real backend uses.
//
// The document is the contract a backend author reads, and nothing checked it
// against the code. It described a scanner where a provider implemented
// Detect and Assess and that was the whole of it -- true when it was written,
// and two architectures out of date by the time this test was added: the
// Supabase and application backends are built as ordered stages that exchange
// typed artifacts through scan.State, and the document mentioned none of the
// fifteen identifiers that involves. A stale contract is worse than a missing
// one, because it is followed.
//
// The list is DERIVED, not written down here: it is every exported name in
// package scan that a backend under backend/ actually references. So the check
// fails when the architecture moves rather than when someone remembers to
// update a list, and the next concept a backend starts using arrives already
// required.
func TestTheProviderGuideNamesEveryCoreConceptABackendUses(t *testing.T) {
	root := filepath.Join("..", "..")

	// What package scan exports.
	declared := map[string]bool{}
	scanFiles, err := filepath.Glob(filepath.Join(root, "scan", "*.go"))
	if err != nil || len(scanFiles) == 0 {
		t.Fatalf("no files in package scan: %v", err)
	}
	reDecl := regexp.MustCompile(`(?m)^(?:type|func)\s+([A-Z]\w*)`)
	// Constants count. scan.Info, scan.Warn and scan.Error are declared in a
	// const block, so a pattern that only reads `type` and `func` would let
	// the three note levels -- the whole of how a stage narrates itself --
	// drift out of the document unnoticed.
	reConst := regexp.MustCompile(`(?m)^\t([A-Z]\w*)(?:\s+\w+)?\s*=`)
	for _, f := range scanFiles {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		for _, m := range reDecl.FindAllStringSubmatch(string(b), -1) {
			declared[m[1]] = true
		}
		for _, m := range reConst.FindAllStringSubmatch(string(b), -1) {
			declared[m[1]] = true
		}
	}
	if len(declared) == 0 {
		t.Fatal("no exported declarations found in package scan; the extractor stopped " +
			"matching and this check would pass against any document")
	}

	// What the real backends use of it.
	used := map[string]bool{}
	reUse := regexp.MustCompile(`\bscan\.([A-Z]\w*)`)
	backends, err := filepath.Glob(filepath.Join(root, "backend", "*", "*.go"))
	if err != nil || len(backends) == 0 {
		t.Fatalf("no backend sources: %v", err)
	}
	for _, f := range backends {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		for _, m := range reUse.FindAllStringSubmatch(string(b), -1) {
			used[m[1]] = true
		}
	}
	if len(used) == 0 {
		t.Fatal("no scan.X references found in any backend; either the extractor broke " +
			"or the architecture changed under this test, and both mean it is measuring " +
			"nothing")
	}

	// What the document names. Prose is not enough: `Error`, `Info` and `Warn`
	// are ordinary English, and a substring test on them would pass against a
	// document that never mentioned notes at all. A concept counts as named
	// when it appears QUALIFIED -- scan.X -- or as a whole word inside a Go
	// fence, which are the two forms a reader can act on.
	b, err := os.ReadFile(filepath.Join(root, "docs", "providers.md"))
	if err != nil {
		t.Fatalf("providers.md: %v", err)
	}
	doc := string(b)
	named := map[string]bool{}
	for _, m := range reUse.FindAllStringSubmatch(doc, -1) {
		named[m[1]] = true
	}
	fences := regexp.MustCompile("(?s)```go\\n(.*?)```").FindAllStringSubmatch(doc, -1)
	if len(fences) == 0 {
		t.Fatal("providers.md has no Go fences at all; it stopped being a contract")
	}
	reWord := regexp.MustCompile(`\b([A-Z]\w*)\b`)
	for _, f := range fences {
		for _, m := range reWord.FindAllStringSubmatch(f[1], -1) {
			named[m[1]] = true
		}
	}

	var missing []string
	for id := range used {
		if declared[id] && !named[id] {
			missing = append(missing, id)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Errorf("docs/providers.md never names %v.\nEvery one is exported by package "+
			"scan and used by a backend under backend/, so a person writing the next "+
			"backend from this document would not know it exists. Name it in a Go fence "+
			"or write it qualified as scan.X -- prose alone does not count, because "+
			"Error and Info are ordinary words.", missing)
	}
}
