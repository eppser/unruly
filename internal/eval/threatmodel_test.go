package eval_test

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// The threat model has to stay true, or it is prose that rots.
//
// It exists to order the report by consequence rather than by which subsystem
// produced a finding, and to make a check that fits nowhere in it recognisable
// as noise. Both properties fail silently the moment a check is added without a
// place in it: the new finding is reported, nobody can say what an attacker
// gains from it, and the document still reads as complete.
//
// Writing it caught fifteen checks with no row and two whole categories missing
// -- disclosure, and what the scan itself leaves behind. That is what this test
// is for.
func TestThreatModelCoversEveryCheck(t *testing.T) {
	id := regexp.MustCompile(`\x60([a-z][a-z0-9]*(?:-[a-z0-9]+)+)\x60`)
	collect := func(path string) map[string]bool {
		b, err := os.ReadFile(filepath.Join("..", "..", path))
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		out := map[string]bool{}
		for _, m := range id.FindAllStringSubmatch(string(b), -1) {
			switch {
			case strings.HasPrefix(m[1], "supabase-"), strings.HasPrefix(m[1], "firebase-"),
				strings.HasPrefix(m[1], "unruly-"), strings.HasPrefix(m[1], "app-"):
				out[m[1]] = true
			}
		}
		return out
	}
	docs := collect("docs/checks.md")
	model := collect("docs/threat-model.md")

	if len(docs) < 30 {
		t.Fatalf("only %d ids found in docs/checks.md; the extractor stopped matching and "+
			"this test would pass by comparing almost nothing", len(docs))
	}

	var missing, invented []string
	for id := range docs {
		if !model[id] {
			missing = append(missing, id)
		}
	}
	for id := range model {
		if !docs[id] {
			invented = append(invented, id)
		}
	}
	sort.Strings(missing)
	sort.Strings(invented)

	for _, m := range missing {
		t.Errorf("%s is a check with no place in the threat model. Either say what an "+
			"attacker gains from it, or it is noise and should not be emitted.", m)
	}
	for _, i := range invented {
		t.Errorf("the threat model names %s, which no longer exists. A model that "+
			"describes checks the tool does not run is worse than none.", i)
	}
}
