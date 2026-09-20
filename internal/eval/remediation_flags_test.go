package eval_test

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// Remediation must not name a flag this binary does not have.
//
// A finding's remediation is an instruction an operator follows. One that
// names an option which does not exist is worse than one that admits a gap:
// the operator runs it, the flag is rejected or ignored, nothing changes, and
// the reasonable conclusion is that the project was clean after all.
//
// This is not hypothetical. backend/neon's reach finding told operators to
// re-run with -bearer, a flag that has never existed in this binary, and it
// shipped that way because nothing was checking. The fix was to route the
// existing -user-jwt through the seam; the check is here so the next one
// cannot ship the same way.
func TestRemediationOnlyNamesFlagsThatExist(t *testing.T) {
	declared := declaredFlagNames(t)
	if len(declared) < 5 {
		t.Fatalf("only %d flags found; the parser stopped matching and this test "+
			"would pass anything", len(declared))
	}

	// Flags as they appear inside an invocation example: "unruly -u ... -flag".
	invocation := regexp.MustCompile(`unruly\s+((?:-[A-Za-z][\w-]*(?:\s+\S+)?\s*)+)`)
	// The leading boundary is load-bearing. Without it "my-app.lovable.app"
	// yields a flag called -app and "<data-api-url>" yields -api-url, and the
	// check drowns in its own false positives.
	flagToken := regexp.MustCompile(`(?:^|\s)-([A-Za-z][\w-]*)`)

	var bad []string
	for _, root := range []string{"backend", "internal", "cmd"} {
		err := filepath.Walk(filepath.Join("..", "..", root),
			func(path string, info os.FileInfo, err error) error {
				if err != nil || info.IsDir() || !strings.HasSuffix(path, ".go") ||
					strings.HasSuffix(path, "_test.go") {
					return err
				}
				b, readErr := os.ReadFile(path)
				if readErr != nil {
					return readErr
				}
				for _, m := range invocation.FindAllStringSubmatch(string(b), -1) {
					for _, f := range flagToken.FindAllStringSubmatch(m[1], -1) {
						name := f[1]
						if declared[name] {
							continue
						}
						bad = append(bad, filepath.Base(path)+": -"+name)
					}
				}
				return nil
			})
		if err != nil {
			t.Fatalf("walk %s: %v", root, err)
		}
	}
	sort.Strings(bad)
	for _, b := range bad {
		t.Errorf("%s is named in an invocation example and is not a registered flag. "+
			"An operator who runs it sees no change and concludes the target was "+
			"clean", b)
	}
}

// declaredFlagNames reads the flag registrations out of main.go rather than
// taking a hand-written list, which would drift the moment a flag was added.
func declaredFlagNames(t *testing.T) map[string]bool {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "cmd", "unruly", "main.go"))
	if err != nil {
		t.Fatal(err)
	}
	// fs.StringVar(&o.x, "name", ...) and the P variants, which also carry a
	// short form as the next argument.
	reg := regexp.MustCompile(`fs\.\w+VarP?\(&[\w.]+,\s*"([\w-]+)"(?:,\s*"([\w-]+)")?`)
	out := map[string]bool{}
	for _, m := range reg.FindAllStringSubmatch(string(b), -1) {
		out[m[1]] = true
		if m[2] != "" {
			out[m[2]] = true
		}
	}
	return out
}
