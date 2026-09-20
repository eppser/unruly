package eval_test

// The accuracy claim must be gated by the measurement it rests on.
//
// docs/auditing.md has carried this as a known hole: `make audit` runs its
// checks, and the corpus scoreboard is not one of them. The project's most
// externally-visible claim -- more accurate than the alternatives, including
// the vendor consoles -- sat outside the gate entirely, so the README could
// drift from benchmark/RESULTS.md and nothing would say so.
//
// Re-running the benchmark cannot be the gate: it brings up fourteen docker
// stacks and takes minutes, and a check nobody can afford to run is a check
// that gets disabled. What CAN be gated, cheaply and offline, is the
// relationship between the claim and the measurement:
//
//   - every corpus project is accounted for -- scored, or listed as not
//     scored with a reason. A project added and never scored is the silent
//     absence this repo keeps rediscovering, and it would make the corpus
//     look larger than the evidence.
//   - every number the README quotes appears in the scoreboard's totals.
//   - the counts the README states match the corpus and the scoreboard.
//   - the scoreboard names a commit that exists, so a reader can tell what
//     was measured, and this test reports how far behind that commit is.
//
// The staleness is REPORTED rather than failed, deliberately. Scanner code
// changes most days; failing on it would mean re-running the benchmark before
// every audit, and the guard would be turned off within a week. What is
// enforced is that the claim never says more than the last measurement did.

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

var numberWords = map[string]int{
	"one": 1, "two": 2, "three": 3, "four": 4, "five": 5, "six": 6,
	"seven": 7, "eight": 8, "nine": 9, "ten": 10, "eleven": 11,
	"twelve": 12, "thirteen": 13, "fourteen": 14, "fifteen": 15,
	"sixteen": 16, "seventeen": 17, "eighteen": 18, "nineteen": 19,
	"twenty": 20,
}

func wordNumber(s string) (int, bool) {
	if n, err := strconv.Atoi(s); err == nil {
		return n, true
	}
	n, ok := numberWords[strings.ToLower(s)]
	return n, ok
}

// mustFind returns the first submatch of re in text, failing the test when the
// pattern is absent. A regex that stops matching because the prose was
// reworded would otherwise disable this check silently, which is the exact
// failure mode it exists to prevent.
func mustFind(t *testing.T, re *regexp.Regexp, text, what string) []string {
	t.Helper()
	m := re.FindStringSubmatch(text)
	if m == nil {
		t.Fatalf("could not find %s in README.md.\nThis check reads the accuracy claim "+
			"and compares it against benchmark/RESULTS.md. If the wording changed, update "+
			"the pattern here -- do not leave it unmatched, because an unmatched pattern "+
			"means the claim is no longer being checked at all.\npattern: %s", what, re)
	}
	return m
}

func TestTheAccuracyClaimMatchesTheMeasurement(t *testing.T) {
	root := filepath.Join("..", "..")
	readBytes := func(p string) string {
		b, err := os.ReadFile(filepath.Join(root, p))
		if err != nil {
			t.Fatalf("read %s: %v", p, err)
		}
		return string(b)
	}
	results := readBytes(filepath.Join("benchmark", "RESULTS.md"))
	readme := readBytes("README.md")

	// --- the corpus, on disk ---
	entries, err := os.ReadDir(filepath.Join(root, "benchmark", "corpus"))
	if err != nil {
		t.Fatalf("read corpus: %v", err)
	}
	var corpus []string
	projectDir := regexp.MustCompile(`^\d\d-`)
	for _, e := range entries {
		if e.IsDir() && projectDir.MatchString(e.Name()) {
			corpus = append(corpus, e.Name())
		}
	}
	sort.Strings(corpus)
	if len(corpus) == 0 {
		t.Fatal("no corpus projects found; this check would pass vacuously")
	}

	// --- what the scoreboard says about each ---
	notScored := map[string]string{}
	if _, after, ok := strings.Cut(results, "## Not scored"); ok {
		for _, line := range strings.Split(after, "\n") {
			line = strings.TrimSpace(line)
			if !strings.HasPrefix(line, "- ") {
				continue
			}
			name, reason, _ := strings.Cut(strings.TrimPrefix(line, "- "), " (")
			notScored[strings.TrimSpace(name)] = strings.TrimSuffix(reason, ")")
		}
	}
	var scored, unaccounted []string
	for _, p := range corpus {
		switch {
		case strings.Contains(results, "| `"+p+"` |"):
			scored = append(scored, p)
		case notScored[p] != "":
		default:
			unaccounted = append(unaccounted, p)
		}
	}
	if len(unaccounted) > 0 {
		t.Errorf("corpus project(s) %v appear in benchmark/corpus but are neither scored in "+
			"RESULTS.md nor listed under '## Not scored' with a reason. A project nobody "+
			"scored makes the corpus look larger than the evidence behind it.", unaccounted)
	}

	// --- the counts the README states ---
	sizeRe := regexp.MustCompile(`corpus\s+of\s+([a-z]+|\d+)\s+projects`)
	if m := mustFind(t, sizeRe, readme, "the corpus size"); m != nil {
		claimed, ok := wordNumber(m[1])
		if !ok {
			t.Errorf("cannot read the claimed corpus size %q", m[1])
		} else if claimed != len(corpus) {
			t.Errorf("README says the corpus holds %d projects; benchmark/corpus holds %d (%v)",
				claimed, len(corpus), corpus)
		}
	}
	scoredRe := regexp.MustCompile(`([A-Za-z]+|\d+)\s+are\s+scored\s+end\s+to\s+end`)
	if m := mustFind(t, scoredRe, readme, "how many projects are scored"); m != nil {
		claimed, ok := wordNumber(m[1])
		if !ok {
			t.Errorf("cannot read the claimed scored count %q", m[1])
		} else if claimed != len(scored) {
			t.Errorf("README says %d projects are scored end to end; RESULTS.md scores %d (%v)",
				claimed, len(scored), scored)
		}
	}

	// --- the numbers the README quotes ---
	//
	// The three recall figures are compared by
	// TestTheReadmeQuotesTheBenchmarkItCites, which predates this check. Not
	// repeated here: two tests asserting the same thing means one of them can
	// rot without anyone noticing, and there is no signal in the second.
	totals := map[string]string{}
	row := regexp.MustCompile(`(?m)^\| ([a-z-]+) \| ([\d.]+)% \| ([\d.]+)% \| \d+ \|`)
	for _, m := range row.FindAllStringSubmatch(results, -1) {
		totals[m[1]] = m[2]
		totals[m[1]+":precision"] = m[3]
	}
	if len(totals) == 0 {
		t.Fatal("parsed no totals from RESULTS.md; the comparison below would be vacuous")
	}

	// A claim of perfect precision must hold for every dimension measured, not
	// just the ones somebody looked at.
	//
	// Required rather than conditional. Written as `if readme contains ...`
	// this arm went inert the moment the sentence wrapped across a line, and
	// it passed a scoreboard doctored to 71.4% precision without a word. A
	// claim this central should not be able to stop being checked by being
	// reworded; if it is ever withdrawn, failing here is the right way to find
	// that out.
	precisionRe := regexp.MustCompile(`100%\s+precision\s+on\s+every`)
	if mustFind(t, precisionRe, readme, "the claim of perfect precision") != nil {
		for dim, v := range totals {
			if strings.HasSuffix(dim, ":precision") && !sameNumber(v, "100.0") {
				t.Errorf("README claims 100%% precision on every dimension, but %s measured %s%%",
					strings.TrimSuffix(dim, ":precision"), v)
			}
		}
	}

	// --- provenance ---
	commitRe := regexp.MustCompile("commit: `([0-9a-f]{7,40})`")
	m := commitRe.FindStringSubmatch(results)
	if m == nil {
		t.Fatal("RESULTS.md does not name the commit it was measured at, so a reader " +
			"cannot tell what these numbers describe")
	}
	if err := exec.Command("git", "-C", root, "cat-file", "-e", m[1]+"^{commit}").Run(); err != nil {
		// A shallow clone has every commit but the tip missing, which is not
		// the same defect and has a different fix. Saying "not in this
		// repository" to someone whose history is intact sends them to
		// re-measure a benchmark that was fine.
		shallow, _ := exec.Command("git", "-C", root, "rev-parse",
			"--is-shallow-repository").Output()
		if strings.TrimSpace(string(shallow)) == "true" {
			t.Skipf("shallow clone: cannot check whether commit %s exists. "+
				"Fetch the full history (actions/checkout needs fetch-depth: 0) "+
				"to run this check", m[1])
		}
		t.Errorf("RESULTS.md names commit %s, which is not in this repository", m[1])
		return
	}
	behind, _ := exec.Command("git", "-C", root, "rev-list", "--count", m[1]+"..HEAD").Output()
	changed, _ := exec.Command("git", "-C", root, "diff", "--name-only", m[1], "HEAD",
		"--", "cmd", "internal", "backend", "scan", "benchmark/corpus").Output()
	n := len(strings.Fields(string(changed)))
	t.Logf("scoreboard measured at %s: %s commit(s) ago, %d score-affecting file(s) changed since",
		m[1], strings.TrimSpace(string(behind)), n)
}

// sameNumber compares two decimal strings by value, so 100 and 100.0 agree.
func sameNumber(a, b string) bool {
	x, err1 := strconv.ParseFloat(a, 64)
	y, err2 := strconv.ParseFloat(b, 64)
	if err1 != nil || err2 != nil {
		return a == b
	}
	return fmt.Sprintf("%.2f", x) == fmt.Sprintf("%.2f", y)
}

// Coverage may rise on its own and may only shrink deliberately.
//
// A correction to the record first, because the reasoning that produced this
// check was wrong. When a too-broad refusal dropped 05-empty-project and
// 06-unreachable from the scoreboard, moving three denominators, I wrote that
// nothing in the suite would have objected. It would have:
// TestTheAccuracyClaimMatchesTheMeasurement compares the count the README
// states against the count RESULTS.md actually scores, and says "README says
// 14 projects are scored end to end; RESULTS.md scores 12". I never saw it
// because I reverted the file after reading the diff instead of running the
// tests against it.
//
// So this is not the missing guard I claimed. What it adds is narrower and
// real: the claim gate is satisfied the moment the README is edited to agree.
// Lowering both together is one commit, it reads as bookkeeping, and the
// accuracy figures move underneath it. A ratchet does not care whether the two
// documents agree -- it asks whether the corpus still grades as much as it did.
//
// The same shape as maxPendingExploits, pointed the other way: that count may
// shrink on its own and may only grow deliberately.
const minScoredProjects = 14

func TestTheCorpusStillScoresAsManyProjectsAsItDid(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "benchmark", "RESULTS.md"))
	if err != nil {
		t.Fatalf("RESULTS.md: %v", err)
	}
	results := string(b)

	// A project is scored if it has at least one row in the per-project table.
	row := regexp.MustCompile("(?m)^\\| `([0-9]{2}-[a-z0-9-]+)` \\|")
	scored := map[string]bool{}
	for _, m := range row.FindAllStringSubmatch(results, -1) {
		scored[m[1]] = true
	}
	if len(scored) == 0 {
		t.Fatal("no scored projects parsed out of RESULTS.md; the extractor stopped " +
			"matching and this check would pass against an empty scoreboard")
	}
	if len(scored) < minScoredProjects {
		var names []string
		for n := range scored {
			names = append(names, n)
		}
		sort.Strings(names)
		t.Errorf("the corpus scores %d projects and the ratchet requires %d. A project "+
			"that stops being scored takes its relations out of every denominator. If "+
			"the README was lowered to match, the claim gate is satisfied and this is "+
			"the only thing left objecting. Either the drop is deliberate -- lower "+
			"minScoredProjects and say why -- or a refusal has become too broad. "+
			"Scored: %v", len(scored), minScoredProjects, names)
	}
}
