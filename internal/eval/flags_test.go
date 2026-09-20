package eval_test

// The CLI is a surface too.
//
// Applying this project's own rule — a branch that has never executed is not
// known to work — to its flags found seventeen with no reference in any test
// or Makefile target. Most were short forms whose long names are covered
// (-rl for -rate-limit, -p for -project-ref). Three were genuinely
// unexercised, and one of those, -fix, is a stated requirement of the brief:
// "A CLI parameter that emits recommended fixes (SQL remediation) for each
// finding."
//
// All three turned out to work. That is the good outcome and not a reason to
// skip the tests: an untested requirement is one regression away from being an
// unmet requirement, and nothing would have said so.
//
//   make fixtures-reset && UNRULY_LIVE=1 go test ./internal/eval -run Flag -v

import (
	"encoding/json"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func scanLabWithFlags(t *testing.T, args ...string) (stdout string, findings []map[string]any) {
	t.Helper()
	key := os.Getenv("UNRULY_FIXTURE_KEY")
	if key == "" {
		t.Skip("UNRULY_FIXTURE_KEY required")
	}
	bin := buildScanner(t)
	out := filepath.Join(t.TempDir(), "f.jsonl")
	base := []string{"-u", "http://127.0.0.1:54321", "-k", key, "-rest-prefix", "/",
		"-j", "-o", out, "-nc"}
	cmd := exec.Command(bin, append(base, args...)...)
	b, _ := cmd.Output() // non-zero exit means findings
	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("no report written: %v", err)
	}
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var f map[string]any
		if err := json.Unmarshal([]byte(line), &f); err != nil {
			t.Fatalf("report line is not JSON: %v", err)
		}
		findings = append(findings, f)
	}
	return string(b), findings
}

// -fix is named in the brief. Without it the report states problems; with it
// the report states what to run.
func TestFlagFixEmitsRemediation(t *testing.T) {
	requireLiveEvals(t)
	with, _ := scanLabWithFlags(t, "-fix")
	without, _ := scanLabWithFlags(t)

	if strings.Count(without, "└─ fix") != 0 {
		t.Error("remediation must be opt-in; a default scan should not print it")
	}
	n := strings.Count(with, "└─ fix")
	if n == 0 {
		t.Fatal("-fix emitted no remediation at all")
	}
	// Every fix line should be SQL somebody can act on, not prose.
	for _, line := range strings.Split(with, "\n") {
		if !strings.Contains(line, "└─ fix") {
			continue
		}
		body := strings.TrimSpace(strings.SplitN(line, "└─ fix", 2)[1])
		if body == "" {
			t.Error("an empty fix line is worse than none: it looks like advice")
		}
	}
	t.Logf("-fix emitted %d remediation lines", n)
}

// -severity filters what reaches the report. A filter that silently does
// nothing would hand somebody a report they believe is scoped.
func TestFlagSeverityFilters(t *testing.T) {
	requireLiveEvals(t)
	counts := map[string]int{}
	for _, sv := range []string{"info", "medium", "critical"} {
		_, f := scanLabWithFlags(t, "-sv", sv)
		counts[sv] = len(f)
		for _, x := range f {
			got, _ := x["severity"].(string)
			if !atLeast(got, sv) {
				t.Errorf("-sv %s let through a %s finding", sv, got)
			}
		}
	}
	if !(counts["info"] >= counts["medium"] && counts["medium"] >= counts["critical"]) {
		t.Errorf("raising the threshold must not increase the count: %v", counts)
	}
	if counts["info"] == counts["critical"] {
		t.Error("the filter is not filtering: info and critical returned the same count")
	}
	t.Logf("info=%d medium=%d critical=%d", counts["info"], counts["medium"], counts["critical"])
}

// -sample decides how much real data a report carries. Findings are
// proof-carrying by design, and this is the dial for how much proof.
func TestFlagSampleBoundsTheProof(t *testing.T) {
	requireLiveEvals(t)
	for _, n := range []string{"1", "5"} {
		_, f := scanLabWithFlags(t, "-sample", n)
		var max int
		for _, x := range f {
			ev, _ := x["evidence"].(map[string]any)
			if ev == nil {
				continue
			}
			if s, ok := ev["sample"].([]any); ok && len(s) > max {
				max = len(s)
			}
		}
		want := map[string]int{"1": 1, "5": 5}[n]
		if max != want {
			t.Errorf("-sample %s yielded at most %d sampled rows, want %d", n, max, want)
		}
	}
}

func atLeast(got, floor string) bool {
	rank := map[string]int{"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
	return rank[got] >= rank[floor]
}

// TestEveryFlagNamedInOutputExists fails when the tool tells an operator to
// pass a flag it does not have.
//
// Remediation text is instructions. "Re-run with -max-rpc-probes 3508", "enable
// with -write -invoke -yes-i-own-this", "narrow the scan with -severity or
// -skip-routes" -- the last of which was shipped in two commits and is not a
// flag. The real one is -no-routes. An operator following it gets
//
//	flag provided but not defined: -skip-routes
//
// and goflags builds its FlagSet with ExitOnError, so the scan does not run at
// all. The advice fails closed, loudly, at exactly the moment somebody is
// already dealing with a scan that went wrong.
//
// This is the same class as evidence commands that do not reproduce, which this
// project has fixed three times: text that looks like a command, is read as a
// command, and was never executed by anything.
func TestEveryFlagNamedInOutputExists(t *testing.T) {
	main, err := os.ReadFile(filepath.Join("..", "..", "cmd", "unruly", "main.go"))
	if err != nil {
		t.Fatalf("read main.go: %v", err)
	}
	src := string(main)

	// The flag set, from the declarations themselves: long name and short.
	defined := map[string]bool{}
	// `\w*` rather than `\w+`: fs.Var( has NOTHING between the dot and "Var",
	// so a flag registered that way was invisible here and read as undefined
	// forever. Found when -route-param -- repeatable, so it needs fs.Var --
	// was reported as a flag "this tool does not define" while appearing in
	// its own -h output. The extractor's own floor check did not catch it: 20
	// other flags still parsed, so it looked healthy while being blind to one
	// registration form.
	decl := regexp.MustCompile(`fs\.\w*VarP?\(\s*&?[\w.\[\]"]+\s*,\s*"([a-z0-9-]+)"(?:\s*,\s*"([a-zA-Z0-9-]*)")?`)
	for _, m := range decl.FindAllStringSubmatch(src, -1) {
		defined[m[1]] = true
		if m[2] != "" {
			defined[m[2]] = true
		}
	}
	if len(defined) < 20 {
		t.Fatalf("parsed only %d flags from main.go; the extractor stopped matching and this "+
			"test would pass by knowing nothing", len(defined))
	}

	// Flags belonging to other programs that this tool's text legitimately
	// names. Anything else must be a flag this tool actually defines.
	foreign := map[string]bool{"run": true, "race": true, "deps": true, "count": true}

	// Go's RE2 has no lookbehind, so the "not part of a hyphenated word" rule
	// is applied by inspecting the preceding byte below.
	lit := regexp.MustCompile(`"((?:[^"\\]|\\.)*)"`)

	// Every non-test source file, not just main.go.
	//
	// This read main.go alone, and almost all remediation text lives in the
	// packages that build the findings -- so the check was looking at a small
	// fraction of the places this tool names a flag. Exposed when a
	// constructor moved out of main.go and the mutation that proves this test
	// works stopped being caught.
	// cmd/unruly and the packages it uses. The other binaries in cmd/
	// have their own flag sets -- cmd/exploitcheck defines -anon -- and
	// checking their strings against this tool's flags is a category error.
	var sources []string
	for _, dir := range []string{filepath.Join("cmd", "unruly"), "internal"} {
		err := filepath.WalkDir(filepath.Join("..", "..", dir), func(p string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
				return err
			}
			sources = append(sources, p)
			return nil
		})
		if err != nil {
			t.Fatalf("walking %s: %v", dir, err)
		}
	}
	if len(sources) < 20 {
		t.Fatalf("only %d source files found; the walk is not reaching them", len(sources))
	}

	var checked int
	for _, path := range sources {
		body, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		checkFlagRefs(t, filepath.Base(path), string(body), defined, foreign, lit, &checked)
	}
	if checked == 0 {
		t.Fatal("no flag references found in any string literal, so this test asserts nothing")
	}
	t.Logf("%d flag references checked across %d files", checked, len(sources))
}

// checkFlagRefs fails for any flag named in a string literal that the tool
// does not define.
func checkFlagRefs(t *testing.T, name, src string, defined, foreign map[string]bool,
	lit *regexp.Regexp, checked *int) {
	t.Helper()
	for i, line := range strings.Split(src, "\n") {
		for _, m := range lit.FindAllStringSubmatch(line, -1) {
			for _, ref := range regexp.MustCompile(`-([a-z][a-z0-9-]{2,})`).FindAllStringSubmatchIndex(m[1], -1) {
				flag := m[1][ref[2]:ref[3]]
				// Skip hyphenated words: read-only, POST-only, service_role-only.
				if ref[0] > 0 {
					if p := m[1][ref[0]-1]; p == '-' || p == '_' || (p >= 'a' && p <= 'z') ||
						(p >= 'A' && p <= 'Z') || (p >= '0' && p <= '9') {
						continue
					}
				}
				*checked++
				if !defined[flag] && !foreign[flag] {
					t.Errorf("%s:%d names -%s, which this tool does not define. An "+
						"operator following this advice gets \"flag provided but not "+
						"defined\" and no scan at all.\n  in: %s", name, i+1, flag, m[1])
				}
			}
		}
	}
}

// "Proof-carrying: findings must include REAL sampled data from the database
// as evidence, not just a boolean" is a requirement of the brief, and it was
// verified by reading reports rather than by anything that runs.
//
// The neighbouring exploitability eval asserts something stronger but
// different: that an independent harness can DEMONSTRATE each high finding.
// That says the claim is true. It says nothing about whether the report hands
// the reader the proof, and a report whose critical finding is a bare verdict
// is the thing every other scanner already ships.
//
// Retrieved evidence is sampled rows OR a response body: a service_role key
// found in a page has no rows to sample, and an application route answering
// anonymously is proven by the bytes it returned. Both are things taken from
// the target rather than concluded about it.
func TestEveryHighFindingCarriesRetrievedEvidence(t *testing.T) {
	requireLiveEvals(t)
	_, findings := scanLabWithFlags(t, "-s", "http://127.0.0.1:54322")

	var checked int
	for _, f := range findings {
		sev, _ := f["severity"].(string)
		if sev != "high" && sev != "critical" {
			continue
		}
		id, _ := f["id"].(string)
		res, _ := f["resource"].(string)
		// unruly-* findings describe the SCAN, not the target: a probe row
		// left behind, a surface not assessed. There is nothing to sample.
		if strings.HasPrefix(id, "unruly-") {
			continue
		}
		checked++

		ev, _ := f["evidence"].(map[string]any)
		if ev == nil {
			t.Errorf("%s %s/%s carries no evidence at all", sev, id, res)
			continue
		}
		sample, _ := ev["sample"].([]any)
		response, _ := ev["response"].(string)
		if len(sample) == 0 && strings.TrimSpace(response) == "" {
			t.Errorf("%s %s/%s is a verdict with nothing retrieved from the target behind "+
				"it: no sampled rows, no response body. The brief calls for real data as "+
				"evidence, and a bare boolean is what every other scanner already ships",
				sev, id, res)
		}
		// And it must be reproducible by hand: a reader who does not trust the
		// scanner needs the request that produced the proof.
		if req, _ := ev["request"].(string); strings.TrimSpace(req) == "" {
			t.Errorf("%s %s/%s carries proof but no request, so nobody can reproduce it "+
				"without reverse-engineering the scanner", sev, id, res)
		}
	}
	if checked < 3 {
		t.Fatalf("only %d high findings about the target were checked; the fixture is not "+
			"producing the report this test was written for", checked)
	}
	t.Logf("%d high+ findings checked for retrieved evidence", checked)
}

// mintAuthenticatedJWT builds a token for the lab fixture's authenticated role.
func mintAuthenticatedJWT(t *testing.T) string {
	t.Helper()
	out, err := exec.Command("python3", filepath.Join("..", "..", "fixtures", "mint-jwt.py"),
		"--role", "authenticated",
		"--sub", "11111111-1111-1111-1111-111111111111").Output()
	if err != nil {
		t.Skipf("cannot mint a fixture JWT: %v", err)
	}
	return strings.TrimSpace(string(out))
}

// Every read in a default scan is performed as `anon`, so a relation this
// scanner calls protected is protected FROM ANON. Policies written TO
// authenticated are routinely far looser -- that is the entire reason the
// escalation pass exists -- and without -user-jwt the scan measures half the
// read surface.
//
// That half was disclosed by a log line, eight lines above the comment in the
// same function explaining that a log line is exactly what does not survive:
// the findings stream is what gets stored, diffed and read by somebody who was
// not watching the terminal. It also only fired when public signup was open,
// so a project with closed signup and thousands of authenticated users said
// nothing at all.
func TestScanDisclosesThatItOnlyReadAsAnon(t *testing.T) {
	requireLiveEvals(t)

	_, findings := scanLabWithFlags(t)
	var skipped string
	for _, f := range findings {
		if id, _ := f["id"].(string); id == "unruly-checks-skipped" {
			skipped, _ = f["description"].(string)
		}
	}
	if skipped == "" {
		t.Fatal("no checks-skipped finding at all, so this test asserts nothing")
	}
	if !strings.Contains(skipped, "role-escalation") {
		t.Errorf("a scan that read only as anon does not say so in the findings stream. "+
			"Everything it reports as protected is protected from ONE role, and the "+
			"report reads as though that were the whole answer.\ngot: %s", skipped)
	}
	if !strings.Contains(skipped, "-user-jwt") {
		t.Error("the skipped check does not name the flag that enables it")
	}

	// And the other direction: with the pass performed, it must NOT be listed
	// as skipped, or the disclosure is noise that operators learn to ignore.
	_, elevated := scanLabWithFlags(t, "-user-jwt", mintAuthenticatedJWT(t))
	for _, f := range elevated {
		if id, _ := f["id"].(string); id != "unruly-checks-skipped" {
			continue
		}
		if d, _ := f["description"].(string); strings.Contains(d, "role-escalation") {
			t.Error("a scan that DID escalate still reports role-escalation as skipped")
		}
	}
}

// The same rule for the documentation, which is where a first-time user reads
// a command before they ever see an error message.
//
// TestEveryFlagNamedInOutputExists covers flags named in Go string literals --
// remediation text, skipped-check hints. It does not read a single line of
// markdown, and the README opens with eight worked invocations. A flag that
// was renamed would leave those examples failing with "unknown flag" and no
// scan, which is the worst place in the project to be wrong.
//
// Only flags on a `unruly` command line are checked: the docs also show
// go, curl, colima, docker and psql invocations, whose flags are none of this
// tool's business.
func TestEveryFlagInTheDocsExists(t *testing.T) {
	main, err := os.ReadFile(filepath.Join("..", "..", "cmd", "unruly", "main.go"))
	if err != nil {
		t.Fatalf("read main.go: %v", err)
	}
	defined := map[string]bool{}
	decl := regexp.MustCompile(`fs\.\w*VarP?\(\s*&?[\w.\[\]"]+\s*,\s*"([a-z0-9-]+)"(?:\s*,\s*"([a-zA-Z0-9-]*)")?`)
	for _, m := range decl.FindAllStringSubmatch(string(main), -1) {
		defined[m[1]] = true
		if m[2] != "" {
			defined[m[2]] = true
		}
	}
	if len(defined) < 20 {
		t.Fatalf("parsed only %d flags; the extractor stopped matching", len(defined))
	}

	docs, err := filepath.Glob(filepath.Join("..", "..", "docs", "*.md"))
	if err != nil {
		t.Fatalf("glob docs: %v", err)
	}
	for _, extra := range []string{"README.md", "SECURITY.md", "CONTRIBUTING.md"} {
		docs = append(docs, filepath.Join("..", "..", extra))
	}

	// Single-character flags are included deliberately. The first version of
	// this required two or more characters after the dash -- copied from the
	// Go-literal test, where the bound exists to avoid matching hyphenated
	// prose like "read-only" -- and silently skipped -u, -w, -p, -l, -s and
	// -o. It reported "7 documented flag references checked" against a README
	// whose examples use fifteen, which is a test asserting half of what it
	// appears to. On a shell command line there is no prose to confuse.
	flagRef := regexp.MustCompile(`(?:^|\s)-{1,2}([a-z][a-z0-9-]*)`)
	var checked int
	for _, doc := range docs {
		body, err := os.ReadFile(doc)
		if err != nil {
			continue // an optional document that does not exist is not a failure
		}
		for i, line := range strings.Split(string(body), "\n") {
			if !strings.Contains(line, "unruly ") {
				continue
			}
			// Only what belongs to THIS command gets graded.
			//
			// Take the line from the `unruly` token onward, because a flag to
			// the left of it is somebody else's: `npm install -g @eppser/unruly`
			// contains "unruly" and `-g` is npm's. Then cut at a pipe, because
			// a flag to the right of one is the next program's: `unruly --agent
			// | jq -r ...` ends with jq's flag, not ours. Both of those were
			// reported as undefined unruly flags while the documentation was
			// correct, and the tempting fix each time was to reword the docs --
			// which would have made the README worse to keep a test quiet.
			cmd := line
			if j := strings.Index(cmd, "unruly "); j >= 0 {
				cmd = cmd[j:]
			}
			if j := strings.Index(cmd, "|"); j >= 0 {
				cmd = cmd[:j]
			}
			// Cut anything after a comment marker: the examples annotate
			// themselves with "# with SQL remediation".
			if j := strings.Index(cmd, "#"); j >= 0 {
				cmd = cmd[:j]
			}
			for _, m := range flagRef.FindAllStringSubmatch(cmd, -1) {
				name := m[1]
				checked++
				if !defined[name] {
					t.Errorf("%s:%d shows `-%s`, which this tool does not define. A reader "+
						"copying this line gets \"unknown flag\" and no scan.\n  %s",
						filepath.Base(doc), i+1, name, strings.TrimSpace(line))
				}
			}
		}
	}
	if checked == 0 {
		t.Fatal("no flags found on any documented unruly command line, so this test " +
			"asserts nothing")
	}
	t.Logf("%d documented flag references checked", checked)
}

// definedFlags reads the flag names this tool declares, long and short.
func definedFlags(t *testing.T) map[string]bool {
	t.Helper()
	src, err := os.ReadFile(filepath.Join("..", "..", "cmd", "unruly", "main.go"))
	if err != nil {
		t.Fatalf("read main.go: %v", err)
	}
	decl := regexp.MustCompile(`fs\.\w*VarP?\(\s*&?[\w.\[\]"]+\s*,\s*"([a-z0-9-]+)"(?:\s*,\s*"([a-zA-Z0-9-]*)")?`)
	out := map[string]bool{}
	for _, m := range decl.FindAllStringSubmatch(string(src), -1) {
		out[m[1]] = true
		if len(m) > 2 && m[2] != "" {
			out[m[2]] = true
		}
	}
	return out
}

// Every command shown in the documentation must actually parse.
//
// The sibling test above reads flag names out of .go files only, so a renamed
// flag breaks every documented example silently: the docs keep showing a
// command that now exits with "unknown flag" before it scans anything. That is
// the first thing a new user runs, and the failure is total rather than
// partial.
//
// Only lines that begin with `unruly ` are read. Remediation blocks contain
// commands for other tools -- `firebase deploy --only storage`, `gcloud
// functions remove-invoker-policy-binding` -- whose flags are none of this
// tool's business.
func TestEveryDocumentedCommandParses(t *testing.T) {
	defined := definedFlags(t)
	if len(defined) < 20 {
		t.Fatalf("only %d flags were parsed out of the source; this test would pass "+
			"on almost anything", len(defined))
	}

	cmd := regexp.MustCompile(`(?m)^\s*unruly\s+(.+)$`)
	flagTok := regexp.MustCompile(`(^|\s)(-{1,2}[a-z][a-z0-9-]*)`)

	var checked int
	for _, path := range docFiles(t) {
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		for _, line := range cmd.FindAllStringSubmatch(string(b), -1) {
			// Stop at a shell operator: what follows belongs to another
			// program, not to this one.
			args := line[1]
			for _, cut := range []string{"|", ">", "#", "&&", ";"} {
				if i := strings.Index(args, cut); i >= 0 {
					args = args[:i]
				}
			}
			for _, m := range flagTok.FindAllStringSubmatch(args, -1) {
				name := strings.TrimLeft(m[2], "-")
				checked++
				if !defined[name] {
					t.Errorf("%s documents `unruly %s`, and -%s is not a flag this tool "+
						"defines. The command in the docs fails before it scans anything.",
						filepath.Base(path), strings.TrimSpace(line[1]), name)
				}
			}
		}
	}
	if checked == 0 {
		t.Fatal("no documented commands were found, so this test is measuring nothing")
	}
	t.Logf("%d flag(s) checked across the documented commands", checked)
}

// docFiles lists the documentation a reader actually follows.
func docFiles(t *testing.T) []string {
	t.Helper()
	root := filepath.Join("..", "..")
	out := []string{filepath.Join(root, "README.md")}
	entries, err := os.ReadDir(filepath.Join(root, "docs"))
	if err != nil {
		t.Fatalf("docs: %v", err)
	}
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".md") {
			out = append(out, filepath.Join(root, "docs", e.Name()))
		}
	}
	return out
}
