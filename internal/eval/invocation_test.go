package eval_test

// The simplest invocation there is must work.
//
//	unruly -u https://<ref>.supabase.co -k <anon key>
//
// A project URL and an anon key is what somebody has when they first try this
// tool. It was refused, with a message telling them to supply -site "(or
// -target)" -- and -u IS -target, which they had just supplied. The scan
// produced an empty report against a project with seven anonymously readable
// tables, one of them holding session tokens. Exit 3 rather than 0 meant it did
// not claim the project was clean, which is the safety net working, but the
// scan never ran at all.
//
// Why it survived this long is the interesting part, and it is a lesson about
// the fixtures rather than the code. A .supabase.co target deliberately does
// not become the -site, because it is an API rather than an application. Every
// fixture in this repository is served from 127.0.0.1, so every fixture target
// takes the other branch and sets -site from the target. The broken path was
// unreachable from the entire test suite, and the one target that would have
// exercised it -- the reference project -- was always scanned with -site
// because that is the invocation that finds the most.
//
// So this test uses a hostname with the managed shape. It does not need that
// host to exist: the assertion is that the scan is ATTEMPTED, not that it
// succeeds.
//
//	go test ./internal/eval -run Invocation

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestInvocationProjectURLAndKeyIsEnough(t *testing.T) {
	// A ref that cannot resolve. The scan will fail to reach it and report
	// that honestly; what matters is that it gets far enough to try.
	cmd := exec.Command(buildScanner(t),
		"-u", "https://unrulycontrolnosuchproject.supabase.co",
		"-k", "test-anon-key", "-timeout", "3", "-nc")
	out, err := cmd.CombinedOutput()
	text := string(out)

	// The property is that the scan RUNS. Asserting on the wording of the
	// refusal was the first attempt and it was useless: improving the message
	// in the same change made the assertion pass against the unfixed guard,
	// because the refusal simply said something else. What discriminates is
	// whether any probing happened at all.
	for _, refusal := range []string{"need -site", "no credential"} {
		if strings.Contains(text, refusal) {
			t.Errorf("a project URL plus a key was refused (%q). The most basic invocation "+
				"there is produced no scan:\n%s", refusal, text)
		}
	}
	// The summary line only appears once the scan has finished probing. Its
	// absence means the run ended before it started.
	if !strings.Contains(text, "findings (") {
		t.Errorf("no scan summary, so nothing was probed; err=%v\n%s", err, text)
	}

	// Exit 1 is the usage code. Anything the scan concludes about an
	// unreachable host -- 3, or 0 -- means it ran; 1 means it never started.
	if code := cmd.ProcessState.ExitCode(); code == 1 {
		t.Errorf("exit 1 (usage error) for the tool's most basic invocation; err=%v\n%s",
			err, text)
	}
}

// And the message when a credential really is missing has to name the thing
// that is missing. Pointing at -site here sent operators to add a flag that
// would not have helped: with an API origin in hand, the gap is the key.
func TestInvocationMissingKeySaysSo(t *testing.T) {
	cmd := exec.Command(buildScanner(t),
		"-u", "https://unrulycontrolnosuchproject.supabase.co",
		"-timeout", "3", "-nc")
	cmd.Env = append(cmd.Environ(), "SUPABASE_ANON_KEY=", "SUPABASE_KEY=")
	out, _ := cmd.CombinedOutput()

	if !strings.Contains(string(out), "no credential") {
		t.Errorf("with an origin but no key, the error does not say the credential is what "+
			"is missing:\n%s", out)
	}
}

// mintRefJWT builds an unsigned token claiming a project ref. Built rather
// than written out, because CI scans committed content for JWT-shaped strings.
func mintRefJWT(ref string) string {
	seg := func(s string) string {
		return base64.RawURLEncoding.EncodeToString([]byte(s))
	}
	return seg(`{"alg":"HS256"}`) + "." + seg(`{"role":"anon","ref":"`+ref+`"}`) + "." +
		seg("not-a-real-signature")
}

// -list had no end-to-end test of any kind, and two behaviours lived only
// inside it.
//
// The first is a safety feature: a managed anon key is a JWT naming the
// project it belongs to, so reusing one across a list would send project A's
// credential to project B's server and then report on the 401s. The guard
// drops the key for any target whose hostname says it belongs elsewhere. It is
// reachable only with a multi-entry list AND managed .supabase.co hostnames,
// and every fixture in this repository is served from 127.0.0.1, so nothing
// had ever executed it.
//
// The second is what the report said about it: nothing. A target the scan
// could not start on produced no finding at all -- it reached the exit code
// and stopped there -- so a list of fifty projects where ten errored wrote a
// report covering forty, with nothing naming the ten that were missing.
//
// The hosts here do not resolve, and do not need to: the guard runs before any
// request, which is the point of it.
func TestListWithholdsAKeyBelongingElsewhereAndSaysSo(t *testing.T) {
	const mine, other = "aaaaaaaaaaaaaaaaaaaa", "bbbbbbbbbbbbbbbbbbbb"

	dir := t.TempDir()
	list := filepath.Join(dir, "targets.txt")
	if err := os.WriteFile(list, []byte(
		"https://"+mine+".supabase.co\nhttps://"+other+".supabase.co\n"), 0o600); err != nil {
		t.Fatalf("write list: %v", err)
	}
	out := filepath.Join(dir, "report.jsonl")

	cmd := exec.Command(buildScanner(t), "-l", list, "-k", mintRefJWT(mine),
		"-timeout", "3", "-j", "-o", out, "-nc")
	stdout, _ := cmd.CombinedOutput()

	if !strings.Contains(string(stdout), "not sending it to") {
		t.Errorf("the key was sent to a project it does not belong to, or the guard is "+
			"silent about withholding it:\n%s", stdout)
	}

	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("no report: %v", err)
	}
	var sawOther bool
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		if line == "" {
			continue
		}
		var f struct {
			ID          string `json:"id"`
			Matched     string `json:"matched"`
			Description string `json:"description"`
		}
		if json.Unmarshal([]byte(line), &f) != nil {
			continue
		}
		if !strings.Contains(f.Matched, other) {
			continue
		}
		sawOther = true
		if f.ID != "unruly-surface-not-assessed" {
			t.Errorf("the target that could not be scanned is reported as %q, which does "+
				"not carry the blindness id the exit code keys on", f.ID)
		}
		// And it must say WHY, because the reason is a decision this scanner
		// made rather than anything the target did.
		if !strings.Contains(f.Description, mine) {
			t.Errorf("the finding does not say the supplied key was withheld, so a thin "+
				"report for this project looks like a property of the project:\n%s",
				f.Description)
		}
	}
	if !sawOther {
		t.Error("the second target produced no finding at all: a list where one entry " +
			"fails writes a report that silently omits it, and a reader diffing two runs " +
			"sees targets appear and disappear for no stated reason")
	}
}

// The invocation matrix.
//
// A whole branch of this program was unreachable from the test suite because
// every fixture is served from 127.0.0.1, and the one shape that mattered --
// a managed https://<ref>.supabase.co target -- appeared nowhere. The bug that
// hid there refused the tool's most basic invocation for 150 iterations.
//
// The lesson is not "test that one case". It is that the suite had been
// testing the shapes the fixtures happen to have. So every documented way of
// telling this scanner where to look is exercised here against a managed
// hostname, and the assertion is the weakest one that still catches the whole
// class: the scan must be ATTEMPTED. Whether it then reaches the host is a
// separate question these hosts deliberately cannot answer.
func TestInvocationMatrixAllOriginFormsAreAccepted(t *testing.T) {
	const ref = "unrulycontrolnosuchproject"
	url := "https://" + ref + ".supabase.co"
	key := mintRefJWT(ref)

	for _, tc := range []struct {
		name string
		args []string
	}{
		{"target url", []string{"-u", url, "-k", key}},
		{"base url", []string{"-base-url", url, "-k", key}},
		{"project ref", []string{"-project-ref", ref, "-k", key}},
		{"target url with site", []string{"-u", url, "-k", key, "-s", "https://" + ref + ".example.invalid"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cmd := exec.Command(buildScanner(t), append(tc.args, "-timeout", "3", "-nc")...)
			out, _ := cmd.CombinedOutput()
			text := string(out)

			for _, refusal := range []string{"need -site", "no credential"} {
				if strings.Contains(text, refusal) {
					t.Errorf("refused with %q; this is a documented way to say where to "+
						"look:\n%s", refusal, text)
				}
			}
			if !strings.Contains(text, "findings (") {
				t.Errorf("no scan summary, so nothing was probed:\n%s", text)
			}
			if code := cmd.ProcessState.ExitCode(); code == 1 {
				t.Errorf("exit 1 (usage error):\n%s", text)
			}
		})
	}
}

// A stored report must say how much was examined.
//
// "21 relations, 12780 requests" was printed to the terminal and appeared
// nowhere in the JSON. So a saved report showing no exposures could not be
// told apart from a scan that discovered nothing and reported the silence --
// the exact confusion this scanner refuses everywhere else, left in the one
// output that outlives the session.
//
// Found by reading a hundred real reports from a measurement study and being
// unable to answer "was this project hardened, or unexamined?" from any of
// them.
func TestReportSaysHowMuchWasExamined(t *testing.T) {
	srv, _ := slowPostgREST(0)
	defer srv.Close()

	out := filepath.Join(t.TempDir(), "report.jsonl")
	cmd := exec.Command(buildScanner(t), "-u", srv.URL, "-k", "test-anon-key",
		"-rest-prefix", "/", "-j", "-o", out, "-silent", "-nc")
	cmd.Run() // non-zero is a verdict, not a failure

	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("no report: %v", err)
	}

	var found bool
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		if line == "" {
			continue
		}
		var f struct {
			ID       string `json:"id"`
			Severity string `json:"severity"`
			Evidence struct {
				Sample []map[string]any `json:"sample"`
			} `json:"evidence"`
		}
		if json.Unmarshal([]byte(line), &f) != nil || f.ID != "unruly-scan-summary" {
			continue
		}
		found = true
		if f.Severity != "info" {
			t.Errorf("the summary is %s; it is a denominator, not a claim that anything "+
				"is wrong", f.Severity)
		}
		if len(f.Evidence.Sample) == 0 {
			t.Fatal("the summary carries no counts, so it says nothing machine-readable")
		}
		for _, k := range []string{"relations", "schemas", "requests"} {
			if _, ok := f.Evidence.Sample[0][k]; !ok {
				t.Errorf("the summary omits %q", k)
			}
		}
	}
	if !found {
		t.Error("no scan summary in the report. A reader diffing two scans cannot tell " +
			"whether fewer findings means the project was fixed or the scan reached less " +
			"of it")
	}
}

// A scan that only asked about reads must say so.
//
// Severity answers how bad, not what kind. Three criticals on a default scan
// mean an anonymous caller can READ things that matter; whether they can also
// change them was never asked, because write probing inserts a row into
// somebody's database and is opt-in.
//
// That was stated only in one info finding among a dozen. A reader looking at
// "critical:3 high:4" and asking "can they edit my data?" got no answer where
// the question occurs.
func TestDefaultScanSaysWritesWereNotTested(t *testing.T) {
	srv, _ := slowPostgREST(0)
	defer srv.Close()

	cmd := exec.Command(buildScanner(t), "-u", srv.URL, "-k", "test-anon-key",
		"-rest-prefix", "/", "-nc")
	out, _ := cmd.CombinedOutput()

	if !strings.Contains(string(out), "whether an anonymous caller can INSERT was NOT tested") {
		t.Errorf("a read-only scan does not say writes went untested:\n%s", out)
	}
	if !strings.Contains(string(out), "-write -yes-i-own-this") {
		t.Error("the notice does not name the flags that would test it")
	}
}

// Running with no arguments is a usage error, not a scan.
//
// It used to run the pipeline against an empty target, emit a not-assessed
// finding about it, and exit 3 -- a could-not-measure verdict on a scan nobody
// asked for. Exit 3 is a claim about a target; there was no target.
//
// It is also the first thing somebody types when trying the tool, so it is the
// worst place to print a coverage complaint instead of a working command.
func TestBareInvocationShowsExamplesAndExitsUsage(t *testing.T) {
	cmd := exec.Command(buildScanner(t))
	// Scrub the environment. The scanner falls back to SUPABASE_URL and
	// SUPABASE_ANON_KEY when the flags are absent, so on a developer machine
	// with those exported -- which is every machine that has ever scanned the
	// testbed -- an argument-less run is NOT a bare run, and this test would
	// pass or fail for reasons having nothing to do with the code.
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + t.TempDir()}
	out, _ := cmd.CombinedOutput()
	text := string(out)

	if code := cmd.ProcessState.ExitCode(); code != 1 {
		t.Errorf("exit %d with no arguments; 1 is the usage code, and 3 would be a "+
			"could-not-measure verdict about a target that was never given", code)
	}
	if !strings.Contains(text, "unruly -u https://") {
		t.Errorf("no runnable example shown:\n%s", text)
	}
	for _, must := range []string{"-fix", "-measure", "-write -yes-i-own-this"} {
		if !strings.Contains(text, must) {
			t.Errorf("the examples do not mention %s, which is one of the few things a "+
				"first-time reader needs to know exists", must)
		}
	}
	// And it must not pretend to have scanned anything.
	if strings.Contains(text, "surface-not-assessed") {
		t.Error("a bare invocation emitted a finding; there was no target to have a " +
			"finding about")
	}
}
