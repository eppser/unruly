package eval_test

// The exit code is the only part of a report a machine reads.
//
// Measured before this test existed: a correctly hardened project, a host that
// is not Supabase at all, an origin returning 500, and a completely
// unreachable address ALL exited 0 — the same code as a clean scan. In CI that
// makes
//
//   unruly -u "$URL" -k "$KEY" && echo "secure"
//
// print "secure" for a typo in the URL. It is this project's entire thesis,
// inverted, and then handed to something that cannot read the prose explaining
// what went wrong.
//
//   make fixtures-reset && UNRULY_LIVE=1 go test ./internal/eval -run ExitCode -v

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

const (
	exitClean      = 0 // scanned, nothing at or above high, every surface measured
	exitFindings   = 2 // findings at high or above
	exitIncomplete = 3 // scan completed but some surface could not be assessed
)

// runScanner returns the exit code of a scan. A non-zero code is the subject
// of the test rather than a failure of it.
func runScanner(t *testing.T, args ...string) int {
	t.Helper()
	if os.Getenv("UNRULY_LIVE") != "1" {
		t.Skip("set UNRULY_LIVE=1 to run live evals")
	}
	bin := buildScanner(t)
	cmd := exec.Command(bin, append(args, "-silent")...)
	if err := cmd.Run(); err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			return ee.ExitCode()
		}
		t.Fatalf("running scanner: %v", err)
	}
	return 0
}

func TestExitCodeVulnerableTargetSignalsFindings(t *testing.T) {
	requireLiveEvals(t)
	key := os.Getenv("UNRULY_FIXTURE_KEY")
	if key == "" {
		t.Skip("UNRULY_FIXTURE_KEY required")
	}
	got := runScanner(t, "-u", "http://127.0.0.1:54321", "-k", key, "-rest-prefix", "/")
	if got != exitFindings {
		t.Errorf("the lab fixture leaks credentials to anon; want exit %d, got %d",
			exitFindings, got)
	}
}

// The case that motivated the whole contract. These targets have nothing to
// say about Supabase security, and each used to exit 0.
func TestExitCodeUnmeasurableTargetsAreNotClean(t *testing.T) {
	requireLiveEvals(t)
	cases := []struct{ name, url string }{
		{"catch-all", "http://127.0.0.1:54352"},
		{"500-origin", "http://127.0.0.1:54364"},
		{"unreachable", "http://127.0.0.1:59999"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := runScanner(t, "-u", tc.url, "-provider", "supabase",
				"-k", "eyJhbGciOiJIUzI1NiJ9.e30.x")
			if got == exitClean {
				t.Errorf("%s cannot be assessed, so exiting %d makes a broken scan "+
					"indistinguishable from a clean one in CI", tc.name, exitClean)
			}
			if got != exitIncomplete {
				t.Errorf("want exit %d for an unmeasurable target, got %d",
					exitIncomplete, got)
			}
		})
	}
}

// Exit 0 must be reachable, or the contract has a branch nothing can take and
// the other codes mean less than they appear to.
func TestExitCodeCleanProjectExitsZero(t *testing.T) {
	requireLiveEvals(t)
	key := os.Getenv("UNRULY_HARDENED_KEY")
	if key == "" {
		t.Skip("UNRULY_HARDENED_KEY required")
	}
	got := runScanner(t, "-u", "http://127.0.0.1:54331", "-k", key, "-rest-prefix", "/")
	if got != exitClean {
		t.Errorf("the hardened fixture serves every surface and is correctly "+
			"configured; want exit %d, got %d", exitClean, got)
	}
}

// Usage errors must not share a code with findings. A typo'd flag exiting 2
// tells CI a vulnerability was found, and someone spends an afternoon looking
// for it.
func TestExitCodeUsageErrorsAreNotFindings(t *testing.T) {
	requireLiveEvals(t)
	cases := []struct {
		name string
		args []string
		want int
	}{
		{"unknown-flag", []string{"--nope-not-a-flag"}, 1},
		{"unknown-flag-with-value", []string{"--nope=1"}, 1},
		{"write-without-consent", []string{
			"-u", "http://127.0.0.1:54321", "-rest-prefix", "/", "-w"}, 1},
		{"invoke-without-write", []string{
			"-u", "http://127.0.0.1:54321", "-rest-prefix", "/", "-invoke"}, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := runScanner(t, tc.args...)
			if got == exitFindings {
				t.Errorf("%s is a usage error; exiting %d makes it indistinguishable "+
					"from a real exposure in CI", tc.name, exitFindings)
			}
			if got != tc.want {
				t.Errorf("want exit %d, got %d", tc.want, got)
			}
		})
	}
}

// Help and version are successes. They print to stdout and a caller piping
// them should not see a failure.
func TestExitCodeHelpAndVersionSucceed(t *testing.T) {
	requireLiveEvals(t)
	for _, arg := range []string{"-h", "-version"} {
		if got := runScanner(t, arg); got != exitClean {
			t.Errorf("%s should exit %d, got %d", arg, exitClean, got)
		}
	}
}

// A privileged key is refused rather than scanned: every finding this tool
// makes is a claim about what an ANONYMOUS caller reaches, and service_role
// bypasses RLS, so the report would be wrong rather than merely noisy. That
// refusal is a usage error too.
func TestExitCodeServiceRoleKeyIsRefused(t *testing.T) {
	requireLiveEvals(t)
	// A syntactically valid JWT claiming service_role. Not a real credential:
	// the check reads the claim and never verifies a signature.
	const svc = "eyJhbGciOiJIUzI1NiJ9." +
		"eyJpc3MiOiJzdXBhYmFzZSIsInJvbGUiOiJzZXJ2aWNlX3JvbGUifQ.sig"
	got := runScanner(t, "-u", "http://127.0.0.1:54321", "-rest-prefix", "/", "-k", svc)
	if got == exitFindings {
		t.Error("refusing a privileged key is a usage error, not a finding")
	}
	if got != 1 {
		t.Errorf("want exit 1 for a refused credential, got %d", got)
	}
}

// -o must ADD a destination, not replace the terminal.
//
// That was a previously-audited defect: writing a report silenced the
// findings, so capturing both renderings of one scan was impossible and two
// scans disagreed. It was fixed, and the fix was left unprotected — a second
// audit reverted the one-line condition and the entire suite still passed. The
// fan-out helper is unit-tested; the WIRING was not, and every live eval that
// uses -o also passes -silent, so none of them would notice.
func TestOutputFileDoesNotSilenceTheTerminal(t *testing.T) {
	requireLiveEvals(t)
	key := os.Getenv("UNRULY_FIXTURE_KEY")
	if key == "" {
		t.Skip("UNRULY_FIXTURE_KEY required")
	}
	bin := buildScanner(t)
	out := filepath.Join(t.TempDir(), "findings.jsonl")

	cmd := exec.Command(bin, "-u", "http://127.0.0.1:54321", "-k", key,
		"-rest-prefix", "/", "-j", "-o", out, "-nc")
	stdout, err := cmd.Output()
	if err != nil {
		if _, statErr := os.Stat(out); statErr != nil {
			t.Fatalf("scan produced no report: %v", err)
		}
	}
	b, readErr := os.ReadFile(out)
	if readErr != nil {
		t.Fatalf("no report file: %v", readErr)
	}
	fileLines := countNonEmpty(string(b))
	// Count LINES that start with a finding id, not occurrences of the
	// substring. The terminal format is `[id] [protocol] [severity] …`, and
	// four findings carry the protocol "unruly", so a naive substring
	// count reported 17 against a correct 13 and made the tool look wrong.
	termFindings := countFindingLines(string(stdout))

	if fileLines == 0 {
		t.Fatal("the file must receive the findings")
	}
	if termFindings == 0 {
		t.Error("writing a file must not silence the terminal: a scan told to save its " +
			"output should not go quiet, and one run must be able to produce both renderings")
	}
	if termFindings != fileLines {
		t.Errorf("both destinations must get the same findings: terminal %d, file %d",
			termFindings, fileLines)
	}
}

// -silent with -o is the pipeline case and must stay quiet.
func TestSilentWithOutputFileWritesOnlyTheFile(t *testing.T) {
	requireLiveEvals(t)
	key := os.Getenv("UNRULY_FIXTURE_KEY")
	if key == "" {
		t.Skip("UNRULY_FIXTURE_KEY required")
	}
	bin := buildScanner(t)
	out := filepath.Join(t.TempDir(), "findings.jsonl")
	cmd := exec.Command(bin, "-u", "http://127.0.0.1:54321", "-k", key,
		"-rest-prefix", "/", "-j", "-o", out, "-silent")
	stdout, _ := cmd.Output()
	if countFindingLines(string(stdout)) != 0 {
		t.Error("-silent must suppress the terminal rendering")
	}
	b, err := os.ReadFile(out)
	if err != nil || countNonEmpty(string(b)) == 0 {
		t.Error("the file must still receive the findings")
	}
}

func countNonEmpty(s string) int {
	var n int
	for _, l := range strings.Split(s, "\n") {
		if strings.TrimSpace(l) != "" {
			n++
		}
	}
	return n
}

// countFindingLines counts rendered findings: lines beginning with a finding
// id in brackets.
func countFindingLines(s string) int {
	var n int
	for _, l := range strings.Split(s, "\n") {
		if strings.HasPrefix(strings.TrimSpace(l), "[supabase") {
			n++
		}
	}
	return n
}

// TestExitCodeHistoricKeysAreReportedByTheBinary closes the last two ids that
// no scan had ever produced.
//
// The reason given for them was that nobody can put a key of their own into
// web.archive.org. True, and beside the point: history.Options carries an
// ArchiveBase and the CLI already exposes it as -archive, so a local stand-in
// is enough. The fixture serves the two endpoints the package calls -- the CDX
// index and the archived bytes -- with one capture per branch.
//
// Driven through the BINARY rather than history.Run, because the distinction
// this project keeps rediscovering is between a rule that can be built and one
// a scan can reach.
func TestExitCodeHistoricKeysAreReportedByTheBinary(t *testing.T) {
	if os.Getenv("UNRULY_LIVE") != "1" {
		t.Skip("set UNRULY_LIVE=1 to run live evals")
	}
	key := os.Getenv("UNRULY_FIXTURE_KEY")
	if key == "" {
		t.Skip("UNRULY_FIXTURE_KEY is required")
	}
	bin := buildScanner(t)
	out := filepath.Join(t.TempDir(), "hist.jsonl")

	cmd := exec.Command(bin, "-u", "http://127.0.0.1:54321", "-k", key,
		"-rest-prefix", "/", "-s", "http://127.0.0.1:54322",
		"-history", "-archive", "http://127.0.0.1:54325",
		"-j", "-o", out, "-silent")
	_ = cmd.Run() // a non-zero exit is expected: the fixture is vulnerable

	body, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("reading report: %v", err)
	}
	got := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(string(body)), "\n") {
		if line == "" {
			continue
		}
		var f struct {
			ID       string `json:"id"`
			Severity string `json:"severity"`
		}
		if json.Unmarshal([]byte(line), &f) == nil {
			got[f.ID] = f.Severity
		}
	}

	// One per branch of snapshotFinding, and the severities are the claim: a
	// service_role key in a public archive is not the same event as an anon key
	// that has since been rotated.
	for id, want := range map[string]string{
		"supabase-historic-service-key-exposed": "critical",
		"supabase-historic-key-not-rotated":     "high",
		"supabase-historic-key-rotated":         "info",
	} {
		switch {
		case got[id] == "":
			t.Errorf("%s was not reported; the archive fixture serves a capture for it", id)
		case got[id] != want:
			t.Errorf("%s reported at %s, want %s", id, got[id], want)
		}
	}
}

// TestExitCodeReportNeverCarriesAWholeCredential is about what the report is
// FOR: people paste it into tickets, chat and pull requests.
//
// The scan holds the operator's key, and against these fixtures it also
// RECOVERS three more -- a service_role key from the site, two from the
// archive, one from a preview host. A report that quoted any of them in full
// would turn "here is my scan output" into a credential disclosure, and the
// finding that says a key is exposed would be the thing exposing it.
//
// Prefixes are the compromise and they must survive: sixteen characters
// identify WHICH key without being usable, so the finding stays actionable.
// The test asserts both halves, because a scanner that redacted everything
// would pass the first half and be useless.
func TestExitCodeReportNeverCarriesAWholeCredential(t *testing.T) {
	if os.Getenv("UNRULY_LIVE") != "1" {
		t.Skip("set UNRULY_LIVE=1 to run live evals")
	}
	key := os.Getenv("UNRULY_FIXTURE_KEY")
	if key == "" {
		t.Skip("UNRULY_FIXTURE_KEY is required")
	}
	bin := buildScanner(t)
	out := filepath.Join(t.TempDir(), "report.jsonl")

	cmd := exec.Command(bin, "-u", "http://127.0.0.1:54321", "-k", key,
		"-rest-prefix", "/", "-s", "http://127.0.0.1:54322",
		"-history", "-archive", "http://127.0.0.1:54325",
		"-preview", "http://127.0.0.1:54324",
		"-j", "-o", out, "-silent")
	_ = cmd.Run() // non-zero is expected against a vulnerable fixture

	body, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("reading report: %v", err)
	}
	report := string(body)

	// Nothing that parses as a whole JWT, from any source.
	whole := regexp.MustCompile(`eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]+`)
	if found := whole.FindAllString(report, -1); len(found) > 0 {
		t.Errorf("%d whole credential(s) in the report, first starting %.24s…: a report "+
			"is something people paste into tickets", len(found), found[0])
	}
	// And specifically not the one the operator handed to the scanner.
	if strings.Contains(report, key) {
		t.Error("the report contains the key the scan was given; sharing the output " +
			"would share the credential")
	}

	// Not vacuous: the findings that identify a key must still identify it.
	var prefixed int
	for _, line := range strings.Split(strings.TrimSpace(report), "\n") {
		var f struct {
			ID       string `json:"id"`
			Evidence struct {
				Reason string `json:"reason"`
			} `json:"evidence"`
		}
		if json.Unmarshal([]byte(line), &f) != nil {
			continue
		}
		if strings.Contains(f.ID, "key") && strings.Contains(f.Evidence.Reason, "eyJ") {
			prefixed++
		}
	}
	if prefixed == 0 {
		t.Error("no key finding carries a prefix; either the fixtures stopped serving " +
			"credentials or redaction went too far and the findings can no longer say " +
			"WHICH key was exposed")
	}
}
