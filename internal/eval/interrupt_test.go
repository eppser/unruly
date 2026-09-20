package eval_test

// A scan that was stopped must not read like a scan that finished.
//
// Ctrl-C and a CI job's timeout are the two most ordinary ways a scan ends
// early, and both were silent: the findings gathered so far were written, the
// process exited 2, and nothing in the report said the relation list was a
// fragment. An operator reading it -- or a pipeline gating on the exit code --
// could not tell a partial scan from a complete one.
//
// The first attempt to demonstrate this proved nothing, and the way it failed
// is worth recording. It sent SIGINT three seconds into a scan of the local
// fixture, got a report back, and concluded the report was a partial one. The
// fixture scan takes 0.16s. The signal arrived at a process that had already
// exited, and the "interrupted" report was simply a complete one -- identical
// finding count to the control, which is what should have given it away.
//
// So this test does not race a real target. It serves a deliberately slow one,
// waits until the scanner is provably mid-scan, and only then signals.
//
//	go test ./internal/eval -run Interrupt

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// slowPostgREST answers like an empty PostgREST, taking delay per request.
// started is closed once the scanner has actually asked for something, which is
// what makes the signal land mid-scan rather than after it.
func slowPostgREST(delay time.Duration) (*httptest.Server, <-chan struct{}) {
	started := make(chan struct{})
	var once sync.Once
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		once.Do(func() { close(started) })
		time.Sleep(delay)
		w.Header().Set("Content-Range", "*/0")
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`[]`))
	}))
	return srv, started
}

// scanAndInterrupt runs a scan against url, signals it once it is under way,
// and returns the report it left behind.
func scanAndInterrupt(t *testing.T, url string, started <-chan struct{}) string {
	t.Helper()
	out := filepath.Join(t.TempDir(), "report.jsonl")
	cmd := exec.Command(buildScanner(t), "-u", url, "-k", "test-anon-key",
		"-rest-prefix", "/", "-j", "-o", out, "-silent")
	if err := cmd.Start(); err != nil {
		t.Fatalf("start scanner: %v", err)
	}

	select {
	case <-started:
	case <-time.After(30 * time.Second):
		cmd.Process.Kill()
		t.Fatal("the scanner never issued a request, so nothing was interrupted")
	}
	// Under way, and every request now costs the server's delay, so the scan
	// cannot finish before the signal arrives.
	if err := cmd.Process.Signal(os.Interrupt); err != nil {
		t.Fatalf("signal scanner: %v", err)
	}

	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case <-done:
	case <-time.After(60 * time.Second):
		cmd.Process.Kill()
		t.Fatal("the scanner did not exit after SIGINT")
	}

	b, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("the interrupted scan left no report at all: %v", err)
	}
	return string(b)
}

func TestInterruptedScanSaysItDidNotFinish(t *testing.T) {
	srv, started := slowPostgREST(400 * time.Millisecond)
	defer srv.Close()

	report := scanAndInterrupt(t, srv.URL, started)

	if !strings.Contains(report, "scan:interrupted") {
		t.Errorf("the scan was stopped mid-request and its report does not say so.\n"+
			"Everything in it is real, but the relation list is a fragment and the "+
			"unreached surfaces read as clean rather than unmeasured -- which is the "+
			"one thing this scanner exists not to do.\nreport:\n%s", report)
	}
	// The notice is only useful if it travels as a coverage finding: that is
	// what makes an interrupted scan drive the could-not-measure exit code
	// instead of inventing a fourth one.
	if !strings.Contains(report, "unruly-surface-not-assessed") {
		t.Error("the interruption notice must carry the blindness id the exit code " +
			"already keys on")
	}
}

// blindIDs mirrors internal/finding. Duplicated deliberately: this test is
// asserting a property of the shipped report, and importing the set from the
// code under test would let a mistake there hide a mistake here.
var blindIDs = map[string]bool{
	"unruly-target-not-discriminating": true,
	"unruly-capability-degraded":       true,
	"unruly-surface-not-assessed":      true,
	"unruly-probes-unresolved":         true,
	"unruly-probe-budget-exhausted":    true,
}

// blindFindings returns the could-not-measure verdicts in a JSONL report.
func blindFindings(t *testing.T, report string) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(report), "\n") {
		if line == "" {
			continue
		}
		var f map[string]any
		if err := json.Unmarshal([]byte(line), &f); err != nil {
			t.Fatalf("report line is not JSON: %v", err)
		}
		if blindIDs[f["id"].(string)] && f["resource"] != "scan:interrupted" {
			out = append(out, f)
		}
	}
	return out
}

// Saying "interrupted" once at the top of a report is not enough.
//
// Cancelling in-flight requests makes them fail, and a failed request is
// indistinguishable from a target that will not answer -- so the report filled
// with verdicts ABOUT THE TARGET, advising "Point -u at the PostgREST endpoint
// itself, or pass -rest-prefix". That sends an operator who pressed Ctrl-C to
// debug a configuration problem they do not have. Findings are read one at a
// time, sorted apart and filtered by id, so the attribution has to be on each.
func TestInterruptedScanAttributesEveryBlindVerdict(t *testing.T) {
	srv, started := slowPostgREST(400 * time.Millisecond)
	defer srv.Close()

	blind := blindFindings(t, scanAndInterrupt(t, srv.URL, started))
	if len(blind) == 0 {
		t.Fatal("the interrupted scan produced no could-not-measure findings, so this test " +
			"asserts nothing")
	}
	for _, f := range blind {
		if !strings.Contains(f["description"].(string), "THE SCAN WAS INTERRUPTED") {
			t.Errorf("%s/%s describes an unmeasured surface as a property of the target, in a "+
				"scan that was cut short: %s", f["id"], f["resource"], f["description"])
		}
		if !strings.Contains(f["remediation"].(string), "re-run the scan and let it finish") {
			t.Errorf("%s/%s tells the operator to fix the target when the cause may be the "+
				"interruption: %s", f["id"], f["resource"], f["remediation"])
		}
	}
}

// The control, and the assertion the first attempt at this test was missing: a
// scan that ran to completion must NOT carry the notice, or it means nothing.
func TestCompletedScanCarriesNoInterruptionNotice(t *testing.T) {
	srv, _ := slowPostgREST(0)
	defer srv.Close()

	out := filepath.Join(t.TempDir(), "report.jsonl")
	cmd := exec.Command(buildScanner(t), "-u", srv.URL, "-k", "test-anon-key",
		"-rest-prefix", "/", "-j", "-o", out, "-silent")
	cmd.Run() // a non-zero exit is a verdict, not a failure

	b, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("no report: %v", err)
	}
	if strings.Contains(string(b), "scan:interrupted") {
		t.Error("a scan nobody interrupted reported that it was interrupted, which would " +
			"make the notice noise and teach operators to ignore it")
	}
	// And the attribution must not leak onto a scan that finished: a report
	// that always blames an interruption explains nothing.
	blind := blindFindings(t, string(b))
	if len(blind) == 0 {
		t.Fatal("this control asserts nothing without blind findings to check")
	}
	for _, f := range blind {
		if strings.Contains(f["description"].(string), "THE SCAN WAS INTERRUPTED") {
			t.Errorf("%s/%s blames an interruption in a scan that ran to completion",
				f["id"], f["resource"])
		}
	}
}
