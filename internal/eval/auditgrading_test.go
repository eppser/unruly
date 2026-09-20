package eval_test

// The audit must tell "could not measure" from "failed".
//
// scripts/audit.sh grades every check by its exit status, and any nonzero
// status was a FAIL. That was fine until the exploit runners learned to report
// exit 3 -- this project's could-not-measure code, the one the scanner itself
// uses and eval-exitcode grades -- when a lab has drifted from its answer key
// or run out of quota. Rendered as FAIL, a changed LABORATORY becomes a red
// audit blaming the scanner: the same confusion the runners were fixed to stop
// making one level down, reappearing one level up.
//
// audit.sh's own header says "Did not run is reported as loudly as failed",
// and the report repeats it: a row marked not run is not a pass. This checks
// the script actually does that, in all three directions -- because a branch
// that renders drift as "not run" is only useful if a genuine regression still
// goes red beside it.
//
// The function body is lifted out of the real script rather than reimplemented
// here. A copy would drift, and then this would be grading a fossil.

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestAuditSeparatesCouldNotMeasureFromFailed(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available; audit.sh owns this behaviour")
	}
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	script := filepath.Join(root, "scripts", "audit.sh")
	if _, err := os.Stat(script); err != nil {
		t.Fatalf("audit.sh: %v", err)
	}

	harness := `set -u
LOGDIR=$(mktemp -d)
PASSED=0; FAILED=0; SKIPPED=0; RETRIED=0
emit() { :; }
environmentFailure() { return 1; }
eval "$(sed -n '/^run() {/,/^}/p' ` + script + `)"
run subject "claim" bash -c 'echo detail; exit ` + "%s" + `'
echo "passed=$PASSED failed=$FAILED skipped=$SKIPPED"`

	for _, tc := range []struct {
		name, code, want string
	}{
		{name: "could not measure", code: "3", want: "passed=0 failed=0 skipped=1"},
		{name: "a genuine failure still fails", code: "1", want: "passed=0 failed=1 skipped=0"},
		{name: "a clean check passes", code: "0", want: "passed=1 failed=0 skipped=0"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cmd := exec.Command("bash", "-c", strings.Replace(harness, "%s", tc.code, 1))
			cmd.Dir = root
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("harness: %v\n%s", err, out)
			}
			if !strings.Contains(string(out), tc.want) {
				t.Errorf("a check exiting %s did not grade as %q:\n%s", tc.code, tc.want, out)
			}
		})
	}
}

// A lab that could not be reset must not be graded against.
//
// The live block used to call `make lab-reset` twice and discard both
// statuses. A reset that fails leaves the lab holding whatever the last run
// wrote; every check below then grades against data nobody chose and reports
// FAIL, which reads as a regression in the scanner rather than a laboratory
// that could not be returned to its seed state.
//
// The two directions are not symmetric, and the test pins both. Before the
// run, the honest answer is "not run": nothing was measured. After the run,
// the results stand -- so it is a FAILURE, because the lab is dirty and the
// next run inherits it, and there is nothing left to skip.
func TestAuditWillNotGradeAgainstALabItCouldNotReset(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available")
	}
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	script := filepath.Join(root, "scripts", "audit.sh")

	// %s is the stub `make`: which invocation of lab-reset fails.
	harness := `set -u
LOGDIR=$(mktemp -d)
PASSED=0; FAILED=0; SKIPPED=0
LIVE_CHECKS="alpha beta"
declare -a LIVE_CLAIMS=("claim a" "claim b")
RESETS=0
emit() { :; }
environmentFailure() { return 1; }
make() { if [ "$1" = "lab-reset" ]; then RESETS=$((RESETS+1)); %s; fi; return 0; }
eval "$(sed -n '/^run() {/,/^}/p' ` + script + `)"
eval "$(sed -n '/^skip() {/,/^}/p' ` + script + `)"
eval "$(sed -n '/^liveChecks() {/,/^}/p' ` + script + `)"
liveChecks
echo "passed=$PASSED failed=$FAILED skipped=$SKIPPED resets=$RESETS"`

	for _, tc := range []struct{ name, stub, want string }{
		{
			name: "the reset before the run fails",
			stub: "return 1",
			want: "passed=0 failed=0 skipped=2",
		},
		{
			name: "the reset after the run fails",
			stub: "[ $RESETS -eq 2 ] && return 1",
			want: "passed=2 failed=1 skipped=0",
		},
		{
			name: "both resets succeed",
			stub: ":",
			want: "passed=2 failed=0 skipped=0",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cmd := exec.Command("bash", "-c", strings.Replace(harness, "%s", tc.stub, 1))
			cmd.Dir = root
			out, _ := cmd.CombinedOutput()
			if !strings.Contains(string(out), tc.want) {
				t.Errorf("wanted %q:\n%s", tc.want, out)
			}
		})
	}
}
