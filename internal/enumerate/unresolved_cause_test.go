package enumerate

import (
	"strings"
	"testing"
)

// The advice must match the cause.
//
// Unresolved probes already block a clean exit, which is right: a candidate
// that could not be measured must never read as one measured and found absent.
// What the finding could not do is say WHY, so it always advised the same
// thing -- lower the rate limit and reduce concurrency.
//
// That advice is correct for a throttling host and wrong for a cold one.
// PostgREST answers 503 with PGRST002 for a window after startup while it
// builds its schema cache, and a scan begun just after a deploy hits it. The
// fix there is to wait and re-run; lowering the rate limit changes nothing and
// sends the operator to tune a knob that was never the problem.
//
// Measured in the benchmark corpus: a key verified warm passed, and the same
// key cold failed 23 of 35 claims. Same target, same credential, opposite
// results, and the difference was seconds of uptime.
func TestUnresolvedAdviceNamesTheActualCause(t *testing.T) {
	starting := Result{Unresolved: 30, UnresolvedByCause: map[string]int{causeStarting: 30}}
	throttled := Result{Unresolved: 30, UnresolvedByCause: map[string]int{causeThrottled: 30}}

	fs, ok := starting.UnresolvedFinding("http://x/rest/v1", 40)
	if !ok {
		t.Fatal("no finding for 30 unresolved probes")
	}
	ft, _ := throttled.UnresolvedFinding("http://x/rest/v1", 40)

	if fs.Remediation == ft.Remediation {
		t.Error("a server that was still starting and one that throttled get identical " +
			"advice, so one of the two operators is being sent to the wrong knob")
	}
	// The cold case must say wait, and must NOT tell the operator to slow down.
	low := strings.ToLower(fs.Remediation + " " + fs.Description)
	if !strings.Contains(low, "wait") && !strings.Contains(low, "again in") {
		t.Errorf("the starting-up case does not advise waiting: %q", fs.Remediation)
	}
	// It may MENTION the rate limit -- saying it will not help is useful -- but
	// it must not instruct the operator to lower it. The first version of this
	// assertion banned the string outright and failed on advice that was
	// correct, which is the test being wrong rather than the code.
	if strings.Contains(strings.ToLower(fs.Remediation), "re-run with -rate-limit set lower") {
		t.Errorf("the starting-up case instructs lowering the rate limit, which is not "+
			"the cause: %q", fs.Remediation)
	}
	// The throttled case must still say what it always said.
	if !strings.Contains(strings.ToLower(ft.Remediation), "-rate-limit") {
		t.Errorf("the throttled case lost its advice: %q", ft.Remediation)
	}

	// A mixture must not claim a single cause it cannot support.
	mixed := Result{Unresolved: 30, UnresolvedByCause: map[string]int{
		causeStarting: 15, causeThrottled: 15,
	}}
	fm, _ := mixed.UnresolvedFinding("http://x/rest/v1", 40)
	if !strings.Contains(fm.Evidence.Reason, causeStarting) ||
		!strings.Contains(fm.Evidence.Reason, causeThrottled) {
		t.Errorf("a mixed run does not report both causes: %q", fm.Evidence.Reason)
	}

	// Deterministic: the same causes must render identically every time, or two
	// scans of an unchanged project produce different bytes.
	for i := 0; i < 20; i++ {
		if again, _ := mixed.UnresolvedFinding("http://x/rest/v1", 40); again.Evidence.Reason != fm.Evidence.Reason {
			t.Fatalf("run %d rendered %q, first run rendered %q", i, again.Evidence.Reason, fm.Evidence.Reason)
		}
	}
}
