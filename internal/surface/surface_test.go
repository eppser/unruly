package surface

import (
	"strings"
	"testing"
)

// The three-way discriminator is the whole value of the Edge Function check.
// Absent, protected and reachable must stay distinct; collapsing 404 into
// "secure" is the same false-assurance bug found in a surveyed shell scanner.
func TestEdgeFunctionClassification(t *testing.T) {
	cases := []struct {
		name      string
		fn        EdgeFunction
		invokable bool
	}{
		{"verify_jwt on", EdgeFunction{Name: "send-email", Status: 401, RequiresJWT: true}, false},
		{"reached anonymously", EdgeFunction{Name: "send-email", Status: 200}, true},
		{"reached but erroring is still reached",
			EdgeFunction{Name: "send-email", Status: 500}, true},
		{"bad request means our payload was wrong, not that we were refused",
			EdgeFunction{Name: "send-email", Status: 400}, true},
	}
	for _, tc := range cases {
		if got := tc.fn.Invokable(); got != tc.invokable {
			t.Errorf("%s: Invokable() = %v, want %v", tc.name, got, tc.invokable)
		}
	}
}

func TestPrivilegedFunctionNameRaisesSeverity(t *testing.T) {
	if !looksPrivileged("admin-api") {
		t.Error("admin-api should be treated as privileged")
	}
	if !looksPrivileged("internal-sync") {
		t.Error("internal-sync should be treated as privileged")
	}
	if looksPrivileged("send-email") {
		t.Error("ordinary function names should not be escalated")
	}
}

// TestUnreachableSurfaceIsReportedNotAssumed guards the shape of bug this
// project keeps finding, on two more surfaces.
//
// SignupOpen() on a zero-value AuthConfig is false, and an empty bucket list is
// empty. So a FAILED fetch of either produced byte-for-byte the output of a
// correctly locked-down project: no finding, no warning, nothing. "I could not
// check" rendered as "there is nothing to find".
func TestUnreachableSurfaceIsReportedNotAssumed(t *testing.T) {
	// An auth config that was never successfully fetched must not read as a
	// project with signup closed.
	var never AuthConfig
	if never.SignupOpen() {
		t.Fatal("fixture assumption wrong")
	}
	if never.Reachable {
		t.Fatal("a zero-value config must not claim to be reachable")
	}

	// The distinction that matters: reachable-and-closed produces no finding,
	// unreachable produces one saying so.
	closed := AuthConfig{Reachable: true, DisableSignup: true}
	if _, ok := authFinding(nil, closed); ok {
		t.Error("signup genuinely closed should produce no finding")
	}
	if closed.SignupOpen() {
		t.Error("closed signup must not read as open")
	}

	// And an unreachable surface must produce an INFO finding whose text says
	// the absence of findings proves nothing.
	f := uncheckedFinding(nil, "auth", "https://x/auth/v1/settings", "impact text")
	if f.Severity.String() != "info" {
		t.Errorf("an unassessed surface is a coverage gap, not a vulnerability; got %s",
			f.Severity)
	}
	if !strings.Contains(f.Description, "is not evidence") {
		t.Error("the finding must state that absence of findings here proves nothing")
	}
}

// TestFunctionStatusClassification pins the 405 case, which turned any
// non-Supabase host into hundreds of findings.
//
// A function that exists ANSWERS a POST — it may succeed, fail, or reject the
// body, but it answers. 405 means the route does not handle POST at all, which
// is what an ordinary web server says about every path it serves. Reading it as
// "the function ran" produced 392 findings against example.com.
func TestFunctionStatusClassification(t *testing.T) {
	cases := map[int]functionState{
		404: functionAbsent,    // no such function
		405: functionAbsent,    // the route does not take POST; not a function
		501: functionAbsent,    // not implemented
		301: functionAbsent,    // a redirect is routing, not execution
		302: functionAbsent,    //
		401: functionProtected, // deployed, verify_jwt on
		403: functionProtected, //
		200: functionReached,
		400: functionReached, // our payload was wrong, so it ran
		500: functionReached, // it ran and failed
	}
	for status, want := range cases {
		if got := classifyFunction(status); got != want {
			t.Errorf("HTTP %d classified %v, want %v", status, got, want)
		}
	}
}

// Detecting an Edge Function means invoking it, so it must be opt-in.
//
// The platform answers 404 for absent and 401 when verify_jwt rejects the
// caller; anything else means the request reached the function, which is to say
// the function ran. Detection and invocation are the same act here, and Edge
// Functions send email, charge cards and write to queues.
func TestEdgeFunctionProbingIsOptIn(t *testing.T) {
	// Absent from Options means off: the zero value must be the safe one, or
	// every caller that forgets the field probes by default.
	var o Options
	if o.AllowFunctions {
		t.Error("the zero value of Options must not permit function probing")
	}
	if o.AllowInvoke {
		t.Error("the zero value of Options must not permit routine invocation")
	}
}

// The attribution must sum to the total.
//
// The two are written by the same helper precisely so they cannot disagree,
// and this is what keeps that true: a ledger whose parts do not add up to its
// total is worse than no ledger, because an operator reading it will believe
// the parts.
func TestRequestAttributionSumsToTheTotal(t *testing.T) {
	var res Result
	res.spend("routines", 7)
	res.spend("storage", 3)
	res.spend("routines", 5)

	var sum int
	for _, n := range res.RequestsBy {
		sum += n
	}
	if sum != res.Requests {
		t.Errorf("attribution sums to %d and the total says %d", sum, res.Requests)
	}
	if res.RequestsBy["routines"] != 12 {
		t.Errorf("routines = %d, want 12: repeated spends on one stage must add",
			res.RequestsBy["routines"])
	}
	// And no stage is anonymous: an empty label is the opaque bucket coming
	// back under a different name.
	for stage := range res.RequestsBy {
		if strings.TrimSpace(stage) == "" {
			t.Error("a request was attributed to an unnamed stage")
		}
	}
}
