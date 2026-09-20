package routes

import (
	"strings"
	"testing"
)

// A bypass is only a bypass if the canonical request was REFUSED.
//
// The whole discipline of this check. Trying ten variants against every
// endpoint and reporting whichever return 200 would report an open API ten
// times over and bury the one endpoint where a variant actually got past
// something. The variant has to succeed where the plain request did not.
func TestOnlyAVariantThatSucceedsWhereTheCanonicalFailedIsReported(t *testing.T) {
	// The canonical request was allowed: nothing here is a bypass, whatever
	// the variants do.
	//
	// The variants carry REAL BODIES, and that matters. The first version gave
	// them empty ones, so the empty-body filter rejected them whatever the
	// canonical-refused precondition did -- measured, by deleting the
	// precondition and watching this test survive. A control that another
	// control already satisfies is not testing its own subject.
	if fs := bypassFindings("https://api.example.invalid", "/admin",
		probeResult{code: 200, body: `{"data":1}`},
		map[string]probeResult{
			"HEAD":              {code: 200, body: `{"users":["a"]}`},
			"uppercase segment": {code: 200, body: `{"users":["a"]}`},
		}); len(fs) > 0 {
		t.Errorf("%d bypass finding(s) for an endpoint that answers 200 to a plain "+
			"request; there is nothing to get past", len(fs))
	}

	// The canonical request was refused and a variant was not.
	fs := bypassFindings("https://api.example.invalid", "/admin",
		probeResult{code: 401, body: `{"detail":"Not authenticated"}`},
		map[string]probeResult{"X-Original-URL": {code: 200, body: `{"users":[]}`}})
	if len(fs) != 1 {
		t.Fatalf("a variant that returned 200 where the plain request returned 401 "+
			"produced %d findings, want 1", len(fs))
	}
	if !strings.Contains(fs[0].Description, "X-Original-URL") {
		t.Errorf("the finding does not name the variant that got through: %q",
			fs[0].Description)
	}
}

// A VARIANT THAT RETURNS THE SAME REFUSAL IS NOT A BYPASS.
//
// Plenty of servers answer 200 with an error body. A check that read the
// status alone would report every one of them, and an operator who chases two
// false bypasses stops reading the third finding.
func TestAVariantReturningTheSameRefusalIsNotABypass(t *testing.T) {
	refusal := `{"detail":"Not authenticated"}`
	if fs := bypassFindings("https://api.example.invalid", "/admin",
		probeResult{code: 401, body: refusal},
		map[string]probeResult{"X-Original-URL": {code: 200, body: refusal}}); len(fs) > 0 {
		t.Error("a variant that returned 200 carrying the SAME refusal body was " +
			"reported as a bypass; the status changed and nothing else did")
	}
}

// AND NEITHER IS AN EMPTY 200.
//
// HEAD returns no body by definition, and a 200 with nothing in it proves the
// route exists rather than that data was reached. Reporting it as a bypass
// asserts a stranger can do something, on no evidence that anything came back.
func TestAnEmptyResponseIsNotABypass(t *testing.T) {
	if fs := bypassFindings("https://api.example.invalid", "/admin",
		probeResult{code: 401, body: `{"detail":"no"}`},
		map[string]probeResult{"HEAD": {code: 200, body: ""}}); len(fs) > 0 {
		t.Error("an empty 200 was reported as a bypass; HEAD returns no body by " +
			"definition, and a route existing is not data being reached")
	}
}

// The variants themselves: the ones that actually get past middleware.
//
// Each is a real misconfiguration rather than a curiosity. Header variants
// exploit a reverse proxy that authorises one path and forwards another; case
// and normalisation variants exploit a matcher that compares strings while the
// server routes on something else.
func TestTheVariantsCoverTheShapesThatGetPastMiddleware(t *testing.T) {
	vs := bypassVariants("/admin/users")

	var headers, paths, methods int
	for _, v := range vs {
		switch {
		case v.Header != "":
			headers++
		case v.Method != "" && v.Method != "GET":
			methods++
		case v.Path != "/admin/users":
			paths++
		}
	}
	if headers < 3 {
		t.Errorf("%d header variants; a reverse proxy that authorises one path and "+
			"forwards another is the commonest bypass there is", headers)
	}
	if paths < 3 {
		t.Errorf("%d path variants; a matcher comparing strings while the server "+
			"routes on something else is the second commonest", paths)
	}
	if methods < 1 {
		t.Errorf("%d method variants; a rule written for GET alone leaves HEAD and "+
			"OPTIONS reaching the same handler", methods)
	}
}

// NOTHING THAT WRITES, WITHOUT CONSENT.
//
// A POST where GET is refused is a real bypass shape and it is also a request
// that can create something in a system this scanner knows nothing about. It
// belongs behind the same consent as every other write.
func TestNoVariantWritesWithoutConsent(t *testing.T) {
	for _, v := range bypassVariants("/admin/users") {
		switch v.Method {
		case "", "GET", "HEAD", "OPTIONS":
		default:
			t.Errorf("variant uses %s, which can change the target, and this list is "+
				"used without write consent", v.Method)
		}
	}
}

// A CATCH-ALL THAT ECHOES THE PATH DEFEATS THE BODY COMPARISON.
//
// Comparing a variant's response against the nonsense-path control catches the
// simple catch-all, which returns the identical index page for everything. It
// does not catch the common variety that puts the requested path INTO the
// response -- `{"error":"no route for /Admin"}`, or an SPA that renders the URL
// -- because then every body differs from every other and each variant looks
// like it reached something new.
//
// So the host's ability to distinguish a path that cannot exist is checked
// separately, and path variants are abandoned when it cannot. Found by
// breaking that check and watching it SURVIVE: the fixture that motivated it
// returned one identical page, so the body comparison was doing all the work.
func TestAPathEchoingCatchAllDoesNotProduceBypasses(t *testing.T) {
	fs := bypassFindings("https://app.example.invalid", "/admin",
		probeResult{code: 401, body: `{"detail":"Not authenticated"}`},
		map[string]probeResult{
			// The control: a path that cannot exist, answered 200 with the
			// path echoed back.
			catchAllControl: {code: 200,
				body: `{"error":"no route for /unruly_control_path_that_cannot_exist"}`},
			// Every path variant gets its own distinct body, so nothing
			// matches the control exactly.
			"uppercase segment":    {code: 200, body: `{"error":"no route for /Admin"}`},
			"double slash":         {code: 200, body: `{"error":"no route for //admin"}`},
			"trailing dot-segment": {code: 200, body: `{"error":"no route for /admin/."}`},
		})

	if len(fs) > 0 {
		t.Errorf("%d bypass finding(s) against a host that answers 200 for a path "+
			"which cannot exist. It distinguishes nothing, so a path variant reaching "+
			"200 proves nothing -- and reporting one bypass per refused endpoint per "+
			"variant is how an operator learns to ignore this check.", len(fs))
	}
}

// And a header variant still works on such a host.
//
// The catch-all defeats PATH variants, not header ones: a header variant is
// judged against the identical request without the header, so the host's
// routing behaviour cancels out of the comparison. Abandoning both would
// discard a sound check because an unsound one shares a fixture.
func TestHeaderVariantsSurviveACatchAllHost(t *testing.T) {
	fs := bypassFindings("https://app.example.invalid", "/admin",
		probeResult{code: 401, body: `{"detail":"Not authenticated"}`},
		map[string]probeResult{
			catchAllControl:            {code: 200, body: `{"error":"no route for /x"}`},
			"X-Original-URL":           {code: 200, body: `{"users":[{"id":1}]}`},
			"X-Original-URL (control)": {code: 200, body: `{"error":"no route for /"}`},
		})
	if len(fs) != 1 {
		t.Errorf("got %d findings; a header variant that returns data its own "+
			"no-header control does not is a bypass whatever the host does with "+
			"unknown paths", len(fs))
	}
}
