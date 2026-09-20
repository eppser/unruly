package routes

import (
	"strings"
	"testing"
)

// IDOR NEEDS THREE ANSWERS, NOT TWO.
//
// "B can read the record at /invoices/42" is not a finding on its own: a
// product catalogue serves every id to everyone, correctly. What makes it one
// is the combination:
//
//	anonymous  -> refused        (the resource is not public)
//	A          -> the record     (A may see it)
//	B          -> THE SAME BODY  (so may B, and B is somebody else)
//
// Drop the anonymous leg and every public endpoint is an IDOR. Drop the
// same-body test and every per-caller endpoint is one, because B legitimately
// receives THEIR record from the same URL. This is why the one-principal
// version was not shipped: with a single identity there is no third answer to
// compare against, and the check cannot be made sound.
func TestIDORNeedsAllThreeAnswers(t *testing.T) {
	record := `{"id":42,"customer":"acme","total":1200}`

	// The real thing.
	f, ok := crossIdentity("https://api.example.invalid/invoices/42",
		probeResult{code: 401, body: `{"detail":"no"}`},
		principalResult{label: "a", res: probeResult{code: 200, body: record}},
		principalResult{label: "b", res: probeResult{code: 200, body: record}})
	if !ok {
		t.Fatal("a record that anonymous callers are refused, that A receives, and that " +
			"B receives IDENTICALLY, produced no finding. That is the whole shape of a " +
			"broken ownership check.")
	}
	if !strings.Contains(f.Description, "b") || !strings.Contains(f.Description, "a") {
		t.Errorf("the finding does not name both identities: %q", f.Description)
	}

	// Public: anonymous gets it too.
	if _, ok := crossIdentity("https://api.example.invalid/products/42",
		probeResult{code: 200, body: record},
		principalResult{label: "a", res: probeResult{code: 200, body: record}},
		principalResult{label: "b", res: probeResult{code: 200, body: record}}); ok {
		t.Error("an endpoint an ANONYMOUS caller can read was reported as an ownership " +
			"failure. A product catalogue serves every id to everyone, correctly, and " +
			"reporting those buries the endpoint where it is wrong.")
	}

	// Scoped: B gets THEIR record, not A's.
	if _, ok := crossIdentity("https://api.example.invalid/invoices/42",
		probeResult{code: 401, body: `{"detail":"no"}`},
		principalResult{label: "a", res: probeResult{code: 200, body: record}},
		principalResult{label: "b", res: probeResult{code: 200,
			body: `{"id":42,"customer":"globex","total":80}`}}); ok {
		t.Error("an endpoint that returned a DIFFERENT record to B was reported as an " +
			"ownership failure. Serving each caller their own row from one URL is the " +
			"correct behaviour, not the broken one.")
	}

	// Refused: B is properly denied.
	if _, ok := crossIdentity("https://api.example.invalid/invoices/42",
		probeResult{code: 401, body: `{"detail":"no"}`},
		principalResult{label: "a", res: probeResult{code: 200, body: record}},
		principalResult{label: "b", res: probeResult{code: 403, body: `{"detail":"forbidden"}`}}); ok {
		t.Error("an endpoint that REFUSED B was reported as an ownership failure")
	}
}

// An empty body is not a record.
//
// Two callers both receiving nothing is not two callers receiving the same
// thing. Without this an endpoint answering 200 with `{}` to everybody looks
// like a perfect IDOR.
func TestAnEmptyBodySharedByBothIsNotAFinding(t *testing.T) {
	for _, body := range []string{"", "{}", "[]", "null"} {
		if _, ok := crossIdentity("https://api.example.invalid/invoices/42",
			probeResult{code: 401, body: `{"detail":"no"}`},
			principalResult{label: "a", res: probeResult{code: 200, body: body}},
			principalResult{label: "b", res: probeResult{code: 200, body: body}}); ok {
			t.Errorf("both callers received %q and it was reported as a shared record; "+
				"two callers receiving nothing is not two callers receiving the same "+
				"thing", body)
		}
	}
}

// Principals parse as an operator would type them.
func TestPrincipalsParseAsTyped(t *testing.T) {
	ps := ParsePrincipals([]string{"a=tokenA", "b=tokenB", " admin = tokenC "})
	if len(ps) != 3 {
		t.Fatalf("parsed %d principals from three, got %+v", len(ps), ps)
	}
	if ps[0].Label != "a" || ps[0].Token != "tokenA" {
		t.Errorf("first principal = %+v", ps[0])
	}
	// A principal with no token names nobody.
	if len(ParsePrincipals([]string{"a=", "=tok", "junk"})) != 0 {
		t.Error("malformed principals were accepted; a label with no token names nobody")
	}
}
