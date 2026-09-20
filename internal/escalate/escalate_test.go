package escalate

import "testing"

func TestJWTRole(t *testing.T) {
	// Real fixture tokens: header.payload.signature, HS256.
	anon := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
		"eyJyb2xlIjoiYW5vbiIsImlzcyI6InN1cGFiYXNlLWZpeHR1cmUifQ.sig"
	authed := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
		"eyJyb2xlIjoiYXV0aGVudGljYXRlZCIsInN1YiI6IjExMTEifQ.sig"
	cases := map[string]string{anon: "anon", authed: "authenticated", "": "unknown", "not.a.jwt": "unknown"}
	for tok, want := range cases {
		if got := JWTRole(tok); got != want {
			t.Errorf("JWTRole(%.20s…) = %q, want %q", tok, got, want)
		}
	}
}

// JWTProjectRef catches a key pasted from the wrong project before any request
// is sent. Without it, a typo costs somebody else's project 2684 requests that
// can only be rejected — and the operator waits through all of them to be told
// the key is "wrong, expired, or for a different project" without learning
// which.
func TestJWTProjectRef(t *testing.T) {
	// {"iss":"supabase","ref":"examplerefexampleref","role":"anon"}
	const withRef = "eyJhbGciOiJIUzI1NiJ9." +
		"eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImV4YW1wbGVyZWZleGFtcGxlcmVmIiwicm9sZSI6ImFub24ifQ.sig"
	if got := JWTProjectRef(withRef); got != "examplerefexampleref" {
		t.Errorf("project ref = %q, want examplerefexampleref", got)
	}

	// Self-hosted deployments and sb_publishable_ keys carry no ref. That must
	// read as "unknown" and never as a mismatch, or the check would refuse
	// every self-hosted scan.
	const noRef = "eyJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoiYW5vbiJ9.sig"
	if got := JWTProjectRef(noRef); got != "" {
		t.Errorf("a token without a ref claim should yield \"\", got %q", got)
	}
	for _, junk := range []string{"", "not-a-jwt", "sb_publishable_abc"} {
		if got := JWTProjectRef(junk); got != "" {
			t.Errorf("JWTProjectRef(%q) = %q, want \"\"", junk, got)
		}
	}
}
