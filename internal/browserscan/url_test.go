package browserscan_test

import (
	"testing"

	"github.com/eppser/unruly/internal/browserscan"
)

// People type what they read off a business card, not what a URL parser wants.
//
// The form rejected "myapp.lovable.app" because it did not start with a
// scheme, which is a correct observation and a useless one: the person typed
// their own address and the tool told them it was not a web address.
func TestABareDomainBecomesAnAddress(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"myapp.lovable.app", "https://myapp.lovable.app"},
		{"www.sdy.mn", "https://www.sdy.mn"},
		{"  sdy.mn  ", "https://sdy.mn"},
		{"sdy.mn/team", "https://sdy.mn/team"},
		{"SDY.MN", "https://sdy.mn"},
		// Already addressed: left alone, including plain http, because a
		// person who typed http meant it and upgrading silently would scan a
		// different origin than the one they named.
		{"https://sdy.mn", "https://sdy.mn"},
		{"http://localhost:3000", "http://localhost:3000"},
		{"https://sdy.mn/", "https://sdy.mn"},
		// A scheme typed with the wrong slashes is still an intent.
		{"https:/sdy.mn", "https://sdy.mn"},
	} {
		if got := browserscan.NormaliseSite(tc.in); got != tc.want {
			t.Errorf("NormaliseSite(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// And what is not an address stays refused, or the form would happily scan
// nothing and report it clean.
func TestNonsenseIsStillRefused(t *testing.T) {
	for _, in := range []string{
		"", "   ", "hello world", "notadomain", "ftp://sdy.mn",
		"javascript:alert(1)", "http://", "..", "a.b",
	} {
		if got := browserscan.NormaliseSite(in); got != "" {
			t.Errorf("NormaliseSite(%q) = %q, want a refusal", in, got)
		}
	}
}
