package main

import (
	"encoding/base64"
	"testing"

	"github.com/eppser/unruly/internal/escalate"
)

// A managed Supabase project's reference is its hostname, which makes a
// mismatched credential catchable before any request leaves the machine.
//
// The first attempt at this check compared the key's ref against the whole
// target string with strings.Contains. That is wrong in the direction that
// matters: a project's ref does not appear in its own site URL, so the
// reference target example-app.test with its correct key
// (ref examplerefexampleref) would have had that key dropped and been
// rescanned with whatever discovery could find.
func TestRefFromHost(t *testing.T) {
	cases := []struct{ in, want string }{
		{"https://abcdefghijklmno.supabase.co", "abcdefghijklmno"},
		{"https://abcdefghijklmno.supabase.co/rest/v1", "abcdefghijklmno"},
		{"abcdefghijklmno.supabase.co", "abcdefghijklmno"},
		{"https://abcdefghijklmno.supabase.co:443", "abcdefghijklmno"},

		// Not a managed project: no ref can be derived, and guessing one would
		// drop a perfectly good key.
		{"https://example-app.test", ""},
		{"https://app.example.com", ""},
		{"http://127.0.0.1:54321", ""},
		{"https://db.staging.supabase.co", ""}, // multi-label: not a ref
		{"https://.supabase.co", ""},
		{"", ""},
	}
	for _, tc := range cases {
		if got := refFromHost(tc.in); got != tc.want {
			t.Errorf("refFromHost(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// Supabase's current publishable key is an opaque sb_publishable_ string, not
// a JWT, so nothing in it can claim a role. The privileged-key warning fires
// on any role that is not "anon", and JWTRole reports "unknown" for anything
// it cannot parse -- so a correct, current-format key drew the warning meant
// for a dangerous one:
//
//	the supplied key claims role "unknown", not anon
//
// Crying wolf over the right credential is worse than saying nothing: the
// warning that matters, a real service_role JWT, then looks identical to the
// one the user has learned to ignore.
func TestRoleWarningIgnoresNonJWTKeys(t *testing.T) {
	cases := []struct {
		name, key string
		warn      bool
	}{
		{"publishable", "sb_publishable_AbCdEf0123456789", false},
		{"empty", "", false},
		{"not-a-jwt", "some-opaque-token", false},
		{"anon-jwt", jwtWithRole(t, "anon"), false},
		{"authenticated-jwt", jwtWithRole(t, "authenticated"), true},
		{"service-role-jwt", jwtWithRole(t, "service_role"), true},
	}
	for _, tc := range cases {
		role := escalate.JWTRole(tc.key)
		got := role != "" && role != "anon" && role != "unknown"
		if got != tc.warn {
			t.Errorf("%s (role %q): warn=%v, want %v", tc.name, role, got, tc.warn)
		}
	}
}

func jwtWithRole(t *testing.T, role string) string {
	t.Helper()
	enc := func(s string) string {
		return base64.RawURLEncoding.EncodeToString([]byte(s))
	}
	return enc(`{"alg":"HS256","typ":"JWT"}`) + "." +
		enc(`{"iss":"supabase","ref":"abcdefghijklmno","role":"`+role+`"}`) + ".sig"
}
