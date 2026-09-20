package creds

import (
	"encoding/base64"
	"testing"
)

func mintPayload(payload string) string {
	seg := func(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }
	return seg(`{"alg":"HS256"}`) + "." + seg(payload) + "." + seg("not-a-signature")
}

// One space used to hide a service_role key completely.
//
// Three packages decoded this claim three ways. Two did it by
// substring-matching `"role":"service_role"`, so a payload written as
// {"role": "service_role"} matched neither branch and came back as the empty
// string -- meaning the channel that reads pages and the channel that reads
// public archives BOTH walked past a leaked service_role key in silence,
// while the flag validation, which parsed JSON properly, would have refused
// the same token.
//
// It stayed invisible because this repository's own JWT minter passes
// separators=(",", ":") -- the fixtures were shaped to fit the matcher.
// Python's json.dumps inserts that space by default, so any key minted by an
// ordinary script has it.
func TestRoleSurvivesJSONWhitespace(t *testing.T) {
	for _, tc := range []struct{ payload, want string }{
		{`{"role":"service_role","ref":"abc"}`, "service_role"},
		{`{"role": "service_role", "ref": "abc"}`, "service_role"},
		{`{"role" : "service_role"}`, "service_role"},
		{"{\n  \"role\": \"service_role\"\n}", "service_role"},
		{`{"ref":"abc","role":"service_role"}`, "service_role"},
		{`{"role":"anon"}`, "anon"},
		{`{"role": "anon"}`, "anon"},
		{`{"role":"authenticated"}`, "authenticated"},
		{`{"ref":"abc"}`, ""},
		{`not json at all`, ""},
	} {
		if got := JWTRole(mintPayload(tc.payload)); got != tc.want {
			t.Errorf("JWTRole(%s) = %q, want %q", tc.payload, got, tc.want)
		}
	}
	// Not a JWT at all.
	for _, junk := range []string{"", "abc", "a.b", "a.b.c.d"} {
		if got := JWTRole(junk); got != "" {
			t.Errorf("JWTRole(%q) = %q, want empty", junk, got)
		}
	}
}

// A padded segment must decode too: not every minter strips the padding, and
// a key this scanner cannot read is a key it will not report.
func TestRoleReadsPaddedSegments(t *testing.T) {
	seg := func(s string) string { return base64.URLEncoding.EncodeToString([]byte(s)) } // keeps '='
	tok := seg(`{"alg":"HS256"}`) + "." + seg(`{"role":"service_role"}`) + "." + seg("sig")
	if got := JWTRole(tok); got != "service_role" {
		t.Errorf("padded token: got %q, want service_role", got)
	}
}

func TestProjectRefIsRead(t *testing.T) {
	if got := JWTProjectRef(mintPayload(`{"role": "anon", "ref": "abcdefghijklmnopqrst"}`)); got != "abcdefghijklmnopqrst" {
		t.Errorf("got %q", got)
	}
	if got := JWTProjectRef(mintPayload(`{"role":"anon"}`)); got != "" {
		t.Errorf("a key with no ref claim returned %q; self-hosted keys have none and "+
			"\"cannot tell\" must not read as \"belongs elsewhere\"", got)
	}
}
