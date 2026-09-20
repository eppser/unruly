// Package creds holds every credential shape this scanner recognises, in one
// place, because holding them in several is how a new one reaches only some of
// the channels that look for it.
//
// The scanner reads application content through four channels: the live site
// and its JS bundles, public archives, and preview deployments. Each was
// carrying its own copy of the patterns. Two credential shapes were added --
// Postgres connection strings and Management API tokens -- and landed only in
// the live-site channel, so the one place a rotated-but-never-revoked secret
// actually survives, a public archive, was not looked at for either. Nothing
// was wrong with the code in the archive channel; it simply did not know the
// patterns had grown.
//
// Severity is not decided here. What a credential MEANS depends on where it
// was found -- a service_role key on the live site is a live exposure, the
// same key in a 2023 archive is a rotation failure -- and that judgement
// belongs to the channel that found it.
package creds

import (
	"encoding/base64"
	"encoding/json"
	"regexp"
	"strings"
)

var (
	// JWT matches Supabase's legacy key format. Role is a claim inside it, so
	// this alone does not say whether the key is anon or service_role.
	JWT = regexp.MustCompile(`eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}`)

	// Publishable is the current anon key format. Public by design.
	Publishable = regexp.MustCompile(`sb_publishable_[A-Za-z0-9_-]{8,}`)

	// SecretKey is the current service key format. Bypasses row-level security.
	SecretKey = regexp.MustCompile(`sb_secret_[A-Za-z0-9_-]{8,}`)

	// MgmtToken is a personal access token for the Management API. The widest
	// blast radius of anything here: it is scoped to the ACCOUNT rather than a
	// project, so it reaches every project's keys, database passwords and
	// existence.
	MgmtToken = regexp.MustCompile(`sbp_[A-Za-z0-9]{30,}`)

	// PGConn is a Postgres URI carrying a password: direct database access,
	// past PostgREST and therefore past row-level security entirely. One
	// pattern covers both Supabase shapes -- db.<ref>.supabase.co:5432 and the
	// aws-*.pooler.supabase.com poolers -- because both are simply URIs.
	//
	// Group 1 is the password, which callers need in order to decide whether
	// this is a leak or a template, and to keep it out of their reports.
	PGConn = regexp.MustCompile(`postgres(?:ql)?://[A-Za-z0-9._-]+:([^@\s"'` + "`" + `]{1,200})@[A-Za-z0-9.-]+(?::\d{2,5})?(?:/[A-Za-z0-9._-]*)?`)
)

// placeholderPasswords are the strings that appear where a password would be
// in a template rather than a leak.
//
// Supabase's dashboard hands out connection strings containing
// [YOUR-PASSWORD], and applications ship that line in a comment or a .env
// example constantly. Reporting it would be a critical finding on a string
// that grants nothing, which is how a scanner teaches people to ignore it.
var placeholderPasswords = map[string]bool{
	"[your-password]": true, "your-password": true, "yourpassword": true,
	"password": true, "<password>": true, "[password]": true, "pass": true,
	"changeme": true, "secret": true, "xxx": true, "xxxx": true, "***": true,
	"postgres": true, "example": true, "placeholder": true, "mypassword": true,
	"${db_password}": true, "$db_password": true, "{password}": true,
}

// PlaceholderPassword reports whether a captured password is a template rather
// than a credential.
func PlaceholderPassword(pw string) bool {
	l := strings.ToLower(pw)
	if placeholderPasswords[l] {
		return true
	}
	// Interpolation of any shape: ${...}, {{...}}, %s, $VAR. A string the
	// application substitutes at runtime is not a leaked password.
	if strings.ContainsAny(pw, "${}%") || strings.HasPrefix(pw, "<") {
		return true
	}
	// A password of one or two characters is not a Supabase password; it is
	// almost always a fragment of something else that parsed like a URI.
	return len(pw) < 6
}

// JWTRole reads the role claim from a Supabase key without verifying the
// signature, which is impossible without the project secret and unnecessary:
// the question is what the token CLAIMS to be.
//
// It returns "" when the token is not a readable JWT or carries no role.
//
// This exists because three packages decoded the same claim three different
// ways, and two of them did it by substring-matching `"role":"service_role"`.
// A payload with one space -- {"role": "service_role"} -- matched neither, so
// the same key was service_role to the flag validation and NOTHING to the
// scanners that read pages and archives. A leaked service_role key would have
// been walked past silently, which is the worst false negative this tool can
// have.
//
// It was invisible because the fixtures mint keys with
// separators=(",", ":"), i.e. shaped to fit the substring matcher. Python's
// json.dumps inserts that space by default, so any key minted by an ordinary
// script has it.
func JWTRole(tok string) string {
	var claims struct {
		Role string `json:"role"`
	}
	if !decodeClaims(tok, &claims) {
		return ""
	}
	return claims.Role
}

// JWTProjectRef reads the ref claim, which names the project a managed key
// belongs to. Empty when absent, which is normal for self-hosted keys.
func JWTProjectRef(tok string) string {
	var claims struct {
		Ref string `json:"ref"`
	}
	if !decodeClaims(tok, &claims) {
		return ""
	}
	return claims.Ref
}

// decodeClaims unmarshals a JWT's payload segment into v.
func decodeClaims(tok string, v any) bool {
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return false
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(parts[1], "="))
	if err != nil {
		// Some minters pad. Try the padded alphabet before giving up.
		raw, err = base64.URLEncoding.DecodeString(parts[1])
		if err != nil {
			return false
		}
	}
	return json.Unmarshal(raw, v) == nil
}

// ---------------------------------------------------------------------------
// Secret material that is not Supabase's.
//
// These live here for the reason the package exists: one place, so a shape
// added for one channel reaches all of them. They arrived with the value
// classifier, which reads sampled database ROWS rather than application
// content -- a fifth channel, and the one where a secret is most likely to be
// somebody else's rather than the project's own.
//
// Every pattern is a vendor-reserved prefix or a format identifier, never an
// English word. That is what makes them safe to apply to arbitrary data: they
// cannot fire on prose, and they work on a schema written in any language.

var (
	// AWSAccessKey. AKIA is reserved by AWS for long-lived access keys.
	AWSAccessKey = regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`)

	// StripeLive is a live secret key. The test-mode prefix (sk_test_) is
	// deliberately absent: it grants nothing and appears in documentation.
	StripeLive = regexp.MustCompile(`\bsk_live_[0-9A-Za-z]{16,}\b`)

	// SlackToken covers bot, user, app and refresh tokens.
	SlackToken = regexp.MustCompile(`\bxox[baprs]-[0-9A-Za-z-]{10,}\b`)

	// GitHubPAT and GitLabPAT are fixed-length by construction.
	GitHubPAT = regexp.MustCompile(`\bghp_[0-9A-Za-z]{36}\b`)
	GitLabPAT = regexp.MustCompile(`\bglpat-[0-9A-Za-z_-]{20}\b`)

	// PrivateKeyPEM matches the armour rather than the key, which is what
	// makes it exact.
	PrivateKeyPEM = regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----`)

	// PasswordHash matches the algorithm identifiers used by the common
	// password hashes. A hash is not a password, but a table of them is a
	// credential store, and an offline attack on one is a known quantity.
	PasswordHash = regexp.MustCompile(`\$(2[aby]\$[0-9]{2}\$[./A-Za-z0-9]{53}|argon2[id]{1,2}\$|scrypt\$|pbkdf2[-_a-z0-9]*\$|6\$[./A-Za-z0-9]{8,})`)
)

// SecretMaterial is every shape above plus the Supabase ones, for callers that
// only need to answer "is there a credential in here at all".
//
// Ordered, so callers that report the first match are deterministic.
var SecretMaterial = []*regexp.Regexp{
	SecretKey, MgmtToken, PGConn,
	AWSAccessKey, StripeLive, SlackToken, GitHubPAT, GitLabPAT,
	PrivateKeyPEM, PasswordHash,
}

// IsJWT reports whether tok is a JWT rather than merely dotted base64.
//
// The header must decode to JSON naming an algorithm. Without that check, a
// signed cookie, a cache key, or any three base64 segments joined by dots
// reads as a credential -- and in sampled database rows, those are common.
func IsJWT(tok string) bool {
	head, _, ok := strings.Cut(tok, ".")
	if !ok {
		return false
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(head, "="))
	if err != nil {
		raw, err = base64.URLEncoding.DecodeString(head)
		if err != nil {
			return false
		}
	}
	var hdr map[string]any
	if json.Unmarshal(raw, &hdr) != nil {
		return false
	}
	_, hasAlg := hdr["alg"]
	return hasAlg
}
