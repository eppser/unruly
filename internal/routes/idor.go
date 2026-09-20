package routes

import (
	"fmt"
	"strings"

	"github.com/eppser/unruly/internal/finding"
)

// Cross-identity access: one caller reading another caller's record.
//
// THIS NEEDS THREE ANSWERS, NOT TWO, and that is why the single-identity
// version was not shipped. "B can read /invoices/42" is not a finding on its
// own -- a product catalogue serves every id to everyone, correctly. What
// makes it one is the combination:
//
//	anonymous  -> refused        the resource is not public
//	A          -> the record     A may see it
//	B          -> THE SAME BODY  so may B, and B is somebody else
//
// Drop the anonymous leg and every public endpoint becomes an IDOR. Drop the
// same-body test and every per-caller endpoint becomes one, because B
// legitimately receives THEIR record from the same URL. With one identity
// there is no third answer to compare against and the check cannot be made
// sound, which is the whole reason adjacent-id guessing waited for this.

// A Principal is a labelled identity the operator supplied.
type Principal struct {
	Label string
	Token string
}

// principalResult is what one identity received.
type principalResult struct {
	label string
	res   probeResult
}

// ParsePrincipals reads -principal values as an operator types them.
//
// A label with no token names nobody, and a token with no label cannot appear
// in a finding, so both are dropped rather than turned into a request.
func ParsePrincipals(raw []string) []Principal {
	var out []Principal
	for _, r := range raw {
		l, tok, ok := strings.Cut(r, "=")
		l, tok = strings.TrimSpace(l), strings.TrimSpace(tok)
		if !ok || l == "" || tok == "" {
			continue
		}
		out = append(out, Principal{Label: l, Token: tok})
	}
	return out
}

// emptyBodies are responses that carry no record.
//
// Two callers both receiving nothing is not two callers receiving the same
// thing. Without this an endpoint answering 200 with `{}` to everybody looks
// like a perfect IDOR, and every such endpoint would be reported.
func isEmptyBody(b string) bool {
	switch strings.TrimSpace(b) {
	case "", "{}", "[]", "null":
		return true
	}
	return false
}

// crossIdentity reports a record one identity reads that belongs to another.
func crossIdentity(url string, anon probeResult, a, b principalResult) (finding.Finding, bool) {
	// A must actually have received something.
	if a.res.code != 200 || isEmptyBody(a.res.body) {
		return finding.Finding{}, false
	}
	// The resource must not be public: if a caller with no credential gets the
	// same thing, there is no ownership to break.
	if anon.code == 200 && strings.TrimSpace(anon.body) == strings.TrimSpace(a.res.body) {
		return finding.Finding{}, false
	}
	// B must have received THE SAME record. A different body is the endpoint
	// scoping correctly, which is the behaviour we want rather than the one we
	// report.
	if b.res.code != 200 || strings.TrimSpace(b.res.body) != strings.TrimSpace(a.res.body) {
		return finding.Finding{}, false
	}

	kinds := classifyBody(a.res.body)
	sev := finding.High
	if len(kinds) > 0 {
		if s := severityFor(kinds); s > sev {
			sev = s
		}
	}

	held := "a record"
	if len(kinds) > 0 {
		held = "a record holding " + strings.Join(kinds, ", ")
	}

	return finding.Finding{
		ID:       "app-cross-identity-read",
		Name:     "One account reads another account's record",
		Severity: sev,
		Protocol: "http",
		Matched:  url,
		Resource: url,
		Description: fmt.Sprintf("%s returns %s. An anonymous caller is refused, "+
			"identity %q receives it, and identity %q receives THE SAME BODY. The "+
			"endpoint therefore checks that somebody is signed in and not that the "+
			"record belongs to them -- which is the difference between a login and an "+
			"authorisation.", url, held, a.label, b.label),
		Remediation: "-- Scope the query by the caller's own identity rather than by the " +
			"identifier in the URL, so the record is selected FOR them instead of " +
			"fetched and then shown to them.",
		Evidence: finding.Evidence{
			Request: "curl -sS -H 'Authorization: Bearer $TOKEN_" +
				strings.ToUpper(b.label) + "' " + url,
			Reason: fmt.Sprintf("anonymous %d, %s 200, %s 200 with an identical body",
				anon.code, a.label, b.label),
			Classes: kinds,
		},
	}, true
}
