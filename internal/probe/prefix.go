package probe

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/eppser/unruly/internal/client"
)

// Correcting a REST prefix the target does not use.
//
// The managed product routes PostgREST through Kong at /rest/v1, and that is
// the default. A self-hosted deployment, a bare PostgREST, or anything behind a
// different gateway serves it somewhere else -- usually the root.
//
// Getting this wrong is not a degraded scan, it is a confidently empty one.
// Measured against a fixture serving PostgREST at the root: 18,755 requests,
// every one answered by PostgREST with PGRST125 "Invalid path specified in
// request URL", 0 relations found, and a report shaped exactly like a project
// with nothing exposed. Nothing in the output named the cause, and the flag
// that fixes it -- -rest-prefix / -- was never mentioned.
//
// PGRST125 is what makes this decidable rather than a guess. It is PostgREST
// answering, so the server IS PostgREST; it just is not mounted where we asked.
// Two requests settle it, and only when that error appears.

// prefixCandidates are tried in order. The root covers bare PostgREST and the
// common self-hosted layouts; nothing here is guessed at random, because a
// scanner that gropes for a prefix on every target is a scanner that sends a
// stranger requests for no reason.
var prefixCandidates = []string{"/"}

// PrefixVerdict is what the two probes established.
type PrefixVerdict int

const (
	// PrefixOK: PostgREST did not object to the configured prefix, so the scan
	// proceeds unchanged. This is every managed project -- the root there
	// answers 401, not PGRST125.
	PrefixOK PrefixVerdict = iota
	// PrefixMoved: PostgREST is somewhere else and the scan found it.
	PrefixMoved
	// PrefixWrongAndUnresolved: PostgREST said the prefix is wrong and no
	// candidate corroborated. Continuing means sending the whole plan to a
	// path the server has already rejected -- measured at 18,756 requests, all
	// of them answered PGRST125, producing a report that says 0 relations.
	//
	// This case is not hypothetical: it is what a wrong prefix looks like when
	// the credential is ALSO not accepted, because then the candidate root
	// answers 401 and cannot corroborate. Both faults are real and the operator
	// needs to hear about the one that is decidable.
	PrefixWrongAndUnresolved
)

// ResolveRestPrefix returns a client addressing PostgREST where it actually is,
// the prefix it settled on, and what it established. The input client is
// returned unchanged unless the target says, in PostgREST's own words, that the
// prefix is wrong.
func ResolveRestPrefix(ctx context.Context, c *client.Client) (*client.Client, string, PrefixVerdict) {
	if !invalidPathHere(ctx, c, restRoot(c)) {
		return c, "", PrefixOK
	}
	for _, p := range prefixCandidates {
		alt := c.WithRestPrefix(p)
		if looksLikePostgREST(ctx, alt) {
			return alt, p, PrefixMoved
		}
	}
	return c, "", PrefixWrongAndUnresolved
}

// restRoot is the REST base with exactly one trailing slash.
//
// RestBase()+"/" produced "http://host//" for a client whose prefix is already
// "/", and a doubled slash is a different path: the candidate that would have
// corrected the scan was rejected because the probe asked for a URL PostgREST
// does not serve.
func restRoot(c *client.Client) string {
	return strings.TrimSuffix(c.RestBase(), "/") + "/"
}

// invalidPathHere reports whether PostgREST answered "that is not a path I
// serve" -- which means it is listening and we are asking in the wrong place.
func invalidPathHere(ctx context.Context, c *client.Client, url string) bool {
	r := c.Do(ctx, "GET", url, nil, nil)
	if r.Err != nil || r.Status != 404 {
		return false
	}
	var e struct {
		Code string `json:"code"`
	}
	return json.Unmarshal(r.Body, &e) == nil && e.Code == "PGRST125"
}

// looksLikePostgREST asks the candidate root for the document PostgREST serves
// there. A 200 carrying an OpenAPI/Swagger document is PostgREST introducing
// itself; anything else is not corroboration and is not accepted.
//
// Deliberately not "any 200": an SPA answering index.html for unknown routes
// returns 200 to everything, and adopting a prefix on that basis would point
// the whole scan at a static site.
func looksLikePostgREST(ctx context.Context, c *client.Client) bool {
	r := c.Do(ctx, "GET", restRoot(c), nil, nil)
	if r.Err != nil || r.Status != 200 {
		return false
	}
	var doc struct {
		Swagger string                     `json:"swagger"`
		OpenAPI string                     `json:"openapi"`
		Paths   map[string]json.RawMessage `json:"paths"`
	}
	if json.Unmarshal(r.Body, &doc) != nil {
		return false
	}
	return doc.Swagger != "" || doc.OpenAPI != "" ||
		(len(doc.Paths) > 0 && strings.Contains(string(r.Body), "\"basePath\""))
}
