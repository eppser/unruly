package probe

import (
	"context"
	"encoding/json"
	"sort"
	"strings"

	"github.com/eppser/unruly/internal/client"
)

// SchemaNames returns the relation names a PostgREST OpenAPI document
// advertises, or nothing when the document is not served.
//
// This tool does not RELY on the OpenAPI root, for a measured reason: on the
// managed product it is service_role-only and answers 401, which is why every
// scanner built around it reports a database with 21 relations as having none.
// That is an argument against depending on it, and it was quietly taken as an
// argument against ever asking.
//
// It is one request, and it is already being made: looksLikePostgREST fetches
// exactly this document to decide whether a candidate mount is PostgREST, and
// then discards the paths. Measured on the corpus project that models an API
// gateway in front of Supabase -- error codes rewritten, hints destroyed, the
// mount moved to /api/db/v2/ -- the document passes through untouched because
// it is a 200, and it names the three readable relations the scan otherwise
// finds none of.
//
// The names are SEEDS, not findings. Every one is probed like any other
// candidate, so a document that lies costs a request and changes no verdict.
// That is the same contract the vocabulary handoff works under.
func SchemaNames(ctx context.Context, c *client.Client) []string {
	r := c.Do(ctx, "GET", restRoot(c), nil, nil)
	if r.Err != nil || r.Status != 200 {
		return nil
	}
	return schemaNamesFrom(r.Body)
}

// schemaNamesFrom is the parsing half, separated so it can be graded without a
// server.
func schemaNamesFrom(body []byte) []string {
	var doc struct {
		Paths map[string]json.RawMessage `json:"paths"`
	}
	if json.Unmarshal(body, &doc) != nil {
		return nil
	}
	var out []string
	for p := range doc.Paths {
		name := strings.TrimPrefix(p, "/")
		switch {
		case name == "":
			// The root path documents the document itself.
			continue
		case strings.HasPrefix(name, "rpc/"):
			// Routines are discovered on their own channel and probed
			// differently -- calling one is not reading a table.
			continue
		case strings.ContainsAny(name, "/{}?&#"):
			// A parameterised or nested path is not a relation name, and it
			// would be pasted into a URL.
			continue
		case !safeRelationName(name):
			continue
		}
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// safeRelationName keeps the same shape the hint oracle accepts: any alphabet,
// no punctuation, and within Postgres's 63-BYTE identifier limit. The document
// is written by the target, so this is the same trust boundary.
func safeRelationName(s string) bool {
	if s == "" || len(s) > 63 {
		return false
	}
	for _, r := range s {
		if r == '_' || r == '$' {
			continue
		}
		if !isLetterOrDigit(r) {
			return false
		}
	}
	return true
}

func isLetterOrDigit(r rune) bool {
	return (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
		(r >= '0' && r <= '9') || r > 127
}
