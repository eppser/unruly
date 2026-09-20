// Package pocketbase assesses a PocketBase backend.
//
// PocketBase does not speak PostgREST, which is why it is here: it is the
// forcing function that keeps the provider seam honest. Nothing in this
// package may reach for a PostgREST concept, and every rule it encodes was
// measured against a real instance rather than carried over by analogy from
// Supabase. Two of those carried-over assumptions were tried and found wrong,
// and the tests in this package exist to keep them wrong.
//
// The boundary in PocketBase is the per-collection rule set. A rule is one of
// three things, and telling them apart is the whole job:
//
//	null         superuser only     -> 403 "Only superusers can perform this action."
//	""           open to the world  -> the verb actually works
//	expression   e.g. id = @request.auth.id, which behaves as a FILTER
package pocketbase

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/eppser/unruly/internal/client"
)

// absentID is a syntactically valid record id that cannot exist: fifteen
// lowercase characters, matching PocketBase's own ^[a-z0-9]+$ id pattern.
//
// Constant, never random. A probe that varied its id between runs would make
// the replayable request in the evidence differ every scan, and byte-identical
// reports are graded by eval-determinism.
const absentID = "zzzzzzzzzzzzzzz"

// Read is what an anonymous LIST established about one collection.
type Read struct {
	// Reached is true when the collection answered at all. A collection that
	// does not exist is not the same as one that refused, and neither is the
	// same as one that was never asked.
	Reached bool
	// Exposed is true only when ROWS CAME BACK.
	//
	// Not when the status was 200. PocketBase answers 200 with
	// {"items":[],"totalItems":0} whenever an expression rule filters every
	// row away, which the default users collection does on every install. A
	// scanner keying on the status alone reports that collection as leaking on
	// every PocketBase target in the world.
	//
	// This is the PostgREST lesson -- a 200 with content-range */0 is a
	// filtered empty result -- arriving unchanged in a backend that shares no
	// code with it.
	Exposed bool
	// Sample is the evidence: the rows themselves, never a boolean.
	Sample []map[string]any
	Status int
	// Request is the exact call an auditor can replay.
	Request string
}

// ReadState asks a collection for rows as an anonymous caller.
func ReadState(ctx context.Context, c *client.Client, base, collection string) Read {
	return readAs(ctx, c, base, collection, "")
}

// readAs asks as a specific principal. An empty token is the anonymous caller,
// which is what makes the escalation diff a comparison of the SAME question
// asked twice rather than two different questions.
func readAs(ctx context.Context, c *client.Client, base, collection, token string) Read {
	url := fmt.Sprintf("%s/api/collections/%s/records?perPage=3", base, collection)
	r := Read{Request: "curl -sS '" + url + "'"}

	var hdr map[string]string
	if token != "" {
		hdr = map[string]string{"Authorization": token}
	}
	resp := c.Get(ctx, url, hdr)
	if resp.Err != nil {
		return r
	}
	r.Status = resp.Status

	// 404 means the collection is not there. Anything else means it answered.
	r.Reached = resp.Status != http.StatusNotFound
	if resp.Status != http.StatusOK {
		return r
	}

	var body struct {
		Items []map[string]any `json:"items"`
	}
	if err := json.Unmarshal(resp.Body, &body); err != nil {
		return r
	}
	r.Sample = body.Items
	r.Exposed = len(body.Items) > 0
	return r
}

// Verb is what a single non-destructive probe established about one verb.
type Verb struct {
	// Denied is true only on 403, and it is the ONLY conclusion available
	// from a status code. It is a negative, and it is what makes precision
	// possible: a denied verb is one this scan can rule out.
	Denied bool
	// Permitted is never set from a status code.
	//
	// A fake-id verb returns 404 both when the rule is open AND when an
	// expression rule filtered the caller out -- measured byte-identical
	// bodies, "The requested resource wasn't found." in both cases. Proving
	// permission means acting on a REAL record, which is destructive, so it
	// belongs behind -write -yes-i-own-this exactly as on Supabase.
	//
	// The field exists so that the honest answer has somewhere to live, and so
	// a test can assert nothing ever sets it from a code alone.
	Permitted bool
	Status    int
	Request   string
}

// VerbState sends one verb at a record id that cannot exist.
//
// Nothing is modified: the id is absent by construction, so a permissive rule
// finds nothing to act on and a restrictive one refuses before looking.
func VerbState(ctx context.Context, c *client.Client, base, collection, verb string) Verb {
	url := fmt.Sprintf("%s/api/collections/%s/records/%s", base, collection, absentID)
	v := Verb{Request: "curl -sS -X " + verb + " '" + url + "'"}

	resp := c.Do(ctx, verb, url, nil, nil)
	if resp.Err != nil {
		return v
	}
	v.Status = resp.Status
	v.Denied = resp.Status == http.StatusForbidden
	return v
}
