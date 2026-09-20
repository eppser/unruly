package routes

import (
	"context"
	"fmt"

	"github.com/eppser/unruly/internal/finding"
)

// discoverSpecs looks for a published API specification and for interactive
// documentation, on ONE base the scan is already probing.
//
// Bounded and cheap: each miss is one request against a host the scan is
// already talking to, and the win is an application's entire endpoint
// inventory. On a real target this is the step that turned "everything answers
// 401" into a list of names to try.
//
// The caller iterates the bases, so this function owns one origin and the
// budget is accounted per origin rather than hidden inside a loop here.
func discoverSpecs(ctx context.Context, base string, rr *runner) []string {
	var found []string
	for _, p := range specPathsProbed {
		// THE WHOLE DOCUMENT, not probe()'s 300-byte evidence snippet.
		//
		// probe truncates deliberately: a finding should carry enough of a
		// response to be recognisable and no more, because evidence gets
		// stored and pasted into tickets. But a specification is 291 KB on
		// a real target and JSON does not parse from its first 300 bytes,
		// so spec discovery silently found nothing -- measured, by the
		// testbed's spec gap staying open while the docs gap closed.
		//
		// Parsed and DISCARDED. What survives is the list of path names
		// and a count; the document itself is not retained.
		code, body, _ := rr.probeFull(ctx, base+p)
		if code != 200 || !looksLikeSpec(body) {
			continue
		}
		rr.res.Findings = append(rr.res.Findings, specFinding(base+p, body))
		found = append(found, specPaths(body)...)
		// One specification per base is enough: the rest are usually the
		// same document at a second address, and probing on is spending
		// somebody's bandwidth to learn nothing.
		break
	}
	for _, p := range docsPathsProbed {
		code, body, _ := rr.probeFull(ctx, base+p)
		if code != 200 || !looksLikeDocsUI(body) {
			continue
		}
		rr.res.Findings = append(rr.res.Findings, docsFinding(base+p))
		break
	}
	return found
}

// specFinding reports a published specification.
//
// INFO, deliberately. Publishing a specification is not a vulnerability --
// many APIs do it on purpose -- and rating it higher would put an inventory
// disclosure above the exposures this scanner exists to find. Its security
// value is not the finding: it is that every path the document names is added
// to the probe list, where the authorization of each is actually tested.
func specFinding(url, body string) finding.Finding {
	paths := specPaths(body)
	return finding.Finding{
		ID:       "app-openapi-schema-exposed",
		Name:     "The API publishes its own specification to anonymous callers",
		Severity: finding.Info,
		Protocol: "http",
		Matched:  url,
		Resource: "api-specification",
		Description: fmt.Sprintf("%s returns an API specification to a caller with no "+
			"credentials, naming %d GET-able endpoint(s) among others. This is not "+
			"itself an exposure -- many APIs publish a specification deliberately -- "+
			"but it removes the step that costs an attacker the most. Every endpoint "+
			"below was probed because this document named it, and an endpoint nobody "+
			"can name is one nobody attacks by accident.", url, len(paths)),
		Remediation: "-- Decide whether this document is meant to be public. If it is, " +
			"nothing here needs fixing and the endpoints it names are what to review.\n" +
			"-- If it is not, serve it behind the same authentication as the API, or " +
			"disable the generator's public route (FastAPI: openapi_url=None; " +
			"Spring: springdoc.api-docs.enabled=false).",
		Evidence: finding.Evidence{
			Request: "curl -sS " + url,
			Reason:  fmt.Sprintf("200 with no credentials; %d GET operations named", len(paths)),
		},
	}
}

// docsFinding reports an interactive documentation UI.
//
// Also INFO: inventory rather than a vulnerability, unless the operator's
// intent says the console should be private. Reported separately from the
// specification because the control differs -- a static document can be moved
// behind authentication, while a mounted UI is usually one framework flag --
// and one finding covering both would give an operator a single instruction
// that fixes half the problem.
func docsFinding(url string) finding.Finding {
	return finding.Finding{
		ID:       "app-docs-exposed",
		Name:     "Interactive API documentation is served to anonymous callers",
		Severity: finding.Info,
		Protocol: "http",
		Matched:  url,
		Resource: "api-documentation",
		Description: url + " serves an interactive API console to a caller with no " +
			"credentials. Beyond naming the endpoints, these consoles let a visitor " +
			"CALL them from the browser, so a reader who would not have written a " +
			"request by hand can still make one.",
		Remediation: "-- If the documentation is meant to be public this needs no fix.\n" +
			"-- Otherwise disable the UI route or require authentication for it " +
			"(FastAPI: docs_url=None, redoc_url=None; springdoc.swagger-ui.enabled=false).",
		Evidence: finding.Evidence{
			Request: "curl -sS " + url,
			Reason:  "200 with no credentials, and the body carries a documentation-UI marker",
		},
	}
}
