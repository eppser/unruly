package routes

import (
	"encoding/json"
	"sort"
	"strings"
)

// Published API specifications, and what they are worth.
//
// On a real target /openapi.json returned 291 KB naming CRM, candidate,
// invoice, document, credential, financial, user and internal-log endpoints.
// That document is what turned "every collection endpoint answers 401" into a
// targeted hunt, and it is what made the one endpoint that did NOT answer 401
// findable at all. Nothing outside the Supabase path looked for it.

// specPathsProbed are the conventional locations. Cheap: each miss is one
// request, and the win is an application's entire endpoint inventory.
var specPathsProbed = []string{
	"/openapi.json", "/swagger.json", "/openapi.yaml", "/swagger.yaml",
	"/api-docs", "/v3/api-docs", "/v2/api-docs", "/.well-known/openapi.json",
	"/api/openapi.json", "/api/swagger.json",
}

// docsPathsProbed are interactive documentation UIs. Reported separately from
// the specification because the remediation differs: a static document can be
// moved behind auth, a mounted UI is usually a framework flag.
var docsPathsProbed = []string{
	"/docs", "/redoc", "/swagger", "/swagger-ui.html", "/swagger-ui/",
	"/api/docs", "/api/redoc", "/documentation",
}

// spec is the part of an OpenAPI or Swagger document this needs.
type spec struct {
	OpenAPI string                    `json:"openapi"`
	Swagger string                    `json:"swagger"`
	Paths   map[string]map[string]any `json:"paths"`
}

// specPaths returns the GET-able, literal paths a specification names.
//
// REGARDLESS OF DECLARED SECURITY. A spec that declares no scheme is not a spec
// that is open, and one that declares bearer auth is not a spec that is closed.
// The document says what its authors intended; only a request says what the
// server does. Skipping the probe because the document claims protection would
// be reporting the documentation rather than the deployment.
func specPaths(body string) []string {
	body = strings.TrimSpace(body)
	if body == "" || !strings.HasPrefix(body, "{") {
		// Not JSON. A single-page application answers 200 with HTML for every
		// path, so /openapi.json on such a host returns the index page, and
		// treating that as a specification would report every application as
		// publishing one.
		return nil
	}
	var s spec
	if err := json.Unmarshal([]byte(body), &s); err != nil {
		return nil
	}
	if s.OpenAPI == "" && s.Swagger == "" {
		// No version marker: some other JSON document that happens to have a
		// `paths` key.
		return nil
	}

	var out []string
	for p, ops := range s.Paths {
		if _, ok := ops["get"]; !ok {
			// POST-only operations are not GET candidates: a GET against one
			// answers 405 and says nothing about authorisation, and probing it
			// with POST needs write consent.
			continue
		}
		// Templates are KEPT here and resolved by the caller, which is the
		// only place that knows what the operator supplied. Dropping them at
		// this layer discarded every endpoint that takes an identifier --
		// which on most APIs is where the data is.
		if notEndpoint(p) {
			continue
		}
		out = append(out, strings.TrimRight(p, "/"))
	}
	sort.Strings(out)
	return out
}

// looksLikeSpec reports whether a body is a usable API specification.
func looksLikeSpec(body string) bool {
	b := strings.TrimSpace(body)
	if !strings.HasPrefix(b, "{") {
		return false
	}
	var s spec
	if err := json.Unmarshal([]byte(b), &s); err != nil {
		return false
	}
	return (s.OpenAPI != "" || s.Swagger != "") && len(s.Paths) > 0
}

// looksLikeDocsUI reports whether a body is an interactive documentation page.
//
// Matched on the markers the generators emit rather than on the path, because
// the path is what was requested and the body is what was served -- and a
// single-page application serves its index for /docs as readily as for
// anything else.
func looksLikeDocsUI(body string) bool {
	low := strings.ToLower(body)
	for _, marker := range []string{
		"swagger-ui", "redoc", "rapidoc", "stoplight-elements",
		"swagger-initializer", "openapi.json", "scalar-api-reference",
	} {
		if strings.Contains(low, marker) {
			return true
		}
	}
	return false
}
