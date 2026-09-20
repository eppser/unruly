package routes

import (
	"strings"
	"testing"

	"github.com/eppser/unruly/internal/finding"
)

func TestPublicSpecificationsAndDocsAreInventoryNotVulnerabilities(t *testing.T) {
	spec := specFinding("https://api.example/openapi.json",
		`{"openapi":"3.0.0","paths":{"/orders":{"get":{}}}}`)
	docs := docsFinding("https://api.example/docs")
	if spec.Severity != finding.Info || docs.Severity != finding.Info {
		t.Fatalf("intentional public API inventory was rated as a vulnerability: spec=%s docs=%s",
			spec.Severity, docs.Severity)
	}
}

// A published specification is an inventory, and it must be read.
//
// On a real target /openapi.json returned 291 KB naming CRM, candidate,
// invoice, document, credential, financial, user and internal-log endpoints.
// That document is what turned "every collection endpoint answers 401" into a
// targeted hunt -- and it is what made the ONE endpoint that did not answer 401
// findable. Nothing outside the Supabase path looked for it.
func TestOperationsInAPublishedSpecBecomeEndpoints(t *testing.T) {
	spec := `{"openapi":"3.0.0","paths":{
		"/crm/customers":{"get":{"summary":"list"}},
		"/system/mode":{"get":{"summary":"mode"}},
		"/invoices/{id}":{"get":{"summary":"one"}},
		"/webhooks/stripe":{"post":{"summary":"hook"}}
	}}`
	got := specPaths(spec)

	for _, want := range []string{"/crm/customers", "/system/mode"} {
		if !contains(got, want) {
			t.Errorf("%s is named in the specification and was not added to the "+
				"inventory; got %v", want, got)
		}
	}
	// POST-only operations are not GET candidates: probing them with GET
	// proves nothing, and probing them with POST needs write consent.
	if contains(got, "/webhooks/stripe") {
		t.Error("a POST-only operation was added as a GET candidate; a GET against it " +
			"answers 405 and says nothing about authorisation")
	}
	// Templates are RETURNED here and resolved by the caller, which is the
	// only place that knows what the operator supplied with -route-param.
	//
	// This used to assert they were dropped at this layer, and dropping them
	// here discarded every endpoint that takes an identifier -- which on most
	// APIs is where the data is. The guarantee it protected is unchanged and
	// now belongs to the caller: a template is never PROBED literally, which
	// TestATemplateIsNeverProbedLiterally asserts against the scan itself.
	if !contains(got, "/invoices/{id}") {
		t.Error("a templated path was dropped at parse time, so the caller never gets " +
			"the chance to fill it with a value the operator supplied")
	}
}

// A SPEC THAT DECLARES NO SECURITY SCHEME IS NOT A SPEC THAT IS OPEN.
//
// And one that declares a scheme is not a spec that is closed. The document
// says what its authors intended; only a request says what the server does. A
// scanner that skipped probing because a spec declared `security` would be
// reporting the documentation rather than the deployment.
func TestOperationsAreExtractedRegardlessOfDeclaredSecurity(t *testing.T) {
	withScheme := `{"openapi":"3.0.0",
		"security":[{"bearerAuth":[]}],
		"components":{"securitySchemes":{"bearerAuth":{"type":"http","scheme":"bearer"}}},
		"paths":{"/system/mode":{"get":{"summary":"mode"}}}}`

	if got := specPaths(withScheme); !contains(got, "/system/mode") {
		t.Errorf("a spec declaring bearer auth had its operations skipped; got %v.\n"+
			"The document says what its authors intended. Only a request says what the "+
			"server does, and reporting the first as though it were the second is "+
			"reporting the documentation rather than the deployment.", got)
	}
}

// Swagger 2.0 is still everywhere.
func TestSwagger2OperationsAreExtracted(t *testing.T) {
	spec := `{"swagger":"2.0","paths":{"/system/mode":{"get":{"summary":"mode"}}}}`
	if got := specPaths(spec); !contains(got, "/system/mode") {
		t.Errorf("a Swagger 2.0 document was not parsed; got %v", got)
	}
}

// Something that is not a specification is not treated as one.
//
// A single-page application answers 200 with HTML for any path, so /openapi.json
// on such a host returns the index page. Treating that as a spec would report
// every application as publishing one.
func TestAnIndexPageIsNotMistakenForASpecification(t *testing.T) {
	for _, body := range []string{
		`<!doctype html><div id="root"></div>`,
		`{"error":"not found"}`,
		`{"paths":"nonsense"}`,
		``,
	} {
		if got := specPaths(body); len(got) > 0 {
			t.Errorf("%q was parsed as a specification yielding %v; a single-page "+
				"application answers 200 with HTML for every path, and treating that "+
				"as a spec would report every application as publishing one", body, got)
		}
	}
}

var _ = strings.TrimSpace
