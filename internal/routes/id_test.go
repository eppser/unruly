package routes

import (
	"strings"
	"testing"

	"github.com/eppser/unruly/internal/finding"
)

// This check went unverified for the whole life of the project.
//
// The finding-id audit collected literals matching `"(supabase|unruly)-…"`,
// and this id begins `app-`. So the audit that exists to guarantee every check
// is named by a test could not see this one, and its budget of zero was zero
// out of a set that was quietly one short. It surfaced when a second check —
// that every emitted id is documented — disagreed with the first.
//
// The rule the finding encodes is the interesting part: a family where every
// route is open is a design choice, and one where every route is closed is
// correct. Only DISAGREEMENT between siblings is evidence of a mistake.
func TestInconsistencyFindingID(t *testing.T) {
	f := Family{
		Base:      "https://x.example",
		Prefix:    "/admin",
		Protected: []string{"/admin/users", "/admin/billing"},
		Open:      []string{"/admin/stats"},
	}
	routes := []Route{{Base: "https://x.example", Path: "/admin/stats", GET: 200, Snippet: `{"customers":25}`, Size: 16}}
	got := inconsistencyFinding(f, "/admin/stats", routes, false)

	if got.ID != "app-route-auth-inconsistency" {
		t.Errorf("ID changed to %q; consumers filter on it", got.ID)
	}
	if got.Resource != "GET /admin/stats" {
		t.Errorf("the open route must be the resource, got %q", got.Resource)
	}
	if got.Evidence.Status != 200 {
		t.Errorf("evidence status = %d, want the response that justified the finding", got.Evidence.Status)
	}
	// The siblings ARE the evidence: without naming them the finding is an
	// assertion that a route is open, which is not a defect on its own.
	for _, want := range []string{"/admin/users", "/admin/billing"} {
		if !strings.Contains(got.Description, want) {
			t.Errorf("the protected siblings must be named; %q missing", want)
		}
	}
	// A privileged-looking prefix runs with service_role often enough that it
	// outranks an ordinary one.
	plain := inconsistencyFinding(
		Family{Base: "https://x.example", Prefix: "/api", Protected: []string{"/api/a"}, Open: []string{"/api/b"}},
		"/api/b", nil, false)
	if !(got.Severity > plain.Severity) {
		t.Errorf("an /admin route must outrank a plain one: %s vs %s",
			got.Severity, plain.Severity)
	}
	if got.Severity < finding.Medium {
		t.Errorf("an unauthenticated admin route is not informational, got %s", got.Severity)
	}
}

// The response excerpt is somebody's live data, and -redact exists because
// findings get pasted into tickets.
func TestInconsistencyFindingHonoursRedact(t *testing.T) {
	f := Family{Base: "https://x.example", Prefix: "/admin", Protected: []string{"/admin/users"}, Open: []string{"/admin/stats"}}
	routes := []Route{{Base: "https://x.example", Path: "/admin/stats", GET: 200, Snippet: `{"email":"real@person.example"}`}}
	got := inconsistencyFinding(f, "/admin/stats", routes, true)
	if strings.Contains(got.Evidence.Response, "real@person.example") {
		t.Error("-redact must suppress the captured response body")
	}
	plain := inconsistencyFinding(f, "/admin/stats", routes, false)
	if !strings.Contains(plain.Evidence.Response, "real@person.example") {
		t.Error("without -redact the excerpt is the proof and must be present")
	}
}

func TestInconsistencyFindingUsesTheObservedMethod(t *testing.T) {
	f := Family{Base: "https://x.example", Method: "POST", Prefix: "/admin",
		Protected: []string{"/admin/users", "/admin/billing"}, Open: []string{"/admin/stats"}}
	routes := []Route{{Base: "https://x.example", Path: "/admin/stats",
		GET: 401, POST: 200, Snippet: `{"error":"unauthorised"}`,
		POSTSnippet: `{"records":25}`, POSTSize: 14}}
	got := inconsistencyFinding(f, "/admin/stats", routes, false)
	if got.Resource != "POST /admin/stats" || !strings.Contains(got.Evidence.Request, "-X POST") {
		t.Fatalf("POST finding has the wrong identity or replay: resource=%q request=%q",
			got.Resource, got.Evidence.Request)
	}
	if got.Evidence.Status != 200 {
		t.Errorf("POST evidence status = %d, want the observed POST response", got.Evidence.Status)
	}
	if !strings.Contains(got.Evidence.Response, "records") || strings.Contains(got.Evidence.Response, "unauthorised") {
		t.Fatalf("POST finding used evidence from a different method: %q", got.Evidence.Response)
	}
}
