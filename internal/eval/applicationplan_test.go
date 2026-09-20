package eval

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Application routes are not a Supabase surface.
//
// The routes pass probes the APPLICATION's own endpoints for inconsistent
// authorisation -- a family where /api/orders/1 requires a session and
// /api/orders/2 does not. It has nothing to do with PostgREST, RLS or any
// database. It sat inside supabase.Stages() because that is where the scan
// happened to be built.
//
// The cost is not tidiness. A Firebase project's routes usually run on Cloud
// Run with the service account's own privilege, which is the most valuable
// thing to check on such a target -- and a correctly invoked Firebase-only
// scan never ran the pass at all. Measured on a live target: "no application
// routes assessed", against an application whose routes were the point.
func TestApplicationRoutesAreNotInsideTheSupabasePlan(t *testing.T) {
	sup := read(t, filepath.Join("..", "..", "backend", "supabase", "stages.go"))
	if strings.Contains(sup, "RoutesStage{") {
		t.Error("supabase.Stages() still constructs the application-routes stage, so a " +
			"scan of a project with a different backend -- or none -- never probes the " +
			"application's own endpoints. Route authorisation is a property of the " +
			"application, not of the database behind it.")
	}
}

// And the application plan runs whatever backend was found.
//
// The point of moving it is that it becomes reachable. A plan that exists and
// is only run from the Supabase path would be the same gap with a new address.
func TestTheApplicationPlanIsRunIndependentlyOfTheBackend(t *testing.T) {
	dir := filepath.Join("..", "..", "backend", "application")
	if _, err := os.Stat(dir); err != nil {
		t.Fatalf("no provider-neutral application plan exists: %v", err)
	}
	app := read(t, filepath.Join(dir, "stages.go"))
	if !strings.Contains(app, "RoutesStage") {
		t.Error("the application plan does not include the routes stage")
	}

	// The engine owns the adapter and constructs it independently of the
	// provider list. Discovery is acquisition-only and must not execute it.
	eng := read(t, filepath.Join("..", "..", "internal", "engine", "engine.go"))
	if !strings.Contains(eng, "application.Stages(") ||
		!strings.Contains(eng, "if a := req.Application; a != nil") {
		t.Error("the unified engine does not construct the application workload " +
			"independently of provider selection")
	}
}

func read(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(b)
}
