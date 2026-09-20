package eval

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// These are architecture tests, not style tests. Each forbidden call is an
// independent execution path: a provider that reaches one path but not the
// others can be detected, reported or accounted differently. The unified
// engine is real only when the command has one execution entry point.
func TestCommandExecutesScansOnlyThroughTheEngine(t *testing.T) {
	dir := filepath.Join("..", "..", "cmd", "unruly")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	forbidden := regexp.MustCompile(`(?:scan\.Pipeline|provider\.StagesFor|provider\.Assess|application\.Stages|supabase\.Stages)\(`)
	var leaks []string
	engineRuns := 0
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if matches := forbidden.FindAllString(string(b), -1); len(matches) > 0 {
			leaks = append(leaks, e.Name()+": "+strings.Join(matches, ", "))
		}
		engineRuns += strings.Count(string(b), "engine.Run(")
	}
	if len(leaks) > 0 {
		t.Fatalf("cmd/unruly still owns scan execution through %v; parsing and rendering may live in the command, provider planning and stage execution may not", leaks)
	}
	if engineRuns != 1 {
		t.Fatalf("cmd/unruly contains %d engine.Run calls, want one target execution entry point", engineRuns)
	}

	engine := readFile(t, filepath.Join("..", "engine", "engine.go"))
	if !strings.Contains(engine, "func Run(") {
		t.Fatal("internal/engine has no Run entry point")
	}
}

func TestCommandDoesNotOwnLifecycleOrReportSemantics(t *testing.T) {
	dir := filepath.Join("..", "..", "cmd", "unruly")
	forbidden := []string{"provider.PrepareFor(", "intent.Verify(", "finding.CoverageIncomplete("}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		src := readFile(t, filepath.Join(dir, e.Name()))
		for _, call := range forbidden {
			if strings.Contains(src, call) {
				t.Errorf("%s owns %s; lifecycle and report truth belong to internal/engine", e.Name(), call)
			}
		}
	}
}

// Discovery acquires facts. Running a route check or a provider from inside
// it makes the order and accounting depend on how a backend was found.
func TestDiscoveryAcquiresFactsAndExecutesNothing(t *testing.T) {
	src := readFile(t, filepath.Join("..", "..", "cmd", "unruly", "discovery.go"))
	for _, forbidden := range []string{
		"application.Stages(", "assessOtherBackends(", "scan.Pipeline(",
		"provider.Assess(", "provider.StagesFor(",
	} {
		if strings.Contains(src, forbidden) {
			t.Errorf("discovery executes %q; it must return detections and application facts to the engine instead", forbidden)
		}
	}
}

// Backend packages belong behind the registry. An import in cmd means adding
// or changing that backend still requires editing the executable.
func TestCommandImportsNoBackendImplementation(t *testing.T) {
	dir := filepath.Join("..", "..", "cmd", "unruly")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var leaks []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		src := readFile(t, filepath.Join(dir, e.Name()))
		if strings.Contains(src, "github.com/eppser/unruly/backend/") {
			leaks = append(leaks, e.Name())
		}
	}
	if len(leaks) > 0 {
		t.Fatalf("command imports backend implementations in %v; providers must own their plans", leaks)
	}
}
