package eval_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// Every finding a reader must ACT on has to appear in the plain-language view.
//
// The capability table held only supabase- ids, so a Firebase project rendered
// no plain section at all -- measured on the lab, where a critical finding was
// present and -plain printed nothing. Somebody given this mode precisely
// because they cannot read the technical output saw silence, which looks
// exactly like a clean project.
//
// One missing entry is a quiet omission, and the next backend would repeat it.
// So the rule is checked rather than remembered: if a check can be emitted at
// high or critical, it either appears in the table or is listed below with the
// reason it is not about data an actor can reach.
func TestPlainModeCoversEverySeriousFinding(t *testing.T) {
	// Findings at high or above that are deliberately NOT in the plain view,
	// each with the reason. Every one of these is about a credential or a
	// disclosure rather than about data somebody can reach right now, and the
	// plain view is organised by actor and verb.
	notAboutReachableData := map[string]string{
		"supabase-service-key-exposed":          "a leaked key, not a reachable table",
		"supabase-management-token-exposed":     "a leaked token, not a reachable table",
		"supabase-db-connection-string-exposed": "a leaked connection string, not a reachable table",
		"supabase-historic-service-key-exposed": "a key found in an archived bundle",
		"supabase-historic-key-not-rotated":     "a key found in an archived bundle",
		"supabase-edge-function-no-jwt":         "a function that runs without a token, not a table of rows",
		"supabase-graphql-rls-bypass":           "the same rows as the REST finding, reached by another route",
		"app-route-auth-inconsistency":          "an application route, above the database this view describes",
		"app-auth-bypass":                       "an application route, above the database this view describes",
		"app-cross-identity-read":               "an application route, above the database this view describes",

		// Residue, and the one exemption that is a genuine trade-off rather
		// than a category error. These describe what THIS SCAN left behind, not
		// what an attacker can reach, and the plain view is organised strictly
		// by actor and verb over the target's data. They are reported in full
		// in the findings, each with the statement that removes it.
		"unruly-probe-row-left-behind":      "this scan's own residue, not the target's exposure",
		"unruly-probe-object-left-behind":   "this scan's own residue, not the target's exposure",
		"unruly-probe-document-left-behind": "this scan's own residue, not the target's exposure",
	}

	mapped := plainMappedIDs(t)
	serious := seriousIDs(t)

	var missing []string
	for id := range serious {
		if mapped[id] {
			continue
		}
		if _, ok := notAboutReachableData[id]; ok {
			continue
		}
		missing = append(missing, id)
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Errorf("these checks can be emitted at high or critical and render NOTHING in "+
			"-plain, so a reader using that mode is told a serious finding does not "+
			"exist:\n  %s\n\nAdd them to the capability table in internal/finding/plain.go, "+
			"or list them in notAboutReachableData with the reason.",
			strings.Join(missing, "\n  "))
	}

	// A stale exemption is how a real gap gets waved through later.
	for id := range notAboutReachableData {
		if !serious[id] {
			t.Errorf("%q is exempted from the plain view but is no longer emitted at "+
				"high or above; drop the exemption", id)
		}
	}
}

// plainMappedIDs reads the capability table's keys.
func plainMappedIDs(t *testing.T) map[string]bool {
	t.Helper()
	path := filepath.Join("..", "finding", "plain.go")
	f, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	out := map[string]bool{}
	ast.Inspect(f, func(n ast.Node) bool {
		kv, ok := n.(*ast.KeyValueExpr)
		if !ok {
			return true
		}
		lit, ok := kv.Key.(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return true
		}
		if v, err := strconv.Unquote(lit.Value); err == nil && strings.Contains(v, "-") {
			out[v] = true
		}
		return true
	})
	return out
}

// seriousIDs is every finding id the code can emit at high or critical.
func seriousIDs(t *testing.T) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	for id, sevs := range severitiesByID(t, filepath.Join("..", "..")) {
		for _, s := range sevs {
			if s == "High" || s == "Critical" {
				out[id] = true
			}
		}
	}
	return out
}
