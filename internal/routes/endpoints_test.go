package routes

import (
	"sort"
	"strings"
	"testing"
)

// An application's own API origin, named in its own bundle, is discoverable.
//
// The extractor required a leading "/" and one of six prefixes. Both are wrong
// in the same way: they encode what an application's API looked like in one
// framework, and a real one had neither property. Verified against the actual
// shapes before this was written -- all three returned zero matches:
//
//	const API_BASE="https://api-host.run.app";
//	fetch(API_BASE+"/system/mode")
//	fetch("https://api-host.run.app/system/mode")
//
// A bundle that hands its backend's address to every reader is not being
// subtle. Refusing to read it is not caution, it is blindness: the whole
// endpoint inventory of a real application sat behind exactly that.
func TestAnAbsoluteAPIOriginInABundleIsFound(t *testing.T) {
	for _, tc := range []struct{ name, js string }{
		{"constant then concatenation",
			`const API_BASE="https://api-host.run.app";fetch(API_BASE+"/system/mode");`},
		{"inline absolute", `fetch("https://api-host.run.app/system/mode");`},
		{"axios base", `axios.create({baseURL:"https://api-host.run.app"});`},
		{"env-style constant",
			`const VITE_API_URL="https://api-host.run.app";fetch(VITE_API_URL+"/system/mode");`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := apiOrigins(tc.js, "https://app.example.invalid")
			if !hasOrigin(got, "https://api-host.run.app") {
				t.Errorf("the bundle names its API origin and extraction found %v.\n"+
					"An application that publishes its backend's address to every "+
					"visitor is not hiding it; not reading it is blindness, and a real "+
					"application's entire endpoint inventory sat behind this.", got)
			}
		})
	}
}

// A third-party SCRIPT host is not an API origin.
//
// The distinction the same-origin shortcut got wrong: refusing to FETCH a
// CDN's copy of React is right, and refusing to inventory the application's
// own backend is not the same decision. A script tag names somewhere code came
// FROM; an API constant names somewhere the application SENDS ITS USERS' DATA.
func TestAThirdPartyScriptHostIsNotTreatedAsAnAPIOrigin(t *testing.T) {
	js := `import React from "https://cdn.jsdelivr.net/npm/react@18/index.js";` +
		`const API_BASE="https://api-host.run.app";`
	got := apiOrigins(js, "https://app.example.invalid")

	if hasOrigin(got, "https://cdn.jsdelivr.net") {
		t.Error("a CDN that served a library was treated as the application's API " +
			"origin; probing it sends traffic to a host the operator never nominated " +
			"and tells you nothing about their application")
	}
	if !hasOrigin(got, "https://api-host.run.app") {
		t.Error("excluding the CDN also excluded the real API origin")
	}
}

// PATHS OUTSIDE THE SIX PREFIXES ARE PATHS.
//
// /system/mode returned a live record to anonymous callers on a real target
// and scored zero matches, because the extractor only accepted
// /api|/rest|/graphql|/internal|/admin|/_api. An allowlist of prefixes is a
// guess about somebody else's URL design, and this one was wrong in the case
// that mattered.
func TestPathsOutsideTheKnownPrefixesAreExtracted(t *testing.T) {
	js := `fetch("/system/mode");fetch("/v2/billing/summary");fetch("/health");`
	got := apiPaths(js)

	for _, want := range []string{"/system/mode", "/v2/billing/summary"} {
		if !contains(got, want) {
			t.Errorf("%s was not extracted from %q; got %v.\nA prefix allowlist is a "+
				"guess about another team's URL design, and the endpoint that leaked a "+
				"real record was outside it.", want, js, got)
		}
	}
}

// And the extractor does not turn every string into a candidate.
//
// Dropping the allowlist widens what counts as a path, and the cost of getting
// that wrong is requests sent to a stranger's server for URLs that were never
// endpoints. Static assets, fragments and template placeholders are not
// endpoints.
func TestObviousNonEndpointsAreNotExtracted(t *testing.T) {
	js := `"/logo.svg";"/styles/main.css";"/fonts/inter.woff2";"#/dashboard";` +
		`"/img/hero.png";"//cdn.example.com/x.js";"/api/orders"`
	got := apiPaths(js)

	for _, unwanted := range []string{"/logo.svg", "/styles/main.css",
		"/fonts/inter.woff2", "#/dashboard", "/img/hero.png"} {
		if contains(got, unwanted) {
			t.Errorf("%s was extracted as an endpoint; probing static assets spends "+
				"somebody else's bandwidth on URLs that were never endpoints, and "+
				"noise is what gets a check switched off. Got %v", unwanted, got)
		}
	}
	if !contains(got, "/api/orders") {
		t.Error("filtering the assets also removed a real endpoint")
	}
}

func hasOrigin(os []string, want string) bool {
	for _, o := range os {
		if o == want {
			return true
		}
	}
	return false
}

var _ = sort.Strings
var _ = strings.TrimSpace
