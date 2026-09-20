package main

import (
	"strings"
	"testing"
)

// The declared API origin must beat the guess.
//
// A self-hosted deployment has no project reference and declares its backend
// origin in its own bundles. Guessing that the website is also the API pointed
// a whole scan at the static file server: 16,558 requests, 0 relations, and a
// report reading clean on a project the same scan finds 21 relations in once it
// is aimed correctly.
//
// A clean report from the wrong host is the worst output this tool can produce,
// because every downstream statement -- exit 0, "no relations exposed" -- is
// true of the host that was scanned and false of the one the operator meant.
func TestResolveOriginPrefersTheDeclaredBackend(t *testing.T) {
	got := resolveOrigin("", "", "https://app.example", "https://api.example", "bundle")
	if got.BaseURL != "https://api.example" {
		t.Fatalf("origin resolved to %q; the application declared https://api.example "+
			"and guessing the website instead is the 16,558-request no-op", got.BaseURL)
	}
	if !strings.Contains(got.Msg, "bundle") {
		t.Errorf("message %q does not say where the declared origin came from; an "+
			"operator cannot check a claim whose source is not named", got.Msg)
	}
}

// With nothing declared, the target itself is the origin -- that is what makes
// a list of self-hosted deployments scannable without a per-entry -base-url.
func TestResolveOriginFallsBackToTheTarget(t *testing.T) {
	got := resolveOrigin("", "", "https://self.example/", "", "")
	if got.BaseURL != "https://self.example" {
		t.Fatalf("origin resolved to %q, want the target with its trailing slash "+
			"trimmed", got.BaseURL)
	}
}

// An origin the operator or discovery already established must not be
// overwritten, and a non-URL target has no origin to take.
func TestResolveOriginLeavesAnEstablishedOriginAlone(t *testing.T) {
	cases := []struct {
		name                        string
		projectRef, baseURL, target string
	}{
		{"managed project has a ref", "abcdefghijklmnopqrst", "", "https://app.example"},
		{"base url already supplied", "", "https://api.example", "https://app.example"},
		{"target is not a URL", "", "", "app.example"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// A declared origin is present precisely to prove it is NOT adopted
			// when an origin already exists.
			got := resolveOrigin(tc.projectRef, tc.baseURL, tc.target, "https://declared.example", "bundle")
			if got.BaseURL != "" {
				t.Errorf("resolved to %q, but an origin was already established; "+
					"overwriting it points the scan somewhere the operator did not ask for",
					got.BaseURL)
			}
		})
	}
}
