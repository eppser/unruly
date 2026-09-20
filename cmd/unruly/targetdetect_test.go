package main

import (
	"testing"
)

// The URL an operator typed is offered to the provider registry.
//
// Detections came only from a SITE's bundles, so pointing -u at a backend
// origin identified nothing. Measured against the Neon lab: the run sent 1707
// requests down the PostgREST path, reported twelve info findings, and never
// ran the Neon backend -- because no Detection existed for it to run from.
//
// The detector was taught to read the target last commit; this is the other
// half, and without it that fix changes nothing an operator can see.
func TestTheTargetIsOfferedToTheProviderRegistry(t *testing.T) {
	o := &options{target: "https://ep-x.apirest.eu-west-1.aws.neon.tech/neondb/rest/v1"}
	got := detectionsFromTarget(o)
	if len(got) == 0 {
		t.Fatal("the target was not offered to the registry, so a scan pointed " +
			"straight at a Neon Data API runs no Neon stage at all")
	}
	if got[0].Provider != "neon" {
		t.Errorf("identified %q, want neon", got[0].Provider)
	}
}

// An ordinary target must not be identified as something else.
//
// This runs on every invocation, so a detector that fires loosely here would
// attach a backend to targets that have nothing to do with it -- and the
// provider name feeds the summary an operator keeps.
func TestAnOrdinaryTargetIdentifiesNoBackend(t *testing.T) {
	for _, target := range []string{
		"https://abcdefghijklmnop.supabase.co",
		"https://example.com",
		"https://neon.tech/docs",
		"",
	} {
		if got := detectionsFromTarget(&options{target: target}); len(got) != 0 {
			t.Errorf("target %q was identified as %q; nothing about it says so",
				target, got[0].Provider)
		}
	}
}
