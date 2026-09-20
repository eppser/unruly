package provider

import (
	"context"
	"strings"
	"testing"

	"github.com/eppser/unruly/internal/client"
)

// A Firebase scan that found no API key must say which surfaces it skipped.
//
// firestoreFindings, authFindings and remoteConfigFindings each begin
// `if d.Credential == "" { return nil }` and return in silence. A report with
// no Firestore, no Auth and no Remote Config findings reads as three surfaces
// that were checked and found sound.
//
// The guard itself is defensible -- Google's client APIs are keyed, and a scan
// with no key to present has no business guessing one. What is not defensible
// is the silence, and it is expensive here rather than theoretical: MEASURED
// against firebase-lab-000000, a Firestore collection whose rule is
// `allow read: if true` answers 200 WITH DOCUMENTS to a request carrying
// `key=` empty, while a collection that cannot exist answers 403. The rules
// are evaluated whether or not a key is presented, so the surface this returns
// silently from may be wide open and readable by anybody.
//
// That is not an argument for probing without a key -- one project's API-key
// configuration does not generalise, and App Check or key restrictions change
// it. It is an argument for saying so.
func TestAFirebaseScanWithNoCredentialSaysWhatItSkipped(t *testing.T) {
	out := firebase{}.assess(context.Background(),
		Detection{Provider: "firebase", Project: "p", Credential: ""},
		ScanOptions{
			Client:     client.New(client.Options{Timeout: 5e9}),
			Candidates: []string{"users", "orders"},
		})

	var note string
	for _, f := range out {
		if f.ID == "unruly-surface-not-assessed" && strings.Contains(f.Description, "Firestore") {
			note = f.Description
		}
	}
	// Provider must be set or the package-level Assess dispatches to nothing
	// and returns empty -- which the first version of this test read as the
	// disclosure being absent. A test whose input never reaches the code
	// reports a confident failure about code it did not run.
	if note == "" {
		var ids []string
		for _, f := range out {
			ids = append(ids, f.ID)
		}
		t.Fatalf("no API key was recovered, so Firestore, Auth and Remote Config were "+
			"never probed, and the scan reported %v. Three surfaces absent from a report "+
			"read as three surfaces that came back clean.", ids)
	}
	for _, surface := range []string{"Firestore", "Auth", "Remote Config"} {
		if !strings.Contains(note, surface) {
			t.Errorf("the disclosure does not name %s among the surfaces it skipped: %q",
				surface, note)
		}
	}
}

// And a scan that HAS a key must not carry the note: a coverage line on every
// ordinary scan is how a disclosure becomes noise and then gets ignored.
func TestAFirebaseScanWithACredentialCarriesNoSuchNote(t *testing.T) {
	out := firebase{}.assess(context.Background(),
		Detection{Provider: "firebase", Project: "p", Credential: "AIza-not-a-real-key"},
		ScanOptions{
			Client:     client.New(client.Options{Timeout: 2e9}),
			Candidates: []string{"users"},
		})
	for _, f := range out {
		// Matched on the canonical Resource, not on prose. The first version
		// of this looked for "no API key" in the Description, which says "No
		// web API key was recovered" -- so the substring never appeared and
		// the assertion passed against every possible finding.
		// scripts/verify-break.sh caught it: making the disclosure fire
		// unconditionally SURVIVED this test.
		if f.Resource == "firebase:no-credential" {
			t.Errorf("a scan holding a credential reported that it had none: %q", f.Description)
		}
	}
}
