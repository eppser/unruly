package main

import (
	"testing"

	"github.com/eppser/unruly/internal/provider"
)

// The same backend found twice is assessed once.
//
// Detections come from two places now: the URL the operator typed, and the
// bundles discovery read. When an application names the endpoint it talks to
// -- which is the ordinary case -- both produce the SAME detection, and every
// stage behind the seam then runs twice.
//
// Measured against the Neon lab with -stats: neon-escalation spent 1770
// requests where one pass over 867 candidates costs about 868. The report also
// carried the provider's "declared unmeasurable" note five times over. Nothing
// said the work was repeated; the only visible symptom was a number twice as
// large as it should be, on somebody else's server.
func TestTheSameBackendIsAssessedOnce(t *testing.T) {
	d := provider.Detection{
		Provider: "neon",
		Project:  "ep-x.apirest.eu-west-1.aws.neon.tech/neondb",
		Source:   "the target URL",
	}
	// The same backend, found again in a bundle: a different Source and Reason,
	// the same project.
	same := d
	same.Source = "https://app.example.com/assets/index.js"
	same.Reason = "found in a bundle"

	other := provider.Detection{Provider: "pocketbase", Project: "https://pb.example.com"}

	got := dedupeDetections([]provider.Detection{d, same, other, d})
	if len(got) != 2 {
		t.Fatalf("got %d detections, want 2: the same provider and project found more "+
			"than once is one backend, and assessing it twice doubles every request "+
			"the stages behind it send", len(got))
	}
	if got[0].Provider != "neon" || got[1].Provider != "pocketbase" {
		t.Errorf("order changed: %v then %v; the first detection decides which provider "+
			"the summary names, so it must survive deduplication",
			got[0].Provider, got[1].Provider)
	}
	if got[0].Source != "the target URL" {
		t.Errorf("kept the %q detection; the FIRST wins, because the target the operator "+
			"typed outranks one found in a minified file", got[0].Source)
	}
}
