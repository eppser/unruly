package supabase

import (
	"context"
	"strings"
	"testing"

	"github.com/eppser/unruly/internal/preview"
	"github.com/eppser/unruly/internal/subdomain"
	"github.com/eppser/unruly/scan"
)

// Preview deployments are swept because a clean production bundle says nothing
// about a branch build nobody watches. Removing a key from main does not
// revoke it, and a rotated key can keep being served by a preview host.
func TestThePreviewStageAgreesWithTheCodeItReplaced(t *testing.T) {
	opts := preview.Options{Site: "https://app.example.invalid", CurrentKey: "k"}

	pv := preview.Run(context.Background(), opts)
	oldRequests := pv.Requests
	old := pv.Findings

	st := &scan.State{Target: opts.Site}
	if _, err := (scan.Pipeline{PreviewStage{Opts: opts}}).
		Run(context.Background(), st); err != nil {
		t.Fatal(err)
	}
	if len(st.Findings()) != len(old) {
		t.Errorf("reported %d findings, the original reported %d",
			len(st.Findings()), len(old))
	}
	if st.Attributed() != oldRequests {
		t.Errorf("attributed %d, original counted %d", st.Attributed(), oldRequests)
	}
}

// With no site and no explicit hosts there is nothing to sweep, and the stage
// must not invent hostnames to probe. Those requests would go to whoever owns
// the names it guessed.
func TestNoSiteAndNoHostsMeansNoSweep(t *testing.T) {
	st := &scan.State{}
	if _, err := (scan.Pipeline{PreviewStage{Opts: preview.Options{}}}).
		Run(context.Background(), st); err != nil {
		t.Fatal(err)
	}
	if st.Attributed() != 0 || len(st.Findings()) != 0 {
		t.Errorf("swept with nothing to sweep: %d requests", st.Attributed())
	}
}

// Subdomain enumeration REPORTS, it does not scan.
//
// A subdomain of a domain the operator nominated is not automatically theirs:
// status pages and documentation portals commonly point at somebody else's
// infrastructure. This tool scans what it was pointed at, so the stage names
// what resolves and stops there.
func TestSubdomainsAreReportedAndNotScanned(t *testing.T) {
	st := &scan.State{}
	stage := SubdomainStage{Opts: subdomain.Options{
		Domain: "example.invalid", Labels: []string{"api", "staging"}, Concurrency: 2}}
	if _, err := (scan.Pipeline{stage}).Run(context.Background(), st); err != nil {
		t.Fatal(err)
	}
	for _, f := range st.Findings() {
		if !strings.Contains(strings.ToLower(f.Description), "not scanned") &&
			!strings.Contains(strings.ToLower(f.Description), "none were scanned") {
			t.Errorf("a subdomain finding does not say the hosts were left unscanned, "+
				"which is the whole point of reporting rather than probing: %q",
				f.Description)
		}
	}
}

// No domain means nothing to enumerate, rather than enumerating the empty
// string.
func TestNoDomainMeansNoEnumeration(t *testing.T) {
	st := &scan.State{}
	if _, err := (scan.Pipeline{SubdomainStage{Opts: subdomain.Options{Domain: ""}}}).
		Run(context.Background(), st); err != nil {
		t.Fatal(err)
	}
	if len(st.Findings()) != 0 {
		t.Errorf("enumerated with no domain: %+v", st.Findings())
	}
}
