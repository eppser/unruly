package main

import (
	"slices"
	"strings"
	"testing"
)

func names(o *options, signupOpen bool) []string {
	var out []string
	for _, s := range skippedChecks(o, signupOpen) {
		out = append(out, s.Name)
	}
	return out
}

// Each condition gets a case naming the flag that produces the disclosure and,
// where there is one, the flag that removes it. Presence AND absence: a
// disclosure that fires unconditionally tells the reader nothing.
func TestSkippedChecksPerCondition(t *testing.T) {
	site := "https://app.example"
	for _, tc := range []struct {
		name       string
		o          *options
		signupOpen bool
		want, gone string
	}{
		{name: "-measure cannot tell a readable relation from a filtered one",
			o: &options{measure: true}, want: "graphql"},
		{name: "without -invoke a routine's callability is unknown",
			o: &options{}, want: "routine-callability"},
		{name: "with -invoke it is measured, not skipped",
			o: &options{invoke: true}, gone: "routine-callability"},
		{name: "without -write, anonymous INSERT is untested",
			o: &options{}, want: "write-exposure"},
		{name: "with -write it is tested",
			o: &options{write: true}, gone: "write-exposure"},
		{name: "-no-residue leaves the bucket upload untried",
			o: &options{write: true, noResidue: true}, want: "bucket-write"},
		{name: "no -history means the archives were not searched",
			o: &options{site: site}, want: "historical-credentials"},
		{name: "a withheld key is disclosed, not just logged",
			o: &options{keyWithheldRef: "aaa"}, want: "supplied-credential"},
		{name: "without -user-jwt the authenticated role is unmeasured",
			o: &options{}, want: "role-escalation"},
		{name: "-no-realtime is a check the operator turned off, and it is said so",
			o: &options{skipRealtime: true}, want: "realtime"},
		{name: "-no-routes likewise",
			o: &options{skipRoutes: true, site: site}, want: "application-routes"},

		// Naming no application silences the route check just as thoroughly as
		// turning it off, and used to do it without a word. Same for subdomain
		// enumeration, which is opt-in and said nothing when it was not opted
		// into -- while historical-credentials, opt-in for the same reason,
		// had always been disclosed.
		{name: "no -site means route consistency was never examined",
			o: &options{}, want: "application-routes"},
		{name: "with a site and routes enabled it is examined",
			o: &options{site: site}, gone: "application-routes"},
		{name: "without -subdomains sibling hosts were not enumerated",
			o: &options{site: site}, want: "subdomain-enumeration"},
		{name: "-subdomains without a site has no domain to work from",
			o: &options{subdomains: true}, want: "subdomain-enumeration"},
		{name: "with both, the enumeration runs",
			o: &options{subdomains: true, site: site}, gone: "subdomain-enumeration"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := names(tc.o, tc.signupOpen)
			if tc.want != "" && !slices.Contains(got, tc.want) {
				t.Errorf("%q is missing from %v", tc.want, got)
			}
			if tc.gone != "" && slices.Contains(got, tc.gone) {
				t.Errorf("%q should not be reported skipped: %v", tc.gone, got)
			}
		})
	}
}

// Open signup changes what an unmeasured authenticated role MEANS: the set of
// people who can obtain it becomes everyone.
func TestSkippedChecksSaysWhenAnyoneCanGetTheRole(t *testing.T) {
	reason := func(open bool) string {
		for _, s := range skippedChecks(&options{}, open) {
			if s.Name == "role-escalation" {
				return s.Reason
			}
		}
		return ""
	}
	closed, open := reason(false), reason(true)
	if closed == "" || open == "" {
		t.Fatal("role-escalation is not reported at all")
	}
	if closed == open {
		t.Error("the reason reads the same whether or not anyone can sign up")
	}
	if !strings.Contains(open, "PUBLIC SIGNUP IS OPEN") {
		t.Errorf("open signup must be stated in the reason: %q", open)
	}
}

// ORDER IS THE CONTRACT: this slice feeds finding.Coverage and reports are
// diffed between runs, so eval-determinism requires byte-identical output. A
// membership check would pass while the report churned.
func TestSkippedChecksOrderIsStable(t *testing.T) {
	o := &options{site: "https://app.example", keyWithheldRef: "aaa"}
	first := names(o, true)
	if len(first) == 0 {
		t.Fatal("no skipped checks produced; this test would grade nothing")
	}
	for i := 0; i < 5; i++ {
		again := names(o, true)
		if !slices.Equal(again, first) {
			t.Fatalf("order changed between calls:\n first: %v\n again: %v", first, again)
		}
	}
}

// A check the operator's inputs make impossible must say so, like every other.
//
// The preview-deployment sweep needs a site or explicit hosts, and refuses to
// invent hostnames without them -- rightly, since those requests would go to
// whoever owns the names it guessed. But it returned early in silence, so a
// scan given only a project reference reported nothing about preview
// deployments and looked exactly like a scan that had swept and found none.
//
// historical-credentials is the same shape -- a check that needs an input the
// operator did not supply -- and it has always been disclosed. The difference
// between them was nothing but which one somebody remembered to add to this
// list, which is the argument for the list being checked rather than curated.
func TestPreviewSweepIsDisclosedWhenThereIsNothingToSweep(t *testing.T) {
	got := names(&options{}, false)
	if !slices.Contains(got, "preview-deployments") {
		t.Errorf("no site and no hosts, so the preview sweep cannot run, and the scan "+
			"disclosed %v -- a reader cannot tell that from a sweep that found nothing", got)
	}
	// And when a site IS given it must go quiet: a disclosure that fires
	// unconditionally tells the reader nothing.
	withSite := names(&options{site: "https://app.example"}, false)
	if slices.Contains(withSite, "preview-deployments") {
		t.Errorf("a site was supplied and the sweep still reported itself skipped: %v", withSite)
	}
}
