package supabase

import (
	"strings"
	"testing"
)

// A thin vocabulary must be disclosed, and the two ways of being thin must not
// be collapsed.
//
// Enumeration falling back to the pinned wordlist lowers relation recall. If
// the report does not say so, "no relations found" reads as a clean project
// when it is really a short wordlist -- the precise failure this whole tool
// argues other scanners make.
//
// These branches had no unit test at all: NotAssessedApplication was emitted in
// two places in scanTarget and named by no test in the repository, so the only
// thing standing behind the distinction was an end-to-end run that had to
// arrange an unreachable site to reach it.
func TestVocabularyShortfall(t *testing.T) {
	cases := []struct {
		name                      string
		site                      string
		supplied, harvest, source int
		wantWarn, wantReport      bool
		wantIn                    string
	}{
		{"no site but seeds were supplied", "", 12, 0, 0,
			false, false, "plus 12 supplied name(s)"},
		{"no site and nothing supplied", "", 0, 0, 0,
			true, false, "cannot reach domain-specific relation names"},
		{"site unreachable", "https://x", 0, 0, 0,
			true, true, "could not be read"},
		{"site read but vocabulary empty", "https://x", 0, 0, 3,
			true, true, "harvested no usable vocabulary"},
		{"vocabulary is fine", "https://x", 0, 40, 3,
			false, false, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			n := vocabularyShortfall(tc.site, tc.supplied, tc.harvest, tc.source)
			if tc.wantIn == "" {
				if n.Msg != "" || n.Report != nil {
					t.Fatalf("a healthy vocabulary produced %q / report=%v; saying "+
						"nothing is the whole point of the last branch", n.Msg, n.Report != nil)
				}
				return
			}
			if !strings.Contains(n.Msg, tc.wantIn) {
				t.Errorf("message %q does not contain %q", n.Msg, tc.wantIn)
			}
			if n.Warn != tc.wantWarn {
				t.Errorf("warn=%v, want %v. Supplied seeds are not a fallback and must "+
					"not be reported as one; a real fallback must not be whispered.",
					n.Warn, tc.wantWarn)
			}
			if (n.Report != nil) != tc.wantReport {
				t.Fatalf("report emitted=%v, want %v. A vocabulary shortfall the report "+
					"does not record is a recall limit the reader never learns about.",
					n.Report != nil, tc.wantReport)
			}
		})
	}
}

// The two exhausted-vocabulary branches describe different worlds.
//
// "no response from the application" is an outage. "N source(s) read, no usable
// vocabulary in them" is a measurement: the site answered and had nothing
// useful in it. Collapsing them sends an operator to debug a network problem
// they do not have -- so the detail each records must differ, and must carry
// the source count that distinguishes them.
func TestVocabularyShortfallSeparatesOutageFromEmptyResult(t *testing.T) {
	outage := vocabularyShortfall("https://x", 0, 0, 0)
	empty := vocabularyShortfall("https://x", 0, 0, 7)

	if outage.Report == nil || empty.Report == nil {
		t.Fatal("both exhausted-vocabulary branches must record a finding")
	}
	od, ed := outage.Report.Description, empty.Report.Description
	if od == ed {
		t.Fatalf("both branches record the same detail %q, so the report cannot "+
			"tell an unreachable site from one that answered with nothing", od)
	}
	if !strings.Contains(ed, "7") {
		t.Errorf("the empty-result detail %q drops the source count, which is the "+
			"evidence that the site was actually read", ed)
	}
	if strings.Contains(od, "7") {
		t.Errorf("the outage detail %q cites a source count, but nothing was read", od)
	}
}
