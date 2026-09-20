package eval_test

import (
	"context"
	"testing"
	"time"

	"github.com/eppser/unruly/internal/finding"
	"github.com/eppser/unruly/internal/probe"
)

// Site content must not be reported like a data leak, and everything that is
// merely SHAPED like site content must still be.
//
// The two errors are not equal: under-reporting a leak is worse than
// over-reporting a page, so the demotion is earned by positive evidence and
// three conditions can each veto it. Every row of the answer key below is one
// of those conditions, and the fixture is fixtures/lab/schema/07_content.sql.
func TestContentIsRatedBelowDataButOnlyWhenItEarnsIt(t *testing.T) {
	_, c := loadFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	names := []string{
		"public_site_content",  // five presentation columns, read-only
		"content_one_column",   // one content column among four
		"content_but_writable", // content-shaped, world-writable
		"content_with_pii",     // content-shaped, one sensitive column
	}
	pr := probe.Run(ctx, c, names, probe.Options{Write: true, SampleRows: 2})
	got := map[string]finding.Finding{}
	for _, f := range pr.Findings("http://127.0.0.1/rest/v1", false) {
		if f.ID == "supabase-anon-read-exposed" {
			got[f.Resource] = f
		}
	}

	for _, tc := range []struct {
		rel  string
		want finding.Severity
		why  string
	}{
		{"public_site_content", finding.Medium,
			"five presentation columns, nothing sensitive, read-only: this is the page"},
		{"content_one_column", finding.High,
			"id+title describes a lookup table as readily as an article; demoting on one " +
				"content column would demote half of every schema"},
		{"content_but_writable", finding.High,
			"changing what a site displays is a finding whether or not the words were " +
				"already public"},
		{"content_with_pii", finding.Critical,
			"a relation carrying anything the sensitive classifier recognises is never " +
				"demoted, whatever else it holds"},
	} {
		f, ok := got[tc.rel]
		if !ok {
			t.Errorf("%s produced no read finding at all", tc.rel)
			continue
		}
		if f.Severity != tc.want {
			t.Errorf("%s is %s, want %s\n  %s\n  reason: %s",
				tc.rel, f.Severity, tc.want, tc.why, f.Evidence.Reason)
		}
	}

	// A demotion has to explain itself, or the reader cannot tell a judgement
	// from a miss, and cannot overrule it when the judgement is wrong.
	if f, ok := got["public_site_content"]; ok {
		if !containsAll(f.Evidence.Reason, "site content", "Confirm") {
			t.Errorf("the demotion does not say why or invite the reader to overrule it: %q",
				f.Evidence.Reason)
		}
	}
}

func containsAll(s string, subs ...string) bool {
	for _, sub := range subs {
		if !contains(s, sub) {
			return false
		}
	}
	return true
}

func contains(s, sub string) bool {
	return len(sub) == 0 || (len(s) >= len(sub) && indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

// Without write probing, nothing may be demoted.
//
// The demotion needs to know the relation is not writable, and without -write
// that was never asked. Demoting anyway is demoting on ignorance -- the exact
// mistake the classifier is built to avoid, made one level up.
//
// This was found by reading the tool's own CSV, not by a test: content_but_
// writable printed medium in a scan without -write while the eval pinned it at
// high, because the eval passes -write and could not see the difference. A
// world-writable page rated medium is the under-report that matters most.
func TestNothingIsDemotedWhenWritesWereNotTested(t *testing.T) {
	_, c := loadFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	// No Write: exactly what a default scan does.
	pr := probe.Run(ctx, c, []string{"public_site_content", "content_but_writable"},
		probe.Options{SampleRows: 2})
	for _, f := range pr.Findings("http://127.0.0.1/rest/v1", false) {
		if f.ID != "supabase-anon-read-exposed" {
			continue
		}
		if f.Severity == finding.Medium {
			t.Errorf("%s was demoted to medium although write access was never tested; "+
				"the demotion requires a write probe that ran and refused", f.Resource)
		}
	}
}
