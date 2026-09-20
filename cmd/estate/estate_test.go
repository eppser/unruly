package main

import (
	"strings"
	"testing"

	"github.com/eppser/unruly/internal/finding"
)

func rel(id, res string, sev finding.Severity, rows int, classes, cols []string) finding.Finding {
	return finding.Finding{
		ID: id, Severity: sev, Resource: res,
		Matched:  "https://aaaaaaaaaaaaaaaaaaaa.supabase.co/rest/v1/" + res,
		Evidence: finding.Evidence{Rows: rows, Classes: classes, Columns: cols},
	}
}

// An estate summary answers three questions across every target at once:
// which classes of data were reached, how much of it, and where it lives.
//
// The numbers must ADD UP ACROSS TARGETS. One project with a leaking
// `customers` table is an incident; four hundred of them is the finding, and a
// summary that reports per-target counts and never totals them leaves the
// reader to do the only arithmetic that matters.
func TestClassesAggregateAcrossTargets(t *testing.T) {
	e := summarizeUnruly([]scanned{
		{Target: "https://a.example", Ref: "aaaaaaaaaaaaaaaaaaaa", Findings: []finding.Finding{
			rel("supabase-anon-read-exposed", "customers", finding.Critical, 25,
				[]string{"pii"}, []string{"email", "full_name"}),
			rel("supabase-anon-read-exposed", "sessions", finding.Critical, 17,
				[]string{"credential"}, []string{"access_token"}),
		}},
		{Target: "https://b.example", Ref: "bbbbbbbbbbbbbbbbbbbb", Findings: []finding.Finding{
			rel("supabase-anon-read-exposed", "customers", finding.High, 400,
				[]string{"pii"}, []string{"email"}),
		}},
	})

	pii := e.ByClass["pii"]
	if pii == nil {
		t.Fatalf("no pii row at all; classes seen: %v", classNames(e))
	}
	if pii.Findings != 2 {
		t.Errorf("pii findings = %d, want 2 (one per target)", pii.Findings)
	}
	if pii.Targets != 2 {
		t.Errorf("pii targets = %d, want 2; the count of AFFECTED PROJECTS is the "+
			"number an owner acts on, and it is not the number of findings", pii.Targets)
	}
	if pii.Rows != 425 {
		t.Errorf("pii rows = %d, want 425 (25 + 400)", pii.Rows)
	}
	if got := e.ByClass["credential"]; got == nil || got.Rows != 17 {
		t.Errorf("credential row wrong: %+v", got)
	}
	if e.Relations != 3 {
		t.Errorf("relations = %d, want 3", e.Relations)
	}
}

// Coverage records are not findings, and not data.
//
// unruly reports what it could not measure as findings in the same stream.
// Counting those as exposures would inflate every total in this report; not
// counting them at all would hide the gaps. They are counted SEPARATELY.
func TestCoverageRecordsAreCountedButNotAsExposure(t *testing.T) {
	e := summarizeUnruly([]scanned{{
		Target: "https://a.example", Ref: "aaaaaaaaaaaaaaaaaaaa",
		Findings: []finding.Finding{
			rel("supabase-anon-read-exposed", "customers", finding.High, 10, []string{"pii"}, nil),
			{ID: "unruly-surface-not-assessed", Severity: finding.Info, Resource: "storage"},
			{ID: "unruly-scan-summary", Severity: finding.Info, Resource: "scan"},
		},
	}})
	if e.Findings != 1 {
		t.Errorf("findings = %d, want 1: coverage records are not exposures", e.Findings)
	}
	if e.CoverageGaps != 2 {
		t.Errorf("coverage gaps = %d, want 2: a surface nobody looked at is a result "+
			"and must survive into the summary", e.CoverageGaps)
	}
}

// REACHABLE is not CAPTURED, and the report must never conflate them.
//
// unruly proves a relation is readable and samples three rows; the row COUNT
// comes from the server. supabomb downloads every row of every accessible
// table onto the operator's disk. Both are worth reporting and they are
// different facts: one is exposure, the other is a copy of the data now
// existing somewhere new.
func TestReachableAndCapturedAreSeparateNumbers(t *testing.T) {
	u := summarizeUnruly([]scanned{{
		Target: "https://a.example", Ref: "aaaaaaaaaaaaaaaaaaaa",
		Findings: []finding.Finding{
			rel("supabase-anon-read-exposed", "customers", finding.High, 400, []string{"pii"}, nil),
		},
	}})
	if u.RowsReachable != 400 {
		t.Errorf("unruly rows reachable = %d, want 400", u.RowsReachable)
	}
	if u.RowsCaptured != 0 {
		t.Errorf("unruly rows captured = %d, want 0: it samples for proof and does "+
			"not download the table", u.RowsCaptured)
	}

	s := summarizeSupabomb([]dumped{{
		Target: "https://a.example", Ref: "aaaaaaaaaaaaaaaaaaaa",
		Tables: map[string][]map[string]any{
			"customers": {{"email": "someone@example.com"}, {"email": "other@example.com"}},
		},
	}})
	if s.RowsCaptured != 2 {
		t.Errorf("supabomb rows captured = %d, want 2", s.RowsCaptured)
	}
}

// What supabomb pulled down is classified with unruly's own classifier.
//
// supabomb reports no data classes at all, so the only way to answer "what
// kind of data was captured" is to look at what it wrote. internal/classify is
// the same code that labels unruly's findings, which is what makes the two
// halves of this report comparable rather than two vocabularies side by side.
//
// The class here is `contact`, and it is the COLUMN NAME that produces it:
// classify.Kinds returns nothing for someone@example.com because the value
// classifier deliberately ignores RFC 2606 reserved domains, which is why this
// fixture cannot exercise the value half at all. That is a known limit of
// testing a data classifier with data that is safe to commit -- against a real
// dump the value half fires -- and it is why both halves are consulted.
func TestCapturedRowsAreClassifiedByValue(t *testing.T) {
	s := summarizeSupabomb([]dumped{{
		Target: "https://a.example", Ref: "aaaaaaaaaaaaaaaaaaaa",
		Tables: map[string][]map[string]any{
			"people": {{"work_email": "someone@example.com"}},
		},
	}})
	if len(s.ByClass) == 0 {
		t.Fatal("no classes at all from a dump containing an email address; the " +
			"classifier was not consulted and the report cannot answer what was taken")
	}
	if s.ByClass["contact"] == nil {
		t.Errorf("an email column in the captured rows produced classes %v, and none "+
			"of them is contact", classNames(s))
	}
}

// Regions come from the owner's account, never from an edge PoP.
//
// Measured on a real project: the API answers behind Cloudflare with
// `cf-ray: ...-FRA` while the project itself is in eu-west-1. A summary that
// read the colo would place Irish data in Germany, on the one table a reader
// consults for exactly that question.
func TestRegionsRollUpAndUnknownIsNotGuessed(t *testing.T) {
	e := summarizeUnruly([]scanned{
		{Target: "https://a.example", Ref: "aaaaaaaaaaaaaaaaaaaa", Region: "eu-west-1",
			Findings: []finding.Finding{
				rel("supabase-anon-read-exposed", "customers", finding.High, 100, []string{"pii"}, nil)}},
		{Target: "https://b.example", Ref: "bbbbbbbbbbbbbbbbbbbb", Region: "eu-west-1",
			Findings: []finding.Finding{
				rel("supabase-anon-read-exposed", "orders", finding.High, 50, nil, nil)}},
		{Target: "https://c.example", Ref: "cccccccccccccccccccc",
			Findings: []finding.Finding{
				rel("supabase-anon-read-exposed", "logs", finding.High, 5, nil, nil)}},
	})

	eu := e.ByRegion["eu-west-1"]
	if eu == nil || eu.Projects != 2 || eu.Rows != 150 {
		t.Fatalf("eu-west-1 rollup wrong: %+v", eu)
	}
	if !contains(eu.Classes, "pii") {
		t.Errorf("eu-west-1 holds a pii finding and its class list is %v; the point of "+
			"this table is which JURISDICTION holds which kind of data", eu.Classes)
	}
	if e.ByRegion["unknown"] == nil {
		t.Error("a project with no region was dropped instead of being reported as " +
			"unknown; an unresolved region is a gap in the answer, not an absence of one")
	}
}

// The summary reports what was found, never what it says.
//
// This is the whole report's safety property: it reads sampled rows and, for
// supabomb, entire dumped tables. A value that survives into the summary turns
// a report an operator forwards into a second copy of the leak.
func TestNoSampledValueReachesTheOutput(t *testing.T) {
	const secret = "hunter2-do-not-print"
	u := summarizeUnruly([]scanned{{
		Target: "https://a.example", Ref: "aaaaaaaaaaaaaaaaaaaa", Region: "eu-west-1",
		Findings: []finding.Finding{{
			ID: "supabase-anon-read-exposed", Severity: finding.Critical, Resource: "sessions",
			Matched: "https://aaaaaaaaaaaaaaaaaaaa.supabase.co/rest/v1/sessions",
			Evidence: finding.Evidence{
				Rows: 3, Classes: []string{"credential"}, Columns: []string{"token"},
				Sample: []map[string]any{{"token": secret}},
			},
		}},
	}})
	if out := render(u); strings.Contains(out, secret) {
		t.Errorf("a sampled value reached the estate summary:\n%s", out)
	}

	s := summarizeSupabomb([]dumped{{
		Target: "https://a.example", Ref: "aaaaaaaaaaaaaaaaaaaa",
		Tables: map[string][]map[string]any{"sessions": {{"token": secret}}},
	}})
	if out := render(s); strings.Contains(out, secret) {
		t.Errorf("a captured value reached the estate summary:\n%s", out)
	}
}

// A thousand targets must render the same way twice.
func TestSummaryIsDeterministic(t *testing.T) {
	var in []scanned
	for i := 0; i < 200; i++ {
		in = append(in, scanned{
			Target: "https://t.example", Ref: "aaaaaaaaaaaaaaaaaaaa", Region: "eu-west-1",
			Findings: []finding.Finding{
				rel("supabase-anon-read-exposed", "customers", finding.High, i,
					[]string{"pii", "credential"}, []string{"email"}),
			},
		})
	}
	if a, b := render(summarizeUnruly(in)), render(summarizeUnruly(in)); a != b {
		t.Error("two renders of the same input differ; map iteration has leaked into " +
			"the output and no two runs of this report can be diffed")
	}
}

func classNames(e Estate) []string {
	var out []string
	for k := range e.ByClass {
		out = append(out, k)
	}
	return out
}

func contains(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}
