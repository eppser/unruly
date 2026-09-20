package main

import (
	"github.com/eppser/unruly/internal/engine"
	"github.com/eppser/unruly/internal/finding"
)

// emitAll canonicalises the report and writes it.
//
// Sorting and deduplication are not cosmetic here. finding.Sort is the
// canonical order this project grades against -- internal/parity measures
// agreement after it, and eval-determinism grades byte identity of two scans of
// an unchanged target -- and finding.Dedup exists because the same statement
// can be reached twice, from two providers or from a stage that runs per
// schema.
//
// scanTarget has three exits and only one of them did this. The other two --
// a scan that found another backend but no Supabase credential, and one that
// stopped because PostgREST answered PGRST125 and could not be located -- wrote
// findings in the order they happened to be appended, with no dedup. Both
// produce a stored report an operator keeps, and both were the paths a reader
// was least likely to check, because they are the quiet ones.
//
// Returning the canonicalised slice matters: the caller goes on to count it,
// hand it to finishReport and ask CoverageIncomplete about it, and all three
// must see what was actually written rather than what was collected.
func emitAll(w finding.Writers, fs []finding.Finding) ([]finding.Finding, finding.Severity, []string, error) {
	r := engine.Finalize(engine.Report{Findings: fs})
	for _, f := range r.Findings {
		if err := w.Write(f); err != nil {
			return r.Findings, r.Worst, r.Blind, err
		}
	}
	return r.Findings, r.Worst, r.Blind, nil
}
