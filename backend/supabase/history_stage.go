package supabase

import (
	"context"

	"github.com/eppser/unruly/internal/history"
	"github.com/eppser/unruly/scan"
)

// HistoryStage looks for credentials the application shipped in the past.
//
// Ported from the "// ---- historical exposure ----" section of scanTarget.
// A clean bundle today says nothing about what shipped last quarter, and
// removing a key from a build does not revoke it.
type HistoryStage struct {
	// Opts carries the site, the current key to compare against, the archive
	// to query, and the operator's redaction choice.
	Opts history.Options
}

// Name is stable: it appears in the spend breakdown and in the not-assessed
// finding the pipeline emits if this stage fails.
func (HistoryStage) Name() string { return "history" }

// Run queries the archive and records what it recovered.
//
// The empty-site guard is carried over deliberately. Without it a scan pointed
// at a bare project ref, with no application to look up, would query a public
// archive for the empty string -- traffic sent to a third party to answer a
// question nobody asked.
func (h HistoryStage) Run(ctx context.Context, st *scan.State) error {
	if h.Opts.Site == "" {
		return nil
	}
	// After the guard, deliberately: announcing this above it would tell the
	// operator a check was starting and then silently skip it.
	st.Note(scan.Info, "checking public archives for previously shipped credentials")
	r := history.Run(ctx, h.Opts)
	scan.Put(st, r)
	st.Note(scan.Info, "%d archived captures indexed, %d fetched, %d credentials recovered",
		r.Captures, r.Scanned, len(r.Snapshots))
	st.Attribute(h.Name(), r.Requests)
	st.Add(r.Findings...)
	return nil
}
