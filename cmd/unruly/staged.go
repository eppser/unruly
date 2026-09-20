package main

import (
	"time"

	"github.com/eppser/unruly/internal/client"
	"github.com/eppser/unruly/scan"
)

// seamInputs is what a detected backend is given.
//
// Extracted so the decision can be graded. The alternative -- building the
// struct inline at the one call site -- is how -rate-limit and -timeout each
// came to skip a stage: the wiring was correct in the flag and wrong in the
// hand-off, and nothing looked at the hand-off.
func seamInputs(o *options, seeds []string, c *client.Client) scan.Inputs {
	return seamInputsFrom(o, seeds, nil, suppliedVocabulary(o), c)
}

func seamInputsFrom(o *options, seeds, harvested, supplied []string, c *client.Client) scan.Inputs {
	return scan.Inputs{
		Seeds: seeds,
		SeedSet: scan.SeedSet{Merged: append([]string(nil), seeds...),
			Harvested: append([]string(nil), harvested...),
			Supplied:  append([]string(nil), supplied...)},
		Redact:      o.redact,
		Client:      c,
		Concurrency: o.concurrency,
		Timeout:     time.Duration(o.timeout) * time.Second,
		// Both flags, matching the expression the rest of main uses. -write
		// alone is not consent: the confirmation exists because the first flag
		// is easy to type by habit, and a backend given consent nobody gave
		// would change data on a project nobody agreed to touch.
		Write: o.write && o.confirmOwn,
		Controls: scan.Controls{
			Write: o.write && o.confirmOwn, Invoke: o.invoke,
			NoResidue: o.noResidue, Measure: o.measure,
			SkipRealtime: o.skipRealtime, Subdomains: o.subdomains,
			History: o.checkHistory,
		},
		Limits: scan.Limits{Relations: o.maxRelation, RPC: o.maxRPC,
			Columns: o.maxColProbe, Collections: o.maxCollections,
			SampleRows: o.sampleRows},
		Deployment: scan.Deployment{Site: o.site, ArchiveBase: o.archiveBase,
			PreviewHosts: splitHosts(o.previewHosts), UserAgent: o.userAgent},
		// The same JWT the Supabase path re-reads relations with. A staged
		// backend that never receives it cannot tell an authenticated caller
		// from a stranger -- and on Neon that is the whole measurement, since
		// an unauthenticated request there is refused identically for every
		// name.
		Bearer:     o.userJWT,
		Credential: o.anonKey,
	}
}
