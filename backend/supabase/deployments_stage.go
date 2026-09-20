package supabase

import (
	"context"

	"github.com/eppser/unruly/internal/finding"
	"github.com/eppser/unruly/internal/preview"
	"github.com/eppser/unruly/internal/subdomain"
	"github.com/eppser/unruly/scan"
)

// PreviewStage sweeps preview and branch deployments of the same application.
//
// Ported from the "// ---- preview deployments ----" section of scanTarget. A
// clean production bundle today says nothing about a branch build nobody
// watches: removing a key from main does not revoke it, and a key rotated in
// production can keep being served by a preview deployment.
type PreviewStage struct {
	Opts preview.Options
}

func (PreviewStage) Name() string { return "preview" }

// Run sweeps the candidate hostnames.
//
// With no site and no explicit hosts there is nothing to sweep, and the stage
// must not invent hostnames: those requests would go to whoever owns the names
// it guessed.
func (p PreviewStage) Run(ctx context.Context, st *scan.State) error {
	if p.Opts.Site == "" && len(p.Opts.Hosts) == 0 {
		return nil
	}
	if len(preview.Candidates(p.Opts.Site, p.Opts.Hosts)) == 0 {
		return nil
	}
	r := preview.Run(ctx, p.Opts)
	scan.Put(st, r)
	st.Note(scan.Info, "%d of %d preview hosts answered, %d serving credentials",
		len(r.Reachable), len(r.Probed), len(r.Findings))
	st.Attribute(p.Name(), r.Requests)
	st.Add(r.Findings...)
	return nil
}

// SubdomainStage names other hosts under the same registrable domain.
//
// Ported from the "// ---- other deployments of the same application ----"
// section. It REPORTS rather than scans, and that is deliberate: a subdomain
// of a domain the operator nominated is not automatically theirs -- status
// pages and documentation portals commonly point at somebody else's
// infrastructure -- and this tool scans what it was pointed at.
// Opts is taken whole, as PreviewStage, HistoryStage and RoutesStage take
// theirs. This stage used to restate the three fields it cared about --
// Domain, Labels, Concurrency -- and the port dropped Timeout on the way
// through, so -timeout stopped binding subdomain enumeration and every lookup
// silently used the package's own 5s default instead. A stage that restates
// its options can forget one; a stage that forwards them cannot.
type SubdomainStage struct {
	Opts subdomain.Options
}

func (SubdomainStage) Name() string { return "subdomains" }

// Run enumerates and reports, never probes.
func (s SubdomainStage) Run(ctx context.Context, st *scan.State) error {
	if s.Opts.Domain == "" {
		return nil
	}
	r := subdomain.Enumerate(ctx, s.Opts)
	scan.Put(st, r)
	if len(r.Hosts) > 0 {
		// "none were scanned" is the load-bearing half. A subdomain of a
		// nominated domain is not automatically the operator's, so this pass
		// reports and stops -- and a list of hosts with no such note reads as
		// a list of hosts that were checked.
		st.Note(scan.Info, "%d of %d candidate host(s) under %s resolve; none were scanned",
			len(r.Hosts), r.Tried, s.Opts.Domain)
	}
	if len(r.Hosts) == 0 {
		return nil
	}
	names := make([]string, 0, len(r.Hosts))
	for _, h := range r.Hosts {
		names = append(names, h.Name)
	}
	st.Add(finding.SubdomainsFound(s.Opts.Domain, names, r.Tried))
	return nil
}
