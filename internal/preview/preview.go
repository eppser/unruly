// Package preview looks for credentials on a project's preview deployments.
//
// Requirement five of this project's brief names "historical key exposure
// (Wayback, preview deployments)". The archive half has been implemented since
// early on. This is the other half, and it is a genuinely different channel: a
// preview build is a separate origin, usually with its own environment
// configuration, frequently pointing at the PRODUCTION database, and almost
// never watched. A key rotated in production can keep being served by a branch
// deployment nobody remembers.
//
// WHAT IS AND IS NOT DISCOVERABLE, because the difference decides what this
// package can honestly claim.
//
// Certificate Transparency does not help. Vercel, Netlify and Cloudflare Pages
// all serve preview hosts under their own wildcard certificates, so no
// per-host certificate is ever issued and crt.sh returns nothing. Measured
// against a real target: two names, both wildcards.
//
// Netlify and Cloudflare Pages hostnames ARE derivable, because they embed the
// branch:
//
//	<branch>--<site>.netlify.app
//	deploy-preview-<n>--<site>.netlify.app
//	<branch>.<project>.pages.dev
//
// A pinned branch list and a small range of preview numbers cover the common
// cases deterministically.
//
// Vercel is NOT derivable. Its preview hosts are
// <project>-git-<branch>-<team>.vercel.app, and the team slug cannot be
// guessed from outside. Those have to be supplied by whoever knows them, which
// is why Options takes an explicit host list as well.
package preview

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/eppser/unruly/internal/client"
	"github.com/eppser/unruly/internal/discover"
	"github.com/eppser/unruly/internal/finding"
)

// branches are the names a preview deployment is most often built from.
// Pinned, so a scan is reproducible.
var branches = []string{
	"main", "master", "develop", "development", "dev", "staging", "stage",
	"preview", "next", "beta", "test", "qa", "canary",
}

// deployPreviewRange caps the numbered Netlify pull-request previews probed.
// Small on purpose: these are guesses at somebody's infrastructure, and a
// scanner should not walk a thousand of them to find out.
const deployPreviewRange = 10

// Result is the outcome of the sweep.
type Result struct {
	// Probed is every hostname tried, so a reader can see the search rather
	// than only its hits.
	Probed []string
	// Reachable are the hosts that answered at all.
	Reachable []string
	Findings  []finding.Finding
	Requests  int
}

// Options configures the sweep.
type Options struct {
	// Site is the production site, used to derive candidate hostnames.
	Site string
	// Hosts are additional preview hostnames supplied by the operator. The
	// only way to reach a Vercel preview, whose team slug is not guessable.
	Hosts []string
	// CurrentKey is production's anon key, so a preview serving a DIFFERENT
	// key can be distinguished from one serving the same one.
	CurrentKey string
	Limiter    *client.Limiter
	// Timeout bounds each host fetch. Zero means discover's own default.
	//
	// It was declared and never used: never passed to discover.Run, never set
	// by the caller, so -timeout did not bind this stage at all and every host
	// got a 20-second default. With up to 23 derived hostnames that is seven
	// minutes an operator asked to be shorter. Every other stage was fixed for
	// this when the flag was introduced; this one arrived later and missed it.
	Timeout time.Duration
}

// Candidates derives preview hostnames from a site plus any supplied
// explicitly. Sorted and deduplicated, so two runs probe the same names.
func Candidates(site string, extra []string) []string {
	host := hostOf(site)
	var out []string
	out = append(out, extra...)

	if name, ok := strings.CutSuffix(host, ".netlify.app"); ok {
		for _, b := range branches {
			out = append(out, b+"--"+name+".netlify.app")
		}
		for i := 1; i <= deployPreviewRange; i++ {
			out = append(out, fmt.Sprintf("deploy-preview-%d--%s.netlify.app", i, name))
		}
	}
	if name, ok := strings.CutSuffix(host, ".pages.dev"); ok {
		// A pages.dev host is <something>.<project>.pages.dev or just
		// <project>.pages.dev; take the last label as the project either way.
		parts := strings.Split(name, ".")
		project := parts[len(parts)-1]
		for _, b := range branches {
			out = append(out, b+"."+project+".pages.dev")
		}
	}

	// Never probe the production host itself: it is already scanned, and
	// reporting its key here would double-count what discovery found.
	filtered := out[:0]
	for _, h := range out {
		if h != "" && h != host {
			filtered = append(filtered, h)
		}
	}
	sort.Strings(filtered)
	return dedup(filtered)
}

// Run fetches each candidate and reports credentials found.
func Run(ctx context.Context, o Options) Result {
	res := Result{}
	hosts := Candidates(o.Site, o.Hosts)
	if len(hosts) == 0 {
		return res
	}
	res.Probed = hosts

	for _, h := range hosts {
		d := discover.Run(ctx, discover.Options{
			Site: urlFor(h), Limiter: o.Limiter, Timeout: o.Timeout,
		})
		res.Requests += d.Requests

		// Everything discovery found, not just the anon key.
		//
		// The first version read d.AnonKey and threw d.Findings away. A
		// service_role or sb_secret_ key is NOT assigned to AnonKey — it is
		// turned into a critical supabase-service-key-exposed finding — so a
		// preview host shipping only a secret key hit the "nothing found"
		// branch and vanished, unreported and not even counted as reachable.
		//
		// That is the single most valuable thing this package could find: a
		// forgotten branch deploy still serving a key that bypasses RLS. An
		// audit caught it, and the package's own doc argues hardest for
		// exactly that case.
		if len(d.Findings) > 0 {
			for _, f := range d.Findings {
				f.Matched = urlFor(h)
				f.Resource = h
				f.Description = "On the preview deployment " + h + ": " + f.Description
				res.Findings = append(res.Findings, f)
			}
			res.Reachable = append(res.Reachable, h)
		}
		if d.AnonKey == "" && d.ProjectRef == "" {
			continue
		}
		if len(d.Findings) == 0 {
			res.Reachable = append(res.Reachable, h)
		}
		if d.AnonKey == "" {
			continue
		}
		res.Findings = append(res.Findings, keyFinding(h, d, o.CurrentKey))
	}
	finding.Sort(res.Findings)
	res.Findings = finding.Dedup(res.Findings)
	return res
}

func keyFinding(host string, d discover.Result, current string) finding.Finding {
	same := current != "" && d.AnonKey == current
	sev := finding.Medium
	extra := " The key differs from the one production serves, so it is a credential the " +
		"operator may not know is live — rotating production would not have touched it."
	if same {
		sev = finding.Low
		extra = " It is the same key production serves, so this is an additional " +
			"distribution channel for a credential that was already public rather than a " +
			"second credential."
	}
	return finding.Finding{
		ID:       "supabase-preview-deployment-key",
		Name:     "Preview deployment serves a Supabase credential",
		Severity: sev,
		Protocol: "http",
		Matched:  urlFor(host),
		Resource: host,
		Description: fmt.Sprintf(
			"%s is a preview deployment and serves a Supabase key to anyone who loads it. "+
				"Preview builds usually carry their own environment configuration, commonly "+
				"point at the production database, and are rarely monitored or taken down.%s",
			host, extra),
		Remediation: "Take down preview deployments that are no longer needed, and set " +
			"branch deployments to use a separate Supabase project rather than production. " +
			"If this key is meant to be retired, rotate it and confirm every deployment " +
			"stops serving the old one:\n" +
			"  curl -sS " + urlFor(host) + " | grep -o 'eyJ[A-Za-z0-9_.-]\\{20,\\}'",
		Evidence: finding.Evidence{
			Request: "curl -sS '" + urlFor(host) + "'",
			Reason:  "credential recovered from " + d.KeySource,
		},
	}
}

// urlFor turns a candidate into a URL, honouring a scheme the caller supplied.
//
// The first version always prefixed https://, which is right for every public
// preview platform and wrong for anything else: a host given as
// http://preview.internal was silently requested over TLS and failed. Found by
// writing the first test that actually ran the sweep — the derivation and the
// finding constructor had tests, and the network path had none.
func urlFor(host string) string {
	if strings.HasPrefix(host, "http://") || strings.HasPrefix(host, "https://") {
		return host
	}
	return "https://" + host
}

func hostOf(site string) string {
	h := site
	if i := strings.Index(h, "://"); i >= 0 {
		h = h[i+3:]
	}
	if i := strings.IndexAny(h, "/:"); i >= 0 {
		h = h[:i]
	}
	return strings.ToLower(h)
}

func dedup(xs []string) []string {
	if len(xs) == 0 {
		return nil
	}
	out := xs[:1]
	for _, x := range xs[1:] {
		if x != out[len(out)-1] {
			out = append(out, x)
		}
	}
	return out
}
