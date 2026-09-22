package main

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/projectdiscovery/gologger"

	"github.com/eppser/unruly/internal/client"
	"github.com/eppser/unruly/internal/discover"
	"github.com/eppser/unruly/internal/escalate"
	"github.com/eppser/unruly/internal/finding"
	"github.com/eppser/unruly/internal/provider"
)

// An origin the scan can already talk to without discovering one.
//
// The third clause is the load-bearing one. A .supabase.co target deliberately
// does not become the -site, because it is an API rather than an application --
// and before that clause existed it therefore counted as NEITHER, so the most
// natural first invocation there is,
//
//	unruly -u https://<ref>.supabase.co -k <anon key>
//
// fell through to the refusal path and was told to supply -site "(or -target)"
// when -u IS -target and the operator had just supplied it. Empty report, exit
// 3, against a project with seven anonymously readable tables. A target that is
// itself a Supabase URL IS an origin.
func haveOrigin(o *options) bool {
	return o.projectRef != "" || o.baseURL != "" ||
		(o.anonKey != "" && strings.HasPrefix(o.target, "http"))
}

// Whether the discovery pass runs.
//
// Discovery serves two purposes and they were conflated: recovering
// credentials, and reporting what the application leaks about itself. It used
// to run only when a credential or origin was MISSING, so `-p <ref> -k <key>
// -s <site>` produced 13 findings where `-u <site>` produced 14 -- the
// project-ref disclosure was never looked for, and a user got a quieter report
// for being more specific with nothing saying a check had been skipped.
//
// So: whenever a site is known it is inspected for findings; what discovery
// recovers is only ADOPTED as credentials when they are absent.
func shouldDiscover(o *options) bool {
	return o.site != "" || !haveOrigin(o) || o.anonKey == ""
}

// What the discovery pass learned.
//
// These values used to be variables declared before the block and read after
// it, several with comments explaining which later stage had forced them out
// into the enclosing scope. That is the shape the whole
// decomposition is against: state crossing a stage boundary in the open, where
// the only thing tying a producer to its consumer is that they share a
// function body.
type detected struct {
	Findings      []finding.Finding
	Requests      int // discovery proper
	LoginWall     bool
	Declared      string // an API origin the application declared for itself
	DeclaredFrom  string
	Detections    []provider.Detection
	DiscoveredKey string
}

// discovery runs the discovery pass and adopts what it recovers.
//
// It mutates o -- projectRef, anonKey, keyFromEnv, keyDiscovered -- because
// adoption is the point: what discovery finds is only taken up as a credential
// when one is absent, and the adoption rules (chooseKey) are themselves tested
// in isolation. Everything else it learned comes back in the struct.
//
// origin is what haveOrigin reported on the way IN, before any of that
// mutation: the log line asks whether the operator supplied credentials, not
// whether the scan has them now.
func discovery(ctx context.Context, o *options, web *client.Client, limiter *client.Limiter,
	timeout time.Duration, origin bool) (detected, error) {

	var out detected
	if err := cannotStart(o.target, o.site); err != nil {
		return out, err
	}
	gologger.Info().Msgf("%s %s%s", verbFor(origin, o.anonKey), o.site,
		disclosureNote(origin, o.anonKey, o.keyFromEnv))
	var observedDetections []provider.Detection
	d := discover.Run(ctx, discover.Options{
		Web: web,
		// -max-bundles belongs here as much as it does in Harvest below.
		// Without it discovery used its own default of 10, so a scan told to
		// read two bundles read ten: measured 15 fetches across 10 distinct
		// files at -max-bundles 2. The flag is a promise about what this tool
		// does to somebody else's CDN, not a tuning hint, and half of the code
		// that reads bundles never saw it.
		Site: o.site, Limiter: limiter, Timeout: timeout,
		MaxBundles: o.maxBundles, UserAgent: o.userAgent,
		Observe: func(site, where, body string) {
			observedDetections = provider.Merge(observedDetections,
				provider.DetectIn(site, where, body)...)
		},
	})

	out.Requests = d.Requests
	out.LoginWall = d.LoginWall
	out.Declared, out.DeclaredFrom = d.BaseURL, d.BaseURLSource
	out.Findings = append(out.Findings, d.Findings...)

	// Backends other than Supabase, recognised in the same bundles the
	// credential scan just read. Supabase keeps its own pipeline; this is what
	// makes a second provider reachable from the command line rather than only
	// from its tests.
	// The target the operator typed, first, then whatever the bundles named.
	// First because a URL somebody supplied outranks one found in a minified
	// file: it is the thing they asked to be scanned, and it decides which
	// provider the summary names.
	dets := dedupeDetections(append(detectionsFromTarget(o), observedDetections...))

	out.Detections = dets

	if o.projectRef == "" {
		o.projectRef = d.ProjectRef
	}
	out.DiscoveredKey = d.AnonKey

	// A credential recovered from the target beats one inherited from the
	// environment. Measured: with SUPABASE_ANON_KEY exported for project A --
	// which is how anyone who works on a Supabase project has their shell --
	// scanning project B by URL discovered B's ref AND B's key out of its own
	// JavaScript, then aborted because the ambient key belonged to A. The tool
	// refused to use the credential it had just found, in favour of one nobody
	// had pointed at this target.
	//
	// An explicit -k still wins: that one IS an instruction about this target.
	ch := chooseKey(o.anonKey, o.keyFromEnv, d.AnonKey, d.ProjectRef,
		escalate.JWTProjectRef(o.anonKey))
	if ch.Warn != "" {
		gologger.Warning().Msg(ch.Warn)
	}
	o.anonKey, o.keyFromEnv, o.keyDiscovered = ch.Key, ch.FromEnv, ch.Discovered
	if d.ProjectRef != "" {
		gologger.Info().Msgf("project ref %s (via %s)", d.ProjectRef, d.RefSource)
	}
	if d.AnonKey != "" {
		gologger.Info().Msgf("credential recovered from %s", d.KeySource)
	}
	return out, nil
}

// Where the scan points when discovery found no project reference.
//
// A target that is not a managed Supabase project still has an origin: if the
// target is a URL and no reference turned up, the target itself is the API
// origin. That is what makes a list of self-hosted deployments work without a
// per-entry -base-url.
//
// What the application SAYS its backend is beats guessing that the website is
// also the API. The managed product's URL carries the project reference, so
// this never mattered there; self-hosted deployments declare an origin and have
// no reference at all, and guessing pointed the entire scan at the static file
// server -- measured at 16,558 requests, 0 relations, and a report reading
// clean on a project the same scan finds 21 relations in once it is aimed
// correctly. A clean report from the wrong host is the worst output this tool
// can produce, so the declared origin wins.
type originChoice struct {
	BaseURL string // "" leaves the caller's origin alone
	Msg     string
}

func resolveOrigin(projectRef, baseURL, target, declared, declaredFrom string) originChoice {
	if projectRef != "" || baseURL != "" || !strings.HasPrefix(target, "http") {
		return originChoice{}
	}
	if declared != "" {
		return originChoice{BaseURL: declared, Msg: fmt.Sprintf("no project ref, but the "+
			"application declares its API origin as %s (%s); scanning there",
			declared, declaredFrom)}
	}
	u := strings.TrimRight(target, "/")
	return originChoice{BaseURL: u, Msg: fmt.Sprintf("no project ref discovered; treating "+
		"%s as the API origin", u)}
}

// detectionsFromTarget offers the target URL itself to the provider registry.
//
// Detections used to come only from a SITE's bundles, which is the right
// source when the endpoint is a string in somebody's JavaScript and the wrong
// one when the operator typed the endpoint. Pointing -u at a Neon Data API
// identified nothing, so the backend behind it never ran: measured, that scan
// sent 1707 requests down the PostgREST path and reported no Neon finding.
//
// Only the URL is offered. No request is made to discover this -- the string
// the operator supplied is the whole evidence, and each detector decides for
// itself whether it is enough. The detectors that require several signals
// together still require them.
func detectionsFromTarget(o *options) []provider.Detection {
	if o.target == "" {
		return nil
	}
	return provider.Detect(provider.Surface{Site: o.target})
}

// dedupeDetections keeps the first sighting of each backend.
//
// Detections come from two places: the URL the operator typed, and the bundles
// discovery read. When an application names the endpoint it talks to -- the
// ordinary case -- both produce the same backend, and every stage behind the
// seam then runs twice.
//
// Measured against the Neon lab with -stats: neon-escalation spent 1770
// requests where one pass over 867 candidates costs about 868, and the
// provider's "declared unmeasurable" note appeared five times in one report.
// Nothing said the work was repeated. The only visible symptom was a number
// twice the size it should be, on somebody else's server.
//
// FIRST wins, because the target the operator typed outranks one found in a
// minified file, and because the first detection decides which provider the
// summary names.
func dedupeDetections(ds []provider.Detection) []provider.Detection {
	seen := make(map[string]bool, len(ds))
	out := ds[:0:0]
	for _, d := range ds {
		key := d.Provider + "\x00" + d.Project
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, d)
	}
	return out
}

// verbFor says what this pass is doing, which depends on whether a credential
// is already in hand.
func verbFor(origin bool, key string) string {
	if origin && key != "" {
		return "inspecting"
	}
	return "discovering credentials from"
}

// disclosureNote says WHERE the credential came from, when there is one.
//
// The line used to read "(credentials supplied)" for any non-empty key, and a
// field report showed it printed when nothing had been supplied: the key was
// exported for other work and inherited. A reader debugging why a scan
// recovered no credential was told the opposite of what happened.
func disclosureNote(origin bool, key string, fromEnv bool) string {
	switch {
	case !origin || key == "":
		return ""
	case fromEnv:
		return " for disclosure (using SUPABASE_ANON_KEY from the environment)"
	default:
		return " for disclosure (credentials supplied)"
	}
}
