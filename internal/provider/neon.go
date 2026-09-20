package provider

import (
	"regexp"
	"strings"

	neonstage "github.com/eppser/unruly/backend/neon"
	"github.com/eppser/unruly/scan"
)

func init() { Register(neon{}) }

// neon recognises a Neon Data API endpoint from an application bundle.
//
// Neon has no publishable key to find, so unlike Supabase there is no
// credential to recover and Detection.Credential stays empty. The endpoint URL
// is the whole identification.
//
// The vendor documentation says a request with NO Authorization header maps
// onto the `anonymous` role. Measured against a live Data API on 2026-08-21
// it does not: every table answers 400 "missing authentication credentials"
// identically, including tables the anonymous role holds no GRANT on. That
// uniformity is the important part -- the response carries no information
// about the table, so it is a blind condition, not an anonymous read.
//
// The URL is the evidence, and the product name is not. Matching "neon" in a
// bundle would fire on a dependency list, a blog link or a CSS colour name and
// produce a confident scan of a host nobody owns -- the same trap the
// PocketBase detector documents, where the SDK constructor with an origin is
// required precisely because the product name alone is not a deployment.
//
// Verified shape (neon.com/docs/data-api/get-started, 2026-08-21):
//
//	https://ep-example.apirest.us-east-1.aws.neon.tech/neondb/rest/v1/posts
//	       \_______/ \_____/                          \____/ \______/
//	       endpoint  the marker                       database  PostgREST
//
// Two things distinguish it from an ordinary Neon connection host: the
// `.apirest.` label, and the /rest/v1/ prefix after a DATABASE segment that
// Supabase does not have.
type neon struct{}

func (neon) Name() string { return "neon" }

// neonEndpoint requires all three signals together: the apirest label, the
// neon.tech suffix, and the database segment before /rest/v1/. Any two of them
// without the third is not a Data API endpoint.
var neonEndpoint = regexp.MustCompile(
	`https://([a-z0-9-]+\.apirest\.[a-z0-9.-]+\.neon\.tech)/([A-Za-z0-9_-]+)/rest/v1/`)

func (n neon) Detect(s Surface) (Detection, bool) {
	// The target itself, first. An operator who typed the Data API URL on the
	// command line has supplied stronger evidence than a bundle can carry --
	// nobody types one by accident -- and leaving this case out made the whole
	// backend unreachable from the invocation they would try first.
	//
	// A trailing slash is appended before matching, not made optional in the
	// pattern: the pattern's final "/" is what proves the prefix is a PATH
	// SEGMENT rather than the start of a longer word, and relaxing it would
	// accept hosts this detector exists to refuse.
	if d, ok := n.detectIn(s.Site, strings.TrimSuffix(s.Site, "/")+"/"); ok {
		return d, true
	}
	// Sorted, because detection order feeds report order and eval-determinism
	// grades byte identity.
	for _, name := range sortedKeys(s.Scripts) {
		if d, ok := n.detectIn(name, s.Scripts[name]); ok {
			return d, true
		}
	}
	return n.detectIn(s.Site, s.HTML)
}

func (n neon) detectIn(where, body string) (Detection, bool) {
	ms := neonEndpoint.FindAllStringSubmatch(body, -1)
	if len(ms) == 0 {
		return Detection{}, false
	}
	// Lowest origin rather than first match: a bundle may name several and
	// "whichever the minifier emitted first" is not a stable answer.
	best := ms[0]
	for _, m := range ms[1:] {
		if m[1]+"/"+m[2] < best[1]+"/"+best[2] {
			best = m
		}
	}
	host, database := best[1], best[2]
	return Detection{
		Provider: "neon",
		// The database is what /rest/v1/ actually serves, and two databases on
		// one endpoint are two different surfaces.
		Project: host + "/" + database,
		// Deliberately empty. Neon's anonymous role answers requests with no
		// Authorization header at all, so there is no key to recover and the
		// absence of one is not a gap in detection.
		Credential: "",
		Source:     where,
		Reason: "a Neon Data API endpoint is constructed with database " +
			database + " on " + host,
	}, true
}

// APIBase returns the origin INCLUDING the database segment, so the shared
// client's RestPrefix "/rest/v1/" appends correctly with no Neon-shaped
// special case anywhere in the core.
//
// This is the test the mission set for the abstraction, and it passes at this
// layer: Supabase's origin is https://<ref>.supabase.co and Neon's is
// https://<host>/<database>, and both are just "the thing /rest/v1/ hangs off".
func (neon) APIBase(d Detection) string {
	if d.Provider != "neon" || d.Project == "" {
		return ""
	}
	return "https://" + strings.TrimSuffix(d.Project, "/")
}

// Cannot says which Neon capabilities this scan does not assess.
//
// CapEscalate and CapWrite are no longer listed: backend/neon measures both,
// the write tier only when the operator consents with -write -yes-i-own-this. The detector exists so a report can say "this
// application talks to a Neon Data API endpoint"; nothing here sends a request
// to that endpoint, and an endpoint found in somebody's bundle is not
// permission to probe it -- the same rule that makes a prospect list not an
// authorization.
//
// Without this the scan would be WORSE than silent. providerName feeds the
// summary, so a bare detection would report "neon, 0 names probed": a count
// that measures nothing, in a stored report an operator keeps. Declaring the
// limits is how this project says "could not look" instead of implying
// "looked and found nothing".
//
// These entries come back out one at a time as the stages land, against a Neon
// project whose owner has asked for it.
func (neon) Cannot() map[Capability]string {
	const why = "no Neon assessment has been written yet. This scan recognised the " +
		"Data API endpoint from the application's own bundle and sent nothing to it: " +
		"an endpoint named in somebody's JavaScript is not permission to probe the " +
		"project behind it. "
	return map[Capability]string{
		CapRead: why + "an unauthenticated read is not measurable over HTTP on the " +
			"configuration observed: with no Authorization header every table answers " +
			"400 identically, granted or not, so the response discriminates nothing. " +
			"Whether the `anonymous` role holds a GRANT is visible in the database and " +
			"not through the API, and this scan does not guess from the one to the other",

		CapStorage: why + "Neon has no object storage product in the Data API surface",
		CapExecute: why + "the /rpc surface IS served -- measured 2026-08-22: a POST to " +
			"a routine that cannot exist answers 404 with PostgREST's function-lookup " +
			"error, which only a served RPC route produces. What could not be measured " +
			"is whether anything behind it is callable, and the reason is a property of " +
			"the Data API rather than of the fixture: its schema cache is a SNAPSHOT " +
			"that no operator-accessible action refreshes. A SECURITY DEFINER routine " +
			"was created in public and answered PGRST202 not-in-cache; NOTIFY pgrst, " +
			"'reload schema' -- PostgREST's own documented reload -- changed nothing " +
			"across two minutes of polling, and neither did restarting the compute " +
			"through the Management API, which shows the Data API runs as a separate " +
			"service. A new TABLE behaves the same way, so this is not about functions. " +
			"The consequence reaches past this capability: on Neon a 404 does not mean " +
			"the relation is absent from the database, only that it is absent from the " +
			"cache, so nothing here reads PGRST205 as proof that something does not exist",
		CapRealtime: why + "Neon's Data API has no subscription surface documented",
	}
}

func (neon) Measures() []Capability {
	return []Capability{CapEscalate, CapWrite, CapListing}
}

// Stages is the work a detected Neon Data API contributes.
//
// Order matters and is not alphabetical. Enumeration runs before the probe
// tiers so names volunteered by the API are tested in the same scan through a
// typed artifact rather than merely reported for a second invocation.
//
// EscalationStage is contributed only when there is a credential to escalate
// WITH. Neon has no anonymous tier to compare against, so with no bearer there
// is no second observation to make and a stage that ran anyway would report
// the refusal as though it were a measurement.
func (neon) Stages(d Detection, in scan.Inputs) []scan.Stage {
	// APIBase is origin + database, which is what the shared client hangs
	// RestPrefix off. These stages build their own URLs by appending a table
	// name, so they need the prefix already on it: <origin>/<db>/<table> is a
	// path that does not exist, and a scan asking for it finds nothing and
	// reports the project clean.
	base := APIBase(d)
	if base != "" {
		base += "/rest/v1"
	}
	if base == "" {
		return nil
	}
	// A missing client is NOT a reason to contribute nothing. Returning nil
	// here would make the backend go quiet exactly as it does when there is
	// genuinely nothing to say, and the two are opposite facts. The stage
	// carries the nil and refuses loudly when it runs.
	names := append([]string(nil), in.Seeds...)
	if len(names) == 0 {
		// Nothing to ask for. The hint oracle needs a near miss to hint AT, so
		// with no vocabulary there is no seed to miss with, and inventing names
		// would be traffic against somebody's project for no measurement.
		return nil
	}

	token := in.Bearer
	var stages []scan.Stage
	if token != "" {
		stages = append(stages, neonstage.EnumerateStage{
			Base: base, Seeds: names, Token: token, Client: in.Client,
		})
	}
	stages = append(stages, neonstage.ReachStage{
		Base: base, Tables: names, Token: token, Client: in.Client,
	})
	if token != "" {
		stages = append(stages, neonstage.EscalationStage{
			Base: base, Tables: names, Token: token,
			Redact: in.Redact, Client: in.Client,
		})
	}
	// Last, and only with consent. Last because a row this stage adds would
	// otherwise appear in the reads above and be reported as data the project
	// was already exposing -- the scan finding its own footprint. Gated here as
	// well as inside the stage: the stage's own check is the last line of
	// defence, not the only one.
	if token != "" {
		consent := in.Write && !in.Controls.NoResidue
		stages = append(stages, neonstage.WriteStage{
			Base: base, Tables: names, Token: token,
			Consent: consent, Client: in.Client,
		})
	}
	return stages
}
