// Package routes checks the application layer for inconsistent authorisation.
//
// Every Supabase scanner surveyed stops at the database. But the database is
// not the only thing holding the anon key: the application's own API routes
// usually hold the service_role key, which bypasses row-level security
// entirely. A route that forgets its auth check is therefore a a wider hole
// than any RLS mistake, and no amount of PostgREST probing will find it.
//
// The signal here is not "this route answered 200" — plenty of routes are
// public by design, and flagging them all would be noise. It is DISAGREEMENT
// WITHIN A FAMILY: sibling routes under a common prefix that mostly demand
// credentials, with one that does not. On the reference target, four of the
// five /api/admin/* routes required a token and /api/admin/logs returned a
// hundred internal pipeline records to an unauthenticated GET.
//
// Expressed as a rule: a family is inconsistent when at least two siblings
// reject anonymous callers and at least one accepts them. That needs no model,
// only a comparison, so it stays deterministic.
package routes

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/eppser/unruly/internal/client"
	"github.com/eppser/unruly/internal/finding"
	"github.com/eppser/unruly/internal/wordlist"
)

// reDynamic spots framework placeholders, which cannot be probed literally.
var reDynamic = regexp.MustCompile(`\[[^\]]+\]|\{[^}]+\}|:[a-zA-Z]+`)

// Route is one probed endpoint.
type Route struct {
	Path string
	// Base is the origin this path was probed against: the site, or a backend
	// the application declared. Without it a finding cannot say WHICH host
	// served the response.
	Base string
	// GET and POST are the observed status codes, 0 when unreachable.
	GET  int
	POST int
	// GETAttempted and POSTAttempted distinguish a request that reached the
	// transport from one the shared circuit breaker refused to send. Status 0
	// alone cannot do that: it also represents a real transport failure.
	GETAttempted  bool
	POSTAttempted bool
	// Snippet and POSTSnippet are short excerpts of the anonymous responses.
	Snippet     string
	POSTSnippet string
	// Size and POSTSize are the corresponding response lengths.
	Size     int
	POSTSize int
}

func (r Route) status(method string) int {
	if method == http.MethodPost {
		return r.POST
	}
	return r.GET
}

func (r Route) response(method string) (string, int) {
	if method == http.MethodPost {
		return r.POSTSnippet, r.POSTSize
	}
	return r.Snippet, r.Size
}

// RequiresAuth reports whether this method rejected an anonymous caller.
func (r Route) RequiresAuth(method string) bool {
	return isAuthReject(r.status(method))
}

// AnonymouslyOpen reports whether this method returned a real answer.
func (r Route) AnonymouslyOpen(method string) bool {
	return r.status(method) == http.StatusOK
}

func isAuthReject(code int) bool {
	return code == http.StatusUnauthorized || code == http.StatusForbidden
}

// Family is a group of sibling routes sharing a parent path.
type Family struct {
	Base      string
	Method    string
	Prefix    string
	Protected []string
	Open      []string
}

// Inconsistent applies the rule: several siblings demand credentials and at
// least one does not. A family where everything is open is a design choice; a
// family where everything is closed is correct. Only disagreement is a bug.
func (f Family) Inconsistent() bool {
	return len(f.Protected) >= 2 && len(f.Open) >= 1
}

// Result is the outcome of a route scan.
type Result struct {
	// Origins are the API hosts the application named in its own bundles, and
	// what was done about each. Reported whether probed or not: a silent
	// decision makes an unscanned backend look like a scanned one.
	Origins []Origin
	// PostProbed records whether POST was used. When false the family
	// comparison saw only GET, and a POST-only route family may look
	// consistent because every sibling answered 405.
	PostProbed bool
	Routes     []Route
	Families   []Family
	Findings   []finding.Finding
	// Requests is the shared client's sent-counter delta for this stage. It
	// includes retries and excludes calls the circuit breaker refused to send.
	Requests int64
}

// ProbedRoutes is the number of route candidates for which the read probe was
// actually attempted. Every route starts with GET, so this is the route-level
// denominator even when POST is enabled too.
func (r Result) ProbedRoutes() int {
	n := 0
	for _, route := range r.Routes {
		if route.GETAttempted {
			n++
		}
	}
	return n
}

// OpenRoutes lists routes in an inconsistent family that answered anonymously.
func (r Result) OpenRoutes() []string {
	var out []string
	for _, f := range r.Families {
		if f.Inconsistent() {
			for _, path := range f.Open {
				out = append(out, f.Method+" "+path)
			}
		}
	}
	sort.Strings(out)
	return out
}

// Options configures the route scan.
type Options struct {
	Site string
	// HARFiles contribute concrete runtime request URLs. Only URL and method
	// are decoded; credentials and bodies are never retained. Cross-origin URLs
	// remain outside scope unless their exact origin is in AllowedOrigins.
	HARFiles []string
	// AllowedOrigins is the exact cross-origin scope the operator authorised.
	// A bundle naming a host proves a relationship, not permission to scan it.
	// The page origin is always in scope.
	AllowedOrigins []string
	// UserAgent identifies the scan to the site. Empty means the build
	// default. This stage reads somebody's WEB server, so it is the traffic a
	// human is most likely to see in a log.
	UserAgent   string
	Concurrency int
	Timeout     time.Duration
	MaxRoutes   int
	// MaxBypassRoutes bounds the expensive alternative-request matrix. It is
	// separate from MaxRoutes because each selected path costs several probes.
	MaxBypassRoutes int
	// MaxBundles is the operator's -max-bundles: how many JavaScript bundles
	// this reader may fetch. Threaded through because it used a hard-coded 40
	// and ignored the flag entirely, so a traffic control somebody set was
	// silently not applied here.
	MaxBundles int
	// Params are values the operator supplied for path templates, so
	// /invoices/{id} can be probed as a record they named. Without them a
	// template is left alone: inventing an identifier means requesting
	// somebody's record on nobody's authority.
	Params Params
	// Principals are labelled identities the operator supplied, so a record
	// one account can read can be asked for as another. Two are needed: with
	// one there is no third answer to compare against and the check cannot be
	// made sound. See crossIdentity.
	Principals []Principal
	// Web, when set, is the scan-wide client for application traffic, and this
	// stage sends everything through it.
	//
	// This package probes the application's own routes -- the largest single
	// source of traffic a scan aims at somebody's web server, measured at
	// roughly ninety requests on a small site. On its own http.Client that
	// traffic had no retry policy, no circuit breaker, and, in probe(), no
	// rate limiting either: fetch() called limiter.Wait and probe() did not,
	// so -rate-limit governed the smaller half of this stage and silently
	// missed the larger one.
	Web *client.Client
	// Limiter is the scan-wide request budget, shared so -rl governs every
	// stage rather than only the PostgREST one.
	Limiter *client.Limiter
	// NoResidue withdraws permission for the POST probe.
	//
	// The body is an empty JSON object, chosen to reach an auth check without
	// constituting a real operation, and against most endpoints that is what
	// happens. It is not a guarantee: an application route whose fields are
	// all optional accepts {} and creates a record, which is the same reason
	// an empty INSERT can land a row. -no-residue asks for certainty, so the
	// probe is declined rather than assumed harmless.
	NoResidue bool
	// AllowPOST permits probing routes with POST.
	//
	// This is a real side-effect risk and it used to run unconditionally. The
	// tool gates a single INSERT into a database behind -write and
	// -yes-i-own-this, while sending POST {} to every route it discovered on
	// somebody's application — /api/subscribe, /api/send-email, /api/orders —
	// with no gate at all. A POST to an unknown endpoint is a write by any
	// reasonable definition.
	//
	// The cost of defaulting it off is honest and specific: many API routes are
	// POST-only and answer 405 to GET, which is not an authorisation signal, so
	// the family comparison sees fewer siblings and can miss an inconsistency.
	// On the reference target the open admin route is only detectable with POST
	// probing enabled. Coverage is traded for not firing unknown side effects
	// at a stranger's application, and the scan says which it chose.
	AllowPOST bool
	// Redact suppresses the response excerpt. The excerpt is the body an
	// unauthenticated caller received, which on the finding that matters most
	// IS production data — the reference target's open admin route returns
	// internal pipeline records. A report shared after -redact must not carry
	// them, and the byte count alone still evidences the exposure.
	Redact bool
}

// runner owns the request client and ledger for one scan. Keeping these on the
// invocation, rather than in package globals, makes two concurrent scans
// independent and lets the race detector enforce that property.
type runner struct {
	web *client.Client
	res *Result
}

func Run(ctx context.Context, o Options) Result {
	if o.Timeout <= 0 {
		o.Timeout = 15 * time.Second
	}
	if o.MaxRoutes <= 0 {
		o.MaxRoutes = 200
	}
	if o.MaxBypassRoutes <= 0 {
		o.MaxBypassRoutes = 20
	}
	if o.MaxBundles <= 0 {
		o.MaxBundles = 40
	}
	if o.Concurrency <= 0 {
		o.Concurrency = client.DefaultConcurrency
	}
	entry := strings.TrimRight(o.Site, "/")
	site := strings.TrimRight(originOf(entry), "/")
	if site == "" {
		return Result{}
	}
	// Defaulted rather than required, so this package's tests keep working --
	// and start grading the path production takes. That matters more here than
	// elsewhere: TestPostProbingIsOptInAndCostsCoverage asserts that no route
	// is POSTed to without -write, and it was asserting it about a code path
	// the binary never ran.
	//
	// The client refuses to follow redirects, which is the policy this package
	// needs and had to set for itself before: a redirect to a login page is an
	// authorisation decision, and following it into a 200 turns "protected"
	// into "anonymous".
	webClient := o.Web
	if webClient == nil {
		webClient = client.NewApplication(client.AppOptions{
			Site: o.Site, Timeout: o.Timeout, Concurrency: o.Concurrency,
			Limiter: o.Limiter, UserAgent: o.UserAgent,
		})
	}
	sentStart, _ := webClient.Stats()
	res := Result{}
	rr := &runner{web: webClient, res: &res}

	o.AllowPOST = o.AllowPOST && !o.NoResidue
	res.PostProbed = o.AllowPOST
	refs, origins := discoverPaths(ctx, entry, site, o.MaxBundles, o.Concurrency, o.Params, rr)
	harRoutes, harOrigins, harErrors := harRefs(o.HARFiles, site)
	for _, ref := range harRoutes {
		refs = appendUniqueRef(refs, ref)
	}
	origins = append(origins, harOrigins...)
	for _, err := range harErrors {
		res.Findings = append(res.Findings,
			finding.NotAssessedStage(entry, "routes:har", err.Error()))
	}
	// An exact -allow-origin is both consent and nomination. Requiring the
	// bundle extractor to rediscover a host the operator explicitly supplied
	// makes the override useless precisely when extraction is incomplete.
	origins = append(origins, o.AllowedOrigins...)
	noteOrigins(&res, origins, o.AllowedOrigins)

	// The site itself, plus every backend the application declared and that is
	// not a vendor's. An application's endpoints usually live on one of those
	// rather than on the page origin -- which is why a scan that only ever
	// asked the site returned nothing on a real target.
	bases := []string{site}
	for _, or := range res.Origins {
		if or.Probed {
			bases = append(bases, or.URL)
		}
	}

	// The application's own published inventory, if it has one.
	//
	// Merged with what the bundles named rather than replacing it: a bundle
	// shows what the front end CALLS, a specification shows what the API
	// OFFERS, and the interesting endpoint is routinely in one and not the
	// other. On the target this was measured against, the endpoint that leaked
	// appeared in both -- but the collection endpoints that correctly refused
	// appeared only in the specification, and they are the controls that make
	// the finding credible.
	allowed := map[string]bool{site: true}
	for _, or := range res.Origins {
		if or.Probed {
			allowed[or.URL] = true
		}
	}
	refs = filterRefs(refs, allowed)
	for _, base := range bases {
		for _, p := range discoverSpecs(ctx, base, rr) {
			// A specification names templates too, and the same rule applies: a
			// value the operator supplied makes the path theirs to probe.
			if reDynamic.MatchString(p) {
				filled, ok := fillTemplate(p, o.Params)
				if !ok {
					continue
				}
				p = filled
			}
			refs = appendUniqueRef(refs, endpointRef{Base: base, Path: p, Source: sourceSpec})
		}
	}

	// Round-robin across origins. A large site inventory must not consume the
	// whole bound before the API origin gets one request.
	targets := fairTargets(refs, o.MaxRoutes)
	if len(targets) < len(refs) {
		res.Findings = append(res.Findings,
			routeBudgetFinding(entry, "application-routes", "-max-routes", len(targets), len(refs)))
	}

	res.Routes = client.Map(ctx, o.Concurrency, targets, func(ctx context.Context, t endpointRef) Route {
		r := Route{Path: t.Path, Base: t.Base}
		r.GET, r.Snippet, r.Size, r.GETAttempted = rr.probe(ctx, http.MethodGet, t.Base+t.Path)
		if o.AllowPOST {
			r.POST, r.POSTSnippet, r.POSTSize, r.POSTAttempted = rr.probe(ctx, http.MethodPost, t.Base+t.Path)
		}
		return r
	})

	// AUTHORISATION BYPASSES, on the endpoints that refused.
	//
	// Only those: a variant of an endpoint that already answers 200 has got
	// past nothing. That also bounds the cost, because on a well-built API
	// most endpoints refuse and on a broken one most do not.
	refusedRoutes := fairRefusedRoutes(res.Routes, o.MaxBypassRoutes)
	refusedTotal := 0
	for _, r := range res.Routes {
		if refused(r.GET) {
			refusedTotal++
		}
	}
	if len(refusedRoutes) < refusedTotal {
		res.Findings = append(res.Findings, routeBudgetFinding(entry,
			"application-bypasses", "-max-bypass-routes", len(refusedRoutes), refusedTotal))
	}
	type soundnessControls struct {
		catchAll probeResult
		root     probeResult
	}
	controls := map[string]soundnessControls{}
	for _, r := range refusedRoutes {
		got := map[string]probeResult{}
		ctrl, ok := controls[r.Base]
		if !ok {
			// These controls describe the origin, not an endpoint. Reusing them is
			// both sounder (every variant gets the same baseline) and much cheaper.
			cc, cb, _ := rr.probeWith(ctx, http.MethodGet,
				r.Base+"/unruly_control_path_that_cannot_exist", "", "")
			rc, rb, _ := rr.probeWith(ctx, http.MethodGet, r.Base+"/", "", "")
			ctrl = soundnessControls{
				catchAll: probeResult{code: cc, body: cb},
				root:     probeResult{code: rc, body: rb},
			}
			controls[r.Base] = ctrl
		}
		got[catchAllControl] = ctrl.catchAll
		for _, v := range bypassVariants(r.Path) {
			m := v.Method
			if m == "" {
				m = http.MethodGet
			}
			code, body, _ := rr.probeWith(ctx, m, r.Base+v.Path, v.Header, v.Value)
			got[v.Name] = probeResult{code: code, body: body}
			// Its own control: the identical request WITHOUT the header. The
			// rewrite variants ask for "/" and name the protected path in a
			// header, and "/" returns the homepage on every ordinary site --
			// so a header that changed nothing would otherwise read as a
			// bypass on every refused endpoint.
			if v.Header != "" {
				switch {
				case m == http.MethodGet && v.Path == "/":
					got[v.Name+" (control)"] = ctrl.root
				case m == http.MethodGet && v.Path == r.Path:
					got[v.Name+" (control)"] = probeResult{code: r.GET, body: r.Snippet}
				default:
					cc, cb, _ := rr.probeWith(ctx, m, r.Base+v.Path, "", "")
					got[v.Name+" (control)"] = probeResult{code: cc, body: cb}
				}
			}
		}
		res.Findings = append(res.Findings,
			bypassFindings(r.Base, r.Path, probeResult{code: r.GET, body: r.Snippet}, got)...)
	}

	// CROSS-IDENTITY READS, when the operator supplied two identities.
	//
	// Only on routes an anonymous caller was refused: if a stranger can read
	// it there is no ownership to break, and asking twice more would spend
	// requests to learn nothing.
	if len(o.Principals) >= 2 {
		a, b := o.Principals[0], o.Principals[1]
		for _, r := range res.Routes {
			if r.GET == 200 {
				continue
			}
			url := r.Base + r.Path
			ac, ab, _ := rr.probeAs(ctx, url, a.Token)
			if ac != 200 {
				continue
			}
			bc, bb, _ := rr.probeAs(ctx, url, b.Token)
			if f, ok := crossIdentity(url,
				probeResult{code: r.GET, body: r.Snippet},
				principalResult{label: a.Label, res: probeResult{code: ac, body: ab}},
				principalResult{label: b.Label, res: probeResult{code: bc, body: bb}}); ok {
				res.Findings = append(res.Findings, f)
			}
		}
	}

	// STANDALONE EXPOSURE, independent of any family.
	//
	// The family check below finds inconsistency, which is a proxy for a
	// missing authorisation check and a good one -- but it assumes an endpoint
	// answering anonymously is fine if its siblings do too, so an API where
	// everything is open scores perfectly consistent. This is the check that
	// sees a lone endpoint handing out data.
	for _, r := range res.Routes {
		if f, ok := standaloneExposure(r, o.Redact); ok {
			res.Findings = append(res.Findings, f)
		}
	}

	res.Families = groupIntoFamilies(res.Routes)
	for _, f := range res.Families {
		if !f.Inconsistent() {
			continue
		}
		for _, open := range f.Open {
			res.Findings = append(res.Findings, inconsistencyFinding(f, open, res.Routes, o.Redact))
		}
	}
	finding.Sort(res.Findings)
	res.Findings = finding.Dedup(res.Findings)
	sentEnd, _ := webClient.Stats()
	res.Requests = sentEnd - sentStart
	return res
}

// reSitemapLoc and reHref find the application's own pages.
var (
	reSitemapLoc = regexp.MustCompile(`<loc>\s*([^<\s]+)\s*</loc>`)
	reHref       = regexp.MustCompile(`href=["'](/[a-zA-Z0-9_\-/]{0,80})["']`)
)

// discoverPaths pulls candidate routes out of the application's own assets.
//
// Crawling matters more than it looks. A framework splits its bundles per
// page, so the JavaScript that calls /api/admin/* is only referenced from
// /admin — fetching the homepage alone finds none of it. On the reference
// target that was the difference between discovering one route and discovering
// the family that actually contained the bug. Pages come from sitemap.xml and
// same-origin links, both of which the application publishes itself.
func discoverPaths(ctx context.Context, entry, site string, maxBundles, conc int, params Params, rr *runner) ([]endpointRef, []string) {
	seen := map[string]endpointRef{}
	origins := map[string]bool{}
	collect := func(body string) {
		// The API origins this bundle names, so the backend an application
		// declares can be reached. Collected alongside the paths because they
		// come from the same read.
		for _, o := range apiOrigins(body, site) {
			origins[o] = true
		}
		// apiPaths, not the old six-prefix pattern. An allowlist of prefixes
		// is a guess about another team's URL design, and this one was wrong
		// in the case that mattered: /system/mode returned a live record to
		// anonymous callers on a real target and scored zero matches.
		for _, ref := range endpointRefs(body, site) {
			p := ref.Path
			// A dynamic segment cannot be probed literally. With a value the
			// operator supplied it becomes a record they named; without one it
			// is left alone, because inventing an identifier means requesting
			// somebody's record on nobody's authority.
			if reDynamic.MatchString(p) {
				if filled, ok := fillTemplate(p, params); ok {
					ref.Path = filled
					seen[ref.Base+"\x00"+filled] = ref
				}
				continue
			}
			seen[ref.Base+"\x00"+p] = ref
		}
	}

	// ANY same-origin script, not four hard-coded directories.
	//
	// This matched only /_next/static, /assets, /static and /js, which covers
	// Next.js and misses much of everything else: Vite emits /index-<hash>.js
	// at the root, Create React App uses /build/, and plenty of applications
	// simply serve /app.js. A bundle outside those four had every route it
	// named missed, and the report read exactly like an application with no
	// API -- "0 routes probed" against a site whose routes were the point.
	//
	// Same-origin only. A CDN's copy of React names no routes belonging to
	// this application, and fetching third-party origins during a scan sends
	// traffic nobody authorised to hosts nobody nominated. Inventorying
	// cross-origin API endpoints is a real gap and a separate change, with its
	// own consent question.
	reAsset := regexp.MustCompile(`["'](/[^"'\s]*\.m?js)(?:\?[^"']*)?["']`)

	home, ok := rr.fetch(ctx, entry)
	if !ok {
		return nil, nil
	}

	// Pages to visit: the homepage, anything in the sitemap, and same-origin
	// links found on the homepage.
	pages := map[string]bool{"/": true}
	if sm, ok := rr.fetch(ctx, site+"/sitemap.xml"); ok {
		for _, m := range reSitemapLoc.FindAllStringSubmatch(sm, -1) {
			if u := strings.TrimPrefix(strings.TrimPrefix(m[1], site), "/"); u != "" {
				pages["/"+strings.TrimRight(u, "/")] = true
			} else {
				pages["/"] = true
			}
		}
	}
	for _, m := range reHref.FindAllStringSubmatch(home, -1) {
		if p := strings.TrimRight(m[1], "/"); p != "" && !strings.Contains(p, ".") {
			pages[p] = true
		}
	}
	// Admin consoles are routinely unlinked and absent from the sitemap, so
	// crawling alone never loads the bundle that names their API routes. The
	// pinned list covers the conventional ones; a 404 costs one request.
	for _, p := range wordlist.Pages() {
		pages[p] = true
	}

	pageList := make([]string, 0, len(pages))
	for p := range pages {
		pageList = append(pageList, p)
	}
	sort.Strings(pageList)
	if len(pageList) > 120 {
		pageList = pageList[:120]
	}

	// Collect each page's HTML and the bundles it references. Per-page code
	// splitting is why this cannot stop at the homepage.
	//
	// Fetched concurrently: most of the pinned page list 404s, and paying a
	// full round trip for each in series dominated total scan time. Results are
	// folded back in input order so discovery stays deterministic.
	bodies := client.Map(ctx, conc, pageList, func(ctx context.Context, p string) string {
		if p == "/" {
			return home
		}
		body, ok := rr.fetch(ctx, site+p)
		if !ok {
			return ""
		}
		return body
	})

	assetSet := map[string]bool{}
	for _, body := range bodies {
		if body == "" {
			continue
		}
		collect(body)
		for _, m := range reAsset.FindAllStringSubmatch(body, -1) {
			assetSet[m[1]] = true
		}
	}

	assets := make([]string, 0, len(assetSet))
	for a := range assetSet {
		assets = append(assets, a)
	}
	sort.Strings(assets)
	// THE OPERATOR'S BOUND, not a hard-coded one.
	//
	// This capped at 40 regardless of -max-bundles, so a traffic control the
	// operator set was ignored by this reader. TestMaxBundlesBoundsEveryBundle-
	// Reader exists for exactly that and passed anyway: the old asset pattern
	// matched only four directories, so its fixture never produced enough
	// bundles to exceed the bound. Widening the pattern revealed the bug -- the
	// test had been green because the input was too small, not because the code
	// was right.
	if maxBundles > 0 && len(assets) > maxBundles {
		assets = assets[:maxBundles]
	}
	for _, js := range client.Map(ctx, conc, assets, func(ctx context.Context, a string) string {
		body, ok := rr.fetch(ctx, site+a)
		if !ok {
			return ""
		}
		return body
	}) {
		collect(js)
	}

	out := make([]endpointRef, 0, len(seen))
	for _, ref := range seen {
		out = append(out, ref)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Base != out[j].Base {
			return out[i].Base < out[j].Base
		}
		return out[i].Path < out[j].Path
	})
	os := make([]string, 0, len(origins))
	for o := range origins {
		os = append(os, o)
	}
	sort.Strings(os)

	return out, os
}

func (rr *runner) fetch(ctx context.Context, url string) (string, bool) {
	r := rr.web.Do(ctx, http.MethodGet, url, nil, nil)
	if r.Err != nil {
		return "", false
	}
	return string(r.Body), true
}

// probe issues one unauthenticated request. POST bodies are an empty JSON
// object: enough to reach an auth check, not enough to constitute a real
// operation.
// probeFull is probe without the evidence truncation.
//
// Used only where the WHOLE body is needed to decide something -- parsing a
// published specification, recognising a documentation UI -- and the body is
// discarded immediately afterwards. probe's 300-byte cap is deliberate and
// stays the default: evidence is stored, diffed and pasted into tickets, so a
// finding should carry enough to be recognisable and no more.
// probeWith is probe with one extra header, for the bypass variants.
func (rr *runner) probeWith(ctx context.Context, method, url, header, value string) (int, string, int) {
	hdr := map[string]string{}
	if header != "" {
		hdr[header] = value
	}
	r := rr.web.Do(ctx, method, url, nil, hdr)
	if r.Err != nil {
		return 0, "", 0
	}
	return r.Status, truncate(strings.TrimSpace(string(r.Body)), 300), len(r.Body)
}

// probeAs issues a GET carrying one identity's bearer token.
func (rr *runner) probeAs(ctx context.Context, url, token string) (int, string, int) {
	return rr.probeWith(ctx, http.MethodGet, url, "Authorization", "Bearer "+token)
}

func (rr *runner) probeFull(ctx context.Context, url string) (int, string, int) {
	r := rr.web.Do(ctx, http.MethodGet, url, nil, nil)
	if r.Err != nil {
		return 0, "", 0
	}
	return r.Status, string(r.Body), len(r.Body)
}

func (rr *runner) probe(ctx context.Context, method, url string) (int, string, int, bool) {
	var payload []byte
	hdr := map[string]string{}
	if method == http.MethodPost {
		payload = []byte(`{}`)
		hdr["Content-Type"] = "application/json"
	}
	r := rr.web.Do(ctx, method, url, payload, hdr)
	attempted := !errors.Is(r.Err, client.ErrRefused)
	if r.Err != nil {
		return 0, "", 0, attempted
	}
	return r.Status, truncate(strings.TrimSpace(string(r.Body)), 300), len(r.Body), attempted
}

// groupIntoFamilies buckets routes by parent path.
func groupIntoFamilies(rs []Route) []Family {
	byPrefix := map[string]*Family{}
	for _, r := range rs {
		i := strings.LastIndex(r.Path, "/")
		if i <= 0 {
			continue
		}
		prefix := r.Path[:i]
		for _, method := range []string{http.MethodGet, http.MethodPost} {
			if r.status(method) == 0 {
				continue
			}
			key := r.Base + "\x00" + method + "\x00" + prefix
			f, ok := byPrefix[key]
			if !ok {
				f = &Family{Base: r.Base, Method: method, Prefix: prefix}
				byPrefix[key] = f
			}
			switch {
			case r.RequiresAuth(method):
				f.Protected = append(f.Protected, r.Path)
			case r.AnonymouslyOpen(method):
				if conventionalPublicPath(r.Path) {
					continue
				}
				f.Open = append(f.Open, r.Path)
			}
		}
	}
	out := make([]Family, 0, len(byPrefix))
	for _, f := range byPrefix {
		sort.Strings(f.Protected)
		sort.Strings(f.Open)
		out = append(out, *f)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Base != out[j].Base {
			return out[i].Base < out[j].Base
		}
		if out[i].Method != out[j].Method {
			return out[i].Method < out[j].Method
		}
		return out[i].Prefix < out[j].Prefix
	})
	return out
}

// conventionalPublicPath identifies endpoints whose job is commonly to be
// public even when their siblings are not. They do not support an
// inconsistency claim by themselves. standaloneExposure still inspects their
// bodies, so a health endpoint leaking a credential or personal data remains
// reportable on direct evidence.
func conventionalPublicPath(path string) bool {
	parts := strings.Split(strings.ToLower(strings.Trim(path, "/")), "/")
	if len(parts) == 0 {
		return false
	}
	switch parts[len(parts)-1] {
	case "health", "healthz", "status", "ping", "ready", "readyz", "live", "livez",
		"version", "metrics", "guide", "docs", "redoc", "swagger", "openapi.json",
		"swagger.json", "api-docs":
		return true
	}
	return false
}

func inconsistencyFinding(f Family, open string, rs []Route, redact bool) finding.Finding {
	method := f.Method
	if method == "" {
		method = http.MethodGet
	}
	var snippet string
	var size int
	var status int
	for _, r := range rs {
		if r.Base == f.Base && r.Path == open {
			snippet, size = r.response(method)
			status = r.status(method)
		}
	}
	if redact {
		snippet = ""
	}
	// A privileged-looking prefix raises severity: these routes typically run
	// with the service_role key, which ignores row-level security entirely.
	sev := finding.Medium
	if looksPrivileged(f.Prefix) {
		sev = finding.High
	}
	return finding.Finding{
		ID:       "app-route-auth-inconsistency",
		Name:     "API route answers anonymously while its siblings require authentication",
		Severity: sev,
		Protocol: "http",
		Matched:  f.Base + open,
		Resource: method + " " + open,
		Description: fmt.Sprintf(
			"%s %s returned data to an unauthenticated request, while %d sibling routes under %s "+
				"reject anonymous callers (%s). Routes in this position usually run with the "+
				"service_role key, which bypasses row-level security entirely, so the gap is "+
				"wider than any RLS misconfiguration. The disagreement between siblings is the "+
				"signal: a route family is either public by design or protected, not both.",
			method, open, len(f.Protected), f.Prefix, strings.Join(f.Protected, ", ")),
		Remediation: fmt.Sprintf(
			`Apply the same authorisation check %s uses to its siblings.

Prefer a shared middleware over a per-route check, so a new route is protected
by default rather than by remembering:

  // middleware.ts
  export const config = { matcher: ["%s/:path*"] }

Then verify no sibling is exempt:
  for r in %s; do curl -s -X %s -o /dev/null -w "$r %%{http_code}\n" "%s$r"; done`,
			f.Prefix, f.Prefix, strings.Join(append(f.Protected, open), " "), method, f.Base),
		Evidence: finding.Evidence{
			Request:  routeReplay(method, f.Base+open),
			Status:   status,
			Response: snippet,
			Reason:   fmt.Sprintf("%d bytes returned anonymously to %s; siblings return 401/403", size, method),
		},
	}
}

func routeReplay(method, url string) string {
	if method == http.MethodPost {
		return fmt.Sprintf("curl -sS -X POST -H 'Content-Type: application/json' --data '{}' '%s'", url)
	}
	return fmt.Sprintf("curl -sS '%s'", url)
}

func filterRefs(refs []endpointRef, allowed map[string]bool) []endpointRef {
	out := make([]endpointRef, 0, len(refs))
	for _, ref := range refs {
		if allowed[ref.Base] {
			out = append(out, ref)
		}
	}
	return out
}

func appendUniqueRef(refs []endpointRef, ref endpointRef) []endpointRef {
	for _, old := range refs {
		if old.Base == ref.Base && old.Path == ref.Path {
			return refs
		}
	}
	return append(refs, ref)
}

// fairTargets selects routes round-robin by origin. A large site inventory
// cannot consume the bound before an explicitly allowed API gets one request.
func fairTargets(refs []endpointRef, max int) []endpointRef {
	byBase := map[string][]endpointRef{}
	var bases []string
	for _, ref := range refs {
		if _, ok := byBase[ref.Base]; !ok {
			bases = append(bases, ref.Base)
		}
		byBase[ref.Base] = appendUniqueRef(byBase[ref.Base], ref)
	}
	sort.Strings(bases)
	for _, base := range bases {
		sort.Slice(byBase[base], func(i, j int) bool {
			return byBase[base][i].Path < byBase[base][j].Path
		})
	}
	var out []endpointRef
	for i := 0; ; i++ {
		added := false
		for _, base := range bases {
			if i >= len(byBase[base]) {
				continue
			}
			out = append(out, byBase[base][i])
			added = true
			if max > 0 && len(out) == max {
				return out
			}
		}
		if !added {
			return out
		}
	}
}

// fairRefusedRoutes applies the expensive bypass matrix round-robin across
// origins. A backend with many protected paths must not starve another backend
// the operator explicitly placed in scope.
func fairRefusedRoutes(routes []Route, max int) []Route {
	byBase := map[string][]Route{}
	var bases []string
	for _, r := range routes {
		if !refused(r.GET) {
			continue
		}
		if _, ok := byBase[r.Base]; !ok {
			bases = append(bases, r.Base)
		}
		byBase[r.Base] = append(byBase[r.Base], r)
	}
	sort.Strings(bases)
	for _, base := range bases {
		sort.Slice(byBase[base], func(i, j int) bool { return byBase[base][i].Path < byBase[base][j].Path })
	}
	var out []Route
	for round := 0; len(out) < max; round++ {
		added := false
		for _, base := range bases {
			if round >= len(byBase[base]) || len(out) >= max {
				continue
			}
			out = append(out, byBase[base][round])
			added = true
		}
		if !added {
			break
		}
	}
	return out
}

var privilegedPrefixes = []string{"admin", "internal", "private", "manage", "ops", "sys", "debug"}

func looksPrivileged(prefix string) bool {
	l := strings.ToLower(prefix)
	for _, p := range privilegedPrefixes {
		if strings.Contains(l, p) {
			return true
		}
	}
	return false
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// containsStr reports whether ss holds want.
func containsStr(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}
