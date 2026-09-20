// Package enumerate recovers relation names from a Supabase project.
//
// The obvious route is gone: PostgREST's OpenAPI root (/rest/v1/) is now
// service_role-only and answers 401 to an anon key. Five of the eight scanners
// surveyed enumerate exclusively from that spec and return an empty result
// with no warning, which is why they report vulnerable databases as clean.
//
// unruly uses two deterministic sources instead:
//
//  1. Vocabulary harvested from the target application itself. JSON keys from
//     public API routes mirror column names, and column names strongly predict
//     relation names. Generic wordlists cannot do this: a 90-entry SaaS list
//     matched 1 of 21 relations on the reference target, because real schemas
//     are domain-specific (signatory_submissions, zero_day_series).
//
//  2. PostgREST's own fuzzy-match hint. A near-miss relation name returns
//     "Perhaps you meant the table 'public.X'", volunteering a real name. The
//     seeds must be word-like: 2-gram seeds recovered 2 relations, while
//     app-derived vocabulary recovered all 21.
package enumerate

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/eppser/unruly/internal/assets"
	"github.com/eppser/unruly/internal/client"
	"github.com/eppser/unruly/internal/finding"
	"github.com/eppser/unruly/internal/sample"
)

var (
	// Word-like tokens only. The oracle matches on similarity, so fragments
	// such as "ab" never clear the threshold.
	// Every alphabet, not one. The previous class was [a-z][a-z0-9_]{2,40},
	// and measured against the benchmark corpus that scored 7% relation recall
	// on a schema whose names are Japanese, Spanish, German and Cyrillic --
	// one relation of fourteen, against 62% to 100% everywhere else. A table
	// called 顧客 contains no character the old class could match, so the
	// application's own bundle named it on every line and yielded no seed.
	reWord = regexp.MustCompile(`[\p{L}][\p{L}\p{N}_]{1,40}`)
)

// stopWords are tokens that appear in every web application and never name a
// relation. Pinned here so vocabulary extraction is reproducible.
var stopWords = map[string]bool{}

func init() {
	for _, w := range strings.Fields(`
		the and for with that this from https http www com org net div span class
		function return var let const null true false undefined object string
		number window document react next node type name value data props
		children style width height color href src alt rel meta link script
		head body html title button input form label section article header
		footer main nav aside svg path fill stroke viewbox xmlns href target
		blank noopener noreferrer charset utf viewport initial scale content
		default export import module require async await promise catch throw
		error console error warn info debug push pop shift slice splice map
		filter reduce foreach length index key ref use state effect memo
		callback context provider consumer fragment component element render
		className onclick onchange onsubmit placeholder disabled readonly
		checked selected hidden required min max step pattern autocomplete`) {
		stopWords[w] = true
	}
}

// Vocabulary is a deterministic, sorted set of candidate names.
type Vocabulary struct {
	Seeds   []string
	Sources []string // which URLs contributed, for reproducibility
	// BundlesFound is how many JS bundles the page referenced; BundlesRead is
	// how many MaxBundles allowed. Unread bundles lower the vocabulary before
	// it is even assembled, so a cap here is upstream of the seed cap.
	BundlesFound int
	BundlesRead  int
	// PagesFound is how many same-origin links the pages referenced;
	// PagesRead is how many were actually read, which is smaller when
	// MaxPages binds.
	PagesFound int
	PagesRead  int
	// Harvested is how many distinct tokens the application yielded, before
	// MaxSeeds was applied. When it exceeds len(Seeds) the vocabulary was
	// truncated, and everything downstream is a lower bound BECAUSE OF THIS,
	// not because the target had nothing more to show.
	Harvested int
}

// HarvestOptions configures vocabulary extraction.
type HarvestOptions struct {
	Site string
	// Paths are additional application routes to read. JSON endpoints are the
	// highest-signal source because their keys mirror column names.
	Paths   []string
	Timeout time.Duration
	// MaxBundles caps how many JS assets are fetched, bounding scan time.
	MaxBundles int
	// MaxPages caps how many LINKED pages are read beyond the conventional
	// list. Zero disables crawling entirely, which is the previous behaviour.
	//
	// Bounded because this is traffic to somebody's web server, and a crawl
	// that follows every link on a paginated site is unbounded in a way the
	// operator did not ask for.
	MaxPages int
	// MaxSeeds caps the seed list. Sorted first, so truncation is stable.
	MaxSeeds int
	// Web, when set, is the scan-wide client for application traffic. Nil
	// keeps this package's own client, which its tests rely on.
	//
	// This stage reads a site's HTML and its JS bundles. On its own client
	// that meant no backoff when the site said 429 and no breaker when it
	// said it repeatedly -- the two things the backend path does carefully.
	Web *client.Client
	// UserAgent identifies the scan to the site whose bundles this reads.
	// Empty means the build default. See the note in internal/discover: this
	// stage ignored -user-agent exactly as it once ignored the rate limit.
	UserAgent string
	// Limiter is the scan-wide request budget. This stage fetches the
	// application's own pages and JS bundles -- traffic to somebody's web
	// server, not to their API -- and was the one stage still exempt after the
	// limiter was made scan-wide. An operator setting -rl 10 to be careful
	// still had roughly seventeen unpaced fetches go out. A courtesy control
	// that covers part of the traffic is not a courtesy control.
	Limiter *client.Limiter
}

// DefaultPaths are conventional public endpoints worth reading on any app.
// Generic by design: nothing here is specific to a single target.
var DefaultPaths = []string{
	"/", "/robots.txt", "/sitemap.xml",
	"/api/config", "/api/health", "/api/data", "/api/search",
	"/manifest.json", "/_next/static/chunks/main.js",
}

// Harvest extracts candidate names from a running application.
//
// It is deterministic: the same site content always yields the same sorted
// seed list, and network failures degrade the result rather than reordering it.

func Harvest(ctx context.Context, o HarvestOptions) Vocabulary {
	if o.Timeout <= 0 {
		o.Timeout = 20 * time.Second
	}
	if o.MaxBundles <= 0 {
		o.MaxBundles = 8
	}
	if o.MaxSeeds <= 0 {
		o.MaxSeeds = 2000
	}
	// One implementation, and it is the one that ships: see the note in
	// internal/discover. Defaulted rather than required so this package's own
	// tests keep working -- and start exercising the production path.
	web := o.Web
	if web == nil {
		web = client.NewApplication(client.AppOptions{
			Site: o.Site, Timeout: o.Timeout, Limiter: o.Limiter,
			UserAgent: o.UserAgent,
		})
	}
	site := strings.TrimRight(o.Site, "/")

	tokens := map[string]bool{}
	var sources []string

	fetch := func(u string) (string, bool) {
		r := web.Do(ctx, http.MethodGet, u, nil, nil)
		if r.Err != nil || r.Status >= 400 {
			return "", false
		}
		return string(r.Body), true
	}

	seenPath := map[string]bool{}
	paths := append(append([]string{}, DefaultPaths...), o.Paths...)
	for _, p := range paths {
		seenPath[p] = true
	}
	sort.Strings(paths)
	paths = dedupSorted(paths)

	var indexHTML string
	for _, p := range paths {
		body, ok := fetch(site + p)
		if !ok {
			continue
		}
		sources = append(sources, p)
		if p == "/" {
			indexHTML = body
		}
		// JSON keys first: highest signal for column and relation names.
		addJSONKeys(body, tokens)
		addWords(body, tokens)
	}

	// ---- linked pages -----------------------------------------------------
	//
	// The conventional list above is what a generic wordlist can guess. The
	// words that actually name this project's relations are on the pages the
	// application links to, and those have names nobody can guess.
	var pagesFound, pagesRead int
	if o.MaxPages > 0 && indexHTML != "" {
		if base, err := url.Parse(site + "/"); err == nil {
			links := linksFrom(base, indexHTML)
			// Drop what the conventional pass already read, so the budget is
			// spent on pages that are actually new.
			var fresh []string
			for _, l := range links {
				if u, err := url.Parse(l); err == nil && !seenPath[u.Path] {
					fresh = append(fresh, l)
				}
			}
			pagesFound = len(fresh)
			// Strided, not truncated. Cutting a sorted list keeps the
			// alphabetically first pages, which on a real site means /about
			// and /blog and never /invoices; a stride spans the whole list at
			// any budget. Deterministic either way, which sort guarantees.
			fresh = sample.Strided(fresh, o.MaxPages)
			if len(fresh) > o.MaxPages {
				fresh = fresh[:o.MaxPages]
			}
			for _, l := range fresh {
				body, ok := fetch(l)
				if !ok {
					continue
				}
				pagesRead++
				sources = append(sources, l)
				addJSONKeys(body, tokens)
				addWords(body, tokens)
			}
		}
	}

	// JS bundles: identifiers frequently mirror the data model.
	var bundlesFound, bundlesRead int
	if indexHTML != "" {
		// Script discovery and the application-before-runtime ordering both
		// live in internal/assets: this package and internal/discover each had
		// their own copy, and a page serving <script src="script.js"> had its
		// credentials missed by both.
		bundles := assets.Scripts(site, indexHTML)
		bundlesFound = len(bundles)
		if len(bundles) > o.MaxBundles {
			bundles = bundles[:o.MaxBundles]
		}
		bundlesRead = len(bundles)
		for _, b := range bundles {
			// site + b, never a URL taken from the page: reJS matches
			// same-origin PATHS only. A scanner that fetched absolute URLs
			// found in a hostile target's HTML would follow that target into
			// the operator's network, and Go strips Authorization across hosts
			// but never custom headers -- so the apikey would travel too.
			if body, ok := fetch(b); ok {
				sources = append(sources, b)
				addWords(body, tokens)
			}
		}
	}

	seeds := make([]string, 0, len(tokens))
	for t := range tokens {
		seeds = append(seeds, t)
	}
	sort.Strings(seeds)
	harvested := len(seeds)
	// Sampled across the whole vocabulary rather than cut at the front. This
	// cap BINDS on ordinary sites: the reference project yields 4,112 tokens
	// against a limit of 2,000, so half the words the application uses about
	// itself were being discarded alphabetically, upstream of both relation
	// and routine discovery.
	seeds = sample.Take(seeds, o.MaxSeeds)
	sort.Strings(seeds)
	sort.Strings(sources)
	return Vocabulary{
		Seeds: seeds, Sources: dedupSorted(sources), Harvested: harvested,
		BundlesFound: bundlesFound, BundlesRead: bundlesRead,
		PagesFound: pagesFound, PagesRead: pagesRead,
	}
}

// addJSONKeys walks any JSON payload and records every object key.
func addJSONKeys(body string, into map[string]bool) {
	var v any
	if json.Unmarshal([]byte(body), &v) != nil {
		return
	}
	var walk func(any, int)
	walk = func(n any, depth int) {
		if depth > 12 {
			return
		}
		switch t := n.(type) {
		case map[string]any:
			for k, sub := range t {
				if tok := strings.ToLower(k); acceptable(tok) {
					into[tok] = true
				}
				walk(sub, depth+1)
			}
		case []any:
			for i, sub := range t {
				if i > 100 {
					break
				}
				walk(sub, depth+1)
			}
		}
	}
	walk(v, 0)
}

// addWords collects candidate names, in the case they were written AND in the
// case Postgres would store them.
//
// Both, because folding is a property of ASCII identifiers rather than of
// identifiers. Postgres lower-cases an unquoted identifier, which is why
// harvesting used to lowercase the whole body and got away with it -- and it
// does NOT fold non-ASCII without a collation. The corpus holds Ünïcödé and
// ünïcödé as two separate relations to pin that down, and lowercasing the body
// collapsed them into one seed, so one of the two could never be asked about
// whatever the wordlist held.
func addWords(body string, into map[string]bool) {
	for _, w := range reWord.FindAllString(body, -1) {
		if acceptable(w) {
			into[w] = true
		}
		// The folded form is what an unquoted name becomes in the catalogue.
		// Identical to w for anything already lower-case, so this costs a seed
		// only where the two genuinely differ.
		if low := strings.ToLower(w); low != w && acceptable(low) {
			into[low] = true
		}
	}
}

func acceptable(w string) bool {
	// Characters, not bytes. len() would reject any name of more than
	// thirteen Japanese characters as longer than forty -- a limit that meant
	// one thing for English and something else entirely for everyone else.
	n := utf8.RuneCountInString(w)
	if n > 40 {
		return false
	}
	// The floor is three for a Latin token and two for a token that is not,
	// and the asymmetry is deliberate rather than sloppy. Three exists to keep
	// out id, js, on and the rest of the two-letter noise every bundle is full
	// of. An ideographic name carries a word per character: 顧客 is
	// "customer", and refusing it because it is two characters long would
	// rule out a large share of the schemas written in CJK while doing nothing
	// about the noise the floor was built for.
	floor := 3
	if !isASCII(w) {
		floor = 2
	}
	if n < floor {
		return false
	}
	// Matched against the folded form, because the stop list is written in
	// lower case and a bundle says Function as often as function.
	return !stopWords[strings.ToLower(w)]
}

// isASCII reports whether every byte is below 0x80.
func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= utf8.RuneSelf {
			return false
		}
	}
	return true
}

func dedupSorted(xs []string) []string {
	if len(xs) == 0 {
		return xs
	}
	out := xs[:1]
	for _, x := range xs[1:] {
		if x != out[len(out)-1] {
			out = append(out, x)
		}
	}
	return out
}

// VocabularyBudgetFinding reports that the harvested vocabulary was truncated.
//
// This was silent, and it is the most upstream bound in the scan: the seeds
// feed relation discovery AND routine discovery, so a cap here lowers both
// without either of them being able to notice. Measured on the reference
// project, the site yields 4,112 tokens against the default 2,000 -- so the
// scan discards half of what the application says about itself and, until
// now, reported a relation list as though the vocabulary had been complete.
//
// The routine budget has said "1200 of 7547 probed" since an audit asked for
// it. That the same disclosure did not exist one layer up is the kind of gap
// that only shows up when you go looking for what the report does NOT say.
func VocabularyBudgetFinding(site string, kept, harvested, bundlesRead, bundlesFound, pagesRead, pagesFound int) finding.Finding {
	return finding.Finding{
		ID:       "unruly-probe-budget-exhausted",
		Name:     "Vocabulary harvesting stopped at the seed budget",
		Severity: finding.Info,
		Protocol: "http",
		Matched:  site,
		Resource: "vocabulary",
		Description: bundleNote(bundlesRead, bundlesFound) + pageNote(pagesRead, pagesFound) + fmt.Sprintf(
			"The application yielded %d distinct tokens and -max-seeds kept %d of them. "+
				"Seeds are what the hint oracle is fed, so BOTH the relations and the "+
				"routines reported are a LOWER BOUND, and the cause is this budget rather "+
				"than anything about the target. The sample is spread across the whole "+
				"vocabulary rather than its first entries, so the loss is not concentrated "+
				"in names beginning with any particular letter.", harvested, kept),
		Remediation: fmt.Sprintf("-- Re-run with -max-seeds %d to use the whole vocabulary. "+
			"It costs proportionally more probes: on a reference project lifting this cap "+
			"grew the routine seed list from 3,782 to 5,894.", harvested),
		Evidence: finding.Evidence{
			Reason: fmt.Sprintf("%d of %d harvested tokens kept", kept, harvested),
		},
	}
}

// bundleNote reports JS bundles the budget declined to read.
//
// This bound is upstream of the seed cap -- an unread bundle lowers the
// vocabulary before it is assembled -- and it binds on ordinary sites: the
// reference project references 9 bundles against a default of 8.
func bundleNote(read, found int) string {
	if found <= read {
		return ""
	}
	return fmt.Sprintf("%d of %d JS bundles were read (-max-bundles), so tokens the "+
		"unread ones would have contributed are missing from what follows. ", read, found)
}

// pageNote reports linked pages the budget declined to read.
//
// Upstream of the seed cap for the same reason bundleNote is: a page not read
// is vocabulary that never existed to be capped, and the words on it are the
// ones no pinned list contains.
func pageNote(read, found int) string {
	if found <= read {
		return ""
	}
	return fmt.Sprintf("The application linked to %d further pages and -max-pages read "+
		"%d of them, so vocabulary that exists only on the rest was never collected. "+
		"The pages read are spread across the link list rather than taken from its "+
		"start, so the loss is not concentrated in one section of the site. ",
		found, read)
}
