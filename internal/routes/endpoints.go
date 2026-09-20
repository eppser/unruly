package routes

import (
	"net/url"
	"regexp"
	"strings"
)

// Endpoint extraction: what an application's own bundle says about its backend.
//
// The previous extractor required a leading "/" and one of six prefixes.
// Both encode what one framework's API happened to look like, and a real
// application had neither property: its bundle named an ABSOLUTE origin on
// another host, and the endpoint that returned a live record to anonymous
// callers was /system/mode -- outside every prefix. All three real shapes
// scored zero matches, measured.

// reAbsolute finds absolute http(s) origins in a bundle.
//
// Deliberately origin-only: what is wanted is the HOST an application talks
// to, not every URL string in a minified file.
var reAbsolute = regexp.MustCompile(`https?://[a-zA-Z0-9.\-]+(?::\d+)?`)

// reAbsoluteURL keeps the path when an application names a complete endpoint.
// An origin and a path are not independent facts: multiplying every origin by
// every path asks hosts for resources the application never associated with
// them. The full URL is the strongest association a bundle can publish.
var reAbsoluteURL = regexp.MustCompile(
	`https?://[a-zA-Z0-9.\-]+(?::\d+)?(?:/[a-zA-Z0-9_\-/\[\]{}.:]{1,120})?`)

// reScriptImport finds origins a bundle loads CODE from.
//
// The distinction the same-origin shortcut got wrong. Refusing to fetch a
// CDN's copy of React is right; refusing to inventory the application's own
// backend is not the same decision. A script host is where code came FROM; an
// API origin is where the application SENDS ITS USERS' DATA, and only the
// second is worth probing.
var reScriptImport = regexp.MustCompile(
	`(?:import\s[^;]*?from\s*["'\x60]|<script[^>]+src\s*=\s*["'\x60]|` +
		`importScripts\(\s*["'\x60])(https?://[a-zA-Z0-9.\-]+(?::\d+)?)`)

// apiOrigins returns the origins this bundle appears to use as an API base,
// excluding the site's own origin and anywhere it loads code from.
func apiOrigins(body, site string) []string {
	skip := map[string]bool{originOf(site): true}
	for _, m := range reScriptImport.FindAllStringSubmatch(body, -1) {
		skip[m[1]] = true
	}

	seen := map[string]bool{}
	var out []string
	for _, o := range reAbsolute.FindAllString(body, -1) {
		o = strings.TrimRight(o, "/")
		if skip[o] || seen[o] || o == "" {
			continue
		}
		seen[o] = true
		out = append(out, o)
	}
	return out
}

// reAnyPath finds absolute-path strings, with NO prefix allowlist.
//
// An allowlist is a guess about another team's URL design, and the one this
// replaces was wrong in the case that mattered. The cost of widening it is
// requests for URLs that were never endpoints, so the filtering moved from a
// guess about what an API looks like to a statement about what an API does
// NOT look like -- see notEndpoint.
var reAnyPath = regexp.MustCompile(`["'\x60](/[a-zA-Z0-9_\-/\[\]{}.:]{1,120})["'\x60]`)

// assetExt are extensions no API serves as an endpoint worth probing.
var assetExt = []string{
	".js", ".mjs", ".css", ".map", ".svg", ".png", ".jpg", ".jpeg", ".gif",
	".webp", ".ico", ".woff", ".woff2", ".ttf", ".eot", ".mp4", ".webm",
	".pdf", ".txt", ".xml", ".wasm", ".avif",
}

// notEndpoint rejects strings that are paths but not endpoints.
//
// Static assets, fragments and protocol-relative URLs. Probing these spends
// somebody else's bandwidth on things that were never endpoints, and noise is
// what gets a check switched off.
func notEndpoint(p string) bool {
	switch {
	case p == "" || p == "/":
		return true
	case strings.HasPrefix(p, "//"): // protocol-relative: another origin
		return true
	case strings.Contains(p, ".."):
		return true
	}
	low := strings.ToLower(p)
	if i := strings.IndexAny(low, "?#"); i >= 0 {
		low = low[:i]
	}
	for _, ext := range assetExt {
		if strings.HasSuffix(low, ext) {
			return true
		}
	}
	return false
}

// apiPaths returns candidate endpoint paths from a bundle.
func apiPaths(body string) []string {
	seen := map[string]bool{}
	var out []string
	for _, m := range reAnyPath.FindAllStringSubmatch(body, -1) {
		p := strings.TrimRight(m[1], "/")
		if p == "" {
			p = "/"
		}
		if notEndpoint(p) || seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, p)
	}
	return out
}

// endpointRef is one route attributed to one origin.
//
// Source is deliberately retained. Agent output and coverage explanations
// need to distinguish a literal URL from a relative path associated only
// because it appeared in the same asset as an API base.
type endpointRef struct {
	Base   string
	Path   string
	Source string
}

const (
	sourceRelative = "relative-path"
	sourceAbsolute = "absolute-url"
	sourceAsset    = "same-asset-api-base"
	sourceSpec     = "openapi"
)

// endpointRefs returns origin-scoped endpoint candidates from one document.
//
// Relative paths always belong to the page origin. They are also associated
// with API bases named in the SAME document, which covers the common
// `fetch(API_BASE + "/orders")` compilation shape without the old global
// origin/path Cartesian product. Cross-origin candidates are still only
// probed when the operator explicitly allows that exact origin.
func endpointRefs(body, site string) []endpointRef {
	paths := apiPaths(body)
	origins := apiOrigins(body, site)
	seen := map[string]bool{}
	var out []endpointRef
	add := func(base, path, source string) {
		base = strings.TrimRight(originOf(base), "/")
		path = strings.TrimRight(path, "/")
		if path == "" {
			path = "/"
		}
		if base == "" || notEndpoint(path) {
			return
		}
		key := base + "\x00" + path
		if seen[key] {
			return
		}
		seen[key] = true
		out = append(out, endpointRef{Base: base, Path: path, Source: source})
	}

	for _, p := range paths {
		add(site, p, sourceRelative)
		for _, base := range origins {
			add(base, p, sourceAsset)
		}
	}
	for _, raw := range reAbsoluteURL.FindAllString(body, -1) {
		u, err := url.Parse(raw)
		if err != nil || u.Scheme == "" || u.Host == "" || u.Path == "" {
			continue
		}
		add(u.Scheme+"://"+u.Host, u.EscapedPath(), sourceAbsolute)
	}
	return out
}

// originOf reduces a URL to scheme://host[:port].
func originOf(u string) string {
	i := strings.Index(u, "://")
	if i < 0 {
		return ""
	}
	rest := u[i+3:]
	if j := strings.IndexAny(rest, "/?#"); j >= 0 {
		rest = rest[:j]
	}
	return u[:i+3] + rest
}
