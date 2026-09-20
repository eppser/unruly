package enumerate

import (
	"net/url"
	"regexp"
	"sort"
	"strings"
)

// Following links, so the words an application uses about itself are not
// limited to the nine paths a generic list can guess.
//
// Recall here is a function of vocabulary. Measured on one project, a pinned
// wordlist alone reached 2 of 7 relations while the application's own words
// reached all seven -- and half of those words can live one link away, on a
// /dashboard or an /invoices that no generic list contains.
//
// Three constraints, none of them optional. A crawler without them is one
// nobody should point at somebody else's site.
//
//   - BOUNDED. -max-pages caps it, and the bound is reported when it binds.
//   - SAME ORIGIN. A link off the target leads to somebody who was never the
//     subject of this scan, and fetching it makes them one.
//   - DETERMINISTIC. Sorted, then strided, so the same site yields the same
//     pages and two scans of an unchanged project agree about what exists.

// hrefRe finds link targets. Deliberately simple: this reads an application's
// own markup to learn its words, not to render it, and a parser would be a
// dependency and an attack surface for no gain.
var hrefRe = regexp.MustCompile(`(?i)href\s*=\s*["']([^"'#>\s]+)["']`)

// linksFrom returns the same-origin page links in html, absolute, sorted and
// deduplicated.
//
// Skipped deliberately: anything that is not a page (assets are already read
// by the bundle pass), anything off-origin, and anything with a query string.
// A query is a different VIEW of a page rather than a different page, and
// following them turns a bounded crawl into an unbounded one on any site with
// a filter control.
func linksFrom(base *url.URL, html string) []string {
	seen := map[string]bool{}
	for _, m := range hrefRe.FindAllStringSubmatch(html, -1) {
		raw := strings.TrimSpace(m[1])
		if raw == "" || strings.HasPrefix(raw, "mailto:") || strings.HasPrefix(raw, "tel:") ||
			strings.HasPrefix(raw, "javascript:") || strings.HasPrefix(raw, "data:") {
			continue
		}
		u, err := base.Parse(raw)
		if err != nil {
			continue
		}
		if u.Host != base.Host || (u.Scheme != "http" && u.Scheme != "https") {
			continue
		}
		if u.RawQuery != "" {
			continue
		}
		if isAssetPath(u.Path) {
			continue
		}
		u.Fragment = ""
		if u.Path == "" {
			u.Path = "/"
		}
		seen[u.String()] = true
	}
	out := make([]string, 0, len(seen))
	for l := range seen {
		out = append(out, l)
	}
	sort.Strings(out)
	return out
}

// isAssetPath reports whether a path is a file the bundle pass already reads,
// or one with no words in it.
func isAssetPath(p string) bool {
	i := strings.LastIndex(p, ".")
	if i < 0 {
		return false
	}
	switch strings.ToLower(p[i:]) {
	case ".js", ".mjs", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp",
		".ico", ".woff", ".woff2", ".ttf", ".eot", ".pdf", ".zip", ".mp4", ".webm":
		return true
	}
	return false
}
