// Package assets finds the scripts a page loads, in one place.
//
// Two packages did this separately: internal/discover, looking for
// credentials, and internal/enumerate, harvesting vocabulary. Both matched a
// short list of framework path prefixes -- /_next/static/, /assets/, /static/,
// /js/ -- and both required a leading slash.
//
// A GitHub Pages site in a live sample served
//
//	<script src="script.js"></script>
//
// and that file contained the project URL and the anon key. Neither package
// fetched it. The scan reported "no anon key found", i.e. not a Supabase
// application at all, about a site that plainly is one. Every hand-written
// page, every build with custom output paths, everything not made by Next or
// Vite was invisible to credential discovery for the same reason.
//
// Fixing it in one package and not the other would have been worse than not
// fixing it: the recall would depend on which stage happened to look, which is
// exactly the divergence internal/creds exists to prevent for credential
// shapes.
package assets

import (
	"net/url"
	"regexp"
	"sort"
	"strings"
)

// reScript matches any script reference a page makes. The origin boundary is
// enforced when the reference is RESOLVED, not here: a regex is the wrong
// place to hold a security property.
var reScript = regexp.MustCompile(`(?:src|href)=["']([^"']+\.js(?:\?[^"']*)?)["']`)

// runtimeChunk names bundles that hold framework plumbing rather than
// application code, by the filename conventions Next.js, Vite and webpack
// share. They are read last, because a budget spent on the webpack runtime is
// a budget spent on the one file guaranteed not to mention the data model.
var runtimeChunk = regexp.MustCompile(`(^|/)(polyfills|webpack|framework|runtime)[-.]`)

// Scripts returns the same-origin script URLs an HTML document references,
// sorted, deduplicated, and ordered so application code comes before framework
// runtime chunks.
//
// site must be the absolute URL the document was fetched from; relative
// references are resolved against it.
func Scripts(site, html string) []string {
	seen := map[string]bool{}
	var app, runtime []string
	for _, m := range reScript.FindAllStringSubmatch(html, -1) {
		ref, ok := SameOrigin(site, m[1])
		if !ok || seen[ref] {
			continue
		}
		seen[ref] = true
		if runtimeChunk.MatchString(m[1]) {
			runtime = append(runtime, ref)
		} else {
			app = append(app, ref)
		}
	}
	sort.Strings(app)
	sort.Strings(runtime)
	return append(app, runtime...)
}

// SameOrigin resolves a reference against the site and refuses anything that
// leaves the origin.
//
// This is deliberate rather than incidental. A scanner that fetched absolute
// URLs found in a hostile target's HTML would follow that target into the
// operator's network -- and Go strips the Authorization header across hosts
// but never custom ones, so the apikey would travel with it. Protocol-relative
// references (//cdn.example/x.js) are another origin wearing a relative path's
// clothes, and are refused for the same reason.
func SameOrigin(site, ref string) (string, bool) {
	if strings.HasPrefix(ref, "//") {
		return "", false
	}
	base, err := url.Parse(site)
	if err != nil || base.Host == "" {
		return "", false
	}
	u, err := url.Parse(ref)
	if err != nil {
		return "", false
	}
	if u.IsAbs() {
		if u.Scheme != base.Scheme || u.Host != base.Host {
			return "", false
		}
		return u.String(), true
	}
	return base.ResolveReference(u).String(), true
}
