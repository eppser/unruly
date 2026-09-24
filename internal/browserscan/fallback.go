package browserscan

import "net/url"

// probeLeaf is the path asked for when the real page cannot be read.
//
// Named so that a human reading their own access log can see what it was, and
// specific enough that it will not collide with a real route. A probe that hit
// a real page would have us reporting on something the operator did not ask
// about.
const probeLeaf = "/unruly-cors-probe-404"

// ProbePath returns a URL on the SAME origin that is certain not to exist.
//
// Some hosts send CORS on every path except the rendered page. Measured on
// zerodayclock.com, Cloudflare in front of Next.js, from a github.io origin:
// the page itself carries no access-control-allow-origin, while robots.txt, a
// 404, and every /_next/static/ chunk carry "*".
//
// A framework's 404 is still one of its pages: it loads the same script tags,
// so a readable 404 names the bundles the unreadable page would have named.
// That is enough, because the bundles themselves are readable.
func ProbePath(page string) string {
	u, err := url.Parse(page)
	if err != nil || u.Host == "" {
		return page + probeLeaf
	}
	return u.Scheme + "://" + u.Host + probeLeaf
}

// SameOrigin reports whether two URLs share scheme and host.
//
// Checked rather than assumed: the fallback is only safe while it stays on the
// origin the operator named. A redirect to somewhere else would have us
// reading a third party's page and reporting it as theirs.
func SameOrigin(a, b string) bool {
	ua, ea := url.Parse(a)
	ub, eb := url.Parse(b)
	if ea != nil || eb != nil {
		return false
	}
	return ua.Scheme == ub.Scheme && ua.Host == ub.Host && ua.Host != ""
}
