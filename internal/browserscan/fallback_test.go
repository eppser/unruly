package browserscan_test

import (
	"testing"

	"github.com/eppser/unruly/internal/browserscan"
)

// Some hosts send CORS on every path EXCEPT the rendered page.
//
// zerodayclock.com, on Cloudflare with Next.js, measured from a github.io
// origin:
//
//	/                          200, no access-control-allow-origin
//	/robots.txt                200, access-control-allow-origin: *
//	/anything-that-404s        404, access-control-allow-origin: *
//	/_next/static/chunks/*.js  200, access-control-allow-origin: *
//
// So the bundles are readable and the page that names them is not. A
// framework's 404 is still one of its pages and loads the same chunks, so
// asking for a path that cannot exist gets a readable copy of the shell.
func TestAProbePathIsOnTheSameOriginAndCannotCollide(t *testing.T) {
	for _, in := range []string{
		"https://zerodayclock.com",
		"https://zerodayclock.com/",
		"https://app.example.com/dashboard",
		"https://example.com/a/b?c=d",
	} {
		got := browserscan.ProbePath(in)
		if got == in {
			t.Errorf("ProbePath(%q) returned the page itself, which is the fetch that "+
				"already failed", in)
		}
		if !browserscan.SameOrigin(in, got) {
			t.Errorf("ProbePath(%q) = %q, a different origin: the bundles are only "+
				"readable on the origin that serves them", in, got)
		}
		// It has to be a path nobody has, or we would read a real page and
		// report on the wrong thing.
		if !containsAny(got, "unruly-cors-probe") {
			t.Errorf("ProbePath(%q) = %q does not name itself; a path that could "+
				"collide with a real route is a scan of something else", in, got)
		}
	}
}

func TestSameOriginRejectsWhatItShould(t *testing.T) {
	for _, tc := range []struct {
		a, b string
		want bool
	}{
		{"https://x.com/a", "https://x.com/b", true},
		{"https://x.com", "https://y.com", false},
		{"https://x.com", "http://x.com", false},
		{"https://x.com", "https://sub.x.com", false},
	} {
		if got := browserscan.SameOrigin(tc.a, tc.b); got != tc.want {
			t.Errorf("SameOrigin(%q,%q) = %v, want %v", tc.a, tc.b, got, tc.want)
		}
	}
}

func containsAny(s, sub string) bool {
	return len(s) >= len(sub) && (func() bool {
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
		return false
	})()
}
