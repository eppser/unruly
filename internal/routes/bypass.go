package routes

import (
	"fmt"
	"strings"

	"github.com/eppser/unruly/internal/finding"
)

// Authentication bypasses: a request that gets past what the plain one did not.
//
// The discipline is the whole check. Trying variants against every endpoint and
// reporting whichever return 200 would report an open API ten times over and
// bury the one endpoint where a variant actually got past something. THE
// VARIANT MUST SUCCEED WHERE THE CANONICAL REQUEST WAS REFUSED, and "succeed"
// has to mean data came back rather than the status changed.

// catchAllControl is the key under which the nonsense-path probe is passed in.
//
// NUL-prefixed rather than "unruly-catch-all-control", which is what it was
// first called. Every "unruly-*" string in this tree is a FINDING ID, and the
// audit that checks each one is documented and named by a test flagged this
// map key as an undocumented finding -- correctly, on its own terms. The
// namespace is not mine to borrow, and a sentinel no variant name can collide
// with says what this is.
const catchAllControl = "\x00catch-all-control"

// A variant is one alternative way of asking for the same resource.
type variant struct {
	// Name is what appears in the finding, so an operator can reproduce it.
	Name string
	// Path is the URL to request; the canonical path when unchanged.
	Path string
	// Method defaults to GET when empty.
	Method string
	// Header and Value are set for header variants.
	Header, Value string
	// Why explains the misconfiguration this variant exploits.
	Why string
}

// probeResult is what one request returned.
type probeResult struct {
	code int
	body string
}

// bypassVariants are the shapes that actually get past middleware.
//
// Every entry is a real misconfiguration rather than a curiosity. The header
// variants exploit a reverse proxy that authorises one path and forwards
// another; the path variants exploit a matcher that compares strings while the
// server routes on something else.
//
// NOTHING HERE WRITES. A POST where GET is refused is a real bypass shape and
// also a request that can create something in a system this scanner knows
// nothing about, so it belongs behind the same consent as every other write
// and is not in this list.
func bypassVariants(path string) []variant {
	p := strings.TrimRight(path, "/")
	if p == "" {
		p = "/"
	}
	return []variant{
		{Name: "X-Original-URL", Path: "/", Header: "X-Original-URL", Value: p,
			Why: "a reverse proxy that authorises the requested path and forwards the " +
				"one this header names"},
		{Name: "X-Rewrite-URL", Path: "/", Header: "X-Rewrite-URL", Value: p,
			Why: "the same rewrite trick under a second header name"},
		{Name: "X-Forwarded-For", Path: p, Header: "X-Forwarded-For", Value: "127.0.0.1",
			Why: "a rule that trusts requests appearing to come from localhost"},
		{Name: "X-Forwarded-Host", Path: p, Header: "X-Forwarded-Host", Value: "localhost",
			Why: "a rule that trusts an internal hostname"},

		{Name: "uppercase segment", Path: upperFirstSegment(p),
			Why: "a matcher comparing paths case-sensitively while the router does not"},
		{Name: "double slash", Path: "/" + p,
			Why: "a matcher that normalises differently from the router"},
		{Name: "trailing dot-segment", Path: p + "/.",
			Why: "a matcher that does not resolve dot-segments before comparing"},
		{Name: "trailing slash", Path: p + "/",
			Why: "a rule written for the exact path while the router treats both alike"},

		{Name: "HEAD", Path: p, Method: "HEAD",
			Why: "a rule written for GET alone, leaving HEAD to reach the same handler"},
		{Name: "OPTIONS", Path: p, Method: "OPTIONS",
			Why: "the same, for OPTIONS"},
	}
}

func upperFirstSegment(p string) string {
	parts := strings.SplitN(strings.TrimPrefix(p, "/"), "/", 2)
	if parts[0] == "" {
		return p
	}
	up := strings.ToUpper(parts[0][:1]) + parts[0][1:]
	if len(parts) == 1 {
		return "/" + up
	}
	return "/" + up + "/" + parts[1]
}

// bypassFindings reports variants that reached data the canonical request did
// not.
//
// Three conditions, and each exists because dropping it produces noise an
// operator would learn to ignore:
//
//   - the canonical request must have been REFUSED. Otherwise there is nothing
//     to get past and every variant of an open endpoint is a "finding".
//   - the variant must return 200 with a body that DIFFERS from the refusal.
//     Plenty of servers answer 200 carrying an error, and a check reading the
//     status alone reports every one of them.
//   - the body must be non-empty. HEAD returns none by definition, and a route
//     existing is not data being reached -- reporting it would assert a
//     stranger can do something on no evidence that anything came back.
//   - the variant's response must DIFFER FROM ITS OWN CONTROL: the identical
//     request without the header. The rewrite variants ask for "/" and name the
//     protected path in a header, and "/" legitimately returns the homepage --
//     so without this every site with a homepage reports a bypass on every
//     refused endpoint. Caught by the testbed's protected-endpoint controls the
//     first time this ran, on all five at once.
func bypassFindings(base, path string, canonical probeResult,
	variants map[string]probeResult) []finding.Finding {

	if !refused(canonical.code) {
		return nil
	}
	// The catch-all control, when one was taken. A host that answers 200 for a
	// path which cannot exist cannot support PATH variants at all: every one
	// of them returns the index page. Header variants survive, because each is
	// judged against its own no-header control.
	control, haveControl := variants[catchAllControl]
	pathVariantsSound := !haveControl || discriminates(control)
	byName := map[string]variant{}
	for _, v := range bypassVariants(path) {
		byName[v.Name] = v
	}

	var out []finding.Finding
	for name, got := range variants {
		if strings.HasSuffix(name, " (control)") || name == catchAllControl {
			continue
		}
		v, known := byName[name]
		// A path variant on a catch-all host proves nothing: it returns the
		// index page, as everything does.
		if known && v.Header == "" && v.Path != path && !pathVariantsSound {
			continue
		}
		// And even where the host does discriminate, a response identical to
		// the catch-all's is the catch-all answering.
		if haveControl && strings.TrimSpace(got.body) == strings.TrimSpace(control.body) &&
			got.code == control.code {
			continue
		}
		if got.code != 200 {
			continue
		}
		body := strings.TrimSpace(got.body)
		if body == "" || body == strings.TrimSpace(canonical.body) {
			continue
		}
		// The same request without the header. A header variant that changes
		// nothing is not a bypass -- it is the server answering the URL it was
		// asked for.
		if ctrl, ok := variants[name+" (control)"]; ok {
			if ctrl.code == got.code && strings.TrimSpace(ctrl.body) == body {
				continue
			}
		}
		why := "an alternative form of the same request"
		if v, ok := byName[name]; ok && v.Why != "" {
			why = v.Why
		}
		url := base + path
		out = append(out, finding.Finding{
			ID:       "app-auth-bypass",
			Name:     "An authorisation check is bypassed by an alternative request",
			Severity: finding.High,
			Protocol: "http",
			Matched:  url,
			Resource: path,
			Description: fmt.Sprintf("GET %s is refused with %d, and the same resource "+
				"is returned with 200 when the request is varied by %q. That variant "+
				"exploits %s. The authorisation decision is therefore made on the shape "+
				"of the request rather than on who is asking.",
				url, canonical.code, name, why),
			Remediation: "-- Apply the authorisation check inside the handler rather than " +
				"in a matcher in front of it, so every route to the same resource is " +
				"covered.\n-- If a proxy makes the decision, ensure it authorises the " +
				"path it forwards, not the one it received.",
			Evidence: finding.Evidence{
				Reason: fmt.Sprintf("canonical GET %d, %s variant 200 with a different body",
					canonical.code, name),
			},
		})
	}
	finding.Sort(out)
	return out
}

// discriminates reports whether a host distinguishes a path that cannot exist.
//
// A single-page application, and Go's own ServeMux with a "/" handler, answer
// 200 with the index page for EVERY unknown path. On such a host every path
// variant -- /Admin, //admin, /admin/. -- returns that page, which differs from
// the refusal, and the check would report a bypass on every refused endpoint.
//
// Caught by two existing soundness tests the first time this ran, whose
// fixture is exactly that shape. Their four findings were all this.
//
// The same control this project already applies to PostgREST: ask for
// something that cannot exist, and if the answer is indistinguishable from a
// real one, the instrument cannot see and must say so rather than guess.
func discriminates(control probeResult) bool {
	return control.code != 200
}

// refused reports whether a status is an authorisation refusal.
//
// 404 is deliberately included: an API that hides a resource behind "not
// found" is making an authorisation decision, and a variant that turns it into
// 200 has got past exactly that.
func refused(code int) bool {
	switch code {
	case 401, 403, 404:
		return true
	}
	return false
}
