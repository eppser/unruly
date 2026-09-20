package routes

import "strings"

import "sort"

// Whose host is it? The consent question, decided explicitly.
//
// An operator types -site https://app.example and the bundle names
// https://api-host.run.app as the backend. Probing it sends requests to a host
// the operator never typed.
//
// The subdomain pass answers a similar question with "discover, report, do not
// scan", because a subdomain is GUESSED from a wordlist and status pages
// routinely point at somebody else's infrastructure. That reasoning does not
// transfer here: an API origin is DECLARED by the application itself as where
// it sends its users' data. It is the backend, and assessing an application
// without it is assessing the paint -- which is exactly the false negative
// this work exists to close.
//
// But "the bundle declared it" is not enough on its own, because a bundle also
// declares the payment processor, the error reporter and the analytics vendor.
// Probing Stripe because a customer's checkout page loads its SDK is never
// what anybody meant, and it is somebody else's production system.

// thirdPartyHosts are API hosts that belong to a vendor rather than to the
// application being scanned.
//
// PINNED AND INCOMPLETE, and that is stated rather than hidden: every
// discovered origin is reported whether it was probed or not, so an operator
// can see what was skipped and say otherwise. A silent denylist would make an
// unscanned backend indistinguishable from a scanned one.
var thirdPartyHosts = []string{
	"stripe.com", "paypal.com", "braintreegateway.com", "adyen.com",
	"sentry.io", "bugsnag.com", "datadoghq.com", "newrelic.com",
	"segment.io", "segment.com", "amplitude.com", "mixpanel.com",
	"google-analytics.com", "googletagmanager.com", "doubleclick.net",
	"googleapis.com", "gstatic.com", "google.com",
	"intercom.io", "hubspot.com", "zendesk.com", "algolia.net", "algolia.com",
	"cloudflare.com", "jsdelivr.net", "unpkg.com", "cdnjs.com",
	"auth0.com", "okta.com", "onelogin.com", "cognito-idp.amazonaws.com",
	"launchdarkly.com", "posthog.com", "openai.com", "anthropic.com",
}

// isThirdPartyAPI reports whether an origin belongs to a vendor.
//
// Suffix-matched on the registrable-ish tail so api.stripe.com and
// checkout.stripe.com are both caught, while a customer's own
// myapp-api.fly.dev is not: fly.dev is a HOSTING platform, not an API vendor,
// and excluding hosting platforms would exclude most customers' backends --
// the real one was on run.app.
func isThirdPartyAPI(origin string) bool {
	h := strings.ToLower(originOf(origin))
	if i := strings.Index(h, "://"); i >= 0 {
		h = h[i+3:]
	}
	if i := strings.Index(h, ":"); i >= 0 {
		h = h[:i]
	}
	for _, t := range thirdPartyHosts {
		if h == t || strings.HasSuffix(h, "."+t) {
			return true
		}
	}
	return false
}

// An Origin is an API host the application named, and what was done about it.
type Origin struct {
	URL string
	// Probed is true only when the operator put this exact cross-origin host in
	// scope. Discovery is evidence that a host is related; it is not authority
	// to scan that host.
	Probed bool
	// Reason says why it was skipped, so a wrong decision is visible rather
	// than silent.
	Reason string
}

// noteOrigins records every discovered origin and decides which to probe.
func noteOrigins(res *Result, origins, allowed []string) {
	inScope := map[string]bool{}
	for _, o := range allowed {
		if base := strings.TrimRight(originOf(strings.TrimSpace(o)), "/"); base != "" {
			inScope[base] = true
		}
	}
	unique := map[string]bool{}
	for _, o := range origins {
		o = strings.TrimRight(originOf(o), "/")
		if o != "" {
			unique[o] = true
		}
	}
	ordered := make([]string, 0, len(unique))
	for o := range unique {
		ordered = append(ordered, o)
	}
	sort.Strings(ordered)
	for _, o := range ordered {
		if inScope[o] {
			res.Origins = append(res.Origins, Origin{URL: o, Probed: true,
				Reason: "explicitly included by -allow-origin"})
			continue
		}
		if isThirdPartyAPI(o) {
			res.Origins = append(res.Origins, Origin{URL: o,
				Reason: "a third-party API host: probing it would send scan traffic to " +
					"somebody else's production system, and it says nothing about this " +
					"application"})
			continue
		}
		res.Origins = append(res.Origins, Origin{URL: o,
			Reason: "declared by the application but outside the operator's explicit " +
				"scope; re-run with -allow-origin " + o})
	}
}
