package routes

import (
	"strings"
	"testing"
)

// WHOSE HOST IS IT? The consent question, decided explicitly.
//
// An operator types -site https://app.example. The bundle names
// https://api-host.run.app as the backend. Probing it sends requests to a host
// the operator never typed.
//
// The subdomain pass faces a similar question and answers "discover, report,
// do not scan", because a subdomain is GUESSED from a wordlist and status
// pages routinely point at somebody else's infrastructure. That reasoning does
// not transfer: an API origin is DECLARED by the application itself as the
// place it sends its users' data. It is the backend, and assessing an
// application without it is assessing the paint.
//
// But "declared by the bundle" is not sufficient on its own, because a bundle
// also declares the payment processor, the error reporter and the analytics
// vendor. Probing Stripe because a customer's checkout page loads its SDK is
// never what anybody meant, and it is somebody else's production system.
//
// So: the application's own backend is probed, and known third-party API hosts
// are not. That list is PINNED AND INCOMPLETE, which is stated rather than
// hidden -- every origin is reported whether probed or not, so an operator can
// see what was skipped and what was not.
func TestKnownThirdPartyAPIsAreNotProbed(t *testing.T) {
	for _, host := range []string{
		"https://api.stripe.com",
		"https://sentry.io",
		"https://www.google-analytics.com",
		"https://api.segment.io",
		"https://firebaseinstallations.googleapis.com",
	} {
		if !isThirdPartyAPI(host) {
			t.Errorf("%s would be probed as the application's own backend. It is "+
				"somebody else's production system, and a customer loading its SDK is "+
				"not an invitation to send it scan traffic.", host)
		}
	}
}

// And the application's own backend is not excluded by that list.
//
// A denylist that catches the real target is worse than no denylist: it
// restores the false negative while looking like caution.
func TestTheApplicationsOwnBackendIsProbable(t *testing.T) {
	for _, host := range []string{
		"https://arc-code-119832744580.europe-west1.run.app",
		"https://api.example.invalid",
		"https://backend.myapp.io",
		"https://myapp-api.fly.dev",
	} {
		if isThirdPartyAPI(host) {
			t.Errorf("%s was excluded as a third party. It is the shape a customer's "+
				"own backend takes, and excluding it restores the false negative while "+
				"looking like caution.", host)
		}
	}
}

// Every discovered origin is REPORTED, probed or not.
//
// The list of third parties is pinned and will be incomplete. An operator who
// can see "these origins were found, these were probed, these were skipped"
// can correct it; one who sees nothing cannot tell a scanned backend from a
// skipped one.
func TestEveryDiscoveredOriginIsReported(t *testing.T) {
	res := &Result{}
	noteOrigins(res, []string{
		"https://api-host.run.app",
		"https://api.stripe.com",
	}, []string{"https://api-host.run.app"})

	if len(res.Origins) != 2 {
		t.Fatalf("reported %d origins, want both the probed and the skipped one: %+v",
			len(res.Origins), res.Origins)
	}
	var probed, skipped int
	for _, o := range res.Origins {
		if o.Probed {
			probed++
			continue
		}
		skipped++
		if o.Reason == "" {
			t.Errorf("origin %s was skipped with no reason given, so an operator "+
				"cannot tell whether the decision was right", o.URL)
		}
	}
	if probed != 1 || skipped != 1 {
		t.Errorf("probed=%d skipped=%d; want the backend probed and the payment "+
			"processor skipped", probed, skipped)
	}
}

func TestDiscoveredCrossOriginIsNotAuthorityToProbeIt(t *testing.T) {
	res := &Result{}
	noteOrigins(res, []string{"https://unknown-service.example"}, nil)
	if len(res.Origins) != 1 || res.Origins[0].Probed {
		t.Fatalf("a bundle mention widened scan scope: %+v", res.Origins)
	}
	if !strings.Contains(res.Origins[0].Reason, "-allow-origin") {
		t.Errorf("the skipped origin gives no actionable scope instruction: %+v", res.Origins[0])
	}
}

var _ = strings.TrimSpace
