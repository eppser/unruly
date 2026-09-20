package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/eppser/unruly/internal/client"
)

// hasScheme recognises a URL that already names its protocol.
//
// Deliberately NOT url.Parse: "example.com:8443" parses with Scheme
// "example.com" and Opaque "8443", so a scheme test written on the parse
// result treats a host:port as already-schemed and leaves it unfetchable.
// This matches the grammar instead -- a scheme, then "://" -- which is the
// thing that actually distinguishes the two.
var hasScheme = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9+.\-]*://`)

// schemeCandidates returns the URLs to try, in order, for whatever the
// operator supplied as a target.
//
// A target that already names a scheme yields exactly ONE candidate: itself,
// byte for byte. That is the whole of the contract and it is not an
// implementation detail. benchmark/README.md criticises another scanner in
// print for force-prepending "https://" to a manual URL -- which turns
// http://127.0.0.1:54401 into https://http://127.0.0.1:54401 and is why that
// tool cannot address a self-hosted or proxied deployment at all. Having
// published that, this scanner does not get to do it. A scheme the operator
// wrote is an instruction, and trying the other one anyway sends a request
// they did not ask for.
//
// A bare host yields two candidates, and the ORDER is a judgement:
//
// HTTPS first for anything routable. Every managed backend this tool
// addresses -- Supabase, Firebase, Neon -- is HTTPS-only and answers port 80
// with a redirect or nothing at all, so http-first would spend a round trip on
// every scan to learn what is already known. It is also the safer default in
// the direction that matters: the fallback puts an anon key on the wire in
// cleartext, and that should require the encrypted attempt to have actually
// failed rather than merely being second in a list.
//
// HTTP first for loopback and private addresses. That is what a local stack
// serves, this project's entire fourteen-project benchmark corpus is local
// stacks, and an https attempt against one fails at the TLS handshake rather
// than fast, which is the slowest possible way to learn nothing.
//
// An explicit :80 or :443 is treated as the operator saying which they meant.
//
// Input naming no host at all is returned unchanged. The empty target is a
// real invocation -- `unruly -base-url ... -key ...` scans one thing and
// passes "" through this same funnel -- and turning that into "https://" would
// manufacture a target out of nothing.
func schemeCandidates(raw string) []string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" || hasScheme.MatchString(trimmed) {
		return []string{raw}
	}

	// Parsed as an authority rather than as a URL: url.Parse("127.0.0.1:54401")
	// fails outright ("first path segment in URL cannot contain colon"), while
	// the same string behind "//" parses as the host:port it plainly is.
	u, err := url.Parse("//" + trimmed)
	if err != nil || u.Host == "" {
		return []string{raw}
	}

	https, http := "https://"+trimmed, "http://"+trimmed
	if plaintextIsLikelier(u) {
		return []string{http, https}
	}
	return []string{https, http}
}

// plaintextIsLikelier decides which protocol to spend the first request on.
//
// It decides ORDER and nothing else. Both candidates are tried either way, so
// being wrong here costs one round trip and never costs a finding -- which is
// why a heuristic is acceptable in this position and would not be in a
// position that decides what gets reported.
func plaintextIsLikelier(u *url.URL) bool {
	switch u.Port() {
	case "443":
		return false
	case "80":
		return true
	}

	host := u.Hostname()
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsUnspecified()
	}
	// Names that cannot resolve to a public address. ".local" is mDNS and
	// ".localhost" is reserved to the loopback by RFC 6761.
	low := strings.ToLower(host)
	return low == "localhost" ||
		strings.HasSuffix(low, ".localhost") ||
		strings.HasSuffix(low, ".local")
}

// firstThatAnswers walks the candidates and returns the first whose transport
// produces an HTTP response.
//
// Any status counts. A 404 or a 500 over HTTPS establishes that the host
// speaks HTTPS, and falling through to cleartext on an unwelcome status --
// rather than on a failure to connect -- would downgrade a connection that was
// working. Only a transport error moves the walk on.
//
// The request is a GET rather than a HEAD. Hosts behind CDNs and app platforms
// answer HEAD with 405 often enough that it is not a reliable liveness probe,
// and a 405 would be read here as "answered" anyway; a GET costs one response
// body that is immediately discarded, on at most two requests per target.
func firstThatAnswers(ctx context.Context, hc *http.Client, lim *client.Limiter, cands []string) (string, error) {
	var failures []string
	for _, cand := range cands {
		// Paced with every other stage. -rate-limit is a promise to the target
		// about how fast it will be asked, and a stage that opts out of it
		// makes the number the operator typed untrue. Two requests is not much
		// traffic; a courtesy control that covers part of the traffic is not a
		// courtesy control.
		lim.Wait(ctx)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, cand, nil)
		if err != nil {
			failures = append(failures, fmt.Sprintf("%s (%v)", cand, err))
			continue
		}
		resp, err := hc.Do(req)
		if err != nil {
			// A cancelled context is the operator stopping the scan, not the
			// candidate being wrong. Trying the next one would send a request
			// after the deadline the operator set.
			if ctx.Err() != nil {
				return "", fmt.Errorf("resolving a scheme for %s: %w", cand, ctx.Err())
			}
			failures = append(failures, fmt.Sprintf("%s (%v)", cand, err))
			continue
		}
		resp.Body.Close()
		return cand, nil
	}
	return "", fmt.Errorf("no scheme answered: tried %s", strings.Join(failures, "; "))
}

// resolveScheme turns whatever the operator supplied into a URL that can be
// fetched, and says whether the encrypted attempt was the one that failed.
//
// The second return value is not decoration. A public host that answers only
// over HTTP means every subsequent request in the scan -- including the one
// carrying the anon key -- travels in cleartext, and the operator is told so
// rather than left to infer it from a URL in the report.
//
// A target that already names its scheme is returned without a request being
// sent. Probing it would spend a round trip deciding something the operator
// already decided, and against a target whose owner is paying for the traffic.
func resolveScheme(ctx context.Context, hc *http.Client, lim *client.Limiter, raw string) (string, bool, error) {
	cands := schemeCandidates(raw)
	if len(cands) < 2 {
		return raw, false, nil
	}
	got, err := firstThatAnswers(ctx, hc, lim, cands)
	if err != nil {
		return raw, false, err
	}
	return got, got != cands[0], nil
}

// schemeProbeClient is the client used ONLY to decide a target's scheme.
//
// Separate from the scan's clients on purpose. Redirects are not followed,
// because the question this probe asks is whether the host answers at all --
// an http host that 301s to https has answered, and chasing the hop would
// spend a second request to learn what the first already established. It also
// keeps the probe from wandering to a different host on a redirect and
// reporting that one as reachable.
func schemeProbeClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}
