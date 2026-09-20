package main

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/eppser/unruly/internal/testrec"
)

// A target written without a scheme must still be scanned.
//
// Before this existed, `unruly -u example.com` reached the network zero times
// and reported "no Supabase project reference found; supply -project-ref or
// -base-url", then exited 3 with the host listed as unreachable. Every word of
// that is defensible in isolation and the whole is misleading: nothing was ever
// requested, so "unreachable" is a claim about a request that was never sent.
// The operator's mistake was a missing "https://" and the report named a
// missing project reference.
//
// The ordering below is a judgement, and it is written down here rather than
// inferred from the code: HTTPS first for anything routable, because every
// managed backend this scanner addresses -- Supabase, Firebase, Neon -- is
// HTTPS-only and redirects or refuses port 80, and because falling back the
// other way would put an anon key on the wire in cleartext before anything had
// established that cleartext was necessary. HTTP first for loopback and
// private addresses, because that is what a local stack serves and this
// project's entire benchmark corpus is fourteen of them.
func TestABareDomainIsTriedOverHTTPSFirstAndHTTPSecond(t *testing.T) {
	for _, c := range []struct {
		name string
		raw  string
		want []string
	}{
		{"public host", "example.com", []string{"https://example.com", "http://example.com"}},
		{"public host with a path", "example.com/app", []string{"https://example.com/app", "http://example.com/app"}},
		{"public host with a port", "example.com:8443", []string{"https://example.com:8443", "http://example.com:8443"}},
		{"subdomain", "my-app.lovable.app", []string{"https://my-app.lovable.app", "http://my-app.lovable.app"}},

		{"loopback by name", "localhost:54321", []string{"http://localhost:54321", "https://localhost:54321"}},
		{"loopback by address", "127.0.0.1:54401", []string{"http://127.0.0.1:54401", "https://127.0.0.1:54401"}},
		{"private range", "192.168.1.10:3000", []string{"http://192.168.1.10:3000", "https://192.168.1.10:3000"}},
		{"private range 10/8", "10.0.0.5:8000", []string{"http://10.0.0.5:8000", "https://10.0.0.5:8000"}},

		{"port 80 is a statement", "example.com:80", []string{"http://example.com:80", "https://example.com:80"}},
		{"port 443 is a statement", "example.com:443", []string{"https://example.com:443", "http://example.com:443"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			got := schemeCandidates(c.raw)
			if len(got) != len(c.want) {
				t.Fatalf("schemeCandidates(%q) returned %d candidates %v, want %d %v",
					c.raw, len(got), got, len(c.want), c.want)
			}
			for i := range got {
				if got[i] != c.want[i] {
					t.Errorf("schemeCandidates(%q)[%d] = %q, want %q (full: %v)",
						c.raw, i, got[i], c.want[i], got)
				}
			}
		})
	}
}

// A target that already carries a scheme is passed through untouched.
//
// This is the specific defect this project has published a criticism of:
// benchmark/README.md records that srdaniellp/supabase-scanner force-prepends
// "https://" to a manually supplied URL, turning http://127.0.0.1:54401 into
// https://http://127.0.0.1:54401 and making it unable to address a self-hosted
// or proxied deployment at all. Having said that about someone else's tool in
// a published benchmark, this one had better not do it.
//
// Exactly ONE candidate is returned, which is the other half of the promise: a
// scheme the operator wrote is an instruction, and quietly trying the other one
// would send a request they did not ask for -- to port 80 of a host they named
// over TLS, or the reverse.
func TestAnExplicitSchemeIsNeverRewrittenAndNeverSecondGuessed(t *testing.T) {
	for _, raw := range []string{
		"https://example.com",
		"http://example.com",
		"http://127.0.0.1:54401",
		"https://abcdefghijklmno.supabase.co",
		"http://localhost:8000/app",
		"https://example.com:8443/path?x=1",
	} {
		got := schemeCandidates(raw)
		if len(got) != 1 {
			t.Errorf("schemeCandidates(%q) returned %d candidates %v; an explicit scheme must yield exactly one",
				raw, len(got), got)
			continue
		}
		if got[0] != raw {
			t.Errorf("schemeCandidates(%q) rewrote it to %q; an explicit scheme is an instruction", raw, got[0])
		}
	}
}

// Whatever comes back must be a URL that can actually be fetched.
//
// A generic invariant rather than a list of cases, because the failure being
// guarded is a class: any candidate whose scheme is not exactly http or https,
// or whose host is empty, is a string that will fail at the transport with a
// message about the URL rather than about the target. "https://http://x" has an
// empty host and would be caught here even if the case above were deleted.
func TestEveryCandidateParsesAsAFetchableURL(t *testing.T) {
	for _, raw := range []string{
		"example.com", "example.com/app", "example.com:8443",
		"localhost:54321", "127.0.0.1:54401", "192.168.1.10:3000",
		"https://example.com", "http://127.0.0.1:54401",
		"my-app.lovable.app", "sub.domain.example.co.uk/deep/path",
	} {
		for i, cand := range schemeCandidates(raw) {
			u, err := url.Parse(cand)
			if err != nil {
				t.Errorf("schemeCandidates(%q)[%d] = %q does not parse: %v", raw, i, cand, err)
				continue
			}
			if u.Scheme != "http" && u.Scheme != "https" {
				t.Errorf("schemeCandidates(%q)[%d] = %q has scheme %q, want http or https", raw, i, cand, u.Scheme)
			}
			if u.Host == "" {
				t.Errorf("schemeCandidates(%q)[%d] = %q has an empty host, so it can never be fetched", raw, i, cand)
			}
			if strings.Count(cand, "://") != 1 {
				t.Errorf("schemeCandidates(%q)[%d] = %q carries %d scheme separators, want 1",
					raw, i, cand, strings.Count(cand, "://"))
			}
		}
	}
}

// Input that names no host is returned unchanged and not decorated.
//
// The empty target is a real invocation: `unruly -base-url ... -key ...` scans
// one thing and passes "" through the same funnel. Turning that into
// "https://" would manufacture a target out of nothing.
func TestInputWithNoHostIsLeftAlone(t *testing.T) {
	for _, raw := range []string{"", "   "} {
		got := schemeCandidates(raw)
		if len(got) != 1 || got[0] != raw {
			t.Errorf("schemeCandidates(%q) = %v, want the input unchanged as a single candidate", raw, got)
		}
	}
}

// The first candidate that ANSWERS is the one scanned.
//
// "Answers" means the transport produced an HTTP response, whatever its
// status. A 404 or a 500 over HTTPS means the host speaks HTTPS, and
// downgrading to cleartext because the encrypted attempt returned an
// unwelcome status -- rather than failing to connect -- would put an anon key
// on the wire over a protocol that was working fine.
func TestTheFirstCandidateThatAnswersIsTheOneUsed(t *testing.T) {
	var seen testrec.Log

	first := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen.Add("first")
		w.WriteHeader(http.StatusNotFound) // an unwelcome status is still an answer
	}))
	defer first.Close()
	second := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen.Add("second")
	}))
	defer second.Close()

	got, err := firstThatAnswers(context.Background(), first.Client(), nil, []string{first.URL, second.URL})
	if err != nil {
		t.Fatalf("firstThatAnswers: %v", err)
	}
	if got != first.URL {
		t.Errorf("chose %q, want the first candidate %q", got, first.URL)
	}
	if seen.Count("second") != 0 {
		t.Errorf("the second candidate was requested %d time(s); a candidate that answered must stop the walk",
			seen.Count("second"))
	}
	if seen.Count("first") == 0 {
		t.Fatal("the first candidate was never requested, so this test proved nothing about which was chosen")
	}
}

// A candidate that cannot be connected to falls through to the next.
//
// This is the case the whole feature exists for: `unruly -u example.com`
// against a host that serves plain HTTP only.
func TestACandidateThatRefusesTheConnectionFallsThroughToTheNext(t *testing.T) {
	var seen testrec.Log

	live := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen.Add("live")
	}))
	defer live.Close()

	dead := deadAddress(t)

	got, err := firstThatAnswers(context.Background(), live.Client(), nil, []string{dead, live.URL})
	if err != nil {
		t.Fatalf("firstThatAnswers: %v", err)
	}
	if got != live.URL {
		t.Errorf("chose %q, want the reachable candidate %q", got, live.URL)
	}
	if seen.Count("live") == 0 {
		t.Fatal("the reachable candidate was never requested; the walk did not reach it")
	}
}

// When nothing answers, the error names every attempt.
//
// The report this replaces said "no Supabase project reference found; supply
// -project-ref or -base-url" for a target that had never been requested at
// all. An operator reading that goes looking for a project reference. The
// operator reading this one sees both URLs that were tried and notices the
// missing scheme was never the problem -- or that it was.
func TestWhenNothingAnswersTheErrorNamesEveryAttempt(t *testing.T) {
	a, b := deadAddress(t), deadAddress(t)

	_, err := firstThatAnswers(context.Background(), http.DefaultClient, nil, []string{a, b})
	if err == nil {
		t.Fatal("no error when neither candidate answered")
	}
	for _, want := range []string{a, b} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not name the attempt %q", err, want)
		}
	}
}

// A target that already names its scheme is not probed at all.
//
// resolveScheme must not spend a request deciding something the operator
// already decided. Measured by pointing it at a server and requiring silence.
func TestAnExplicitSchemeCostsNoRequest(t *testing.T) {
	var seen testrec.Log

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen.Add("hit")
	}))
	defer srv.Close()

	got, fellBack, err := resolveScheme(context.Background(), srv.Client(), nil, srv.URL)
	if err != nil {
		t.Fatalf("resolveScheme: %v", err)
	}
	if got != srv.URL {
		t.Errorf("resolveScheme(%q) = %q, want it unchanged", srv.URL, got)
	}
	if fellBack {
		t.Error("reported a fallback for a target whose scheme the operator wrote")
	}
	if n := seen.Len(); n != 0 {
		t.Errorf("sent %d request(s) resolving a target that needed no resolving", n)
	}
}

// deadAddress returns a URL nothing is listening on.
//
// Bound and closed rather than guessed, because a hard-coded port is a port
// something else on the machine may be using -- which would turn "nothing
// answered" into "something did" and pass or fail this test for a reason that
// has nothing to do with the code.
func deadAddress(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserving a port: %v", err)
	}
	addr := l.Addr().String()
	if err := l.Close(); err != nil {
		t.Fatalf("closing the reserved port: %v", err)
	}
	return "http://" + addr
}
