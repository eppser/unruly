package eval_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
)

// Every request to the site must carry the operator's User-Agent.
//
// -user-agent exists so a scan can say who it is: its help suggests pointing it
// at "a page or mailbox you control". That is an ethics control, and the
// traffic it matters for is the WEB traffic -- the requests that land in a
// human's access log, not the API calls nobody reads.
//
// It reached the PostgREST client and nothing else. Measured against a
// recording server: 134 requests, NONE carrying the override, because four
// separate stages -- discovery, vocabulary harvesting, route probing and
// archive checking -- each called client.UserAgent() directly. An operator who
// set it believed they were identifying themselves and was not.
//
// This is the second control with that exact shape. internal/enumerate still
// carries the note about the first: the rate limiter was made scan-wide and
// this stage stayed exempt, so -rl 10 still let roughly seventeen unpaced
// fetches out. Hence a test over EVERY request rather than a check of the four
// call sites, which would pass the moment a fifth stage was written.
func TestEveryRequestCarriesTheOperatorsUserAgent(t *testing.T) {
	requireLiveEvals(t)
	const ua = "unruly-eval/1.0 (+https://example.invalid/who-we-are)"

	var mu sync.Mutex
	agents := map[string]int{}
	body := `<html><body>` +
		`<a href="/api/admin/users">u</a><a href="/api/admin/logs">l</a>` +
		`<a href="/api/public/stats">s</a>` +
		`<script src="/app.js"></script></body></html>`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		agents[r.Header.Get("User-Agent")]++
		mu.Unlock()
		if strings.HasSuffix(r.URL.Path, ".js") {
			w.Header().Set("Content-Type", "application/javascript")
			fmt.Fprint(w, `const SUPABASE_URL="http://127.0.0.1:54321";`)
			return
		}
		fmt.Fprint(w, body)
	}))
	defer srv.Close()

	cmd := exec.Command(buildScanner(t), "-u", srv.URL, "-k", "eyJhbGciOiJIUzI1NiJ9.e30.x",
		"-rest-prefix", "/", "-user-agent", ua, "-silent", "-timeout", "20")
	cmd.Env = append(os.Environ(), "SUPABASE_ANON_KEY=", "SUPABASE_URL=")
	_ = cmd.Run()

	mu.Lock()
	defer mu.Unlock()
	total, ours := 0, 0
	for got, n := range agents {
		total += n
		if got == ua {
			ours += n
		}
	}
	if total < 10 {
		t.Fatalf("only %d requests reached the server, which is too few for this to "+
			"be measuring the stages it names", total)
	}
	if ours != total {
		var wrong []string
		for got, n := range agents {
			if got != ua {
				wrong = append(wrong, fmt.Sprintf("%dx %q", n, got))
			}
		}
		t.Errorf("%d of %d requests carried the operator's User-Agent; the rest went "+
			"out as something else, so a scan told to identify itself did not: %s",
			ours, total, strings.Join(wrong, ", "))
	}
}

// -no-routes must stop the scan touching application routes.
//
// It is a consent control, and consent controls fail in only one direction
// that matters: the operator says "do not probe this project's own pages" and
// the scan does anyway. Route probing is the most intrusive thing this tool
// does to a web server -- it requests admin-looking paths, and on a real
// deployment those requests land in a log next to somebody's alerting.
//
// Both halves are asserted. Without the flag the routes MUST be probed, or the
// flag is disabling something that never happened and the test proves nothing.
func TestNoRoutesStopsProbingApplicationRoutes(t *testing.T) {
	requireLiveEvals(t)

	probeCount := func(extra ...string) (routes, total int) {
		var mu sync.Mutex
		paths := []string{}
		body := `<html><body>` +
			`<a href="/api/admin/users">u</a><a href="/api/admin/logs">l</a>` +
			`<a href="/api/public/stats">s</a></body></html>`
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			paths = append(paths, r.URL.Path)
			mu.Unlock()
			fmt.Fprint(w, body)
		}))
		defer srv.Close()

		args := append([]string{"-u", srv.URL, "-k", "eyJhbGciOiJIUzI1NiJ9.e30.x",
			"-rest-prefix", "/", "-silent", "-timeout", "20"}, extra...)
		cmd := exec.Command(buildScanner(t), args...)
		cmd.Env = append(os.Environ(), "SUPABASE_ANON_KEY=", "SUPABASE_URL=")
		_ = cmd.Run()

		mu.Lock()
		defer mu.Unlock()
		for _, p := range paths {
			// Only the routes discovered from the application's OWN markup.
			//
			// Not every /api/ request: the vocabulary harvest fetches a fixed
			// list of likely JSON endpoints (/api/config, /api/search and so
			// on) because their keys mirror column names, and that is a
			// different capability. -no-routes promises to skip "the
			// application route authorisation check", which is the stage that
			// takes the links off the page and asks whether siblings agree.
			//
			// The first version of this test counted every /api/ path and
			// failed on requests the flag never claimed to stop -- and a shell
			// measurement I had run beforehand printed an empty count that I
			// read as zero, which is why the broad assertion looked justified.
			if strings.HasPrefix(p, "/api/admin/") || p == "/api/public/stats" {
				routes++
			}
		}
		return routes, len(paths)
	}

	withRoutes, totalWith := probeCount()
	if withRoutes == 0 {
		t.Fatalf("the default scan probed no application routes at all (%d requests), "+
			"so -no-routes would disable nothing and this test would pass on a tool "+
			"that ignores it", totalWith)
	}

	withoutRoutes, totalWithout := probeCount("-no-routes")
	if withoutRoutes != 0 {
		t.Errorf("-no-routes still probed %d application route(s): the operator said "+
			"not to touch this project's own pages and the scan did", withoutRoutes)
	}
	if totalWithout >= totalWith {
		t.Errorf("-no-routes sent %d requests against %d without it; the flag is not "+
			"reducing the traffic it promises to remove", totalWithout, totalWith)
	}
}
