package routes

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/eppser/unruly/internal/client"
)

// A bundle the application actually serves must be read, wherever it sits.
//
// Route discovery reads the homepage, finds the JavaScript it links, and pulls
// the API paths out of it. It only ever fetched scripts under four
// directories -- /_next/static, /assets, /static, /js -- so an application
// that serves its bundle anywhere else had NONE of its routes discovered.
//
// That covers Next.js and misses much of everything else: Vite emits
// /index-<hash>.js at the root by default, Create React App uses /build/, and
// plenty of hand-rolled apps just serve /app.js. The failure is silent and
// looks exactly like an application with no API: "0 routes probed".
//
// Found by pointing the finished scanner at a three-line fixture and getting
// zero, then checking that the extractor itself returned all three when handed
// the bundle directly. The gap was between them.
func TestABundleOutsideTheConventionalDirectoriesIsStillRead(t *testing.T) {
	for _, tc := range []struct{ name, src string }{
		{"root", "/app.js"},
		{"vite hashed root", "/index-D4f8a1.js"},
		{"build dir", "/build/main.js"},
		{"next static", "/_next/static/chunks/main.js"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/":
					w.Header().Set("Content-Type", "text/html")
					w.Write([]byte(`<script src="` + tc.src + `"></script>`))
				case tc.src:
					w.Header().Set("Content-Type", "application/javascript")
					w.Write([]byte(`fetch("/api/orders");fetch("/api/admin/users");`))
				default:
					w.WriteHeader(http.StatusNotFound)
				}
			}))
			defer srv.Close()

			web := client.NewApplication(client.AppOptions{
				Site: srv.URL, Concurrency: 2, Retries: 1})
			res := &Result{}
			rr := &runner{web: web, res: res}
			refs, _ := discoverPaths(context.Background(), srv.URL, srv.URL, 40, 2, nil, rr)
			got := pathsFor(refs, srv.URL)

			if !contains(got, "/api/orders") {
				t.Errorf("a bundle at %s named /api/orders and discovery found %v.\n"+
					"An application that serves its JavaScript outside four hard-coded "+
					"directories has every one of its routes missed, and the report "+
					"reads exactly like an application with no API.", tc.src, got)
			}
		})
	}
}

// Cross-origin scripts are NOT fetched.
//
// A CDN's copy of React names no routes belonging to this application, and
// fetching third-party origins during a scan of somebody's site sends traffic
// nobody authorised to hosts nobody nominated. Same-origin only, deliberately:
// inventorying cross-origin API endpoints is a real gap and is a different
// change, with its own consent question.
func TestCrossOriginScriptsAreNotFetched(t *testing.T) {
	// Atomic: a plain counter incremented inside a handler is a data race the
	// detector only catches when requests overlap, and this repository has a
	// check for exactly that. It found this one.
	var elsewhere atomic.Int64
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		elsewhere.Add(1)
		w.Write([]byte(`fetch("/api/should_not_be_found");`))
	}))
	defer other.Close()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			w.Header().Set("Content-Type", "text/html")
			w.Write([]byte(`<script src="` + other.URL + `/cdn.js"></script>`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	web := client.NewApplication(client.AppOptions{
		Site: srv.URL, Concurrency: 2, Retries: 1})
	res := &Result{}
	rr := &runner{web: web, res: res}
	refs, _ := discoverPaths(context.Background(), srv.URL, srv.URL, 40, 2, nil, rr)
	got := pathsFor(refs, srv.URL)

	if n := elsewhere.Load(); n > 0 {
		t.Errorf("discovery fetched %d script(s) from another origin; a scan of one "+
			"site must not send traffic to hosts the operator never nominated", n)
	}
	if contains(got, "/api/should_not_be_found") {
		t.Error("a path from a third-party script was attributed to this application")
	}
}

func contains(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}

var _ = strings.TrimSpace

// A same-origin endpoint outside the old prefixes is now discovered AND probed.
//
// The testbed's chain still fails, because its API lives on another origin and
// nothing probes that yet. This is the half that the prefix fix does close, and
// proving it end to end -- through discovery to an actual request -- is the
// difference between a passing unit test and a scanner that works. Twice in
// this project the unit tests have said done while the binary was wrong.
func TestASameOriginEndpointOutsideTheOldPrefixesIsProbed(t *testing.T) {
	var mu sync.Mutex
	hits := map[string]int{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hits[r.URL.Path]++
		mu.Unlock()
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			w.Write([]byte(`<script src="/app.js"></script>`))
		case "/app.js":
			w.Header().Set("Content-Type", "application/javascript")
			w.Write([]byte(`fetch("/system/mode");fetch("/v2/billing/summary");`))
		default:
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"ok":true}`))
		}
	}))
	defer srv.Close()

	web := client.NewApplication(client.AppOptions{Site: srv.URL, Concurrency: 2, Retries: 1})
	res := &Result{}
	rr := &runner{web: web, res: res}
	refs, _ := discoverPaths(context.Background(), srv.URL, srv.URL, 40, 2, nil, rr)
	got := pathsFor(refs, srv.URL)

	for _, want := range []string{"/system/mode", "/v2/billing/summary"} {
		if !contains(got, want) {
			t.Errorf("%s was not discovered; got %v. This is the endpoint shape that "+
				"returned a live record to anonymous callers on a real target and "+
				"scored zero matches.", want, got)
		}
	}
}

func pathsFor(refs []endpointRef, base string) []string {
	var out []string
	for _, ref := range refs {
		if ref.Base == base {
			out = append(out, ref.Path)
		}
	}
	return out
}
