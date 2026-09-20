package routes

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
)

func TestAbsoluteEndpointsStayOnTheOriginThatNamedThem(t *testing.T) {
	refs := endpointRefs(`
		fetch("https://one.example/users");
		fetch("https://two.example/invoices");
	`, "https://app.example")

	want := map[string]bool{
		"https://one.example/users":    true,
		"https://two.example/invoices": true,
	}
	for _, ref := range refs {
		delete(want, ref.Base+ref.Path)
		if ref.Base == "https://one.example" && ref.Path == "/invoices" {
			t.Error("a path from the second origin was multiplied onto the first")
		}
		if ref.Base == "https://two.example" && ref.Path == "/users" {
			t.Error("a path from the first origin was multiplied onto the second")
		}
	}
	if len(want) != 0 {
		t.Fatalf("absolute endpoint associations were lost: %v", want)
	}
}

func TestCrossOriginRequiresExactOperatorScope(t *testing.T) {
	var backendHits atomic.Int64
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		backendHits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"ok":true}`))
	}))
	defer backend.Close()

	app := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Write([]byte(`<script src="/app.js"></script>`))
		case "/app.js":
			w.Write([]byte(`const API="` + backend.URL + `";fetch(API+"/orders");`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer app.Close()

	without := Run(context.Background(), Options{Site: app.URL, Concurrency: 2})
	if backendHits.Load() != 0 {
		t.Fatal("a bundle mention widened scope and sent traffic to another origin")
	}
	if len(without.Origins) != 1 || without.Origins[0].Probed {
		t.Fatalf("the unscoped origin was not reported as skipped: %+v", without.Origins)
	}

	_ = Run(context.Background(), Options{
		Site: app.URL, AllowedOrigins: []string{backend.URL}, Concurrency: 2,
	})
	if backendHits.Load() == 0 {
		t.Fatal("the exact origin explicitly placed in scope was not probed")
	}
}

func TestFamiliesNeverCrossOriginBoundaries(t *testing.T) {
	fs := groupIntoFamilies([]Route{
		{Base: "https://one.example", Path: "/admin/a", GET: 401},
		{Base: "https://one.example", Path: "/admin/b", GET: 401},
		{Base: "https://two.example", Path: "/admin/open", GET: 200},
	})
	for _, f := range fs {
		if f.Inconsistent() {
			t.Fatalf("responses from two origins were combined into one family: %+v", f)
		}
	}
}

func TestConcurrentScansKeepTheirClientsAndLedgersSeparate(t *testing.T) {
	newApp := func(path string) (*httptest.Server, *atomic.Int64) {
		hits := &atomic.Int64{}
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == path {
				hits.Add(1)
				w.Write([]byte(`{"ok":true}`))
				return
			}
			if r.URL.Path == "/" {
				w.Write([]byte(`fetch("` + path + `")`))
				return
			}
			w.WriteHeader(http.StatusNotFound)
		}))
		return srv, hits
	}
	one, oneHits := newApp("/one")
	two, twoHits := newApp("/two")
	defer one.Close()
	defer two.Close()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); _ = Run(context.Background(), Options{Site: one.URL}) }()
	go func() { defer wg.Done(); _ = Run(context.Background(), Options{Site: two.URL}) }()
	wg.Wait()

	if oneHits.Load() == 0 || twoHits.Load() == 0 {
		t.Fatalf("concurrent scans crossed clients: one=%d two=%d", oneHits.Load(), twoHits.Load())
	}
}

func TestRouteLimitIsFairAcrossOrigins(t *testing.T) {
	refs := []endpointRef{
		{Base: "https://a.example", Path: "/1"},
		{Base: "https://a.example", Path: "/2"},
		{Base: "https://a.example", Path: "/3"},
		{Base: "https://b.example", Path: "/only"},
	}
	got := fairTargets(refs, 2)
	if len(got) != 2 || got[0].Base == got[1].Base {
		t.Fatalf("the first origin exhausted the bound: %+v", got)
	}
}

func TestBypassLimitIsFairAcrossOrigins(t *testing.T) {
	routes := []Route{
		{Base: "https://a.example", Path: "/1", GET: 401},
		{Base: "https://a.example", Path: "/2", GET: 401},
		{Base: "https://b.example", Path: "/only", GET: 403},
	}
	got := fairRefusedRoutes(routes, 2)
	if len(got) != 2 || got[0].Base == got[1].Base {
		t.Fatalf("one origin exhausted the bypass allowance: %+v", got)
	}
}

func TestBypassControlsAreSharedPerOrigin(t *testing.T) {
	var catchAllHits atomic.Int64
	app := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Write([]byte(`fetch("/admin/a");fetch("/admin/b");fetch("/admin/c")`))
		case "/unruly_control_path_that_cannot_exist":
			catchAllHits.Add(1)
			w.WriteHeader(http.StatusNotFound)
		default:
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(`{"error":"login required"}`))
		}
	}))
	defer app.Close()

	_ = Run(context.Background(), Options{
		Site: app.URL, MaxRoutes: 3, MaxBypassRoutes: 3, Concurrency: 1,
	})
	if catchAllHits.Load() != 1 {
		t.Fatalf("origin-level catch-all control was repeated %d times", catchAllHits.Load())
	}
}

func TestRouteBudgetTruncationIsReported(t *testing.T) {
	app := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			w.Write([]byte(`fetch("/a");fetch("/b")`))
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer app.Close()

	got := Run(context.Background(), Options{Site: app.URL, MaxRoutes: 1, Concurrency: 1})
	for _, f := range got.Findings {
		if f.ID == "unruly-probe-budget-exhausted" && f.Resource == "application-routes" {
			return
		}
	}
	t.Fatal("a truncated application inventory was reported as complete")
}

func TestEntryURLPathDoesNotBecomeTheOrigin(t *testing.T) {
	var bundleHits atomic.Int64
	app := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/secret-entry":
			w.Write([]byte(`<script src="/static/app.js"></script>`))
		case "/static/app.js":
			bundleHits.Add(1)
			w.Write([]byte(`fetch("/api/orders")`))
		case "/api/orders":
			w.Write([]byte(`{"orders":[]}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer app.Close()

	got := Run(context.Background(), Options{Site: app.URL + "/secret-entry", Concurrency: 1})
	if bundleHits.Load() == 0 {
		t.Fatal("root-relative bundle was requested below the entry path instead of the origin")
	}
	for _, r := range got.Routes {
		if r.Base == app.URL && r.Path == "/api/orders" && r.GET == 200 {
			return
		}
	}
	t.Fatalf("route from a path-based entry page was not probed: %+v", got.Routes)
}

func TestAllowedOriginAlsoNominatesSpecDiscovery(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/openapi.json":
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"openapi":"3.0.0","paths":{"/private/report":{"get":{}}}}`))
		case "/private/report":
			w.Write([]byte(`{"ok":true}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer backend.Close()
	app := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/entry" {
			w.Write([]byte(`<html>no backend literal here</html>`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer app.Close()

	got := Run(context.Background(), Options{
		Site: app.URL + "/entry", AllowedOrigins: []string{backend.URL}, Concurrency: 1,
	})
	for _, r := range got.Routes {
		if r.Base == backend.URL && r.Path == "/private/report" && r.GET == 200 {
			return
		}
	}
	t.Fatalf("explicit origin was authorized but never used for spec discovery: %+v", got.Routes)
}
