package routes

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/eppser/unruly/internal/client"
)

func writeHAR(t *testing.T, entries string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "runtime.har")
	body := `{"log":{"entries":[` + entries + `]}}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func harEntry(method, rawURL string) string {
	return fmt.Sprintf(`{"request":{"method":%q,"url":%q,"headers":[{"name":"Authorization","value":"secret"}],"postData":{"text":"private"}},"response":{"content":{"text":"private-response"}}}`,
		method, rawURL)
}

func TestHARIngestsOnlyRouteIdentity(t *testing.T) {
	path := writeHAR(t, harEntry("GET", "https://app.test/api/orders/42?token=secret")+","+
		harEntry("POST", "https://api.test/admin/run"))
	refs, origins, errs := harRefs([]string{path}, "https://app.test/path")
	if len(errs) != 0 || len(refs) != 2 || len(origins) != 1 {
		t.Fatalf("refs=%+v origins=%v errs=%v", refs, origins, errs)
	}
	if refs[0].Base != "https://api.test" || refs[0].Path != "/admin/run" ||
		refs[1].Path != "/api/orders/42" {
		t.Fatalf("runtime routes were not canonicalized: %+v", refs)
	}
	for _, ref := range refs {
		if ref.Source != sourceHAR {
			t.Errorf("source=%q, want %q", ref.Source, sourceHAR)
		}
		if ref.Path == "secret" {
			t.Fatal("HAR credentials or bodies entered route identity")
		}
	}
}

func TestHARCrossOriginNeverWidensScope(t *testing.T) {
	var crossRequests atomic.Int64
	cross := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		crossRequests.Add(1)
		w.WriteHeader(http.StatusNotFound)
	}))
	defer cross.Close()
	site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			_, _ = w.Write([]byte("<html></html>"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer site.Close()
	path := writeHAR(t, harEntry("GET", cross.URL+"/api/private"))

	web := client.NewApplication(client.AppOptions{Site: site.URL, Concurrency: 4})
	r := Run(context.Background(), Options{Site: site.URL, HARFiles: []string{path},
		Web: web, Concurrency: 4, MaxBundles: 1, MaxRoutes: 10, MaxBypassRoutes: 1})
	withoutConsent := crossRequests.Load()
	if withoutConsent != 0 {
		t.Fatalf("HAR widened scope and sent %d cross-origin requests", withoutConsent)
	}
	if len(r.Origins) != 1 || r.Origins[0].Probed {
		t.Fatalf("out-of-scope HAR origin was not disclosed: %+v", r.Origins)
	}

	web = client.NewApplication(client.AppOptions{Site: site.URL, Concurrency: 4})
	_ = Run(context.Background(), Options{Site: site.URL, HARFiles: []string{path},
		AllowedOrigins: []string{cross.URL}, Web: web, Concurrency: 4,
		MaxBundles: 1, MaxRoutes: 10, MaxBypassRoutes: 1})
	withConsent := crossRequests.Load()
	if withConsent <= withoutConsent {
		t.Fatal("an explicitly allowed HAR origin was never probed")
	}
}

func TestMalformedHARIsACoverageGap(t *testing.T) {
	path := filepath.Join(t.TempDir(), "broken.har")
	if err := os.WriteFile(path, []byte(`{"not":"a har"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("<html></html>"))
	}))
	defer site.Close()
	r := Run(context.Background(), Options{Site: site.URL, HARFiles: []string{path},
		Concurrency: 2, MaxBundles: 1, MaxRoutes: 1, MaxBypassRoutes: 1})
	for _, f := range r.Findings {
		if f.ID == "unruly-surface-not-assessed" && f.Resource == "routes:har" {
			return
		}
	}
	t.Fatalf("malformed runtime inventory disappeared: %+v", r.Findings)
}

func TestHARRoutesStillObeyPOSTConsent(t *testing.T) {
	var mu sync.Mutex
	var methods []string
	site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/runtime-action" {
			mu.Lock()
			methods = append(methods, r.Method)
			mu.Unlock()
			_, _ = w.Write([]byte(`{"ok":true}`))
			return
		}
		if r.URL.Path == "/" {
			_, _ = w.Write([]byte("<html></html>"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer site.Close()
	path := writeHAR(t, harEntry("POST", site.URL+"/api/runtime-action"))

	run := func(allow, noResidue bool) []string {
		mu.Lock()
		methods = nil
		mu.Unlock()
		_ = Run(context.Background(), Options{Site: site.URL, HARFiles: []string{path},
			AllowPOST: allow, NoResidue: noResidue, Concurrency: 2,
			MaxBundles: 1, MaxRoutes: 10, MaxBypassRoutes: 1})
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), methods...)
	}
	for _, tc := range []struct {
		allow, noResidue bool
		wantPOST         bool
	}{{false, false, false}, {true, true, false}, {true, false, true}} {
		got := run(tc.allow, tc.noResidue)
		sawPOST := false
		for _, method := range got {
			sawPOST = sawPOST || method == http.MethodPost
		}
		if sawPOST != tc.wantPOST {
			t.Errorf("allow=%v noResidue=%v methods=%v", tc.allow, tc.noResidue, got)
		}
	}
}
