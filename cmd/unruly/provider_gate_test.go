package main

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/eppser/unruly/internal/finding"
)

// Provider selection is a traffic boundary, not only a choice of findings.
// A forgotten ambient key must not cause even the two PostgREST prefix probes
// to reach a plain application.
func TestNonSupabaseTargetSendsNoPostgRESTProbeAndStillHasASummary(t *testing.T) {
	var mu sync.Mutex
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		paths = append(paths, r.URL.Path)
		mu.Unlock()
		http.NotFound(w, r)
	}))
	defer srv.Close()

	o := &options{
		target: srv.URL, site: srv.URL,
		anonKey: "eyJhbGciOiJIUzI1NiJ9.e30.x", keyFromEnv: true,
		restPrefix: defaultRestPrefix,
		timeout:    2, concurrency: 2, rateLimit: 1000,
		maxBundles: 1, maxRoutes: 5, maxBypassRoutes: 1,
		maxSeeds: 10, maxCollections: 1,
		userAgent: "unruly-provider-gate-test",
	}
	var report bytes.Buffer
	_, _, _, err := scanTarget(context.Background(), o, finding.Writers{{
		Out: &report, Agent: true, NoColor: true, MinSev: finding.Info,
	}})
	if err != nil {
		t.Fatalf("plain application scan failed: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	for _, p := range paths {
		if strings.HasPrefix(p, defaultRestPrefix) {
			t.Fatalf("non-Supabase target received a PostgREST probe at %q; all paths: %v", p, paths)
		}
	}
	if !bytes.Contains(report.Bytes(), []byte(`"id":"unruly-scan-summary"`)) {
		t.Fatalf("agent artifact has no scan denominator:\n%s", report.Bytes())
	}
	if !bytes.Contains(report.Bytes(), []byte("application routes")) {
		t.Fatalf("agent summary does not describe the application assessment:\n%s", report.Bytes())
	}
}
