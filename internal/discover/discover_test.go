package discover

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// The URL a credential was found at must be fetchable.
//
// assets.Scripts already returns absolute URLs -- SameOrigin hands back
// u.String() for an absolute reference and base.ResolveReference for a relative
// one -- so prepending the site produced
//
//	https://site.example/https://site.example/assets/index-a1b2.js
//
// That string is res.KeySource, and it becomes the Matched URL of the
// service_role and management-token findings, so the evidence address on a
// critical finding did not resolve. The asset was fetched via the correct URL,
// which is why only the report was wrong and nothing failed loudly.
func TestCredentialSourceURLIsNotDoubled(t *testing.T) {
	// Shape only: role anon, signature not verified by anything here. CI's
	// secret scan excludes _test.go for exactly this reason.
	const anon = "eyJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoiYW5vbiJ9.QUJDREVGR0hJSktMTU5PUA"

	var siteURL string
	mux := http.NewServeMux()
	mux.HandleFunc("/assets/app.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		fmt.Fprintf(w, "const k=%q;", anon)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// An ABSOLUTE src, which is what a built bundle commonly emits and the
		// case the join bug needed.
		fmt.Fprintf(w, `<html><body><script src="%s/assets/app.js"></script></body></html>`,
			siteURL)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	siteURL = srv.URL

	res := Run(context.Background(), Options{Site: srv.URL, MaxBundles: 5})

	if res.KeySource == "" {
		t.Fatal("no credential recovered, so this test asserts nothing about where " +
			"one was found; the fixture is not exercising the bundle path")
	}
	if n := strings.Count(res.KeySource, "http"); n != 1 {
		t.Errorf("key source is a doubled URL: %s", res.KeySource)
	}
	if _, err := url.Parse(res.KeySource); err != nil {
		t.Errorf("key source does not parse: %v", err)
	}
	// The strongest form of the assertion: the address the report gives must
	// actually serve the asset the credential came from.
	resp, err := http.Get(res.KeySource)
	if err != nil {
		t.Fatalf("reported source is not fetchable: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("reported source %s answered %d; evidence has to resolve",
			res.KeySource, resp.StatusCode)
	}
}
