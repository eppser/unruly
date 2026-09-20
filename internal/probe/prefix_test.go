package probe

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/eppser/unruly/internal/client"
)

// The three answers the two probes can produce, each graded against a server
// shaped like the deployment it represents.
//
// This is unit-graded rather than fixture-graded because the third case --
// PostgREST mounted somewhere neither the default nor the root, or serving no
// OpenAPI document -- is a real self-hosted configuration that no fixture in
// this repository has. Shipping that branch without grading it would leave the
// scan's stop condition resting on an argument rather than a measurement.
func TestResolveRestPrefixVerdicts(t *testing.T) {
	const pgrst125 = `{"code":"PGRST125","details":null,"hint":null,` +
		`"message":"Invalid path specified in request URL"}`
	const openapi = `{"swagger":"2.0","info":{"title":"standard public schema"},` +
		`"basePath":"/","paths":{"/open_no_rls":{}}}`

	cases := []struct {
		name    string
		handler http.HandlerFunc
		want    PrefixVerdict
		wantTo  string
		why     string
	}{{
		name: "managed layout answers normally",
		handler: func(w http.ResponseWriter, r *http.Request) {
			// The managed root is service_role-only, so it answers 401 -- not
			// PGRST125. Every managed project takes this path and must not be
			// moved anywhere.
			w.WriteHeader(http.StatusUnauthorized)
		},
		want: PrefixOK,
		why:  "a 401 at the REST root is the managed product working; moving would break every real scan",
	}, {
		name: "bare PostgREST at the root",
		handler: func(w http.ResponseWriter, r *http.Request) {
			if strings.HasPrefix(r.URL.Path, "/rest/v1") {
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write([]byte(pgrst125))
				return
			}
			_, _ = w.Write([]byte(openapi))
		},
		want:   PrefixMoved,
		wantTo: "/",
		why:    "PostgREST said the prefix is wrong and introduced itself at the root",
	}, {
		name: "wrong prefix, nothing at the root either",
		handler: func(w http.ResponseWriter, r *http.Request) {
			if strings.HasPrefix(r.URL.Path, "/rest/v1") {
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write([]byte(pgrst125))
				return
			}
			// Mounted at some third path, or serving no OpenAPI document.
			w.WriteHeader(http.StatusNotFound)
		},
		want: PrefixWrongAndUnresolved,
		why:  "continuing would send the whole plan to a path the server has already rejected",
	}, {
		name: "an SPA answering 200 to everything",
		handler: func(w http.ResponseWriter, r *http.Request) {
			if strings.HasPrefix(r.URL.Path, "/rest/v1") {
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write([]byte(pgrst125))
				return
			}
			_, _ = w.Write([]byte("<!doctype html><html><body>app</body></html>"))
		},
		want: PrefixWrongAndUnresolved,
		why: "a single-page app returns 200 to every path; adopting on a 200 alone " +
			"would point the whole scan at a static site",
	}}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(tc.handler)
			defer srv.Close()
			c := client.New(client.Options{BaseURL: srv.URL, Retries: 0})

			got, to, verdict := ResolveRestPrefix(context.Background(), c)
			if verdict != tc.want {
				t.Errorf("verdict = %v, want %v: %s", verdict, tc.want, tc.why)
			}
			if to != tc.wantTo {
				t.Errorf("prefix = %q, want %q", to, tc.wantTo)
			}
			if tc.want == PrefixMoved && got.RestBase() != srv.URL {
				t.Errorf("moved client addresses %q, want the root %q", got.RestBase(), srv.URL)
			}
			if tc.want != PrefixMoved && got.RestBase() != srv.URL+"/rest/v1" {
				t.Errorf("client was moved to %q when it should not have been", got.RestBase())
			}
		})
	}
}
