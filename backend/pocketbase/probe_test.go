package pocketbase

import (
	"context"
	"time"

	"github.com/eppser/unruly/internal/client"
	"net/http"
	"net/http/httptest"
	"testing"
)

// A collection that returns 200 with an EMPTY items array is not exposed.
//
// PocketBase rules can be expressions. `id = @request.auth.id` on the default
// users collection filters every row away for an anonymous caller and still
// answers 200 with {"items":[],"totalItems":0}. Measured on the lab: treating
// that 200 as a read exposure would report the DEFAULT users collection as
// leaking on every PocketBase target in the world.
//
// It is the PostgREST lesson -- a 200 with content-range */0 is a filtered
// empty result -- arriving unchanged in a backend that shares no code with it.
func TestAFilteredEmptyListIsNotAReadExposure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"items":[],"page":1,"perPage":1,"totalItems":0,"totalPages":0}`))
	}))
	defer srv.Close()

	got := ReadState(context.Background(), pbTestClient(srv.URL), srv.URL, "users")
	if got.Exposed {
		t.Error("a 200 with zero rows was reported as a read exposure; the default " +
			"users collection answers exactly this way on every PocketBase install")
	}
	if !got.Reached {
		t.Error("the collection answered and must be recorded as reached: it is not " +
			"exposed, which is a different fact from not having been examined")
	}
}

// Rows actually returned ARE an exposure, and the rows are the evidence.
func TestRowsReturnedAreAReadExposureAndBecomeEvidence(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"items":[{"id":"a1","secret":"card-4111111111111111"}],` +
			`"page":1,"perPage":1,"totalItems":1,"totalPages":1}`))
	}))
	defer srv.Close()

	got := ReadState(context.Background(), pbTestClient(srv.URL), srv.URL, "public_notes")
	if !got.Exposed {
		t.Fatal("rows came back to an anonymous caller and were not reported")
	}
	if len(got.Sample) == 0 {
		t.Error("no sampled row: a finding without evidence is the boolean this " +
			"scanner refuses to emit")
	}
}

// 403 proves DENIAL. 404 proves nothing.
//
// This is the correction that matters most. A fake-id verb returns 404 both
// when the rule is open AND when an expression rule filtered the caller out --
// measured byte-identical bodies on the lab, "The requested resource wasn't
// found." in both cases. Only 403 "Only superusers can perform this action."
// is conclusive, and it is conclusive in the NEGATIVE.
//
// A scanner that read 404 as permission would claim update exposure on the
// default users collection of every PocketBase deployment.
func TestOnlyA403IsConclusiveAndItProvesDenial(t *testing.T) {
	cases := []struct {
		name       string
		status     int
		body       string
		wantDenied bool
	}{
		{"null rule, superuser only", 403,
			`{"message":"Only superusers can perform this action.","status":403}`, true},
		{"open rule, absent record", 404,
			`{"message":"The requested resource wasn't found.","status":404}`, false},
		{"expression rule filtered the caller out", 404,
			`{"message":"The requested resource wasn't found.","status":404}`, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(c.status)
				_, _ = w.Write([]byte(c.body))
			}))
			defer srv.Close()

			v := VerbState(context.Background(), pbTestClient(srv.URL), srv.URL, "x", "PATCH")
			if v.Denied != c.wantDenied {
				t.Errorf("Denied=%v, want %v", v.Denied, c.wantDenied)
			}
			// The crucial property: a 404 must never be recorded as proof of
			// permission. Permission requires acting on a REAL record, which
			// is destructive and stays behind -write.
			if v.Permitted {
				t.Error("permission was claimed from a status code alone; only a real " +
					"write against a real record can establish it")
			}
		})
	}
}

// pbTestClient forwards every control a caller would, which is why the probes
// take a client instead of making one.
func pbTestClient(base string) *client.Client {
	return client.New(client.Options{
		BaseURL:    base,
		RestPrefix: "/",
		Timeout:    5 * time.Second,
		UserAgent:  "unruly-test",
		Limiter:    client.NewLimiter(0),
	})
}
