package probe

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/eppser/unruly/internal/client"
)

// A target that answers every name identically is not swept candidate by
// candidate.
//
// Measured against a live Neon Data API: an unauthenticated caller is refused
// before the endpoint looks at the table, so all 3508 candidates answer 400.
// The scan spent 1200 of them establishing that, having already been told by
// the enumerator that absent and present relations could not be shown to
// differ. Every one of those went to somebody's project to learn nothing.
func TestAUniformTargetIsNotSweptCandidateByCandidate(t *testing.T) {
	var seen int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&seen, 1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"message":"missing authentication credentials"}`))
	}))
	defer srv.Close()

	names := make([]string, 60)
	for i := range names {
		names[i] = fmt.Sprintf("relation_%02d", i)
	}
	res := Run(context.Background(), probeControlClient(srv.URL), names, Options{})

	if got := atomic.LoadInt64(&seen); got > int64(controlSampleSize)+1 {
		t.Errorf("the stage sent %d requests across %d candidates that all answer the "+
			"same way; the control plus %d candidates settles it",
			got, len(names), controlSampleSize)
	}
	if res.Discriminating {
		t.Error("a target that answers every name identically was called discriminating")
	}
	if res.ControlDetail == "" {
		t.Error("nothing says why the sweep was abandoned; an empty relation list with " +
			"no reason reads as a project with nothing in it")
	}
}

// A target whose relations answer DIFFERENTLY is still swept.
//
// The half that protects recall. Without it the bound above is a way to make
// every scan cheap by refusing to look. Corpus project 07 runs a proxy that
// destroys PostgREST's error semantics and is still probed to 75% recall,
// because its relations answer differently from each other even when none
// answers correctly.
func TestATargetThatDistinguishesRelationsIsStillProbed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/relation_07" {
			w.Header().Set("Content-Range", "0-0/1")
			w.WriteHeader(http.StatusPartialContent)
			_, _ = w.Write([]byte(`[{"id":1,"email":"a@example.invalid"}]`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"code":"PGRST205","message":"Could not find the table"}`))
	}))
	defer srv.Close()

	names := make([]string, 60)
	for i := range names {
		names[i] = fmt.Sprintf("relation_%02d", i)
	}
	res := Run(context.Background(), probeControlClient(srv.URL), names, Options{})

	if !res.Discriminating {
		t.Fatal("a target that answers an absent name 404 and a present one with rows " +
			"was called non-discriminating, so nothing was probed")
	}
	var found bool
	for _, r := range res.Relations {
		if r.Name == "relation_07" {
			found = true
		}
	}
	if !found {
		t.Error("relation_07 returns rows and was not probed: the bound bought its " +
			"cheapness by not looking")
	}
}

func probeControlClient(base string) *client.Client {
	return client.New(client.Options{
		BaseURL: base, RestPrefix: "/", UserAgent: "unruly-test",
		Limiter: client.NewLimiter(0),
	})
}
