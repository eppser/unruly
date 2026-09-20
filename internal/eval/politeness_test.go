package eval_test

import (
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"sync/atomic"
	"testing"
)

// A site that refuses everything must stop being asked.
//
// The backend path has honoured this for a long time: 25 consecutive refusals
// with nothing usable in between opens a circuit breaker, and the scan stops
// sending. The application path did not, because it was never on the same
// client -- discover, enumerate/vocab and routes each built their own bare
// http.Client with no retry policy, no breaker, and no shared transport.
//
// Measured before this was fixed: a host answering 429 with Retry-After: 0 to
// every request received 131 of them, roughly two thirds speculative route
// probes, with no backoff and nothing to stop it. On the same run the database
// on the other end of the scan was treated correctly.
//
// That asymmetry is backwards. The website and the database belong to the same
// person, and they did not consent twice. A scanner that measures how hard it
// can push someone's CDN has already done the damage it exists to warn about.
//
// The bound here is deliberately loose -- several subsystems each get their own
// breaker, and they run concurrently, so the total is a multiple of the budget
// rather than the budget itself. It is set where it separates "stopped" from
// "ran the whole plan against a wall", which is the property that matters.
func TestASiteThatRefusesEverythingStopsBeingAsked(t *testing.T) {
	var n atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n.Add(1)
		// Retry-After: 0 removes backoff delay from the measurement, so what
		// is left is purely "did it keep asking".
		w.Header().Set("Retry-After", "0")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

	bin := buildScanner(t)
	cmd := exec.Command(bin, "-u", "http://127.0.0.1:1",
		"-k", "eyJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoiYW5vbiJ9.x",
		"-s", srv.URL, "-silent", "-j",
		"-o", filepath.Join(t.TempDir(), "r.json"))
	cmd.Env = append(os.Environ(), "SUPABASE_ANON_KEY=")
	_ = cmd.Run()

	const limit = 100
	if got := n.Load(); got > limit {
		t.Errorf("a site that answered 429 to every request received %d of them "+
			"(limit %d): the application path is not honouring the refusal budget "+
			"the backend path has honoured all along", got, limit)
	}
	if n.Load() == 0 {
		t.Fatal("the site received no requests at all, so this test measured nothing")
	}
}

// And the politeness must not be bought by breaking discovery.
//
// Without this half, the assertion above is satisfied perfectly by a scanner
// that never fetches an application at all. Against a site that ANSWERS, the
// same scan must still read the page, read its bundles, and use the routes
// those bundles contain. Vocabulary harvesting belongs to a selected backend;
// doing it for a target with no such backend just repeats reads and consumes
// tokens that have no downstream consumer.
func TestARespondingSiteStillHasItsBundleInspected(t *testing.T) {
	var bundles, routes atomic.Int64
	mux := http.NewServeMux()
	mux.HandleFunc("/app.js", func(w http.ResponseWriter, r *http.Request) {
		bundles.Add(1)
		// A domain-specific name no pinned wordlist would guess.
		w.Write([]byte(`const q = "/api/quokka_sightings";`))
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/quokka_sightings" {
			routes.Add(1)
		}
		w.Write([]byte(`<html><head><script src="/app.js"></script></head><body>hi</body></html>`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	bin := buildScanner(t)
	out := filepath.Join(t.TempDir(), "r.json")
	cmd := exec.Command(bin, "-u", "http://127.0.0.1:1",
		"-k", "eyJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoiYW5vbiJ9.x",
		"-s", srv.URL, "-j", "-o", out)
	cmd.Env = append(os.Environ(), "SUPABASE_ANON_KEY=")
	_ = cmd.Run()

	if bundles.Load() == 0 {
		t.Error("the scan never read the application's bundle, so no vocabulary could " +
			"be harvested from it")
	}
	// The path has to reach probing, not just the fetch. Asserting on the bundle
	// read alone would pass while extraction was dropped on the floor.
	if routes.Load() == 0 {
		t.Error("the application route named only in the bundle was never probed")
	}
}

// A site that throttles briefly must still be read.
//
// The refusal-budget test above proves the scan STOPS when a site refuses
// everything. This proves the opposite half, which is where the retry policy
// earns its place: a site that answers 429 to the first request for its bundle
// and serves it on the second must still be harvested.
//
// Before application traffic moved onto the shared client there was no retry
// policy on this path at all -- one 429 and the bundle was gone, taking with
// it every domain-specific relation name that bundle contained. Silent, and
// worth 21 relations against 2 on the reference project.
//
// A single 429 is not hypothetical. It is what a CDN in front of somebody's
// marketing site does to a burst of requests from one address, which is
// exactly what a scan looks like.
func TestASiteThatThrottlesBrieflyStillHasItsBundleInspected(t *testing.T) {
	var asked, served, routes atomic.Int64
	mux := http.NewServeMux()
	mux.HandleFunc("/app.js", func(w http.ResponseWriter, r *http.Request) {
		// Refuse the first TWO asks, then behave. Deterministic on purpose: a
		// random refusal makes a flaky test, and a flaky test teaches people to
		// re-run rather than to look.
		//
		// Two, not one, and the number is the whole test. Two stages read this
		// bundle independently -- discovery looking for credentials, harvesting
		// looking for vocabulary -- so a single refusal is absorbed by whichever
		// stage asks second, with or without a retry policy. The first version
		// of this test refused once and passed with retries disabled, proving
		// nothing while appearing to prove the thing it was named for.
		//
		// At two, the first stage exhausts its one retry and still fails, and
		// only the retry budget of the second gets the file. Remove -retries
		// and the route inventory is gone.
		if asked.Add(1) <= 2 {
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		served.Add(1)
		w.Write([]byte(`const q = "/api/quokka_sightings";`))
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/quokka_sightings" {
			routes.Add(1)
		}
		w.Write([]byte(`<html><head><script src="/app.js"></script></head><body>hi</body></html>`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	bin := buildScanner(t)
	cmd := exec.Command(bin, "-u", "http://127.0.0.1:1",
		"-k", "eyJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoiYW5vbiJ9.x",
		"-s", srv.URL, "-j", "-o", filepath.Join(t.TempDir(), "r.json"))
	cmd.Env = append(os.Environ(), "SUPABASE_ANON_KEY=")
	_ = cmd.Run()

	if served.Load() == 0 {
		t.Errorf("the bundle was refused twice and never successfully read (%d asks): "+
			"a brief throttle from a CDN is enough to lose an application's entire "+
			"route inventory", asked.Load())
	}
	if routes.Load() == 0 {
		t.Error("the route from the eventually served bundle was never probed")
	}
}
