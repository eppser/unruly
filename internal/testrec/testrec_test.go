package testrec_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"sync"
	"testing"

	"github.com/eppser/unruly/internal/testrec"
)

// The point of the package is that concurrent handlers do not lose entries.
// Run it through a real server so the goroutines are the ones net/http makes,
// not ones this test arranges to be convenient.
func TestLogKeepsEveryEntryUnderConcurrentHandlers(t *testing.T) {
	var log testrec.Log
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Add(r.URL.Path)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	const n = 200
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			resp, err := http.Get(fmt.Sprintf("%s/p%03d", srv.URL, i))
			if err != nil {
				return
			}
			resp.Body.Close()
		}(i)
	}
	wg.Wait()

	if got := log.Len(); got != n {
		t.Fatalf("recorded %d of %d requests: a dropped entry means an assertion "+
			"downstream is describing evidence that was never collected", got, n)
	}
	seen := log.Entries()
	sort.Strings(seen)
	for i := 0; i < n; i++ {
		want := fmt.Sprintf("/p%03d", i)
		if seen[i] != want {
			t.Fatalf("entry %d = %q, want %q", i, seen[i], want)
		}
	}
}

// Entries must hand back a copy: a caller that sorts or truncates what it gets
// must not be editing the recorder, and must not be reading a slice the server
// may still be appending to.
func TestEntriesIsACopy(t *testing.T) {
	var log testrec.Log
	log.Add("b")
	log.Add("a")
	got := log.Entries()
	sort.Strings(got)
	got[0] = "clobbered"
	if e := log.Entries(); e[0] != "b" || e[1] != "a" {
		t.Fatalf("caller edited the recorder through Entries: %v", e)
	}
}

func TestLastAndHasAndCount(t *testing.T) {
	var log testrec.Log
	if log.Last() != "" {
		t.Fatalf("empty log should have no last entry")
	}
	log.Add("GET /rls_disabled")
	log.Add("GET /rls_enabled")
	if log.Last() != "GET /rls_enabled" {
		t.Fatalf("Last = %q", log.Last())
	}
	if !log.Has("rls_disabled") {
		t.Fatalf("Has missed a recorded entry")
	}
	if log.Has("open_guestbook") {
		t.Fatalf("Has invented an entry")
	}
	if n := log.Count("GET "); n != 2 {
		t.Fatalf("Count = %d, want 2", n)
	}
}
