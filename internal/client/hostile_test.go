package client

import (
	"github.com/eppser/unruly/internal/testrec"

	"bytes"
	"compress/gzip"
	"context"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"testing"
	"time"
)

// This client points at hosts nobody controls -- that is the entire purpose --
// and it carries the operator's credentials on every request. So the responses
// it must survive are not merely malformed, they are adversarial.

// A host that answers 302 must not be able to harvest the project credential.
//
// Go strips Authorization when a redirect crosses domains. It does NOT strip
// custom headers, and Supabase's apikey is one. Measured before the fix: a
// redirect from the target to a second origin delivered
// apikey="SECRET-PROJECT-KEY" and the bearer token to that origin.
func TestRedirectCannotHarvestTheCredential(t *testing.T) {
	var forwarded testrec.Log
	collector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for _, h := range []string{"apikey", "Authorization"} {
			if v := r.Header.Get(h); v != "" {
				forwarded.Add(h + ": " + v)
			}
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`[]`))
	}))
	defer collector.Close()

	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, collector.URL+"/collect", http.StatusFound)
	}))
	defer target.Close()

	c := New(Options{BaseURL: target.URL, AnonKey: "SECRET-PROJECT-KEY", RestPrefix: "/"})
	resp := c.Get(context.Background(), c.RestURL("anything"), nil)

	if forwarded.Len() > 0 {
		t.Errorf("a host that answers 302 received the credential: %v. "+
			"A scanner that hands the operator's key to the thing it is scanning is a "+
			"liability whatever else it gets right.", forwarded.Entries())
	}
	// The redirect itself is the answer, and it must be visible rather than
	// silently followed into someone else's 200.
	if resp.Status != http.StatusFound {
		t.Errorf("status %d: the 302 is the interesting answer and must reach the caller",
			resp.Status)
	}
}

// A response far larger than anything a finding quotes must not be read into
// memory whole.
func TestOversizedBodyIsBounded(t *testing.T) {
	const huge = 64 << 20 // 64MB, well past maxBody and drainLimit
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		chunk := strings.Repeat("A", 1<<20)
		for i := 0; i < huge>>20; i++ {
			if _, err := w.Write([]byte(chunk)); err != nil {
				return
			}
		}
	}))
	defer srv.Close()

	c := New(Options{BaseURL: srv.URL, AnonKey: "k", RestPrefix: "/", Timeout: 30 * time.Second})
	resp := c.Get(context.Background(), c.RestURL("huge"), nil)

	if resp.Err != nil {
		t.Fatalf("the request should complete, not error: %v", resp.Err)
	}
	if len(resp.Body) > maxBody {
		t.Errorf("kept %d bytes, cap is %d: findings quote samples, not whole tables",
			len(resp.Body), maxBody)
	}
}

// A host that accepts the connection and then says nothing must not hang the
// scan. Without a deadline one unresponsive relation stalls everything behind
// it.
func TestSilentHostDoesNotHangTheScan(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release // never answers within the client's timeout
	}))
	defer func() { close(release); srv.Close() }()

	c := New(Options{
		BaseURL: srv.URL, AnonKey: "k", RestPrefix: "/",
		Timeout: 300 * time.Millisecond, Retries: 0,
	})

	done := make(chan Response, 1)
	go func() { done <- c.Get(context.Background(), c.RestURL("silent"), nil) }()

	select {
	case resp := <-done:
		if resp.Err == nil {
			t.Error("a host that never answers must surface as an error, not as an empty " +
				"result: an unanswered probe is not a measured absence")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the client hung on a silent host; one unresponsive relation would stall " +
			"every probe behind it")
	}
}

// A compressed response that expands enormously must not be read into memory.
//
// Go's transport decompresses gzip transparently, so the byte limits apply to
// the DECOMPRESSED stream -- which is what makes them adequate here, and what
// makes replacing the LimitReader with a plain ReadAll a memory-exhaustion bug
// rather than a tidy-up. Measured: 509KB on the wire, 512MB expanded, and the
// client keeps maxBody and moves on.
func TestDecompressionBombIsBounded(t *testing.T) {
	var zipped bytes.Buffer
	zw := gzip.NewWriter(&zipped)
	chunk := []byte(strings.Repeat("\x00", 1<<20))
	for i := 0; i < 512; i++ {
		if _, err := zw.Write(chunk); err != nil {
			t.Fatalf("building the bomb: %v", err)
		}
	}
	zw.Close()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write(zipped.Bytes())
	}))
	defer srv.Close()

	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)

	c := New(Options{BaseURL: srv.URL, AnonKey: "k", RestPrefix: "/", Timeout: 60 * time.Second})
	resp := c.Get(context.Background(), c.RestURL("bomb"), nil)

	runtime.ReadMemStats(&after)
	grownMB := int64(after.TotalAlloc-before.TotalAlloc) >> 20

	if len(resp.Body) > maxBody {
		t.Errorf("kept %d bytes of a 512MB expansion, cap is %d", len(resp.Body), maxBody)
	}
	// maxBody + drainLimit is ~9MB; anything near the expanded size means the
	// whole bomb was materialised.
	if grownMB > 64 {
		t.Errorf("heap grew %d MB reading a 512MB expansion: the limits are being applied "+
			"after the stream was already materialised", grownMB)
	}
}
