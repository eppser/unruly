package history

import (
	"bytes"
	"compress/gzip"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// Regression: the Wayback Machine serves archived assets gzip-encoded.
//
// During the research phase a shell sweep of 80 archived scripts reported zero
// credentials and was believed. curl without --compressed hands back raw gzip,
// so the pattern match ran against binary and found nothing — a false negative
// that read as a clean bill of health.
//
// Go's transport negotiates and decodes gzip transparently, but only while the
// caller leaves Accept-Encoding alone. Setting that header by hand disables the
// automatic decode and silently reintroduces the bug, so this test pins the
// behaviour rather than the intention.
func TestArchivedContentIsDecompressed(t *testing.T) {
	const secret = "eyJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoiYW5vbiJ9.QUJDREVGR0hJSktMTU5PUA"

	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write([]byte(`createClient("https://abc.supabase.co","` + secret + `")`)); err != nil {
		t.Fatal(err)
	}
	zw.Close()
	payload := buf.Bytes()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Mirrors the archive: gzip regardless of what the client asked for.
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("Content-Type", "application/javascript")
		w.Write(payload)
	}))
	defer srv.Close()

	res := &Result{}
	body, ok := get(context.Background(), srv.Client(), srv.URL, res)
	if !ok {
		t.Fatal("fetch failed")
	}
	if strings.HasPrefix(body, "\x1f\x8b") {
		t.Fatal("body is still gzip-compressed; pattern matching will silently find nothing")
	}
	creds := credentials(body)
	if len(creds) != 1 || creds[0] != secret {
		t.Fatalf("credential not recovered from a gzip response: got %v", creds)
	}
}

// A 503 must not be reported as "nothing archived". The CDX index answers 503
// under load often enough that accepting it once produced a false negative on
// the first live run.
func TestTransientArchiveErrorsAreRetried(t *testing.T) {
	// atomic even though these retries are sequential today: the same pattern
	// in internal/enumerate WAS a race, and "probably not concurrent" is not a
	// property a test should depend on.
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if hits.Load() < 3 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.Write([]byte("20260101000000 https://x.test/a.js"))
	}))
	defer srv.Close()

	res := &Result{}
	body, ok := get(context.Background(), srv.Client(), srv.URL, res)
	if !ok {
		t.Fatal("transient 503s must be retried, not accepted as an empty archive")
	}
	if !strings.Contains(body, "x.test") {
		t.Errorf("unexpected body %q", body)
	}
	if hits.Load() != 3 {
		t.Errorf("expected 3 attempts, got %d", hits.Load())
	}
}

// A genuine 404 is a real answer and must not burn retries.
func TestPermanentErrorsAreNotRetried(t *testing.T) {
	// atomic even though these retries are sequential today: the same pattern
	// in internal/enumerate WAS a race, and "probably not concurrent" is not a
	// property a test should depend on.
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	if _, ok := get(context.Background(), srv.Client(), srv.URL, &Result{}); ok {
		t.Error("404 should not report success")
	}
	if hits.Load() != 1 {
		t.Errorf("404 is a real answer; expected 1 attempt, got %d", hits.Load())
	}
}
