package client

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// A hostile target can send very little and cost the scanner a great deal.
//
// Go's HTTP client advertises gzip and decompresses transparently, so a few
// kilobytes on the wire can become gigabytes in memory. Everything the scanner
// reads goes through a bounded reader for this reason; that is easy to state
// and worth proving, because the bound is one refactor from being an
// io.ReadAll.
func TestGzipBombIsBounded(t *testing.T) {
	// 256 MB of zeros compresses to a few hundred kilobytes.
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	chunk := make([]byte, 1<<20)
	for i := 0; i < 256; i++ {
		if _, err := zw.Write(chunk); err != nil {
			t.Fatalf("building the bomb: %v", err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("closing: %v", err)
	}
	bomb := buf.Bytes()
	t.Logf("bomb: %d bytes on the wire, %d bytes decompressed", len(bomb), 256<<20)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("Content-Type", "application/json")
		w.Write(bomb)
	}))
	defer srv.Close()

	c := New(Options{BaseURL: srv.URL, AnonKey: "k", RestPrefix: "/", Retries: 0})

	done := make(chan Response, 1)
	go func() { done <- c.Get(context.Background(), srv.URL+"/x", nil) }()

	select {
	case resp := <-done:
		if len(resp.Body) > maxBody {
			t.Errorf("kept %d bytes from a 256 MB response; the cap is %d",
				len(resp.Body), maxBody)
		}
	case <-time.After(60 * time.Second):
		t.Fatal("reading a gzip bomb did not finish: the response is being decompressed " +
			"without a bound, and a hostile target decides how much memory this scan uses")
	}
}

// The same bound on the path that reads a hostile site's own pages.
//
// ReadBody is what discovery, vocabulary harvesting, archives and preview
// sweeps use, and those fetch content the target chooses completely. It is the
// likeliest place for this to be aimed, because it is the only place the
// scanner reads something other than a database API.
func TestReadBodyBoundsAHostilePage(t *testing.T) {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	chunk := make([]byte, 1<<20)
	for i := 0; i < 128; i++ {
		zw.Write(chunk)
	}
	zw.Close()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("Content-Type", "text/html")
		w.Write(buf.Bytes())
	}))
	defer srv.Close()

	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()

	const limit = 8 << 20
	done := make(chan int, 1)
	go func() {
		b, _ := ReadBody(resp, limit)
		done <- len(b)
	}()

	select {
	case n := <-done:
		if n > limit {
			t.Errorf("ReadBody returned %d bytes against a limit of %d", n, limit)
		}
	case <-time.After(60 * time.Second):
		t.Fatal("ReadBody did not finish on a 128 MB decompressed page: the target is " +
			"choosing how much memory this scan uses")
	}
}

// Deeply nested JSON must not turn into unbounded recursion.
//
// The size cap does not help here: 800 KB of nested arrays is well inside the
// 1 MB limit, and a decoder that recurses per level would exhaust the
// goroutine stack. A stack overflow in Go is fatal and cannot be recovered,
// so this would be a hostile target ending the scan outright.
//
// It does not happen, and the reason is worth pinning: encoding/json enforces
// a maximum nesting depth and returns "exceeded max depth" rather than
// recursing. That is the standard library's guarantee, not this program's.
// Measured directly: depth 100 decodes, depth 10,000 and 400,000 are refused.
//
// The scanner leans on that without saying so anywhere. A future change --
// most plausibly swapping in a faster JSON library, which is tempting at
// twelve thousand requests per scan -- would drop the protection silently, and
// the symptom would be a crash on one target in a list rather than a wrong
// answer.
func TestDeeplyNestedJSONIsRefusedNotRecursed(t *testing.T) {
	const depth = 400000
	var b bytes.Buffer
	// Shaped to match []map[string]any so the decoder walks INTO the value.
	// A bare [[[... is rejected on type mismatch at the second bracket and
	// proves nothing about depth.
	b.WriteString(`[{"v":`)
	b.Write(bytes.Repeat([]byte("["), depth))
	b.Write(bytes.Repeat([]byte("]"), depth))
	b.WriteString(`}]`)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Range", "0-0/1")
		w.WriteHeader(http.StatusPartialContent)
		w.Write(b.Bytes())
	}))
	defer srv.Close()

	c := New(Options{BaseURL: srv.URL, AnonKey: "k", RestPrefix: "/", Retries: 0})

	done := make(chan int, 1)
	go func() {
		resp := c.Get(context.Background(), srv.URL+"/x", nil)
		done <- len(resp.DecodeRows())
	}()
	select {
	case rows := <-done:
		// Refused, so no rows. The finding built from this reports what the
		// count header said and carries no sample, which is the honest
		// outcome: the response was unreadable, not empty.
		if rows != 0 {
			t.Errorf("decoded %d rows from a 400,000-deep value; the decoder walked in",
				rows)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("decoding never finished: a target choosing the nesting depth is choosing " +
			"how long this scan runs")
	}

	// Ordinary nesting must still decode, or the protection has become a bug.
	var ok []map[string]any
	shallow := []byte(`[{"v":[[["x"]]]}]`)
	if err := jsonUnmarshalForTest(shallow, &ok); err != nil || len(ok) != 1 {
		t.Errorf("a normally nested row failed to decode: %v", err)
	}
}

// jsonUnmarshalForTest keeps the shallow-decode assertion honest: it uses the
// same decoder the scanner does rather than a hand-rolled check.
func jsonUnmarshalForTest(b []byte, v any) error { return json.Unmarshal(b, v) }
