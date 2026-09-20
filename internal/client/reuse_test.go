package client

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

// Connection reuse is load-bearing for the speed claim, and until now it was
// asserted only in a comment next to the transport settings.
//
// It is easy to lose by accident. Go returns a connection to the pool only
// when the response body is read to EOF and closed; a client that reads part
// of a body and closes it discards the connection instead, silently. At the
// measured saturation point of 64 concurrent requests that turns every probe
// into a fresh TCP and TLS handshake, and the concurrency figure this scanner
// is tuned to stops describing anything real.
//
// So it is measured: count distinct connections the server accepts against the
// number of requests served.

// countingServer reports how many distinct TCP connections it accepted.
type countingServer struct {
	*httptest.Server
	mu    sync.Mutex
	conns map[string]bool
	reqs  int
}

func newCountingServer(t *testing.T, body string) *countingServer {
	t.Helper()
	cs := &countingServer{conns: map[string]bool{}}
	// Unstarted, because ConnState must be installed BEFORE the serve
	// goroutine reads it. Setting it on an already-running httptest.Server is
	// a data race, and the race detector says so — found while investigating a
	// runtime fault that turned out to be emulation, which is a reminder that
	// a spurious-looking signal is worth one check before it is dismissed.
	cs.Server = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cs.mu.Lock()
		cs.reqs++
		cs.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Range", "0-0/1")
		_, _ = w.Write([]byte(body))
	}))
	cs.Server.Config.ConnState = func(c net.Conn, s http.ConnState) {
		if s != http.StateNew {
			return
		}
		cs.mu.Lock()
		cs.conns[c.RemoteAddr().String()] = true
		cs.mu.Unlock()
	}
	cs.Server.Start()
	t.Cleanup(cs.Close)
	return cs
}

func (cs *countingServer) counts() (conns, reqs int) {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	return len(cs.conns), cs.reqs
}

func TestConnectionsAreReusedAcrossRequests(t *testing.T) {
	cs := newCountingServer(t, `[{"id":1}]`)
	c := New(Options{
		ProjectRef: "x", BaseURL: cs.URL, RestPrefix: "/", AnonKey: "k",
		Concurrency: 8, Retries: 1,
	})

	// Sequential, so concurrency cannot explain the connection count: with
	// reuse working this is one connection for all of them.
	const n = 50
	for i := 0; i < n; i++ {
		resp := c.Get(context.Background(), c.RestURL(fmt.Sprintf("t%d", i)), nil)
		if resp.Status != 200 {
			t.Fatalf("request %d: status %d", i, resp.Status)
		}
	}

	conns, reqs := cs.counts()
	if reqs != n {
		t.Fatalf("server saw %d requests, want %d", reqs, n)
	}
	if conns > 2 {
		t.Errorf("%d sequential requests opened %d connections; the pool is not "+
			"being reused and every probe pays a handshake", n, conns)
	}
	t.Logf("%d sequential requests over %d connection(s)", reqs, conns)
}

// A body larger than the read limit must still leave the connection reusable.
// Do reads at most 1 MiB, and a body that is not drained to EOF is a
// connection Go will not put back.
func TestOversizedBodyDoesNotBurnTheConnection(t *testing.T) {
	big := "[" + string(make([]byte, 2<<20)) + "]"
	cs := newCountingServer(t, big)
	c := New(Options{
		ProjectRef: "x", BaseURL: cs.URL, RestPrefix: "/", AnonKey: "k",
		Concurrency: 4, Retries: 1,
	})

	const n = 10
	for i := 0; i < n; i++ {
		if resp := c.Get(context.Background(), c.RestURL(fmt.Sprintf("big%d", i)), nil); resp.Status != 200 {
			t.Fatalf("request %d: status %d", i, resp.Status)
		}
	}
	conns, reqs := cs.counts()
	if reqs != n {
		t.Fatalf("server saw %d requests, want %d", reqs, n)
	}
	if conns > 2 {
		t.Errorf("%d requests with oversized bodies opened %d connections; the "+
			"read limit is truncating without draining, so each response costs a "+
			"new handshake", n, conns)
	}
	t.Logf("%d oversized responses over %d connection(s)", reqs, conns)
}
