package client

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// A host that refuses everything must be abandoned, and one that is merely
// throttling must not be.
//
// The distinction is the whole design: 429 after a real answer is a target
// asking us to slow down, and the backoff already handles it. 429 with nothing
// usable ever is a wall, and continuing to push against it costs a scan two
// minutes and seventeen hundred requests to learn nothing.
func TestBreakerOpensOnlyWhenNothingUsefulWasEverSeen(t *testing.T) {
	t.Run("refuses everything", func(t *testing.T) {
		var hits atomic.Int64
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			hits.Add(1)
			w.WriteHeader(http.StatusTooManyRequests)
		}))
		defer srv.Close()
		c := New(Options{BaseURL: srv.URL, RefusalBudget: 5, Retries: 0})

		var refused int
		for i := 0; i < 200; i++ {
			if errors.Is(c.Do(context.Background(), "GET", srv.URL+"/x", nil, nil).Err, ErrRefused) {
				refused++
			}
		}
		if !c.GaveUp() {
			t.Fatal("200 consecutive 429s and the breaker never opened")
		}
		// The point is not that it noticed, it is that it stopped ASKING.
		if got := hits.Load(); got > 6 {
			t.Errorf("sent %d requests to a host that refused every one; the breaker "+
				"is reporting rather than preventing", got)
		}
		if refused == 0 {
			t.Error("callers cannot tell a refused target from one never asked")
		}
	})

	t.Run("throttles after answering", func(t *testing.T) {
		var n atomic.Int64
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if n.Add(1) == 1 {
				w.WriteHeader(http.StatusNotFound) // a real answer, and useful
				return
			}
			w.WriteHeader(http.StatusTooManyRequests)
		}))
		defer srv.Close()
		c := New(Options{BaseURL: srv.URL, RefusalBudget: 5, Retries: 0})

		for i := 0; i < 50; i++ {
			c.Do(context.Background(), "GET", srv.URL+"/x", nil, nil)
		}
		if c.GaveUp() {
			t.Error("the target answered before it started throttling, so it is " +
				"throttling and not refusing; abandoning it trades recall for speed")
		}
	})

	// A 401 wall is an answer, and it is also a rejected credential. Both are
	// true and they are different questions, so they are counted separately.
	//
	// This subtest used to assert that a 401 wall must NOT stop the scan, on
	// the grounds that giving up on it "stops measuring auth walls entirely".
	// That rationale did not survive measurement: after fifty identical 401s
	// there is nothing further to measure, and continuing cost one real scan
	// 18,208 requests to produce a report that said 0 relations about a project
	// with six critical findings. What must remain true is that a 401 is never
	// counted as a REFUSAL -- the host is alive and answering, which is what
	// the refusal breaker is asking about.
	t.Run("a 401 wall answers, and is a rejected credential", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
		}))
		defer srv.Close()
		c := New(Options{BaseURL: srv.URL, RefusalBudget: 5, Retries: 0})
		for i := 0; i < 60; i++ {
			c.Do(context.Background(), "GET", srv.URL+"/x", nil, nil)
		}
		if c.refusals.Load() != 0 {
			t.Errorf("401 counted as a refusal (%d); the host is answering",
				c.refusals.Load())
		}
		if !c.KeyRejected() {
			t.Error("sixty 401s and not one acceptance is a credential this target " +
				"does not take")
		}
	})

	// 403 is NOT a rejected credential. It is a rules decision, and Firestore
	// answers it to every collection that is protected or does not exist --
	// counting it here stopped a healthy Firebase scan before it reached the
	// Realtime Database, which two evals caught.
	t.Run("403 is a rules decision, not a bad key", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusForbidden)
		}))
		defer srv.Close()
		c := New(Options{BaseURL: srv.URL, Retries: 0})
		for i := 0; i < 200; i++ {
			c.Do(context.Background(), "GET", srv.URL+"/x", nil, nil)
		}
		if c.KeyRejected() || c.GaveUp() {
			t.Error("403 means the target knows who we are and said no; a scanner " +
				"that reads it as a bad key abandons every well-protected project")
		}
	})
}

// The backoff must not be paid on the last attempt.
//
// A delay before a retry is politeness; a delay before returning is dead time.
// With retries disabled every 429 used to cost a full backoff for a retry that
// was never going to happen.
func TestNoBackoffWhenNoRetryRemains(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()
	c := New(Options{BaseURL: srv.URL, Retries: 0, RefusalBudget: -1})

	start := time.Now()
	for i := 0; i < 10; i++ {
		c.Do(context.Background(), "GET", srv.URL+"/x", nil, nil)
	}
	// Ten local requests are milliseconds of work. Anything approaching a
	// second means a backoff is being paid for a retry that cannot happen.
	if d := time.Since(start); d > time.Second {
		t.Errorf("ten no-retry 429s took %s; the final attempt is still backing off", d)
	}
}

// A credential the project will not accept is not a project with nothing in it.
//
// This is the commonest way a scan produces a confident, empty, wrong report:
// the key was rotated since the bundle was built, or came from an archived
// copy, or belongs to another project. Every request is answered 401, no
// relation is ever found, and "0 relations" is indistinguishable from a
// hardened project unless the scan says which of the two it saw.
func TestRejectedCredentialIsDistinguishedFromAnEmptyProject(t *testing.T) {
	t.Run("every answer is a rejection", func(t *testing.T) {
		var hits atomic.Int64
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			hits.Add(1)
			w.WriteHeader(http.StatusUnauthorized)
		}))
		defer srv.Close()
		c := New(Options{BaseURL: srv.URL, Retries: 0})

		for i := 0; i < 500; i++ {
			c.Do(context.Background(), "GET", srv.URL+"/x", nil, nil)
		}
		if !c.KeyRejected() {
			t.Fatal("500 consecutive 401s and the scan still treated the key as working")
		}
		if !c.GaveUp() {
			t.Error("the key does not work, so continuing to ask cannot change the answer")
		}
		// Stopped asking, not merely noticed.
		if got := hits.Load(); got > authRejectBudget+5 {
			t.Errorf("sent %d requests with a credential the target refused every time", got)
		}
	})

	// The precision half, and the reason the budget is 50 rather than 5: a
	// working anon key still draws 401 from storage bucket listing and the
	// auth admin routes. A scan that gave up on those would report a working
	// project as unmeasurable.
	t.Run("a few rejections among real answers", func(t *testing.T) {
		var n atomic.Int64
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if n.Add(1)%4 == 0 {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			w.WriteHeader(http.StatusOK)
		}))
		defer srv.Close()
		c := New(Options{BaseURL: srv.URL, Retries: 0})

		for i := 0; i < 400; i++ {
			c.Do(context.Background(), "GET", srv.URL+"/x", nil, nil)
		}
		if c.KeyRejected() {
			t.Error("a quarter of endpoints answered 401 and three quarters answered; " +
				"that is a working key, and abandoning it loses the whole scan")
		}
	})

	// And a rejection that arrives only AFTER acceptances is not a rejected
	// key either -- it is an endpoint this key may not reach.
	t.Run("rejections after a good answer", func(t *testing.T) {
		var n atomic.Int64
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if n.Add(1) == 1 {
				w.WriteHeader(http.StatusOK)
				return
			}
			w.WriteHeader(http.StatusUnauthorized)
		}))
		defer srv.Close()
		c := New(Options{BaseURL: srv.URL, Retries: 0})
		for i := 0; i < 300; i++ {
			c.Do(context.Background(), "GET", srv.URL+"/x", nil, nil)
		}
		if c.KeyRejected() {
			t.Error("the project accepted this key once, so it is a working key")
		}
	})
}

// Clients share a connection pool, so the sockets are reused rather than
// re-dialled per client.
//
// A transport IS the pool. One per client means no reuse between them, which is
// invisible in a scan and expensive in a suite: around fifty test clients, each
// dialling up to twice the concurrency cap, exhausted this machine's ephemeral
// port range mid-audit and cost three runs before the errno was read.
func TestClientsShareOneConnectionPool(t *testing.T) {
	var conns atomic.Int64
	// Unstarted, because ConnState has to be set BEFORE the serving goroutine
	// reads it. Setting it on an already-running httptest.Server is a data
	// race, and the detector caught it.
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	srv.Config.ConnState = func(_ net.Conn, s http.ConnState) {
		if s == http.StateNew {
			conns.Add(1)
		}
	}
	srv.Start()
	defer srv.Close()

	// Ten clients, as ten tests would build them, each making a request.
	for i := 0; i < 10; i++ {
		c := New(Options{BaseURL: srv.URL, Concurrency: 4, Retries: 0})
		if r := c.Do(context.Background(), "GET", srv.URL+"/x", nil, nil); r.Status != 200 {
			t.Fatalf("request %d: status %d err %v", i, r.Status, r.Err)
		}
	}
	// Serial requests through a shared pool need one connection. Allow a little
	// slack for a pool entry expiring; ten would mean no sharing at all.
	if n := conns.Load(); n > 3 {
		t.Errorf("ten clients opened %d connections; the transport is not shared, so "+
			"every client dials its own and the ports accumulate", n)
	}

	// A different pool size must NOT inherit a pool sized for another: a scan
	// that lowers -concurrency asked for fewer connections.
	a := New(Options{BaseURL: srv.URL, Concurrency: 4})
	b := New(Options{BaseURL: srv.URL, Concurrency: 8})
	if a.http.Transport == b.http.Transport {
		t.Error("clients with different concurrency share a pool sized for one of them")
	}
}
