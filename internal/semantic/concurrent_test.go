package semantic_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/eppser/unruly/internal/semantic"
)

// The columns of one relation are asked about in parallel.
//
// A wide table is dozens of round trips. Whether issuing them together saves
// anything depends on the server -- see augmentWorkers, where the measurements
// are -- but issuing them together at all is the precondition, and that is
// what this grades.
//
// This blocks every call until enough of them are in flight, so a serial
// Augment cannot pass it -- it hangs until the context deadline and returns
// the deadline error instead of the answer.
func TestColumnsAreAskedAboutInParallel(t *testing.T) {
	const want = 2
	gate := make(chan struct{})
	var once sync.Once
	var mu sync.Mutex
	inFlight := 0

	f := &blockingClassifier{fn: func(ctx context.Context, col string) (semantic.Result, error) {
		mu.Lock()
		inFlight++
		enough := inFlight >= want
		mu.Unlock()
		if enough {
			once.Do(func() { close(gate) })
		}
		select {
		case <-gate: // released once `want` calls have arrived
			return semantic.Result{Class: "pii", P: 0.99}, nil
		case <-ctx.Done(): // a serial Augment lands here, and says so
			return semantic.Result{}, ctx.Err()
		}
	}}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cols := []string{"a", "b", "c", "d"}
	got, err := semantic.Augment(ctx, f, cols, map[string][]string{}, map[string][]string{})
	if err != nil {
		t.Fatalf("Augment never got %d calls in flight at once, so it is still "+
			"serial: %v", want, err)
	}
	if len(got) != 1 || got[0] != "pii" {
		t.Errorf("got %v, want [pii]", got)
	}
	if n := f.count(); n != len(cols) {
		t.Errorf("asked %d columns, want %d", n, len(cols))
	}
}

// Which error surfaces does not depend on which request lost the race.
//
// Byte-identical output across runs is a published property of this scanner,
// and the reported error is part of the report. With the columns in flight at
// once the LAST one can fail first in wall-clock time; the error kept has to
// be the first in sorted column order regardless.
func TestTheReportedErrorIsTheFirstColumnNotTheFirstFailure(t *testing.T) {
	f := &blockingClassifier{fn: func(_ context.Context, col string) (semantic.Result, error) {
		switch col {
		case "aaa":
			time.Sleep(40 * time.Millisecond) // fails LAST in wall-clock
			return semantic.Result{}, errors.New("aaa failed")
		case "zzz":
			return semantic.Result{}, errors.New("zzz failed") // fails FIRST
		}
		return semantic.Result{}, nil
	}}
	for i := 0; i < 5; i++ { // a race decided the same way five times is not a race
		_, err := semantic.Augment(context.Background(), f,
			[]string{"zzz", "aaa", "mmm"}, map[string][]string{}, map[string][]string{})
		if err == nil || err.Error() != "aaa failed" {
			t.Fatalf("run %d reported %v; want the error from the first column in "+
				"sorted order, or the report changes between runs", i, err)
		}
	}
}

// blockingClassifier answers through a function, and counts, under a lock --
// because the calls now really are concurrent.
type blockingClassifier struct {
	fn func(ctx context.Context, col string) (semantic.Result, error)
	mu sync.Mutex
	n  int
}

func (b *blockingClassifier) Enabled() bool { return true }
func (b *blockingClassifier) Classify(ctx context.Context, col string, _ []string) (semantic.Result, error) {
	b.mu.Lock()
	b.n++
	b.mu.Unlock()
	return b.fn(ctx, col)
}
func (b *blockingClassifier) count() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.n
}

// The cap is on the CLASSIFIER, not on one relation.
//
// Relations are scanned 64-wide. A per-relation worker pool therefore bounds
// nothing: four in flight per relation times sixty-four relations is 256
// concurrent requests at a sidecar serving four slots, which at the 340ms per
// column measured against Ollama is twenty-one seconds of queue against a
// twenty-second request timeout. Every classification in the scan would start failing, and
// it would fail as "the model was slow", which is the hardest kind of bug to
// see.
//
// So the limit lives where every caller passes through it.
func TestTheWholeScanNeverExceedsTheInFlightCap(t *testing.T) {
	// Atomics, not a mutex: a counter touched inside an HTTP handler is exactly
	// what internal/eval's TestNoBareCounterInsideAnHTTPHandler looks for, and
	// a test that measures concurrency is the last place to argue with it.
	var inFlight, peak atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n := inFlight.Add(1)
		for {
			p := peak.Load()
			if n <= p || peak.CompareAndSwap(p, n) {
				break
			}
		}
		time.Sleep(20 * time.Millisecond) // long enough for a pile-up to show
		inFlight.Add(-1)
		_, _ = w.Write([]byte(`{"choices":[{"logprobs":{"top_logprobs":[{"Z":0}]}}]}`))
	}))
	defer srv.Close()

	c, err := semantic.New(semantic.Options{Endpoint: srv.URL + "/v1/completions", Model: "m"})
	if err != nil {
		t.Fatal(err)
	}
	// Sixty-four relations, each asking about four columns: the real shape.
	var wg sync.WaitGroup
	for rel := 0; rel < 64; rel++ {
		wg.Add(1)
		go func(rel int) {
			defer wg.Done()
			cols := []string{"a", "b", "c", "d"}
			_, err := semantic.Augment(context.Background(), c, cols,
				map[string][]string{}, map[string][]string{})
			if err != nil {
				t.Errorf("relation %d: %v", rel, err)
			}
		}(rel)
	}
	wg.Wait()

	if got := peak.Load(); got > semantic.MaxInFlight {
		t.Errorf("%d requests were in flight at once; the cap is %d. A per-relation "+
			"pool does not bound a 64-wide scan", got, semantic.MaxInFlight)
	} else if got < 2 {
		t.Errorf("peak concurrency was %d, so nothing ran in parallel and this test "+
			"proves nothing", got)
	}
}
