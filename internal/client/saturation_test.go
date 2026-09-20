package client

import (
	"context"
	"fmt"
	"os"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// DefaultConcurrency is described in the source as "the measured saturation
// point of PostgREST". Nothing in the tree recorded that measurement, and no
// test would have noticed if the number were wrong -- the same shape as a
// scanner reporting a surface it never probed.
//
// This measures it, against a real Supabase project, and fails when the
// default is far from the best concurrency observed. It is opt-in because it
// puts real load on a real host:
//
//	UNRULY_SATURATION=1 \
//	UNRULY_SAT_URL=https://<ref>.supabase.co \
//	UNRULY_SAT_KEY=<anon key> \
//	UNRULY_SAT_REL=<a readable relation> \
//	go test ./internal/client/ -run Saturation -v
//
// Point it at a project you own. It issues only counted reads.

type level struct {
	concurrency int
	perSecond   float64
	errors      int
	throttled   int
	p50         time.Duration
}

func TestSaturationPointIsWhereTheDefaultSaysItIs(t *testing.T) {
	if os.Getenv("UNRULY_SATURATION") == "" {
		t.Skip("set UNRULY_SATURATION=1 to measure against a real project")
	}
	base, key := os.Getenv("UNRULY_SAT_URL"), os.Getenv("UNRULY_SAT_KEY")
	if base == "" || key == "" {
		t.Fatal("UNRULY_SAT_URL and UNRULY_SAT_KEY are required")
	}

	// Repeats, then median. A single sweep is not enough to set a default
	// with: across three consecutive sweeps of the same project the best
	// concurrency moved between 16 and 32, and one sweep measured 96 as slower
	// than 128. Asserting on one sample would make this test flaky in both
	// directions -- it passed on the first sweep and would have failed on the
	// next two, against an unchanged scanner and an unchanged target.
	const perLevel = 60
	// One sweep per level is enough to check the SHAPE against a second
	// project without putting three sweeps of load on somebody's production
	// database; the default of three is for setting the constant.
	repeats := 3
	if os.Getenv("UNRULY_SAT_QUICK") != "" {
		repeats = 1
	}
	concurrencies := []int{1, 2, 4, 8, 16, 32, 64, 96, 128}

	var levels []level
	for _, c := range concurrencies {
		var samples []level
		for r := 0; r < repeats; r++ {
			samples = append(samples, measure(t, base, key, c, perLevel))
		}
		levels = append(levels, medianLevel(samples))
	}

	t.Log("concurrency   req/s    p50      errors  429s")
	for _, l := range levels {
		t.Logf("%9d  %7.1f  %7s  %6d  %4d",
			l.concurrency, l.perSecond, l.p50.Round(time.Millisecond), l.errors, l.throttled)
	}

	best := levels[0]
	for _, l := range levels {
		if l.errors == 0 && l.perSecond > best.perSecond {
			best = l
		}
	}
	t.Logf("best observed: concurrency %d at %.1f req/s; default is %d",
		best.concurrency, best.perSecond, DefaultConcurrency)

	// The claim under test is not "the default is optimal" -- throughput
	// plateaus, and which point tops the plateau moves from sweep to sweep. It
	// is that the default sits ON the plateau rather than past the knee.
	//
	// Latency is the sharper half of that, and the half that stayed stable
	// across sweeps. Measured on a free-tier project with the default at 64:
	//
	//	concurrency  16-32  ->  p50   27-52ms
	//	concurrency  64     ->  p50  303-410ms   in all three sweeps
	//
	// Queueing past the knee buys no throughput and costs an order of
	// magnitude of latency, which for a scanner is wall-clock time spent
	// waiting on requests the server has not started.
	var atDefault level
	for _, l := range levels {
		if l.concurrency == DefaultConcurrency {
			atDefault = l
		}
	}
	if atDefault.concurrency == 0 {
		t.Fatalf("the sweep never measured the default (%d)", DefaultConcurrency)
	}
	// Half, not three quarters. The top of the plateau moved between 16 and 96
	// across sweeps of the same project, so a tight bound here would fail on
	// noise; this is a guard against a default that is grossly wrong, not a
	// tuning oracle. The end-to-end scan timing in client.go is what actually
	// chose the number, because it measures the product rather than a proxy.
	if atDefault.perSecond < 0.5*best.perSecond {
		t.Errorf("default concurrency %d achieves %.1f req/s, only %.0f%% of the best "+
			"observed (%.1f req/s at %d), which is too far off the plateau to be a "+
			"defensible default.",
			DefaultConcurrency, atDefault.perSecond,
			100*atDefault.perSecond/best.perSecond, best.perSecond, best.concurrency)
	}
	var bestP50 time.Duration = 1 << 62
	for _, l := range levels {
		if l.errors == 0 && l.p50 < bestP50 {
			bestP50 = l.p50
		}
	}
	if atDefault.p50 > 4*bestP50 {
		t.Errorf("default concurrency %d has p50 %s against %s at the fastest level: "+
			"requests are queueing rather than being served, which is what being past "+
			"the knee looks like",
			DefaultConcurrency, atDefault.p50.Round(time.Millisecond),
			bestP50.Round(time.Millisecond))
	}
	if atDefault.throttled > 0 {
		t.Errorf("default concurrency %d drew %d rate-limit responses; a default that "+
			"provokes 429s trades correctness for speed, since a throttled probe "+
			"cannot classify anything", DefaultConcurrency, atDefault.throttled)
	}
}

// medianLevel takes the middle sample by throughput, carrying that sample's
// latency and error counts so the reported row describes one real sweep rather
// than an average of runs that never happened.
func medianLevel(samples []level) level {
	sort.Slice(samples, func(i, j int) bool { return samples[i].perSecond < samples[j].perSecond })
	m := samples[len(samples)/2]
	// Errors and 429s are summed across every repeat, not taken from the
	// median sample: one throttled response anywhere is a fact about the
	// default, and picking the middle sweep could discard it.
	m.errors, m.throttled = 0, 0
	for _, s := range samples {
		m.errors += s.errors
		m.throttled += s.throttled
	}
	return m
}

// measure issues the workload a scan is actually made of.
//
// Not repeated counted reads of one relation: that contends on a single table
// and saturates early, which is how this harness first "proved" the default was
// three times too high while end-to-end scans were nearly twice as fast at it.
// The dominant request in a scan is a probe for a relation name that does not
// exist -- a cheap 404 whose cost is the round trip -- and each candidate is a
// DIFFERENT name, so nothing contends.
func measure(t *testing.T, base, key string, concurrency, n int) level {
	t.Helper()
	c := New(Options{
		BaseURL: base, AnonKey: key, Concurrency: concurrency,
		Timeout: 30 * time.Second,
	})
	urlFor := func(i int) string {
		return c.RestURL(fmt.Sprintf("unruly_sat_probe_%d_%d", concurrency, i)) +
			"?select=*&limit=1"
	}

	// Warm the pool before timing. A scan reaches its bursty stages with
	// connections already established; a cold client charges the first
	// `concurrency` requests a TLS handshake each, which penalises exactly the
	// levels under test and is a property of the harness, not the target.
	if os.Getenv("UNRULY_SAT_COLD") == "" {
		var wu sync.WaitGroup
		for i := 0; i < concurrency; i++ {
			wu.Add(1)
			go func(i int) {
				defer wu.Done()
				c.Get(context.Background(), urlFor(1_000_000+i), nil)
			}(i)
		}
		wu.Wait()
	}

	var errs, throttled int64
	durations := make([]time.Duration, n)

	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	start := time.Now()
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			t0 := time.Now()
			resp := c.Get(context.Background(), urlFor(i), nil)
			durations[i] = time.Since(t0)
			switch {
			case resp.Err != nil:
				atomic.AddInt64(&errs, 1)
			case resp.Status == 429:
				atomic.AddInt64(&throttled, 1)
			case resp.Status >= 500:
				atomic.AddInt64(&errs, 1)
			}
		}(i)
	}
	wg.Wait()
	elapsed := time.Since(start)

	sort.Slice(durations, func(i, j int) bool { return durations[i] < durations[j] })
	return level{
		concurrency: concurrency,
		perSecond:   float64(n) / elapsed.Seconds(),
		errors:      int(errs),
		throttled:   int(throttled),
		p50:         durations[n/2],
	}
}

// A sweep that silently measured nothing would report a flat line and pass.
func TestSaturationHarnessActuallyIssuesRequests(t *testing.T) {
	srv := newCountingServer(t, `[{"id":1}]`)

	// 20 timed requests plus 4 warm-up requests, one per unit of concurrency.
	// The warm-up is deliberately counted here: it is the line that changed
	// this harness's verdict on the default, so a change to it must break a
	// test rather than quietly alter what the sweep measures.
	const timed, warmup = 20, 4
	l := measure(t, srv.URL, "test", warmup, timed)
	if _, got := srv.counts(); got != timed+warmup {
		t.Fatalf("harness issued %d requests, expected %d timed + %d warm-up; the "+
			"sweep would report throughput for traffic it never sent",
			got, timed, warmup)
	}
	if l.perSecond <= 0 {
		t.Fatal("throughput was not measured")
	}
	fmt.Fprintf(os.Stderr, "harness ok: %.0f req/s against a local server\n", l.perSecond)
}
