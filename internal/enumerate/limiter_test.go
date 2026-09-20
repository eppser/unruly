package enumerate

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/eppser/unruly/internal/client"
)

// Vocabulary harvesting fetches the application's own pages and JS bundles.
// That is traffic to somebody's web server rather than to their API, and it
// was the one stage still exempt after -rate-limit was made scan-wide: it
// built its own http.Client and never called Wait, so an operator setting
// -rl 10 to be careful still had roughly seventeen unpaced fetches go out.
//
// The limiter's own unit test could not catch that, because the stage never
// reached the limiter to be tested. This test watches the server instead.
func TestHarvestHonoursTheRateLimit(t *testing.T) {
	var served int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&served, 1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"account_id":1,"invoice_total":2}`))
	}))
	t.Cleanup(srv.Close)

	const rps = 4
	start := time.Now()
	v := Harvest(context.Background(), HarvestOptions{
		Site: srv.URL, Timeout: 10 * time.Second,
		Limiter: client.NewLimiter(rps),
	})
	elapsed := time.Since(start)

	n := atomic.LoadInt64(&served)
	if n == 0 {
		t.Fatal("no requests reached the server; the harvest did not run")
	}
	if len(v.Seeds) == 0 {
		t.Error("the server returns JSON keys, so seeds must be harvested")
	}
	// The bucket starts full, so the first rps fetches are free.
	if n > rps {
		floor := time.Duration(float64(n-rps)/float64(rps)*float64(time.Second)) - 150*time.Millisecond
		if elapsed < floor {
			t.Errorf("%d fetches at %d rps finished in %s, under the %s floor; "+
				"this stage is not paced and -rate-limit does not cover it",
				n, rps, elapsed.Round(time.Millisecond), floor.Round(time.Millisecond))
		}
	}
	t.Logf("%d fetches at %d rps took %s", n, rps, elapsed.Round(time.Millisecond))
}
