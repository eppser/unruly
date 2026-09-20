package eval_test

import (
	"os"
	"strings"
	"testing"
)

// The live gate must come BEFORE the network warm-up.
//
// runEdgeSurface warmed the Deno runtime first and consulted UNRULY_LIVE
// second, so a plain `go test ./...` spent 30 seconds per Edge test waiting for
// a host that is not running, four times over, and then skipped. Measured at
// 120.7 seconds -- more than half the entire offline suite, spent
// proving that a service nobody started is not running.
//
// That is not only slow. A suite whose offline path is dominated by a
// deliberate two-minute stall is a suite people stop running, and this
// repository's whole argument rests on its tests being run.
//
// Checked structurally rather than by timing, because a timing assertion
// either flakes on a loaded machine or is loose enough to pass at 90 seconds.
func TestTheEdgeLiveGateComesBeforeTheWarmUp(t *testing.T) {
	src := readFile(t, "edge_test.go")

	body := between(t, src, "func runEdgeSurface(", "\n}\n")
	warm := strings.Index(body, "warmEdgeRuntime(")
	gate := strings.Index(body, "requireLiveEvals(")

	if warm < 0 {
		t.Fatal("runEdgeSurface no longer warms the runtime; if that is deliberate, " +
			"delete this test rather than leaving it to pass on an absent call")
	}
	if gate < 0 {
		t.Fatal("runEdgeSurface does not check the live gate at all, so every offline " +
			"run pays for a warm-up it can never use")
	}
	if gate > warm {
		t.Error("runEdgeSurface warms the Edge runtime before checking UNRULY_LIVE, so " +
			"an offline run waits 30s per test for a host nobody started and then skips")
	}
}

// between returns the text from the first marker to the next end marker.
func between(t *testing.T, src, from, to string) string {
	t.Helper()
	i := strings.Index(src, from)
	if i < 0 {
		t.Fatalf("marker %q not found", from)
	}
	rest := src[i:]
	j := strings.Index(rest, to)
	if j < 0 {
		t.Fatalf("end marker %q not found after %q", to, from)
	}
	return rest[:j]
}

var _ = os.Getenv
