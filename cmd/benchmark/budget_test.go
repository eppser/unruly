package main

import (
	"os"
	"testing"
	"time"
)

// The 90-second bring-up budget was hardcoded, and the comments in bringUp
// record two separate rounds of projects timing out and then answering in one
// second by hand. A budget that cannot be raised on a slower machine turns a
// loaded laptop into a missing row in the published scoreboard.
func TestTheBringUpBudgetIsConfigurable(t *testing.T) {
	t.Setenv("UNRULY_BENCH_BRINGUP", "240s")
	if got := bringUpBudget(); got != 240*time.Second {
		t.Errorf("UNRULY_BENCH_BRINGUP=240s gave %s, want 4m0s", got)
	}

	// An unset or unparseable value must not silently become zero, which
	// would fail every project instantly and look like a corpus-wide outage.
	os.Unsetenv("UNRULY_BENCH_BRINGUP")
	if got := bringUpBudget(); got < 90*time.Second {
		t.Errorf("default budget is %s, want at least 90s", got)
	}
	t.Setenv("UNRULY_BENCH_BRINGUP", "not-a-duration")
	if got := bringUpBudget(); got < 90*time.Second {
		t.Errorf("a junk budget gave %s, want the default", got)
	}
}
