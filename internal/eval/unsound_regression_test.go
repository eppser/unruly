package eval_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/eppser/unruly/internal/soundness"
)

// A permanent regression: the probe this project rejected, re-run against real
// controls to prove the soundness harness actually catches it.
//
// Without this, soundness.Require() is only known to reject a hand-written
// stub. Here it is handed the real zero-match DELETE, issued against a real
// writable relation and a real protected one, and must still reject it. If a
// future change ever made this pass, the harness would have stopped working
// and every other soundness test would be worthless.
func TestZeroMatchDeleteIsCaught(t *testing.T) {
	c := matrixClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	zeroMatchDelete := func(rel string) soundness.Outcome {
		resp := c.Do(ctx, "DELETE", c.RestURL(rel)+"?id=eq.-99999999", nil, nil)
		return soundness.Outcome{
			Verdict: fmt.Sprintf("http-%d", resp.Status),
			Detail:  "zero-match DELETE",
		}
	}

	fake := &testing.T{}
	soundness.Require(fake, soundness.Probe{
		Name:          "zero-match-delete",
		Detects:       "whether the anonymous role may write",
		PositiveInput: "m_rls_selnone_insanon_nn (writable)",
		Positive:      func() soundness.Outcome { return zeroMatchDelete("m_rls_selnone_insanon_nn") },
		NegativeInput: "m_rls_selnone_insnone_nn (protected)",
		Negative:      func() soundness.Outcome { return zeroMatchDelete("m_rls_selnone_insnone_nn") },
	}, "reached", "blocked")

	if !fake.Failed() {
		t.Error("the zero-match DELETE probe should have been rejected as unsound")
	} else {
		t.Log("zero-match DELETE correctly rejected: both controls answered identically")
	}
}
