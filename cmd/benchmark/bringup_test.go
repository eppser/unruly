package main

import (
	"errors"
	"github.com/eppser/unruly/internal/eval"
	"testing"
)

// A project that never answers gets the whole cycle again, not just compose up.
//
// Measured, with the per-phase timing this runner now prints: every project in
// the corpus binds in 3.8 to 6.4 seconds, and exactly one per run hangs for the
// entire budget and then answers in ten seconds when started by hand. Which one
// rotates between runs -- 03 on one, 08 and 16 on the next -- so it is the
// sequence, not the fixture.
//
// The existing retry covers `compose up` REPORTING an error. This failure
// reports success: the container starts, the published port never maps, and
// nothing answers until the budget runs out. Raising the budget cannot help
// something that is never going to answer, which is why raising it from 90s to
// 300s changed nothing. Tearing down and starting again can.
func TestBringUpRetriesTheWholeCycleWhenNothingAnswers(t *testing.T) {
	orig := bringUpOnce
	defer func() { bringUpOnce = orig }()

	t.Run("a project that answers on the second attempt is not skipped", func(t *testing.T) {
		calls, stopped := 0, 0
		bringUpOnce = func(dir string, tgt *eval.Target) (func(), error) {
			calls++
			if calls == 1 {
				return func() { stopped++ }, errors.New("did not answer within 5m0s")
			}
			return func() { stopped++ }, nil
		}
		if _, err := bringUp("dir", nil); err != nil {
			t.Fatalf("second attempt succeeded but bringUp returned %v", err)
		}
		if calls != 2 {
			t.Errorf("%d attempt(s), want 2", calls)
		}
		if stopped != 1 {
			t.Errorf("the failed attempt was stopped %d time(s), want 1: leaving its "+
				"containers up is what holds the port the retry needs", stopped)
		}
	})

	t.Run("a project that never answers is reported, not retried forever", func(t *testing.T) {
		calls := 0
		bringUpOnce = func(dir string, tgt *eval.Target) (func(), error) {
			calls++
			return func() {}, errors.New("did not answer within 5m0s")
		}
		if _, err := bringUp("dir", nil); err == nil {
			t.Fatal("both attempts failed and bringUp reported success; a project " +
				"that is genuinely down must reach the not-scored list")
		}
		if calls != 2 {
			t.Errorf("%d attempt(s), want exactly 2", calls)
		}
	})
}
