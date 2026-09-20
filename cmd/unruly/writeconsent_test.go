package main

import (
	"strings"
	"testing"
)

// -write alone must be refused. Nothing was testing that.
//
// The rule is two flags: -write says what to do, -yes-i-own-this says the
// target is yours to do it to. validateFlags refuses the first without the
// second, and 119 tests ran against a build with that refusal disabled --
// every test in cmd/unruly, plus the flag-behaviour evals -- and not one
// failed. Found with scripts/verify-break.sh.
//
// It is load-bearing rather than decorative. Three places compute write
// consent, and only two apply it:
//
//	seamInputs        Write: o.write && o.confirmOwn   (tested)
//	ScanOptions       Write: o.write && o.confirmOwn
//	probe.Options     Write: o.write                   <- no consent term
//
// The third is safe ONLY because validateFlags returns an error first, so
// o.write cannot be true there without o.confirmOwn. Remove the refusal and
// that line issues INSERT requests against somebody's project on one flag.
// A safety property held up by a guard two hundred lines away, with no test
// on the guard, is a property held by luck.
func TestWriteWithoutOwnershipIsRefused(t *testing.T) {
	for _, tc := range []struct {
		name             string
		write, confirmed bool
		wantErr          bool
	}{
		{name: "neither flag", wantErr: false},
		{name: "-write alone is refused", write: true, wantErr: true},
		{name: "the confirmation alone is harmless", confirmed: true, wantErr: false},
		{name: "both together are accepted", write: true, confirmed: true, wantErr: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Only the two fields under test are set; a target is supplied so
			// the function does not refuse for an unrelated reason and pass
			// this test for the wrong one.
			o := &options{projectRef: "abcdefghijklmnopqrst", write: tc.write, confirmOwn: tc.confirmed}
			err := validateFlags(o)
			if tc.wantErr && err == nil {
				t.Fatal("-write was accepted without -yes-i-own-this. That flag pair is " +
					"the whole consent model: -write is a habit, the confirmation is the " +
					"decision, and probe.Options carries no consent term of its own")
			}
			if !tc.wantErr && err != nil && strings.Contains(err.Error(), "yes-i-own-this") {
				t.Fatalf("refused for consent when consent was not the issue: %v", err)
			}
			if tc.wantErr && err != nil && !strings.Contains(err.Error(), "yes-i-own-this") {
				t.Errorf("the refusal does not name the flag that would allow it: %v", err)
			}
		})
	}
}
