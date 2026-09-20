package main

import (
	"fmt"
	"strings"
)

// cannotStart reports why discovery cannot begin, or nil when it can.
//
// Extracted because it has already been wrong once, in the way that matters.
// The call site's comment records it: "With a target URL in hand the gap is
// the credential, and naming -site here sent operators to add a flag that
// would not have helped."
//
// These sentences are the tool's entire output on a failed invocation -- the
// most-read text it produces when something goes wrong -- and until now they
// were reachable only by starting a scan.
func cannotStart(target, site string) error {
	if site != "" {
		return nil
	}
	// A target that is a URL means the origin is known and the CREDENTIAL is
	// what is missing. Leading with -site is the bug this encodes a fix for:
	// -site is offered as a way to DISCOVER a key, not named as the gap.
	if strings.HasPrefix(target, "http") {
		return fmt.Errorf("no credential for %s: pass -key, or point -site at the "+
			"application so one can be discovered from it", target)
	}
	// No URL and no site: nothing to discover from, so every route in is worth
	// naming.
	return fmt.Errorf("need -site (or -target) to discover credentials, or supply a " +
		"credential with -key plus an origin via -project-ref or -base-url")
}

// noKey reports why no anon key could be established.
//
// The login-wall branch is the reason this is a function. "no anon key found"
// is true and useless against a site that serves a sign-in screen: the key
// ships in the bundle loaded AFTER authenticating, so the fix is to point
// -site past the sign-in -- and a scanner that says only "not found" sends the
// operator to re-check a flag that was already correct.
//
// Collapsing the two branches into one sentence would look like simplification
// and would cost exactly that diagnosis, which is why the test asserts they
// DIFFER rather than asserting each in isolation.
func noKey(site string, loginWall bool) error {
	if loginWall {
		return fmt.Errorf("no anon key found: %s serves a sign-in screen, and an "+
			"application's key ships in the bundle it loads AFTER authenticating. "+
			"Point -site at a page past the sign-in, or pass -key", site)
	}
	return fmt.Errorf("no anon key found; supply -key or set SUPABASE_ANON_KEY")
}
