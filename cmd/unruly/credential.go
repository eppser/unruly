package main

import "fmt"

// credential is which key this target is scanned with, and what the report
// must disclose about that choice.
type credential struct {
	Key string
	// WithheldRef names the project a supplied key was issued for, when that
	// key was NOT sent. Empty when nothing was withheld.
	//
	// Set even when the fallback succeeds. The scan then proceeds normally, so
	// it is tempting to treat that as nothing to report -- but the operator
	// passed -key and it was not used, and a reader comparing two reports
	// needs to know which credential produced each.
	WithheldRef string
	Warn        string
	// Err aborts the scan.
	Err error
}

// credentialFor decides, AFTER discovery, which key goes to this target.
//
// THE BUG IT FIXES: withholding used to set the key to "" and stop there, so a
// scan that had ALREADY recovered the target's own credential threw it away
// and reported "backend not assessed". The order was:
//
//	d := discover.Run(...)  // recovers THIS target's key
//	chooseKey(...)          // keeps the operator's -key, discards the discovered one
//	o.anonKey = ""          // withholds the operator's key
//	                        // ... and nothing restored the discovered one
//
// It was a scoping accident rather than a decision: d is declared inside the
// discovery block and is not in scope where the withholding happens, so the
// fallback the code's own comment promised -- "not sending it, discovering
// this target's own key" -- could not be written there. Naming every input in
// a signature makes a missing one a compile error instead of a wrong answer.
//
// Reachable on a custom domain, where the hostname carries no project
// reference, so the pre-scan check cannot fire and only this one can. The
// result was silence on a target the scan could have read.
//
// WHY ONE EXPLICIT TARGET STILL ABORTS: a mismatched -key there is either the
// wrong key for the right target or the right key for the wrong target, and
// the two are indistinguishable from in here. Falling back silently resolves
// the first and hides the second -- and the second means scanning somebody who
// never asked. The list case is different: that code already chose to carry
// on, so restoring the credential it had is a fix rather than a new policy.
func credentialFor(current, currentRef, projectRef, discovered string, inList bool) credential {
	if projectRef == "" || current == "" || currentRef == "" || currentRef == projectRef {
		// Nothing to compare, or nothing wrong. A key that is not a JWT has no
		// reference and is taken at face value.
		return credential{Key: current}
	}
	if !inList {
		return credential{Err: fmt.Errorf(
			"the supplied key was issued for project %q but the target is %q. "+
				"Scanning would send thousands of requests that can only be rejected. "+
				"Use that project's own anon key, or scan %s instead",
			currentRef, projectRef, currentRef)}
	}
	return credential{
		// The fallback. Empty when discovery found nothing, which is the old
		// behaviour and still correct -- but no longer the only outcome.
		Key:         discovered,
		WithheldRef: currentRef,
		Warn: fmt.Sprintf("the supplied key was issued for project %q but this target "+
			"is %q; not sending it, using the key discovered on this target",
			currentRef, projectRef),
	}
}
