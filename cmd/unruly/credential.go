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
//
// WHY AN AMBIENT KEY DOES NOT ABORT: fromEnv says the key came from
// SUPABASE_ANON_KEY rather than from -k, and discovery.go already states the
// distinction -- an env var is "how anyone who works on a Supabase project has
// their shell", not an instruction about the target in front of them. Treating
// the two alike meant one stale export blocked every unrelated Supabase target
// with "use that project's own anon key", blaming the operator for a
// credential they never aimed here and naming a project nobody asked to scan.
//
// Reported from a real run: a site disclosed its project ref in HTML, shipped
// no recoverable key, and the scan died on the shell's leftover. That is the
// failure SECURITY.md calls a vulnerability in this project -- a false
// negative, indistinguishable in the report from a target that genuinely
// refused.
//
// chooseKey already covers the case where the target DOES ship its own key.
// This covers the one where it does not: drop the ambient key and say so,
// because a scan without a credential is a smaller answer than no scan.
func credentialFor(current, currentRef, projectRef, discovered string, inList, fromEnv bool) credential {
	if projectRef == "" || current == "" || currentRef == "" || currentRef == projectRef {
		// Nothing to compare, or nothing wrong. A key that is not a JWT has no
		// reference and is taken at face value.
		return credential{Key: current}
	}
	if !inList && fromEnv {
		// Same fallback as the list case below, so it is built in one place:
		// two copies of "use what discovery found, and disclose what was
		// withheld" means a mutation lands on one and the other goes
		// unchecked, which is a decision made twice and verified in neither.
		return withhold(currentRef, discovered, fmt.Sprintf(
			"SUPABASE_ANON_KEY in your environment belongs to project %q, but this "+
				"target is %q, and no credential for it was recoverable from the site. "+
				"Ignoring the ambient key -- sending it would only collect rejections. "+
				"The backend cannot be assessed without a key for %s: pass one with -k, "+
				"or unset SUPABASE_ANON_KEY if it is left over from other work",
			currentRef, projectRef, projectRef))
	}
	if !inList {
		return credential{Err: fmt.Errorf(
			"the supplied key was issued for project %q but the target is %q. "+
				"Scanning would send thousands of requests that can only be rejected. "+
				"Use that project's own anon key, or scan %s instead",
			currentRef, projectRef, currentRef)}
	}
	return withhold(currentRef, discovered, fmt.Sprintf(
		"the supplied key was issued for project %q but this target is %q; not "+
			"sending it, using the key discovered on this target", currentRef, projectRef))
}

// withhold builds the one outcome shared by every non-aborting mismatch: send
// whatever discovery recovered from THIS target, and disclose the credential
// that was held back.
//
// discovered is "" when the target shipped none, which is a scan without a key
// rather than no scan. That is the smaller answer, and it is still an answer.
func withhold(withheldRef, discovered, warn string) credential {
	return credential{
		Key:         discovered,
		WithheldRef: withheldRef,
		Warn:        warn,
	}
}
