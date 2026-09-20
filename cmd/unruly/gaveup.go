package main

import "github.com/eppser/unruly/internal/finding"

// Why the scan stopped seeing.
//
// Two different stories end in the same silence, and the reader cannot tell
// them apart from the findings alone: a host that would not talk to us, and a
// host that talked and would not accept our key.
//
// Both branches mean the same thing to the report -- nothing was measured, so
// exit 0 is not available -- and completely different things to the operator.
// A rejected credential is fixed by getting a working key. A host that answered
// 429, 5xx or nothing at all to every request is fixed by rate limiting, a
// different network, or asking whoever runs it. Reporting either one as the
// other sends someone to spend an afternoon on the wrong problem, and the
// scan's own output is the only evidence they have about which it was.
//
// The distinction is drawn from the client rather than guessed here: the
// breaker sets KeyRejected only when EVERY answer so far was an authentication
// refusal, which is a much narrower claim than "some requests failed".
func gaveUpFinding(base string, sent int64, keyRejected bool, role, keySource string) finding.Finding {
	if keyRejected {
		return finding.CredentialRejected(base, sent, role, keySource)
	}
	return finding.TargetRefused(base, sent,
		"the host answered 429, 5xx or nothing at all to every request")
}
