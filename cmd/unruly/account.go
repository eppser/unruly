package main

import (
	"github.com/eppser/unruly/internal/escalate"
	"github.com/eppser/unruly/internal/finding"
)

// What to report after trying to obtain an authenticated session.
//
// This runs only under -write -yes-i-own-this, and it is the one place the
// scanner can leave something behind on the target: an account it created to
// measure what a logged-in user reaches that anon does not. Everything about
// that account has to end up in the report, because the report is the only
// record the project owner gets. A created account that is not reported is
// residue this tool promised not to leave, and nothing else in the run would
// mention it.
//
// The three things worth separating:
//
//	could not get a session   -- a coverage gap, not a clean result. The
//	                             escalation comparison did not happen, so
//	                             "anon sees everything" is unmeasured rather
//	                             than false.
//	weak password accepted    -- a finding about the PROJECT, independent of
//	                             whether we went on to use the session.
//	account created           -- residue, reported for cleanup. Reusing a
//	                             stored account is not residue and must not
//	                             be reported as if it were, or the owner goes
//	                             looking for something that is not there.
type accountOutcome struct {
	Token    string
	Warn     bool
	Msg      string
	Findings []finding.Finding
}

func accountNote(restBase, baseURL string, acct escalate.Account, err error) accountOutcome {
	if err != nil {
		out := accountOutcome{Msg: "no authenticated session: " + err.Error()}
		out.Findings = append(out.Findings, finding.NotAssessedVerb(restBase,
			"authenticated", "escalation", err.Error()))
		return out
	}
	out := accountOutcome{Token: acct.Token}
	if acct.WeakAccepted {
		out.Findings = append(out.Findings,
			finding.WeakPasswordAccepted(baseURL, escalate.WeakPassword))
	}
	if acct.Created {
		out.Warn = true
		out.Msg = "created account " + acct.Email + " to measure what a logged-in user " +
			"can reach; it is reported for cleanup"
		out.Findings = append(out.Findings, finding.ProbeAccountLeftBehind(baseURL, acct.Email))
		return out
	}
	out.Msg = "reusing stored account " + acct.Email
	return out
}
