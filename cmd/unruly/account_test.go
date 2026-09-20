package main

import (
	"errors"
	"strings"
	"testing"

	"github.com/eppser/unruly/internal/escalate"
)

// An account this scan created must always reach the report.
//
// This is the one place the scanner can leave something behind on a target it
// was authorised to write to. The report is the only record the project owner
// gets, so a created account that is not reported is exactly the residue this
// tool promises not to leave -- and nothing else in the run would mention it.
func TestAccountNoteReportsAnAccountItCreated(t *testing.T) {
	n := accountNote("https://x/rest/v1", "https://x", escalate.Account{
		Token: "tok", Email: "probe@example.test", Created: true}, nil)

	if n.Token != "tok" {
		t.Errorf("token not carried through: %q", n.Token)
	}
	if !n.Warn {
		t.Error("creating an account on someone's project is logged at info level; " +
			"the one action with lasting effect must be the loud one")
	}
	var found bool
	for _, f := range n.Findings {
		if f.ID == "unruly-probe-account-left-behind" {
			found = true
			if !strings.Contains(f.Description+f.Remediation+f.Matched, "probe@example.test") {
				t.Error("the residue finding does not name the account, so the owner " +
					"cannot delete the thing it is telling them about")
			}
		}
	}
	if !found {
		t.Fatalf("an account was created and no finding says so; got %d finding(s)",
			len(n.Findings))
	}
}

// Reusing a stored account is not residue and must not be reported as if it
// were, or the owner goes looking for something that is not there.
func TestAccountNoteDoesNotReportAReusedAccountAsResidue(t *testing.T) {
	n := accountNote("https://x/rest/v1", "https://x", escalate.Account{
		Token: "tok", Email: "probe@example.test", Created: false}, nil)

	for _, f := range n.Findings {
		if f.ID == "unruly-probe-account-left-behind" {
			t.Fatal("a reused account was reported as left behind")
		}
	}
	if n.Warn {
		t.Error("reusing an account changes nothing on the target and must not warn")
	}
}

// A weak password the project accepted is a fact about the PROJECT, so it is
// reported whether or not this run created the account that proved it.
func TestAccountNoteReportsAWeakPasswordEitherWay(t *testing.T) {
	for _, created := range []bool{true, false} {
		n := accountNote("https://x/rest/v1", "https://x", escalate.Account{
			Token: "tok", Email: "p@example.test", Created: created, WeakAccepted: true}, nil)
		var found bool
		for _, f := range n.Findings {
			if strings.Contains(f.ID, "weak-password") {
				found = true
			}
		}
		if !found {
			t.Errorf("created=%v: the project accepted a weak password and no finding "+
				"says so", created)
		}
	}
}

// Failing to get a session is a coverage gap, not a clean result.
//
// The escalation comparison never happened, so "anon reaches everything there
// is" is unmeasured rather than false. Reporting nothing here would let the
// scan exit as though the middle tier of the threat model had been checked.
func TestAccountNoteRecordsAMissingSessionAsUnmeasured(t *testing.T) {
	n := accountNote("https://x/rest/v1", "https://x", escalate.Account{},
		errors.New("signup closed"))

	if n.Token != "" {
		t.Error("a failed acquisition handed back a token")
	}
	if len(n.Findings) != 1 {
		t.Fatalf("got %d findings, want exactly one recording the gap", len(n.Findings))
	}
	f := n.Findings[0]
	if !strings.Contains(f.Description+f.Remediation, "signup closed") {
		t.Error("the reason the session could not be obtained is dropped, so the " +
			"report says a check did not run without saying why")
	}
}
