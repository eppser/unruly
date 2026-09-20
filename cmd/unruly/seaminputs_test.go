package main

import (
	"testing"

	"github.com/eppser/unruly/internal/client"
)

// The operator's JWT must reach the backends.
//
// -user-jwt is documented as "re-reads relations as that role and reports the
// delta". On the Supabase path it does. A staged backend never saw it, and on
// Neon that is the difference between a scan and a shrug: without a credential
// every table answers identically, so the reach check reports the surface
// unassessed and no escalation stage runs at all. An operator who supplied a
// token would get the same "not assessed" as one who supplied nothing, with
// nothing in the report to say why.
func TestTheOperatorsJWTReachesTheSeam(t *testing.T) {
	o := &options{userJWT: "header.payload.signature", redact: true}
	in := seamInputs(o, []string{"widgets"}, client.New(client.Options{}))

	if in.Bearer != o.userJWT {
		t.Errorf("the seam was given Bearer %q, want the operator's -user-jwt. A "+
			"backend that never receives it cannot tell an authenticated caller "+
			"from a stranger, and reports the surface unassessed either way",
			in.Bearer)
	}
	if !in.Redact {
		t.Error("-redact did not reach the seam")
	}
	if in.Client == nil {
		t.Error("no client reached the seam; every staged backend would refuse to run")
	}
	if len(in.Seeds) != 1 {
		t.Errorf("seeds did not reach the seam: %v", in.Seeds)
	}
}

// Write consent reaches the seam, and only when BOTH flags were given.
//
// -write alone is not consent: the second flag exists because the first is
// easy to type by habit. A backend that received consent the operator did not
// give would change data on a project nobody agreed to touch.
func TestWriteConsentReachesTheSeamOnlyWhenBothFlagsAreGiven(t *testing.T) {
	c := client.New(client.Options{})
	for _, tc := range []struct {
		name             string
		write, confirmed bool
		want             bool
	}{
		{"neither flag", false, false, false},
		{"-write alone", true, false, false},
		{"confirmation alone", false, true, false},
		{"both", true, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o := &options{write: tc.write, confirmOwn: tc.confirmed}
			if got := seamInputs(o, nil, c).Write; got != tc.want {
				t.Errorf("seam received Write=%v, want %v. Consent is both flags: "+
					"-write alone is a habit, the confirmation is the decision",
					got, tc.want)
			}
		})
	}
}
