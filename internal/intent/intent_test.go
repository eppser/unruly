package intent

import (
	"strings"
	"testing"
)

// The manifest says what access was INTENDED; the scan says what is real.
//
// unruly proves what an attacker can reach. It has never known what the
// attacker was SUPPOSED to reach, so a relation readable by anyone is reported
// as an exposure whether it is a public price list or a table of payslips, and
// a relation that is correctly locked is reported as nothing at all. The
// operator supplies the missing half.
//
// An agent reads the application once and writes this down. Verification is
// then arithmetic: no model runs during a scan, the same manifest and the same
// target give the same answer, and the answer can be re-checked after a fix.
func TestRealityMorePermissiveThanIntendedIsAViolation(t *testing.T) {
	m := Manifest{SchemaVersion: 1, Expect: []Expectation{
		{Resource: "invoices", Operation: Read, Subject: Anonymous, Result: Deny},
	}}
	got := Verify(m, []Observation{
		{Resource: "invoices", Operation: Read, Subject: Anonymous, Allowed: true},
	})

	if len(got) != 1 {
		t.Fatalf("verified %d expectations, want 1", len(got))
	}
	if got[0].State != Violated {
		t.Errorf("anonymous read of a relation intended to deny it came back %v, "+
			"want Violated", got[0].State)
	}
}

// Reality matching intent is a MATCH, not silence.
//
// Recording the matches is what makes the manifest a coverage statement rather
// than a filter: "17 of 20 expectations verified, 2 violated, 1 unverified" is
// a sentence about the whole intended policy. Reporting only violations would
// make a manifest nobody checked look exactly like one that passed.
func TestRealityMatchingIntentIsRecordedAsAMatch(t *testing.T) {
	m := Manifest{SchemaVersion: 1, Expect: []Expectation{
		{Resource: "invoices", Operation: Read, Subject: Anonymous, Result: Deny},
	}}
	got := Verify(m, []Observation{
		{Resource: "invoices", Operation: Read, Subject: Anonymous, Allowed: false},
	})
	if got[0].State != Matched {
		t.Errorf("a correctly denied read came back %v, want Matched", got[0].State)
	}
}

// AN EXPECTATION NOBODY MEASURED IS NOT A PASS.
//
// The whole argument of this tool, applied to its own newest feature. If the
// scan never established whether other_tenant can read invoices -- because no
// second identity was supplied, because the relation was never discovered,
// because the request was rate-limited -- then the expectation is UNVERIFIED.
// Counting it as satisfied would let a manifest full of intentions produce a
// clean report from a scan that tested none of them.
func TestAnExpectationWithNoObservationIsUnverifiedNotSatisfied(t *testing.T) {
	m := Manifest{SchemaVersion: 1, Expect: []Expectation{
		{Resource: "invoices", Operation: Read, Subject: OtherTenant, Result: Deny},
	}}
	got := Verify(m, nil)

	if got[0].State != Unverified {
		t.Fatalf("an expectation the scan never tested came back %v; counting it as "+
			"satisfied lets a manifest of intentions produce a clean report from a scan "+
			"that measured none of them", got[0].State)
	}
	if got[0].Detail == "" {
		t.Error("an unverified expectation says nothing about why, so the operator " +
			"cannot tell a missing identity from a missing relation")
	}
}

// Intending to ALLOW something that is denied is also a mismatch.
//
// Less urgent than an over-permission and still worth reporting: a policy that
// denies what the product needs is an outage waiting to happen, and it is
// evidence the manifest and the database disagree -- which means one of them
// is wrong and the operator should learn which.
func TestRealityMoreRestrictiveThanIntendedIsReported(t *testing.T) {
	m := Manifest{SchemaVersion: 1, Expect: []Expectation{
		{Resource: "invoices", Operation: Read, Subject: Owner, Scope: ScopeOwn, Result: Allow},
	}}
	got := Verify(m, []Observation{
		{Resource: "invoices", Operation: Read, Subject: Owner, Allowed: false},
	})
	if got[0].State != Violated {
		t.Errorf("an intended allow that is denied came back %v; the manifest and the "+
			"database disagree and the operator should hear which", got[0].State)
	}
}

// A manifest from a future version is refused rather than half-read.
//
// The version exists so an old binary meeting a new manifest says so instead
// of ignoring the fields it does not recognise -- which would silently drop
// expectations and report the remainder as full coverage.
func TestAManifestFromAnUnknownVersionIsRefused(t *testing.T) {
	_, err := Parse([]byte("schema_version: 99\nexpect: []\n"))
	if err == nil {
		t.Fatal("a manifest from an unknown schema version was accepted; unrecognised " +
			"expectations would be dropped and the rest reported as full coverage")
	}
	if !strings.Contains(err.Error(), "99") {
		t.Errorf("error %q does not say which version it found", err)
	}
}

// An unknown subject or operation is a typo, not a silent no-op.
func TestAnUnknownSubjectIsRefused(t *testing.T) {
	_, err := Parse([]byte(`
schema_version: 1
expect:
  - resource: invoices
    operation: read
    subject: onwer
    result: deny
`))
	if err == nil {
		t.Fatal("a misspelt subject was accepted; the expectation would match no " +
			"observation and be reported as unverified forever")
	}
}

func TestOwnScopeIsNotSatisfiedByAnUnscopedAllow(t *testing.T) {
	m := Manifest{SchemaVersion: 1, Expect: []Expectation{{
		Resource: "invoices", Operation: Read, Subject: Owner,
		Scope: ScopeOwn, Result: Allow,
	}}}
	got := Verify(m, []Observation{{
		Resource: "invoices", Operation: Read, Subject: Owner,
		Scope: ScopeAll, Allowed: true,
	}})
	if got[0].State != Violated {
		t.Fatalf("an all-rows allow satisfied an own-rows expectation: %+v", got[0])
	}
}

func TestMorePermissiveObservationCannotBeHiddenByAnotherInterface(t *testing.T) {
	m := Manifest{SchemaVersion: 1, Expect: []Expectation{{
		Resource: "invoices", Operation: Read, Subject: Anonymous, Result: Deny,
	}}}
	got := Verify(m, []Observation{
		{Resource: "invoices", Operation: Read, Subject: Anonymous, Allowed: true},
		{Resource: "invoices", Operation: Read, Subject: Anonymous, Allowed: false},
	})
	if len(got) != 1 || got[0].State != Violated {
		t.Fatalf("a denial hid an allowed interface: %+v", got)
	}

	m.Expect[0] = Expectation{Resource: "invoices", Operation: Read,
		Subject: Owner, Scope: ScopeOwn, Result: Allow}
	got = Verify(m, []Observation{
		{Resource: "invoices", Operation: Read, Subject: Owner, Scope: ScopeOwn, Allowed: true},
		{Resource: "invoices", Operation: Read, Subject: Owner, Allowed: true},
	})
	if len(got) != 1 || got[0].State != Violated {
		t.Fatalf("an own-only observation hid an unscoped allow: %+v", got)
	}
}

func TestUnknownManifestFieldsAreRefused(t *testing.T) {
	_, err := Parse([]byte("schema_version: 1\nexpect: []\nexpectations: []\n"))
	if err == nil {
		t.Fatal("an unknown field was ignored, so a newer manifest could lose rules silently")
	}
}
