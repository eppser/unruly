package supabase

import (
	"testing"

	"github.com/eppser/unruly/scan"
)

func TestTheSupabasePlanValidates(t *testing.T) {
	if err := scan.Validate(Stages(Config{})); err != nil {
		t.Fatalf("the provider's own stage list is not a runnable plan:\n%v", err)
	}
}

// A default scan asks for no permission it was not given.
//
// The descriptors describe the CONFIGURED stage, so this is a real check
// rather than a tautology: with -write off, no Supabase stage may declare
// itself a mutator, and a read-only scan must therefore pass consent with
// nothing granted. If that ever fails, either a stage started declaring the
// type rather than the configuration, or a stage really did gain the ability
// to write by default.
func TestADefaultSupabaseScanNeedsNoConsent(t *testing.T) {
	if err := scan.CheckConsent(Stages(Config{}), scan.Consent{}); err != nil {
		t.Errorf("a read-only scan exceeded what an operator granting nothing "+
			"authorised:\n%v", err)
	}
}

// And a -write scan declares exactly what it will do.
//
// The point of the declaration is that it is checkable in advance. A scan
// configured to write must SAY it writes -- otherwise the plan-level consent
// check passes vacuously and the only guard left is the per-stage one it was
// added to back up.
func TestAWriteScanDeclaresThatItMutates(t *testing.T) {
	cfg := Config{Write: true, Invoke: true, Site: "https://app.example.invalid"}
	if err := scan.CheckConsent(Stages(cfg), scan.Consent{}); err == nil {
		t.Error("a scan configured to write, invoke routines and POST to application " +
			"routes claimed it needed no write consent; the plan-level check would " +
			"pass on every scan and guard nothing")
	}
	if err := scan.CheckConsent(Stages(cfg),
		scan.Consent{Write: true, ThirdParty: true}); err != nil {
		t.Errorf("a fully authorised scan was refused: %v", err)
	}
}
