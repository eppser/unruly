package provider

import (
	"os"
	"strings"
	"testing"
)

// Escalation is measured now, so Neon must stop declaring it unmeasurable.
//
// Cannot() is not documentation. It drives the report: a declared limit prints
// as "could not look", and a capability that IS measured but still listed
// there tells an operator the scan skipped the very check it performed. The
// entry comes out when the stage lands, which is what this grades.
func TestNeonNoLongerDeclaresEscalationUnmeasurable(t *testing.T) {
	cannot := (neon{}).Cannot()
	if why, still := cannot[CapEscalate]; still {
		t.Errorf("Neon still declares CapEscalate unmeasurable (%q), but "+
			"backend/neon measures it against the recorded lab: a report would "+
			"say it could not look at the one thing it looked hardest at", why)
	}
}

// The write tier is measured now, so Neon must stop declaring it unmeasurable.
//
// The declaration was kept deliberately while the stage existed and the seam
// did not run it: a capability listed in Cannot() prints as "could not look",
// and removing that before the binary could reach the tier would have told an
// operator it was measured when nothing ran it. The seam now contributes the
// stage under -write -yes-i-own-this, so the declaration comes out.
func TestNeonNoLongerDeclaresWriteUnmeasurable(t *testing.T) {
	if why, still := (neon{}).Cannot()[CapWrite]; still {
		t.Errorf("Neon still declares CapWrite unmeasurable (%q), but backend/neon "+
			"measures it and the seam contributes the stage when the operator "+
			"consents", why)
	}
}

// The remaining limits must not rest on a claim we have disproved.
//
// Two statements in this file came from the vendor docs and are false against
// the live project, measured 2026-08-21:
//
//   - that a request with no Authorization header maps to the `anonymous`
//     role. It does not; every table answers 400 identically, including ones
//     the anonymous role has no GRANT on.
//   - that escalation needs an external auth provider because Neon has no
//     sign-up call. Neon Auth has open, unverified sign-up.
//
// A wrong reason attached to a real limit is worse than no reason: it is the
// sentence an operator plans around.
func TestNeonLimitsDoNotRestOnDisprovenClaims(t *testing.T) {
	for capability, why := range (neon{}).Cannot() {
		low := strings.ToLower(why)
		if strings.Contains(low, "anonymous` role") || strings.Contains(low, "anonymous role") {
			if strings.Contains(low, "maps a request with no authorization header") {
				t.Errorf("%v still says a headerless request maps to the anonymous "+
					"role; measured, it is refused identically for every table", capability)
			}
		}
		if strings.Contains(low, "no sign-up call") {
			t.Errorf("%v still says Neon has no sign-up call; Neon Auth sign-up is "+
				"open and unverified on the lab, which is what makes the "+
				"escalation reachable by a stranger", capability)
		}
	}
}

// The package comment must not carry the disproven claim either.
//
// The doc comment is what the next person reads before touching the detector.
// Leaving the vendor's version there means the correction survives only as
// long as this conversation does.
func TestNeonDocCommentDoesNotRepeatTheDisprovenMapping(t *testing.T) {
	src, err := os.ReadFile("neon.go")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(src), "maps a request with NO\n// Authorization header onto the `anonymous` role") ||
		strings.Contains(string(src), "maps a request with NO Authorization header onto the `anonymous` role") {
		t.Error("neon.go still documents the vendor claim that a headerless request " +
			"maps to the anonymous role. Measured against the live Data API it is " +
			"refused 400 for every table, granted or not -- non-discriminating, " +
			"which is a blind condition rather than an anonymous read")
	}
}

// The target URL is itself evidence.
//
// Detection reads bundles, which is right when the endpoint is a string inside
// somebody's JavaScript. It left out the simplest case: the operator points -u
// at the Data API and says "scan this". Measured against the live lab, that
// invocation sent 1707 requests down the PostgREST path, reported twelve info
// findings, and never ran the Neon backend at all -- so the escalation this
// project can prove was absent from the report of a scan aimed straight at it.
//
// A URL supplied on the command line is stronger evidence than one found in a
// bundle, not weaker: nobody typed it by accident.
func TestTheTargetURLIsEnoughToIdentifyNeon(t *testing.T) {
	for _, site := range []string{
		"https://ep-x.apirest.eu-west-1.aws.neon.tech/neondb/rest/v1",
		"https://ep-x.apirest.eu-west-1.aws.neon.tech/neondb/rest/v1/",
		"https://ep-x.apirest.c-4.us-east-2.aws.neon.tech/appdb/rest/v1",
	} {
		t.Run(site, func(t *testing.T) {
			d, ok := (neon{}).Detect(Surface{Site: site})
			if !ok {
				t.Fatalf("pointing the scanner at %s did not identify Neon. The whole "+
					"backend is then unreachable from the invocation an operator "+
					"would type first", site)
			}
			if d.Provider != "neon" {
				t.Errorf("identified %q", d.Provider)
			}
			if d.Project == "" {
				t.Error("no project recorded, so APIBase has nothing to build from")
			}
		})
	}
}

// A neon.tech host that is NOT a Data API must still be rejected.
//
// The reason the detector demands three signals together: a Postgres
// connection host, a docs link or the vendor console are all neon.tech, and
// scanning a host nobody owns is the worst thing this tool can do.
func TestATargetURLThatIsNotADataAPIIsNotIdentified(t *testing.T) {
	for _, site := range []string{
		"https://neon.tech/docs/data-api",
		"https://console.neon.tech/app/projects",
		"https://ep-x.c-4.us-east-2.aws.neon.tech/neondb",
		"https://ep-x.apirest.eu-west-1.aws.neon.tech/",
	} {
		if _, ok := (neon{}).Detect(Surface{Site: site}); ok {
			t.Errorf("%s was identified as a Neon Data API endpoint; it is not one, and "+
				"a false identification points a scan at somebody else's host", site)
		}
	}
}
