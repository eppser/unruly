package routes

import (
	"fmt"
	"strings"
	"testing"

	"github.com/eppser/unruly/internal/finding"
)

// A LONE ENDPOINT THAT HANDS OUT DATA IS A FINDING.
//
// The route check emitted a finding only when a FAMILY was inconsistent --
// /orders/1 requiring a session while /orders/2 did not. Inconsistency is a
// proxy for a missing authorisation check, and it is a good one, but it
// carries an assumption nobody stated: that an endpoint answering anonymously
// is fine if its siblings do too.
//
// So an API where EVERYTHING is open scores perfectly consistent, and the
// worst case is the blind spot. On a real target one endpoint returned a live,
// database-backed record containing an employee address to anyone who asked,
// and it was alone in its family. Discovered, probed, 200, and silent.
func TestALoneEndpointServingSensitiveDataIsReported(t *testing.T) {
	r := Route{
		Base: "https://api-host.run.app", Path: "/system/mode", GET: 200,
		Snippet: `{"success":true,"data":{"mode":"maintenance",` +
			`"updated_by_email":"ops.lead@example.invalid","updated_at":"2026-08-21T09:14:00Z"}}`,
	}
	f, ok := standaloneExposure(r, false)
	if !ok {
		t.Fatal("an endpoint returning a live record with an employee address to an " +
			"anonymous caller produced no finding, because it was alone in its family. " +
			"An API where everything is open is perfectly consistent.")
	}
	if f.Severity != finding.Low {
		t.Errorf("severity %s for a contact-class record, want low", f.Severity)
	}
	if f.Evidence.Status != 200 {
		t.Errorf("evidence status = %d, want the response that justified the finding", f.Evidence.Status)
	}

	// A CREDENTIAL must not come out at the same level as an address.
	//
	// The first version asserted only `>= Low`, which is the floor -- so a
	// mapping that returned Low for everything passed. Measured, by feeding
	// the severity switch field:class pairs it could never match and watching
	// the test survive.
	cred := Route{Base: "https://api-host.run.app", Path: "/system/mode", GET: 200,
		Snippet: `{"data":{"password_hash":"$2b$12$abcdefghijklmnopqrstuv"}}`}
	cf, ok := standaloneExposure(cred, false)
	if !ok {
		t.Fatal("an endpoint serving a password hash to anyone produced no finding")
	}
	if cf.Severity != finding.Critical {
		t.Errorf("a password hash served to anonymous callers came out %s, not "+
			"critical; severity has stopped following the class", cf.Severity)
	}
	// The CLASS, not a field:class pair: severity is a function of the class,
	// and mixing the classifier's two output shapes made the severity switch
	// match nothing while looking correct.
	if !strings.Contains(strings.Join(f.Evidence.Classes, ","), "contact") {
		t.Errorf("classes %v do not name what was found; the class is the reason the "+
			"finding exists", f.Evidence.Classes)
	}
}

// THE VALUE IS REDACTED AND THE CLASS IS NOT.
//
// The finding has to say an employee address was exposed without republishing
// it. Reporting a leak by copying the leaked value into a file that gets
// stored, diffed and pasted into tickets makes the report a second copy of the
// problem.
func TestTheExposedValueIsRedactedAndTheClassKept(t *testing.T) {
	r := Route{
		Base: "https://api-host.run.app", Path: "/system/mode", GET: 200,
		Snippet: `{"updated_by_email":"ops.lead@example.invalid"}`,
	}
	f, ok := standaloneExposure(r, true)
	if !ok {
		t.Fatal("no finding")
	}
	whole := f.Description + f.Evidence.Reason + fmt.Sprint(f.Evidence.Sample)
	if strings.Contains(whole, "ops.lead@example.invalid") {
		t.Error("the finding repeats the exposed address; a report that copies the " +
			"leaked value is a second copy of the leak")
	}
	if len(f.Evidence.Classes) == 0 {
		t.Error("redaction removed the classes too, so the finding no longer says " +
			"what kind of data was exposed -- which is the whole content of it")
	}
}

// AN ENDPOINT THAT REFUSES IS NOT REPORTED.
//
// The five endpoints on the testbed that correctly answer 401 are the
// controls, and they matter as much as the finding. A scan that flags them
// sends somebody to fix five things that are already right and discredits the
// one that is real.
func TestAnEndpointThatRefusesIsNotReported(t *testing.T) {
	// The refusal body CLASSIFIES, deliberately. With a plain
	// {"detail":"Not authenticated"} this test passed whatever the status
	// check did -- measured, by breaking the check and watching it survive --
	// because that body holds nothing worth protecting and the classifier
	// rejected it for a different reason.
	//
	// Real refusals carry text like this. If the status is not checked, an
	// endpoint that correctly REFUSES is reported as one that leaks.
	for _, code := range []int{401, 403, 404, 405, 500, 302} {
		r := Route{Base: "https://api-host.run.app", Path: "/crm/customers", GET: code,
			Snippet: `{"detail":"Not authenticated","support_email":"help@vendor.invalid"}`}
		if _, ok := standaloneExposure(r, false); ok {
			t.Errorf("an endpoint answering %d was reported as exposed", code)
		}
	}
}

// AND NEITHER IS AN ENDPOINT THAT RETURNS NOTHING SENSITIVE.
//
// Plenty of endpoints answer 200 to anyone on purpose: /health, /version, a
// public price list. Reporting all of them would bury the one that matters,
// and noise is what gets a check switched off. The classifier is the
// discriminator -- if there is nothing in the body worth protecting, there is
// nothing to report.
func TestAHealthEndpointIsNotReported(t *testing.T) {
	for _, body := range []string{
		`{"status":"ok"}`,
		`{"version":"1.4.2","commit":"a91f2"}`,
		`{"success":true,"data":{"mode":"maintenance"}}`,
	} {
		r := Route{Base: "https://api-host.run.app", Path: "/health", GET: 200, Snippet: body}
		if f, ok := standaloneExposure(r, false); ok {
			t.Errorf("%s was reported as an exposure (%s); an endpoint that is open on "+
				"purpose and holds nothing worth protecting is not a finding, and "+
				"reporting it buries the one that is", body, f.Severity)
		}
	}
}
