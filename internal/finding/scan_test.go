package finding

import (
	"errors"
	"strings"
	"testing"
)

// These three describe the scan rather than the target, and until now none of
// them had a test that executed the constructor.
//
// They passed the emit-site coverage check by accident: they build ids that
// OTHER packages also construct, so the check found a site it could see and
// was satisfied. The accident held until a fourth constructor was added in
// main.go whose id was unique, and two audit checks failed on it.
//
// The lesson is not about those three functions. It is that "some package
// constructs this id under test" and "this code runs under test" are different
// claims, and only the second is worth anything.

func TestInterruptedSaysTheListIsAFragment(t *testing.T) {
	f := Interrupted("https://app.example.com", errors.New("context canceled"))

	if f.Resource != InterruptedResource {
		t.Errorf("resource %q: the exit-code machinery keys on this", f.Resource)
	}
	if f.Severity != Info {
		t.Errorf("severity %v; an interrupted scan is unmeasured, not dangerous", f.Severity)
	}
	if !strings.Contains(f.Description, "FRAGMENT") {
		t.Error("the finding does not say the results are partial, which is the one thing " +
			"it exists to say")
	}
	if !strings.Contains(f.Description, "context canceled") {
		t.Error("the cause is not carried, so a reader cannot tell a Ctrl-C from a timeout")
	}
}

func TestTargetFailedNamesTheWithheldKey(t *testing.T) {
	plain := TargetFailed("https://b.example.com", errors.New("no credential"), "")
	if !strings.Contains(plain.Description, "not scanned") {
		t.Error("a target that produced no scan must say so; absence of findings for it " +
			"is not evidence that it is sound")
	}
	if strings.Contains(plain.Description, "deliberately not sent") {
		t.Error("no key was withheld here, and claiming one was would send the reader " +
			"looking for a decision nobody made")
	}

	withheld := TargetFailed("https://b.example.com", errors.New("no credential"), "aaaa")
	if !strings.Contains(withheld.Description, "aaaa") {
		t.Error("the key was withheld because it belongs to another project, and the " +
			"report does not say so -- a thin result then looks like a property of this " +
			"target rather than a decision the scanner made")
	}
}

func TestNotAssessedSchemaIsNotAnEmptySchema(t *testing.T) {
	f := NotAssessedSchema("https://ref.supabase.co/rest/v1", "staging", "no vocabulary matched")

	if f.Resource != "schema:staging" {
		t.Errorf("resource %q", f.Resource)
	}
	if !strings.Contains(f.Description, "unmeasured") {
		t.Error("an exposed schema nobody could enumerate must be reported as unmeasured, " +
			"not left to read as empty")
	}
	if !strings.Contains(f.Remediation, "Accept-Profile: staging") {
		t.Error("the remediation does not show how to reach the schema by hand, so a " +
			"reader cannot check the claim")
	}
}

// The offline emit site for unruly-target-refused, and the property that
// matters most about it: it must read as unmeasured, not as clean.
//
// This finding exists because a refusing host produces a report shaped exactly
// like a hardened one -- no findings, several "not assessed" lines. A reader
// who skims the severities sees nothing above info in both cases.
func TestTargetRefusedReadsAsUnmeasuredNotClean(t *testing.T) {
	f := TargetRefused("https://example.test", 88, "429 to everything")
	if f.ID != "unruly-target-refused" {
		t.Errorf("id = %q", f.ID)
	}
	if f.Severity != Info {
		t.Errorf("severity = %s; a statement about the scan must never compete "+
			"with a statement about the target", f.Severity)
	}
	if !strings.Contains(f.Description, "88") {
		t.Error("the count is the evidence; without it the claim is a boolean")
	}
	for _, must := range []string{"not a clean result", "absence of measurement"} {
		if !strings.Contains(f.Description, must) {
			t.Errorf("description does not say %q", must)
		}
	}
	// Remediation is piped into psql verbatim by operators and by the eval, so
	// every non-SQL line must be a comment. Here there is no SQL at all.
	for _, line := range strings.Split(f.Remediation, "\n") {
		if line != "" && !strings.HasPrefix(line, "--") {
			t.Errorf("non-comment line in remediation would be executed as SQL: %q", line)
		}
	}
}

// Offline emit sites for the two "the scan could not see" statements added
// with the prefix and credential work, plus the property that matters about
// each: an empty report must never be mistakable for a clean one.
func TestScanCouldNotSeeFindingsSaySoPlainly(t *testing.T) {
	rejected := CredentialRejected("https://x.test", 18755, "service_role", "harvested from the target")
	if rejected.ID != "unruly-credential-rejected" || rejected.Severity != Info {
		t.Errorf("rejected = %s/%s", rejected.ID, rejected.Severity)
	}
	// The role matters: it tells the reader which key to go and find.
	if !strings.Contains(rejected.Description, "service_role") {
		t.Error("the finding does not say which role the rejected key claimed")
	}
	if !strings.Contains(rejected.Description, "NOTHING below is a statement") {
		t.Error("an unmeasured project must not read as a clean one")
	}

	corrected := RestPrefixCorrected("https://x.test", "/rest/v1", "/")
	if corrected.ID != "unruly-rest-prefix-corrected" || corrected.Severity != Info {
		t.Errorf("corrected = %s/%s", corrected.ID, corrected.Severity)
	}
	// A scan that moves must name both addresses, or the reader cannot tell
	// what the findings below describe.
	for _, must := range []string{"/rest/v1", "PGRST125"} {
		if !strings.Contains(corrected.Description, must) {
			t.Errorf("description does not mention %q", must)
		}
	}
	// Remediation is piped into psql verbatim; neither of these has any SQL.
	for _, f := range []Finding{rejected, corrected} {
		for _, line := range strings.Split(f.Remediation, "\n") {
			if line != "" && !strings.HasPrefix(line, "--") {
				t.Errorf("%s: non-comment line would execute as SQL: %q", f.ID, line)
			}
		}
	}
}

// Offline emit site for the stop condition, and the property that makes it
// worth stopping for: an unmeasured project must not read as a clean one.
func TestRestPrefixUnresolvedReadsAsUnmeasured(t *testing.T) {
	f := RestPrefixUnresolved("https://x.test", "/rest/v1")
	if f.ID != "unruly-rest-prefix-unresolved" || f.Severity != Info {
		t.Errorf("finding = %s/%s", f.ID, f.Severity)
	}
	if !strings.Contains(f.Description, "NOTHING below is a statement") {
		t.Error("a scan that never reached an address that exists must say so")
	}
	if !strings.Contains(f.Remediation, "-rest-prefix") {
		t.Error("the operator is not told the flag that fixes this")
	}
	for _, line := range strings.Split(f.Remediation, "\n") {
		if line != "" && !strings.HasPrefix(line, "--") {
			t.Errorf("non-comment line would execute as SQL: %q", line)
		}
	}
}

// Offline emit site for the account this scanner leaves behind, and the two
// properties that make it honest: it names the account, and its remediation is
// executable.
func TestProbeAccountLeftBehindNamesWhatToDelete(t *testing.T) {
	f := ProbeAccountLeftBehind("https://x.test", "unruly-probe-abc123@example.invalid")
	if f.ID != "unruly-probe-account-left-behind" || f.Severity != Info {
		t.Errorf("finding = %s/%s", f.ID, f.Severity)
	}
	// Residue is this scanner's own mess; an operator who cannot find it
	// cannot clear it.
	if !strings.Contains(f.Remediation, "unruly-probe-abc123@example.invalid") {
		t.Error("the remediation does not name the account to delete")
	}
	if !strings.Contains(f.Remediation, "DELETE FROM auth.users") {
		t.Error("no executable statement: the operator is left to work it out")
	}
	// Every non-SQL line is piped into psql verbatim, so it must be a comment.
	for _, line := range strings.Split(f.Remediation, "\n") {
		if line == "" || strings.HasPrefix(line, "--") {
			continue
		}
		if !strings.HasPrefix(line, "DELETE FROM") {
			t.Errorf("non-comment, non-SQL line would be executed: %q", line)
		}
	}
}

// Offline emit site for the password-policy finding, and the property that
// makes it checkable rather than an assertion.
func TestWeakPasswordAcceptedNamesWhatWasAccepted(t *testing.T) {
	f := WeakPasswordAccepted("https://x.test", "password123")
	if f.ID != "supabase-weak-password-policy" || f.Severity != Low {
		t.Errorf("finding = %s/%s", f.ID, f.Severity)
	}
	// A reader who cannot see which password was taken cannot verify the claim
	// or judge how bad it is.
	if !strings.Contains(f.Description, "password123") {
		t.Error("the finding does not name the password the project accepted")
	}
	// Low on purpose: nobody's data moved. Rating it higher pushes a real
	// exposure down the page.
	if f.Severity >= Medium {
		t.Error("a password policy is not exposure and must not outrank one")
	}
	for _, line := range strings.Split(f.Remediation, "\n") {
		if line == "" || strings.HasPrefix(line, "--") {
			continue
		}
		if !strings.HasPrefix(line, "SELECT") {
			t.Errorf("non-comment, non-SQL line would be executed: %q", line)
		}
	}
}

// Offline emit site for the subdomain listing, and the property that keeps it
// honest: it must claim nothing about the hosts it names.
func TestSubdomainsFoundClaimsNothingAboutTheHosts(t *testing.T) {
	f := SubdomainsFound("example.com",
		[]string{"staging.example.com", "api.example.com"}, 34)
	if f.ID != "unruly-subdomains-found" || f.Severity != Info {
		t.Errorf("finding = %s/%s", f.ID, f.Severity)
	}
	// Discovering that a host exists says nothing about its posture. Rating it
	// as though it did would be the same error as reporting a Firestore 403.
	for _, must := range []string{"NOTHING was scanned", "nothing is claimed"} {
		if !strings.Contains(f.Description, must) {
			t.Errorf("description does not say %q, so a reader may take the list as "+
				"a verdict on those hosts", must)
		}
	}
	// It must say how many were tried, or the list implies it found everything.
	if !strings.Contains(f.Description, "34") {
		t.Error("the candidate count is missing, so the coverage of the list is unstated")
	}
	if len(f.Evidence.Columns) != 2 {
		t.Errorf("evidence carries %d hosts, want the 2 it found", len(f.Evidence.Columns))
	}
	for _, line := range strings.Split(f.Remediation, "\n") {
		if line != "" && !strings.HasPrefix(line, "--") {
			t.Errorf("non-comment line would execute as SQL: %q", line)
		}
	}
}
