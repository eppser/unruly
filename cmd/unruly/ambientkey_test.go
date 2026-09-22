package main

import (
	"strings"
	"testing"
)

// An ambient SUPABASE_ANON_KEY must not abort a scan of an unrelated target.
//
// Reported from a real run against a site whose HTML disclosed a project ref
// and whose bundle yielded no key:
//
//	[INF] project ref xiqbvmezmicfggkrkfsh (via html)
//	[ERR] the supplied key was issued for project "jmcqeffsqckkefqiivhk" but the
//	      target is "xiqbvmezmicfggkrkfsh" ... Use that project's own anon key
//	[WRN] exit 3 ... could not be assessed — this is not a clean result
//
// Nobody supplied a key for that target. It was exported for another project
// and forgotten, which discovery.go already calls "how anyone who works on a
// Supabase project has their shell". chooseKey handles the case where the
// target ships its own key; this is the case where it does not, and the scan
// died on a credential the operator never aimed here.
//
// The consequence is the one SECURITY.md calls a vulnerability in this
// project: a false negative. The target reported unassessed because of the
// operator's shell, and a reader cannot tell that from a target that genuinely
// refused.
func TestAnAmbientKeyForAnotherProjectDoesNotAbort(t *testing.T) {
	got := credentialFor("keyA", "projA", "projB", "", false, true /* fromEnv */)
	if got.Err != nil {
		t.Fatalf("aborted on an ambient key: %v\nAn env var is context about the "+
			"operator's own work, not an instruction about this target", got.Err)
	}
	if got.Key != "" {
		t.Errorf("kept key %q, which belongs to another project and can only be "+
			"rejected", got.Key)
	}
	if got.WithheldRef != "projA" {
		t.Errorf("WithheldRef = %q; a report has to disclose which credential was "+
			"dropped, or two runs of the same target are indistinguishable", got.WithheldRef)
	}
	if !strings.Contains(got.Warn, "SUPABASE_ANON_KEY") {
		t.Errorf("warning %q does not name the environment variable responsible; the "+
			"operator has to know what to unset", got.Warn)
	}
	// The old message told them to "use that project's own anon key", which
	// blames them for supplying something they did not aim here, and points at
	// the wrong project.
	if strings.Contains(got.Warn, "scan projA instead") {
		t.Errorf("warning %q suggests scanning the ambient key's project; nobody asked "+
			"to scan that", got.Warn)
	}
}

// An explicit -k still aborts. That one IS an instruction about this target,
// and a mismatch there is either the wrong key for the right target or the
// right key for the wrong one -- indistinguishable, and the second means
// scanning somebody who never asked.
func TestAnExplicitKeyForAnotherProjectStillAborts(t *testing.T) {
	got := credentialFor("keyA", "projA", "projB", "", false, false /* fromEnv */)
	if got.Err == nil {
		t.Fatal("an explicitly supplied -k for the wrong project was accepted")
	}
}

// The list case is unchanged: it already falls back to the discovered key.
func TestTheListFallbackIsUnchanged(t *testing.T) {
	for _, fromEnv := range []bool{true, false} {
		got := credentialFor("keyA", "projA", "projB", "discovered", true, fromEnv)
		if got.Err != nil {
			t.Errorf("fromEnv=%v: list entry aborted: %v", fromEnv, got.Err)
		}
		if got.Key != "discovered" {
			t.Errorf("fromEnv=%v: key %q, want the discovered one", fromEnv, got.Key)
		}
	}
}

// The warning has to be actionable without naming a project nobody asked
// about, and has to say the backend went unassessed rather than implying a
// clean result.
//
// Verified at this level rather than by scanning. The first attempt built an
// HTML fixture carrying the project ref from the field report, and unruly did
// exactly what it is for: resolved the ref and sent five probes to a stranger's
// Supabase host. The tool's whole job is turning identifiers into targets, so a
// fixture containing a real identifier is a live scan wearing a costume.
func TestTheAmbientWarningIsActionableAndHonest(t *testing.T) {
	got := credentialFor("keyA", "projA", "projB", "", false, true)
	for _, want := range []string{
		"SUPABASE_ANON_KEY", // what to unset
		"-k",                // how to supply the right one
		"projB",             // which project actually needs a credential
		"cannot be assessed",
	} {
		if !strings.Contains(got.Warn, want) {
			t.Errorf("warning is missing %q:\n  %s", want, got.Warn)
		}
	}
	if got.Err != nil {
		t.Errorf("an ambient key must not abort: %v", got.Err)
	}
}
