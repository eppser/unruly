package main

import "testing"

// A Supabase scan needs POSITIVE EVIDENCE that the target is Supabase.
//
// Measured: with SUPABASE_ANON_KEY exported and the target a plain website,
// unruly ran the whole PostgREST pipeline -- 1,200 relation probes plus
// routine probes -- against a host with no database behind it. The findings
// were degraded ("enumeration cannot be distinguished from a target with
// nothing to find") and the traffic was real.
//
// An environment variable is not an instruction. It is routinely exported for
// project A and forgotten while somebody scans site B, and this repository
// already says so in run(): "Ambient, not an instruction. A key exported for
// one project must not decide how a different project is scanned." It recorded
// that and then scanned anyway.
func TestAnAmbientKeyIsNotEvidenceOfSupabase(t *testing.T) {
	// restPrefix carries its DEFAULT, as it does in every real scan. Without
	// it this test constructs a state no binary is ever in: the first version
	// of the gate treated a non-empty restPrefix as evidence, passed here with
	// the field left zero, and let the pipeline run against a plain website.
	// The tests were green and the binary was wrong.
	o := &options{site: "https://example.invalid", anonKey: "eyJhbGc",
		keyFromEnv: true, restPrefix: defaultRestPrefix,
		// baseURL as resolveOrigin leaves it: the program's own inference,
		// which must not count as the operator having said anything.
		baseURL: "https://example.invalid"}
	if ok, _ := supabaseSelected(o); ok {
		t.Error("a key inherited from the environment was treated as evidence that an " +
			"arbitrary website is a Supabase project; that is 1,200 probes at somebody " +
			"else's host on the strength of a forgotten export")
	}
}

// A key TYPED by the operator is not evidence either.
//
// Passing -k says "here is a credential", not "this host is Supabase". The
// legitimate case -- a self-hosted project behind a custom domain -- is served
// by saying where the API is, which is what -base-url and -rest-prefix are
// for, and that IS positive evidence.
func TestASuppliedKeyAloneIsNotEvidenceOfSupabase(t *testing.T) {
	o := &options{site: "https://example.invalid", anonKey: "eyJhbGc",
		restPrefix: defaultRestPrefix}
	if ok, _ := supabaseSelected(o); ok {
		t.Error("-k alone selected the Supabase pipeline for an arbitrary host; a " +
			"credential is not a statement about what the target runs")
	}
}

// The ordinary cases still work, and that is the whole difficulty.
//
// A gate that refuses the normal path is a gate somebody removes. Each of
// these is a real statement that the target is Supabase.
func TestPositiveEvidenceSelectsSupabase(t *testing.T) {
	for _, tc := range []struct {
		name string
		o    *options
	}{
		{"managed host", &options{target: "https://abcdefghijklm.supabase.co"}},
		{"discovered project ref", &options{site: "https://app.invalid", projectRef: "abcdefghijklm"}},
		{"operator located the API", &options{site: "https://app.invalid", apiLocated: true}},

		{"operator named the provider", &options{site: "https://app.invalid", provider: "supabase"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if ok, _ := supabaseSelected(tc.o); !ok {
				t.Errorf("%s did not select the Supabase pipeline; a gate that refuses "+
					"the ordinary path is a gate somebody removes", tc.name)
			}
		})
	}
}

// And the refusal says what would make it run.
func TestTheRefusalNamesWhatWouldSelectIt(t *testing.T) {
	_, why := supabaseSelected(&options{site: "https://example.invalid",
		keyFromEnv: true, restPrefix: defaultRestPrefix,
		// baseURL as resolveOrigin leaves it: the program's own inference,
		// which must not count as the operator having said anything.
		baseURL: "https://example.invalid"})
	if why == "" {
		t.Error("the scan declined the Supabase pipeline and said nothing about why, " +
			"so an operator whose project IS Supabase cannot tell what to pass")
	}
}
