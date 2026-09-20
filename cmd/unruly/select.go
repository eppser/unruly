package main

import "strings"

// defaultRestPrefix is what -rest-prefix is when nobody sets it. Compared
// against rather than against empty: see supabaseSelected.
const defaultRestPrefix = "/rest/v1"

// supabaseSelected reports whether there is POSITIVE EVIDENCE that this target
// is a Supabase project, and if not, what would provide it.
//
// It exists because a key was enough. Measured: with SUPABASE_ANON_KEY
// exported and the target a plain website, unruly ran the whole PostgREST
// pipeline -- 1,200 relation probes plus routine probes -- against a host with
// no database behind it, and reported degraded capabilities because
// "enumeration cannot be distinguished from a target with nothing to find".
// The traffic was real and the conclusion was noise.
//
// AN ENVIRONMENT VARIABLE IS NOT AN INSTRUCTION. It is routinely exported for
// one project and forgotten while somebody scans another. run() already says
// exactly this -- "Ambient, not an instruction. A key exported for one project
// must not decide how a different project is scanned" -- and then scanned
// anyway; the observation was recorded and never acted on.
//
// A key TYPED by the operator is not evidence either. Passing -k says "here is
// a credential", not "this host is Supabase". The legitimate case -- a
// self-hosted project behind a custom domain -- is served by saying where the
// API is, and that is positive evidence.
//
// The gate must not refuse the ordinary path. A gate that gets in the way of
// the normal case is a gate somebody removes, so every real way of knowing
// counts: the managed host, a discovered project reference, an operator
// locating the API, or an operator naming the provider outright.
func supabaseSelected(o *options) (bool, string) {
	switch {
	case strings.Contains(hostOf(o.target), ".supabase."):
		return true, ""
	case strings.Contains(hostOf(o.baseURL), ".supabase."):
		return true, ""
	case o.projectRef != "":
		// Recovered from the application's own bundles, or typed. Either way
		// it names a Supabase project.
		return true, ""
	case o.apiLocated:
		// The operator said where the API is. That is a statement about what
		// the target runs, which a credential is not.
		//
		// apiLocated is captured at flag-parse time, NOT read from baseURL
		// here. Two fields lied in turn: restPrefix carries the default
		// "/rest/v1", so testing it against empty is true on every scan; and
		// resolveOrigin later assigns o.baseURL = o.target for any URL, so
		// testing THAT is true on every scan too. Both versions passed their
		// unit tests -- which built options structs by hand, in a state no
		// binary is ever in -- and both let 2,725 requests reach a plain
		// website. Found by running the binary against the reproduction, twice.
		return true, ""
	case o.provider == "supabase":
		return true, ""
	}
	return false, "no Supabase project was found at this target: the host is not a " +
		"Supabase origin, no project reference was recovered from the application, and " +
		"no API location was given. A SUPABASE_ANON_KEY in the environment is not " +
		"evidence -- it is routinely exported for one project and forgotten while " +
		"another is scanned. If this target IS Supabase, say so: -base-url <api origin> " +
		"(with -rest-prefix if it is not /rest/v1), -project-ref <ref>, or " +
		"-provider supabase."
}
