package postgrest

import (
	"strings"
	"testing"
)

// Every case below is a REAL response captured from a live Supabase project
// (ref examplerefexampleref) during the research that motivated this tool.
// They are the executable specification: if these pass, the classifier agrees
// with reality; if they fail, the scanner is lying about a database.

func TestClassifyRead(t *testing.T) {
	cases := []struct {
		name      string
		status    int
		rangeHdr  string
		bodyLen   int
		wantState ReadState
		wantRows  int
	}{
		// --- real captures: anonymously readable relations -------------------
		{"signatory_submissions 206", 206, "0-0/124", 405, ReadExposed, 124},
		{"sessions 206", 206, "0-0/17", 165, ReadExposed, 17},
		{"daily_snapshot 206", 206, "0-0/104", 218, ReadExposed, 104},
		{"agent_runs 206", 206, "0-0/465", 300, ReadExposed, 465},

		// --- real captures: relation exists, RLS filtered every row ----------
		{"cves 200 empty", 200, "*/0", 2, ReadEmpty, 0},
		{"v3_cves 200 empty", 200, "*/0", 2, ReadEmpty, 0},

		// --- real captures: denied and absent --------------------------------
		{"no api key", 401, "", 98, ReadDenied, 0},
		{"forbidden", 403, "", 0, ReadDenied, 0},
		{"admin_config absent", 404, "", 120, ReadNotFound, 0},

		// --- regression: 206 must not be treated as a miss -------------------
		// supascan and the first unruly prototype both matched only 200
		// and therefore reported every readable table as absent.
		{"REGRESSION 206 is a read", 206, "0-0/1", 50, ReadExposed, 1},

		// --- regression: 404 is NOT "secure" ---------------------------------
		// One surveyed tool prints "SECURE: table properly blocked" on 404,
		// which is false assurance about a table that simply does not exist.
		{"REGRESSION 404 is absence not safety", 404, "", 100, ReadNotFound, 0},

		// --- no count header: fall back to payload shape ---------------------
		{"200 no count, rows present", 200, "", 405, ReadExposed, -1},
		{"200 no count, empty array", 200, "", 2, ReadEmpty, 0},
		{"200 range total unknown", 200, "0-0/*", 405, ReadExposed, -1},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, rows := ClassifyRead(tc.status, tc.rangeHdr, tc.bodyLen)
			if got != tc.wantState {
				t.Errorf("state = %v, want %v", got, tc.wantState)
			}
			if rows != tc.wantRows {
				t.Errorf("rows = %d, want %d", rows, tc.wantRows)
			}
		})
	}
}

func TestClassifyWrite(t *testing.T) {
	cases := []struct {
		name   string
		status int
		body   Body
		want   WriteState
	}{
		// --- real capture: RLS enforced --------------------------------------
		// POST /rest/v1/cves {} -> 401
		// {"code":"42501","message":"new row violates row-level security policy
		//  for table \"cves\""}
		{"cves blocked by RLS", 401, Body{Code: "42501",
			Message: `new row violates row-level security policy for table "cves"`},
			WriteBlockedRLS},

		// --- real capture: reached the table ---------------------------------
		// POST /rest/v1/signatory_submissions {} -> 400
		// {"code":"23502","message":"null value in column \"name\" ... violates
		//  not-null constraint"}
		// RLS did not stop this; the schema did. That is write access.
		{"signatory_submissions reached", 400, Body{Code: "23502",
			Message: `null value in column "name" of relation "signatory_submissions" violates not-null constraint`},
			WriteReached},
		{"sessions reached", 400, Body{Code: "23502",
			Message: `null value in column "code" of relation "sessions" violates not-null constraint`},
			WriteReached},
		// PGRST204 is raised by PostgREST before any SQL runs, so it is
		// returned identically for protected and open relations. Measured on
		// the reference target: cves (protected) and signatory_submissions
		// (open) both answer 400/PGRST204 to an unknown-column INSERT.
		{"REGRESSION PGRST204 proves nothing", 400, Body{Code: "PGRST204",
			Message: "Could not find the '__probe__' column of 'cves' in the schema cache"},
			WriteInconclusive},
		{"REGRESSION PGRST102 proves nothing", 400, Body{Code: "PGRST102"},
			WriteInconclusive},
		{"bad uuid cast reached", 400, Body{Code: "22P02",
			Message: `invalid input syntax for type uuid: "-1"`}, WriteReached},
		{"unique violation reached", 409, Body{Code: "23505"}, WriteReached},
		{"fkey violation reached", 409, Body{Code: "23503"}, WriteReached},

		// --- regression: 204 is a successful write ---------------------------
		// supascan maps anything outside {200,201,401,403} to "possible", so a
		// 204 (PostgREST's default write success) is under-reported instead of
		// raised as critical.
		{"REGRESSION 204 is success", 204, Body{}, WriteReached},
		{"201 created", 201, Body{}, WriteReached},
		{"200 with representation", 200, Body{}, WriteReached},

		// --- absent / unclear -------------------------------------------------
		{"relation absent", 404, Body{Code: "PGRST205"}, WriteInconclusive},
		{"42703 undefined column from PG is real", 400, Body{Code: "42703"}, WriteReached},
		{"server error", 500, Body{}, WriteInconclusive},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, reason := ClassifyWrite(tc.status, tc.body)
			if got != tc.want {
				t.Errorf("state = %v, want %v (reason %q)", got, tc.want, reason)
			}
		})
	}
}

// TestHintedRelation covers the enumeration oracle. These hints are verbatim
// from the live target; the oracle is what recovers domain-specific relation
// names that no generic wordlist contains.
func TestHintedRelation(t *testing.T) {
	cases := []struct {
		hint string
		want string
		ok   bool
	}{
		{"Perhaps you meant the table 'public.signatory_submissions'", "signatory_submissions", true},
		{"Perhaps you meant the table 'public.agent_runs'", "agent_runs", true},
		{"Perhaps you meant the table 'public.sessions'", "sessions", true},
		{"Perhaps you meant the table 'public.zero_day_series'", "zero_day_series", true},
		{"Perhaps you meant the table 'cve_articles'", "cve_articles", true},
		{"Perhaps you meant the view 'public.something'", "", false},
		{"", "", false},
		{"Could not find the table 'public.nope' in the schema cache", "", false},
	}
	for _, tc := range cases {
		got, ok := HintedRelation(tc.hint)
		if ok != tc.ok || got != tc.want {
			t.Errorf("HintedRelation(%q) = (%q,%v), want (%q,%v)", tc.hint, got, ok, tc.want, tc.ok)
		}
	}
}

// TestWriteProbeSoundness documents why unruly never probes writes with a
// zero-match DELETE or PATCH. Both an RLS-protected relation and a fully open
// one answer 204, so the probe cannot discriminate and yields a false positive
// on every protected table.
func TestWriteProbeSoundness(t *testing.T) {
	protected, _ := ClassifyWrite(204, Body{}) // cves,   DELETE ?id=eq.-99999999 -> 204
	open, _ := ClassifyWrite(204, Body{})      // sessions, same probe            -> 204
	if protected != open {
		t.Fatal("expected the zero-match probe to be indistinguishable")
	}
	if protected != WriteReached {
		t.Fatalf("204 must classify as reached, got %v", protected)
	}
	// Both look identical, which is exactly why only INSERT may drive a
	// write finding. Enforced by probe.WriteProbe.
}

// TestHintedFunction covers the RPC arm of the oracle. These hints are
// verbatim from the live target and recovered all three of its token-gated
// SECURITY DEFINER admin routines with no prior knowledge.
func TestHintedFunction(t *testing.T) {
	cases := []struct {
		hint string
		want string
		ok   bool
	}{
		{"Perhaps you meant to call the function public.admin_list_submissions", "admin_list_submissions", true},
		{"Perhaps you meant to call the function public.admin_review_submission", "admin_review_submission", true},
		{"Perhaps you meant to call the function public.admin_reorder_submission", "admin_reorder_submission", true},
		{"Perhaps you meant to call the function do_thing", "do_thing", true},
		// An exact-name call with the wrong signature returns hint:null, so
		// there is nothing to extract. Enumeration must probe near-misses.
		{"", "", false},
		{"Could not find the function public.zzz without parameters in the schema cache", "", false},
		// The table arm must not match the function arm.
		{"Perhaps you meant the table 'public.sessions'", "", false},
	}
	for _, tc := range cases {
		got, ok := HintedFunction(tc.hint)
		if ok != tc.ok || got != tc.want {
			t.Errorf("HintedFunction(%q) = (%q,%v), want (%q,%v)", tc.hint, got, ok, tc.want, tc.ok)
		}
	}
}

// Everything the hint oracle returns is chosen by the host being scanned, and
// that host is untrusted by definition. The names flow into a URL and into the
// -fix remediation, which exists to be pasted into a SQL console.
//
// Measured before the gate existed: all three of these were accepted verbatim.
// The first would have been emitted as
//
//	ALTER TABLE users; DROP TABLE audit_log; -- ENABLE ROW LEVEL SECURITY;
//
// so a hostile host could get arbitrary SQL run by the person scanning it.
func TestHintedNamesRejectAnythingButAnIdentifier(t *testing.T) {
	hostile := map[string]string{
		"SQL injected into the remediation an operator pastes": "users; DROP TABLE audit_log; --",
		"query parameters injected into the request":           "x?select=*&limit=999999",
		"path escape onto other endpoints":                     "a/../../auth/v1/admin/users",
		"quote that would break out of a quoted identifier":    `x" ; DROP TABLE t; --`,
		"newline, for anything that logs or splits on lines":   "x\ny",
		"space, which a quoted Postgres identifier allows":     "my table",
		"over Postgres's 63-character identifier limit":        strings.Repeat("a", 64),
	}
	for why, name := range hostile {
		hint := "Perhaps you meant the table 'public." + name + "'"
		if got, ok := HintedRelation(hint); ok {
			t.Errorf("%s: accepted %q from a hint", why, got)
		}
		// HintedFunction stops at the first separator, so several of these
		// arrive already truncated -- "x\" ; DROP TABLE t; --" becomes "x".
		// That neutralises the payload, so the requirement is not that the
		// hint is REJECTED but that whatever survives is an identifier and
		// nothing more. Asserting rejection would have been asserting the
		// wrong property, and the test said so before this comment did.
		if got, ok := HintedFunction("Perhaps you meant to call the function public." + name); ok {
			if !safeIdentifier.MatchString(got) {
				t.Errorf("%s: routine name %q escaped the identifier set", why, got)
			}
			if strings.ContainsAny(got, `;'"/?&# `+"\n") {
				t.Errorf("%s: routine name %q still carries a dangerous character", why, got)
			}
		}
	}
}

// And the gate must not cost recall on the names real projects use.
func TestHintedNamesStillAcceptOrdinaryIdentifiers(t *testing.T) {
	for _, name := range []string{
		"users", "signatory_submissions", "agent_runs", "daily_snapshot",
		"Table2", "_private", "a$b", strings.Repeat("a", 63),
	} {
		if got, ok := HintedRelation("Perhaps you meant the table 'public." + name + "'"); !ok || got != name {
			t.Errorf("relation %q was rejected (got %q, ok=%v); the gate must not cost "+
				"recall on names real projects use", name, got, ok)
		}
		if got, ok := HintedFunction("Perhaps you meant to call the function public." + name); !ok || got != name {
			t.Errorf("routine %q was rejected (got %q, ok=%v)", name, got, ok)
		}
	}
}
