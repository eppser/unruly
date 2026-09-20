package finding

import (
	"strings"
	"testing"
)

func plainFixture() []Finding {
	return []Finding{
		{ID: "supabase-anon-read-exposed", Severity: Critical, Resource: "users",
			Evidence: Evidence{Rows: 4, Reason: "email:contact, password_hash:credential"}},
		{ID: "supabase-anon-delete-allowed", Severity: Critical, Resource: "orders"},
		{ID: "supabase-anon-update-allowed", Severity: Critical, Resource: "orders"},
		{ID: "supabase-anon-insert-allowed", Severity: High, Resource: "feedback"},
		{ID: "supabase-authenticated-escalation", Severity: Critical, Resource: "salaries",
			Evidence: Evidence{Rows: 9, Reason: "iban:financial"}},
		// Scan-describing findings must not appear: this view is about data an
		// actor can reach, and a coverage note is not that.
		{ID: "unruly-surface-not-assessed", Severity: Info, Resource: "delete:x"},
		{ID: "unruly-scan-summary", Severity: Info, Resource: "scan"},
	}
}

// The point of this rendering is that a non-technical reader learns who can do
// what to which data, in that order.
func TestPlainAnswersWhoCanDoWhat(t *testing.T) {
	got := Plain(plainFixture())

	if !strings.Contains(got, "Anyone on the internet, with no account and no password, can:") {
		t.Errorf("no heading naming the unauthenticated actor:\n%s", got)
	}
	if !strings.Contains(got, "Anyone who signs up for an account can also:") {
		t.Errorf("the signed-up actor is not distinguished:\n%s", got)
	}
	// The dangerous verbs must be spelled out, not left as jargon.
	for _, want := range []string{
		"permanently delete rows from", "change the contents of",
		"add new rows to", "read everything in",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing plain phrasing %q:\n%s", want, got)
		}
	}
	// And the data has to be named in words somebody recognises.
	for _, want := range []string{
		"passwords or access tokens",
		"email addresses or phone numbers",
		"card or payment details",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("data kind not translated: %q\n%s", want, got)
		}
	}
	if !strings.Contains(got, "(4 rows)") {
		t.Errorf("row counts are missing, so the reader cannot judge scale:\n%s", got)
	}
}

// Worst first. Somebody reading three lines before losing interest must have
// read the worst three, and losing data outranks having it altered or read.
func TestPlainOrdersByConsequence(t *testing.T) {
	got := Plain(plainFixture())
	del := strings.Index(got, "permanently delete rows from")
	chg := strings.Index(got, "change the contents of")
	add := strings.Index(got, "add new rows to")
	read := strings.Index(got, "read everything in")
	if !(del < chg && chg < add && add < read) {
		t.Errorf("verbs are not ordered worst-first (delete %d, change %d, add %d, read %d):\n%s",
			del, chg, add, read, got)
	}
	// The unauthenticated actor comes first: they cost an attacker nothing.
	if strings.Index(got, "Anyone on the internet") > strings.Index(got, "Anyone who signs up") {
		t.Error("the signed-up actor is listed before the anonymous one")
	}
}

// Scan-describing findings must not leak into a view about data.
func TestPlainExcludesScanCommentary(t *testing.T) {
	got := Plain(plainFixture())
	for _, unwanted := range []string{"surface-not-assessed", "scan-summary", "delete:x"} {
		if strings.Contains(got, unwanted) {
			t.Errorf("scan commentary reached the plain view (%q):\n%s", unwanted, got)
		}
	}
}

// A project with nothing reachable must render empty, so the caller can say so
// in its own words rather than printing an empty heading.
func TestPlainIsEmptyWhenNothingIsReachable(t *testing.T) {
	if got := Plain([]Finding{
		{ID: "unruly-scan-summary", Resource: "scan"},
		{ID: "supabase-rpc-discoverable", Resource: "admin_thing"},
	}); got != "" {
		t.Errorf("expected empty, got:\n%s", got)
	}
}

// Same input, same bytes: this output gets pasted into tickets and diffed.
func TestPlainIsDeterministic(t *testing.T) {
	first := Plain(plainFixture())
	for i := 0; i < 25; i++ {
		if got := Plain(plainFixture()); got != first {
			t.Fatalf("unstable rendering:\n%s\n---\n%s", first, got)
		}
	}
}

// Every verb the model defines must be renderable.
//
// The render loop listed its verbs a second time, so adding one to the enum
// did not add it to the report: the heading printed with nothing beneath it,
// which reads as "anyone can do nothing" on a project where somebody can read
// a live credential. Found on the Firebase lab, not in a test.
func TestEveryVerbHasAPhraseAndIsRendered(t *testing.T) {
	for v := verb(0); v <= lastVerb; v++ {
		if v.phrase() == "" {
			t.Errorf("verb %d has no phrase, so anything mapped to it renders as a "+
				"heading with nothing under it", v)
		}
	}
	// And every verb the capability table uses is within the rendered range.
	for id, c := range capability {
		if c.what > lastVerb {
			t.Errorf("%s maps to a verb outside the rendered range", id)
		}
		if c.what.phrase() == "" {
			t.Errorf("%s maps to a verb with no phrase", id)
		}
	}
}

// The Neon escalation renders as what it actually is.
//
// Registering an id in the capability table is enough to satisfy the coverage
// control, which only asks that something renders. It does not ask whether the
// sentence is TRUE, and the tier is the part that can be wrong: reported as
// `anyone` this would tell a reader that a stranger with no account reads the
// table, and on a Neon Data API a caller with no Authorization header is
// refused before the table is consulted.
//
// `signedUp` is the honest tier, and it is not a softer one. Sign-up on the
// measured project is open and unverified, so "anyone who signs up" is anyone
// who wants to -- which the finding's own description says in full.
func TestPlainPutsTheNeonEscalationBehindSignup(t *testing.T) {
	got := Plain([]Finding{{
		ID:       "neon-authenticated-read-unrestricted",
		Severity: High,
		Protocol: "neon",
		Resource: "rls_disabled",
	}})

	if !strings.Contains(got, "rls_disabled") {
		t.Fatalf("the table is not named in plain output:\n%s", got)
	}
	if !strings.Contains(got, "read everything in") {
		t.Errorf("plain output does not say what can be done:\n%s", got)
	}
	if !strings.Contains(got, "signs up") {
		t.Errorf("plain output does not put this behind signing up:\n%s", got)
	}
	if strings.Contains(got, "no account and no password") {
		t.Errorf("plain output says a caller with NO account can read this. On a Neon "+
			"Data API a request with no Authorization header is refused before the "+
			"table is consulted, so that sentence is false:\n%s", got)
	}
}
