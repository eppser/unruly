package finding

import (
	"bytes"
	"strings"
	"testing"
)

// Determinism is a product requirement, not an implementation detail: a scan
// of an unchanged target must be byte-identical so CI can diff it. These tests
// are the guard.

func TestSortIsTotalAndStable(t *testing.T) {
	mk := func(id, res string, s Severity) Finding {
		return Finding{ID: id, Resource: res, Severity: s, Matched: "https://x/" + res}
	}
	in := []Finding{
		mk("supabase-anon-read-exposed", "sessions", Critical),
		mk("supabase-project-ref-leak", "csp", Info),
		mk("supabase-anon-insert-allowed", "agent_runs", Critical),
		mk("supabase-anon-read-exposed", "agent_runs", Critical),
		mk("supabase-open-admin-route", "/api/admin/logs", High),
	}
	want := []string{
		"supabase-anon-insert-allowed/agent_runs",
		"supabase-anon-read-exposed/agent_runs",
		"supabase-anon-read-exposed/sessions",
		"supabase-open-admin-route//api/admin/logs",
		"supabase-project-ref-leak/csp",
	}

	// Shuffling the input must not change the output.
	for _, perm := range [][]int{{0, 1, 2, 3, 4}, {4, 3, 2, 1, 0}, {2, 0, 4, 1, 3}} {
		cp := make([]Finding, len(in))
		for i, p := range perm {
			cp[i] = in[p]
		}
		Sort(cp)
		for i, f := range cp {
			if got := f.ID + "/" + f.Resource; got != want[i] {
				t.Fatalf("perm %v index %d: got %s, want %s", perm, i, got, want[i])
			}
		}
	}
}

func TestFingerprintStableAndEvidenceIndependent(t *testing.T) {
	base := Finding{
		ID: "supabase-anon-read-exposed", Protocol: "postgrest",
		Matched: "https://ref.supabase.co/rest/v1/sessions", Resource: "sessions",
	}
	withData := base
	withData.Evidence = Evidence{Rows: 17, Sample: []map[string]any{{"id": 1}}}

	if base.Fingerprint() != withData.Fingerprint() {
		t.Error("fingerprint must not depend on evidence; database contents change between runs")
	}
	if base.Fingerprint() == "" || len(base.Fingerprint()) != 16 {
		t.Errorf("fingerprint should be a 16-char content address, got %q", base.Fingerprint())
	}

	other := base
	other.Resource = "agent_runs"
	if base.Fingerprint() == other.Fingerprint() {
		t.Error("different resources must fingerprint differently")
	}
}

func TestDedup(t *testing.T) {
	f := Finding{ID: "a", Matched: "u", Resource: "r"}
	got := Dedup([]Finding{f, f, f})
	if len(got) != 1 {
		t.Fatalf("expected 1 finding after dedup, got %d", len(got))
	}
}

func TestWriteMatchesProjectDiscoveryFormat(t *testing.T) {
	var buf bytes.Buffer
	w := Writer{Out: &buf, NoColor: true}
	err := w.Write(Finding{
		ID: "supabase-anon-read-exposed", Protocol: "postgrest", Severity: Critical,
		Matched:  "https://ref.supabase.co/rest/v1/sessions",
		Resource: "sessions",
		Evidence: Evidence{Rows: 17, Sample: []map[string]any{{"access_token": "4cc276"}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	want := "[supabase-anon-read-exposed] [postgrest] [critical] https://ref.supabase.co/rest/v1/sessions [17 rows]"
	if !strings.HasPrefix(out, want) {
		t.Errorf("line format drifted from nuclei style:\n got: %q\nwant prefix: %q", out, want)
	}
	if !strings.Contains(out, "proof") || !strings.Contains(out, "access_token") {
		t.Error("proof-carrying output must include the real sampled row")
	}
}

func TestRedactDropsSampleButKeepsFinding(t *testing.T) {
	var buf bytes.Buffer
	w := Writer{Out: &buf, NoColor: true, Redact: true}
	_ = w.Write(Finding{
		ID: "supabase-anon-read-exposed", Protocol: "postgrest", Severity: Critical,
		Matched: "https://x/sessions", Resource: "sessions",
		Evidence: Evidence{Rows: 17, Sample: []map[string]any{{"access_token": "4cc276"}}},
	})
	if strings.Contains(buf.String(), "4cc276") {
		t.Error("-redact must suppress sampled secrets")
	}
	if !strings.Contains(buf.String(), "17 rows") {
		t.Error("-redact must still report the finding and its row count")
	}
}

func TestSeverityFilter(t *testing.T) {
	var buf bytes.Buffer
	w := Writer{Out: &buf, NoColor: true, MinSev: High}
	_ = w.Write(Finding{ID: "low-thing", Severity: Low, Matched: "u"})
	if buf.Len() != 0 {
		t.Error("findings below -severity threshold must be suppressed")
	}
	_ = w.Write(Finding{ID: "crit-thing", Severity: Critical, Matched: "u"})
	if buf.Len() == 0 {
		t.Error("findings at or above threshold must be emitted")
	}
}

func TestJSONRoundTripsSeverity(t *testing.T) {
	var buf bytes.Buffer
	w := Writer{Out: &buf, JSON: true}
	_ = w.Write(Finding{ID: "x", Severity: Critical, Matched: "u"})
	if !strings.Contains(buf.String(), `"severity":"critical"`) {
		t.Errorf("severity must serialise as a name, got %s", buf.String())
	}
}

// A target must not be able to write to the operator's terminal.
//
// Findings carry text the scanned host chose -- error codes and messages,
// object names, response snippets, row identifiers -- and this renderer emits
// ANSI escapes of its own, so its output IS a terminal control stream.
// Measured before safeText existed: a hostile evidence string rendered
// verbatim, clearing the screen and printing a green "scan complete: 0
// findings". A scanner that can be made to display that by the thing it is
// scanning has no business reporting anything.
func TestTerminalOutputCannotBeDrivenByTheTarget(t *testing.T) {
	lie := "\x1b[2J\x1b[1;1H\x1b[32mscan complete: 0 findings\x1b[0m"
	f := Finding{
		ID: "supabase-anon-read-exposed", Name: "n", Severity: High,
		Protocol: "postgrest", Matched: "http://target/rest/v1/x" + lie,
		Resource:    "x",
		Remediation: "ALTER TABLE x ENABLE ROW LEVEL SECURITY;" + lie,
		Evidence:    Evidence{Reason: "responded 200 with body: " + lie},
	}

	var buf bytes.Buffer
	w := Writer{Out: &buf, ShowFix: true}
	if err := w.Write(f); err != nil {
		t.Fatalf("write: %v", err)
	}
	out := buf.String()

	// The renderer's own colours are fine; the target's are not. Every escape
	// the target supplied was a CSI sequence, so no bare ESC may be followed
	// by the sequences it sent.
	for _, seq := range []string{"\x1b[2J", "\x1b[1;1H", "\x1b[32m"} {
		if strings.Contains(out, seq) {
			t.Errorf("the target's %q reached the terminal", strings.TrimPrefix(seq, "\x1b"))
		}
	}
	// The text should still be visible -- neutralised, not hidden, or an
	// operator cannot tell that something was stripped.
	if !strings.Contains(out, "scan complete: 0 findings") {
		t.Error("the injected text was dropped entirely; it should be shown inert so the " +
			"operator can see what the target sent")
	}
	if !strings.Contains(out, `\x1b`) {
		t.Error("control characters should render as an escape, not vanish")
	}
}

// And the renderer's own colouring must survive, or the fix has broken the
// report to protect it.
func TestSanitisingKeepsTheRenderersOwnColour(t *testing.T) {
	var buf bytes.Buffer
	w := Writer{Out: &buf}
	if err := w.Write(Finding{
		ID: "x", Severity: High, Protocol: "postgrest",
		Matched: "http://target/rest/v1/x", Evidence: Evidence{Rows: 3},
	}); err != nil {
		t.Fatalf("write: %v", err)
	}
	if !strings.Contains(buf.String(), "\x1b[") {
		t.Error("the renderer's own ANSI colour was stripped along with the target's")
	}
}
