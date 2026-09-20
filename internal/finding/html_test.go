package finding

import (
	"bytes"
	"strings"
	"testing"
)

func htmlFixture() []Finding {
	return []Finding{
		{ID: "supabase-anon-read-exposed", Severity: Critical, Resource: "sessions",
			Protocol: "postgrest", Matched: "https://ref.supabase.co/rest/v1/sessions",
			Description: "Anonymous SELECT returned 17 rows.",
			Remediation: "ALTER TABLE sessions ENABLE ROW LEVEL SECURITY;",
			Evidence: Evidence{
				Rows: 17, Reason: "access_token:credential",
				Request: "curl -sS 'https://ref.supabase.co/rest/v1/sessions'",
				Sample:  []map[string]any{{"access_token": "sk_live_MUST_NOT_APPEAR"}},
			}},
		{ID: "unruly-scan-summary", Severity: Info, Resource: "scan",
			Description: "17 relations examined."},
	}
}

func render(t *testing.T, fs []Finding) string {
	t.Helper()
	var buf bytes.Buffer
	if err := WriteHTML(&buf, "https://app.example", "2026-08-17T00:00:00Z", fs); err != nil {
		t.Fatalf("render: %v", err)
	}
	return buf.String()
}

// The report is the artefact most likely to be forwarded, so it must not carry
// the credentials the findings are about. Same rule as the CSV, and asserted
// without -redact for the same reason: nobody remembers a flag when attaching
// a file to a ticket.
func TestHTMLNeverCarriesSampledData(t *testing.T) {
	got := render(t, htmlFixture())
	if strings.Contains(got, "sk_live_MUST_NOT_APPEAR") {
		t.Error("the HTML report carries a sampled credential")
	}
	// It must still prove the finding: the replayable request survives, which
	// establishes the result without carrying the data.
	if !strings.Contains(got, "curl -sS") {
		t.Error("the replayable request is missing, so the report asserts without proof")
	}
}

// Table names, reasons and response bodies come from the TARGET. A report that
// interpolates them without escaping turns a scanned project into script
// running in the reader's browser -- a scanner handing its user a payload from
// the thing it was pointed at.
func TestHTMLEscapesTargetControlledText(t *testing.T) {
	got := render(t, []Finding{{
		ID: "supabase-anon-read-exposed", Severity: High,
		Resource:    `<script>alert(1)</script>`,
		Description: `<img src=x onerror=alert(2)>`,
		Evidence:    Evidence{Reason: `"><svg onload=alert(3)>`},
	}})
	// The property is that no TAG from the target survives as markup. Checking
	// for attribute substrings was the first attempt and was wrong: after
	// escaping, "onerror=alert(2)" still appears inside &lt;img src=x
	// onerror=alert(2)&gt;, which is inert text. What must never appear is a
	// raw < that opens an element.
	// <script is excluded from this list on purpose: the report ships one of
	// its own for the copy button, so its presence says nothing about the
	// target's text. <img and <svg appear nowhere in the template, which makes
	// them clean probes.
	for _, tag := range []string{"<img", "<svg"} {
		if strings.Contains(got, tag) {
			t.Errorf("a raw %q from target-controlled text reached the report as markup", tag)
		}
	}
	// Escaped, not dropped: the operator still has to see what the table is
	// called, however hostile the name.
	if !strings.Contains(got, "&lt;script&gt;alert(1)") {
		t.Error("the resource name was discarded rather than escaped; the operator still " +
			"has to see what the table is called, however hostile the name")
	}
	// And the target's script tag must appear ONLY in escaped form.
	if strings.Contains(got, "<script>alert(1)") {
		t.Error("the target's script tag survived as markup")
	}
}

// One file, no network. A report that fetches a stylesheet tells someone it was
// opened, and one that needs the internet is useless in the room where it is
// usually read.
func TestHTMLIsSelfContained(t *testing.T) {
	got := render(t, htmlFixture())
	for _, external := range []string{`src="http`, `href="http`, "@import", "//cdn."} {
		if strings.Contains(got, external) {
			t.Errorf("the report loads something external: %q", external)
		}
	}
}

// The button is the point of the feature.
func TestHTMLBundlesTheFixSQL(t *testing.T) {
	got := render(t, htmlFixture())
	if !strings.Contains(got, "Copy all SQL") {
		t.Error("no copy button")
	}
	// The relation's remediation must reach the copy buffer. Matched on the
	// relation rather than on a literal ALTER, because the statement is chosen
	// at run time now: a view needs security_invoker, where enabling row-level
	// security would error.
	if !strings.Contains(got, "ENABLE ROW LEVEL SECURITY") ||
		!strings.Contains(got, "sessions") {
		t.Error("the remediation SQL is not in the report")
	}
	// Info findings must not pad the paste buffer: a block full of
	// informational SQL is one nobody runs.
	if strings.Contains(got, "17 relations examined.</pre>") {
		t.Error("informational remediation reached the SQL block")
	}
}

// Reports get diffed between runs. Given the same findings and timestamp, the
// bytes must match.
func TestHTMLIsDeterministic(t *testing.T) {
	first := render(t, htmlFixture())
	for i := 0; i < 15; i++ {
		if got := render(t, htmlFixture()); got != first {
			t.Fatal("HTML rendering is not stable across calls")
		}
	}
}
