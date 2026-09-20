package finding

import (
	"bytes"
	"encoding/csv"
	"strings"
	"testing"
)

// A CSV is the shape most likely to be forwarded: pasted into a sheet, attached
// to a ticket, mailed on. So it must never carry the sampled rows, which are
// the credentials the finding is warning about.
func TestCSVNeverCarriesSampledData(t *testing.T) {
	f := Finding{
		ID: "supabase-anon-read-exposed", Severity: Critical, Protocol: "postgrest",
		Resource: "sessions", Matched: "https://ref.supabase.co/rest/v1/sessions",
		Evidence: Evidence{
			Rows:   17,
			Reason: "17 rows returned to the anonymous role",
			Sample: []map[string]any{{
				"access_token": "sk_live_SHOULD_NOT_APPEAR",
				"email":        "person@example.invalid",
			}},
		},
	}
	var buf bytes.Buffer
	// Redact deliberately NOT set: the guarantee must hold without it, because
	// nobody remembers a flag when they are forwarding a spreadsheet.
	w := Writer{Out: &buf, CSV: true}
	if err := w.Write(f); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := buf.String()
	for _, secret := range []string{"sk_live_SHOULD_NOT_APPEAR", "person@example.invalid"} {
		if strings.Contains(got, secret) {
			t.Errorf("the CSV carries sampled data (%q):\n%s", secret, got)
		}
	}
	// It must still be actionable: the verdict, the object and the count.
	for _, want := range []string{"critical", "supabase-anon-read-exposed", "sessions", "17"} {
		if !strings.Contains(got, want) {
			t.Errorf("the CSV omits %q, so the row is not actionable:\n%s", want, got)
		}
	}
}

// It has to survive a spreadsheet. Commas, quotes and newlines inside a
// description are ordinary in this tool's output, and a hand-rolled join would
// corrupt the file at the first one.
func TestCSVQuotesHostileFields(t *testing.T) {
	f := Finding{
		ID: "unruly-surface-not-assessed", Severity: Info, Resource: `a,b"c`,
		Evidence: Evidence{Reason: "line one\nline two, with a comma"},
	}
	var buf bytes.Buffer
	if err := (Writer{Out: &buf, CSV: true}).Write(f); err != nil {
		t.Fatalf("write: %v", err)
	}
	rec, err := csv.NewReader(&buf).ReadAll()
	if err != nil {
		t.Fatalf("the output does not parse as CSV: %v", err)
	}
	if len(rec) != 1 || len(rec[0]) != len(csvColumns) {
		t.Fatalf("expected one row of %d columns, got %v", len(csvColumns), rec)
	}
	if rec[0][2] != `a,b"c` {
		t.Errorf("resource was mangled: %q", rec[0][2])
	}
	if !strings.Contains(rec[0][6], "line two, with a comma") {
		t.Errorf("reason was mangled: %q", rec[0][6])
	}
}

// The header and the row must not drift apart, or every column lands under the
// wrong name and the file is worse than no file.
func TestCSVHeaderMatchesTheRow(t *testing.T) {
	var head bytes.Buffer
	if err := CSVHeader(&head); err != nil {
		t.Fatalf("header: %v", err)
	}
	hrec, err := csv.NewReader(&head).ReadAll()
	if err != nil || len(hrec) != 1 {
		t.Fatalf("header does not parse: %v %v", err, hrec)
	}
	row := Finding{ID: "x", Severity: Low}.csvRow()
	if len(hrec[0]) != len(row) {
		t.Fatalf("header has %d columns and a row has %d", len(hrec[0]), len(row))
	}
	// And severity has to be first: the column somebody sorts by.
	if hrec[0][0] != "severity" {
		t.Errorf("first column is %q; a report is read worst-first", hrec[0][0])
	}
}
