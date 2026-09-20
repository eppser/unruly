package finding

import (
	"bytes"
	"strings"
	"testing"
)

// A relation outside the default schema must not be shown as a URL that
// reaches something else.
//
// PostgREST addresses another schema with an Accept-Profile header, not with a
// path, so there IS no URL for reporting.daily_revenue -- and the terminal was
// printing http://host/daily_revenue, which resolves to public.daily_revenue
// or to nothing at all. The evidence line carries the header and is replayable;
// the headline was not, and the headline is what an operator copies.
//
// The multi-schema pass is one of the things this scanner does that the
// alternatives do not, so naming its findings ambiguously undersells the only
// place they appear.
func TestASchemaQualifiedFindingSaysWhichSchema(t *testing.T) {
	var buf bytes.Buffer
	w := Writer{Out: &buf, NoColor: true}
	f := Finding{
		ID: "supabase-anon-read-exposed", Protocol: "postgrest", Severity: Critical,
		Matched:  "http://127.0.0.1:54321/daily_revenue",
		Resource: "reporting.daily_revenue",
		Evidence: Evidence{Rows: 14},
	}
	if err := w.Write(f); err != nil {
		t.Fatal(err)
	}
	line := buf.String()
	if !strings.Contains(line, "reporting.daily_revenue") {
		t.Errorf("the headline does not name the schema:\n%s\nAn operator copying "+
			"that URL reaches public.daily_revenue, which is a different table or "+
			"no table", line)
	}

	// And a relation in the default schema keeps its line unchanged: the URL
	// alone is exact there, and repeating the name would be noise on every
	// finding a normal project produces.
	buf.Reset()
	g := Finding{
		ID: "supabase-anon-read-exposed", Protocol: "postgrest", Severity: High,
		Matched:  "http://127.0.0.1:54321/open_no_rls",
		Resource: "open_no_rls",
		Evidence: Evidence{Rows: 12},
	}
	if err := w.Write(g); err != nil {
		t.Fatal(err)
	}
	if got := strings.Count(buf.String(), "open_no_rls"); got != 1 {
		t.Errorf("the default-schema line names the relation %d times:\n%s", got,
			buf.String())
	}
}
