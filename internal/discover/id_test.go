package discover

import "testing"

// The project ref is the address of the database. A response header that
// carries it turns "find the Supabase project behind this site" from guesswork
// into a lookup, which is why this is reported at all.
func TestProjectRefDisclosureFindingID(t *testing.T) {
	f := refLeakFinding("https://x.example",
		"content-security-policy", "connect-src https://abcdefghijklmno.supabase.co",
		"abcdefghijklmno")
	if f.ID != "supabase-project-ref-disclosure" {
		t.Errorf("ID changed to %q; consumers filter on it", f.ID)
	}
	if f.Resource != "content-security-policy" {
		t.Errorf("the leaking header must be the resource, got %q", f.Resource)
	}
}
