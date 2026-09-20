package client

import "testing"

// A base that already ends in the REST prefix is not given a second one.
//
// Pasting the full REST URL is the obvious thing to do -- it is the URL the
// vendor console shows, and the one an operator copies. Appending the default
// prefix to it produces /rest/v1/rest/v1, a path no PostgREST serves, and the
// consequences are worse than a wasted request:
//
//   - every probe 404s, so the control for a relation that cannot exist gets
//     the SAME clean 404 as a relation that can. The target looks like it
//     discriminates when nothing has been reached at all.
//   - measured against a live Neon Data API: the scan then ran the fallback
//     expansion it would otherwise have skipped and spent 1200 probes, and
//     reported 0 relations with three degraded capabilities. Every one of
//     those requests went to somebody's project asking for a path that cannot
//     exist.
//
// The doubling is silent. Nothing in the report names it, which is why this
// went unnoticed through several live runs.
//
// The expected values follow the shape RestBase already produces -- no
// trailing slash -- rather than one invented here. The claim under test is
// that the prefix is not appended twice, and encoding a different convention
// alongside it would make a failure ambiguous.
func TestARestPrefixIsNotAppendedTwice(t *testing.T) {
	for _, tc := range []struct {
		name, base, prefix, want string
	}{
		{
			name:   "operator pasted the full REST URL",
			base:   "https://ep-x.apirest.eu-west-1.aws.neon.tech/neondb/rest/v1",
			prefix: "/rest/v1/",
			want:   "https://ep-x.apirest.eu-west-1.aws.neon.tech/neondb/rest/v1",
		},
		{
			name:   "with a trailing slash already",
			base:   "https://ep-x.apirest.eu-west-1.aws.neon.tech/neondb/rest/v1/",
			prefix: "/rest/v1/",
			want:   "https://ep-x.apirest.eu-west-1.aws.neon.tech/neondb/rest/v1",
		},
		{
			name:   "the ordinary case is untouched",
			base:   "https://abcdefghijklmnop.supabase.co",
			prefix: "/rest/v1/",
			want:   "https://abcdefghijklmnop.supabase.co/rest/v1",
		},
		{
			name:   "a bare PostgREST at the root is untouched",
			base:   "http://127.0.0.1:3000",
			prefix: "/",
			want:   "http://127.0.0.1:3000",
		},
		{
			name:   "a path that merely CONTAINS the prefix is not treated as ending in it",
			base:   "https://example.com/rest/v1/api",
			prefix: "/rest/v1/",
			want:   "https://example.com/rest/v1/api/rest/v1",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := New(Options{BaseURL: tc.base, RestPrefix: tc.prefix})
			if got := c.RestBase(); got != tc.want {
				t.Errorf("RestBase() = %q, want %q. A doubled prefix asks for a path no "+
					"PostgREST serves, and every 404 it collects looks like a target "+
					"that reports absence correctly", got, tc.want)
			}
		})
	}
}
