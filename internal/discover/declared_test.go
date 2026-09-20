package discover

import "testing"

// The application's own statement of where its backend is.
//
// The managed URL carries the project reference, so this never mattered there
// and the gap stayed invisible: a self-hosted deployment declares an origin and
// has no reference at all, and the scan fell back to treating the WEBSITE as
// the API. Measured on a fixture that declares both a URL and a working key:
// 16,558 requests to a static file server and 0 relations, on a target where
// aiming correctly finds 18.
func TestDeclaredAPIOriginIsRead(t *testing.T) {
	cases := []struct{ name, body, want string }{
		{"plain assignment",
			`const SUPABASE_URL="https://db.example.com";`, "https://db.example.com"},
		{"vite prefix",
			`VITE_SUPABASE_URL: "https://api.example.org/"`, "https://api.example.org"},
		{"next public prefix",
			`{"NEXT_PUBLIC_SUPABASE_URL":"http://10.0.0.4:8000"}`, "http://10.0.0.4:8000"},
		{"camel case, minified",
			`a.supabaseUrl="https://x.y.z",a.k=1`, "https://x.y.z"},
		{"managed url is still read",
			`SUPABASE_URL="https://abcdefghijklmnopqrst.supabase.co"`,
			"https://abcdefghijklmnopqrst.supabase.co"},

		// Precision. A bare URL in a bundle is not a backend address, and a
		// scanner that adopts one points its whole run somewhere arbitrary.
		{"an unrelated url", `const API="https://analytics.example.com";`, ""},
		{"a firebase url", `databaseURL:"https://p-default-rtdb.firebaseio.com"`, ""},
		{"the word supabase in prose",
			`// we migrated from supabase last year, see https://blog.example.com`, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var res Result
			scanDeclaredURL(tc.body, "test", &res)
			if res.BaseURL != tc.want {
				t.Errorf("BaseURL = %q, want %q", res.BaseURL, tc.want)
			}
			if tc.want != "" && res.BaseURLSource != "test" {
				t.Errorf("source = %q; a reader must be able to check the claim",
					res.BaseURLSource)
			}
		})
	}
}

// First wins, and stays won. Bundles repeat the value, and a scan of an
// unchanged site must produce a byte-identical report.
func TestDeclaredAPIOriginIsStable(t *testing.T) {
	var res Result
	scanDeclaredURL(`SUPABASE_URL="https://first.example"`, "a.js", &res)
	scanDeclaredURL(`SUPABASE_URL="https://second.example"`, "b.js", &res)
	if res.BaseURL != "https://first.example" || res.BaseURLSource != "a.js" {
		t.Errorf("got %q from %q; a later bundle must not move the target",
			res.BaseURL, res.BaseURLSource)
	}
}
