package browserscan_test

import (
	"testing"

	"github.com/eppser/unruly/internal/browserscan"
)

// A browser can reach all four backends, and the page said otherwise.
//
// The first version of this page labelled Firebase, Neon and PocketBase
// "CLI only". That was my prototype's scope presented as a platform limit,
// and it was wrong. Measured against live endpoints from a github.io origin:
//
//	Firebase RTDB     access-control-allow-origin: https://eppser.github.io
//	Firestore REST    access-control-allow-origin: https://eppser.github.io
//	Firebase Storage  access-control-allow-origin: *
//	PocketBase        access-control-allow-origin: *
//
// Firestore looked closed at first only because I probed it with OPTIONS,
// which returns no header; a real GET does. These platforms are built to be
// called from browsers, which is the same property that makes Supabase work
// here.
func TestBackendsAreDetectedFromAnApplicationBundle(t *testing.T) {
	for _, tc := range []struct {
		name, bundle, wantKind, wantHost string
	}{
		{
			name:     "firebase config object",
			bundle:   `const cfg={apiKey:"AIzaSyD-1234567890abcdefghijklmnopqr",authDomain:"demo.firebaseapp.com",projectId:"my-demo-app",databaseURL:"https://my-demo-app-default-rtdb.europe-west1.firebasedatabase.app"};`,
			wantKind: "firebase",
			wantHost: "my-demo-app",
		},
		{
			name:     "legacy rtdb url only",
			bundle:   `fetch("https://legacy-project.firebaseio.com/users.json")`,
			wantKind: "firebase",
			wantHost: "legacy-project",
		},
		{
			name:     "pocketbase client",
			bundle:   `import PocketBase from "pocketbase"; const pb=new PocketBase("https://api.example-app.fly.dev");`,
			wantKind: "pocketbase",
			wantHost: "https://api.example-app.fly.dev",
		},
		{
			name:     "neon data api",
			bundle:   `const url="https://ep-cool-bird-12345678.apirest.c-2.us-east-1.aws.neon.tech/rest/v1";`,
			wantKind: "neon",
			wantHost: "https://ep-cool-bird-12345678.apirest.c-2.us-east-1.aws.neon.tech",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := browserscan.DetectBackends(tc.bundle)
			if len(got) == 0 {
				t.Fatalf("nothing detected, so the page would tell this app's owner " +
					"there is no database to check")
			}
			var found bool
			for _, b := range got {
				if b.Kind == tc.wantKind {
					found = true
					if b.Ref != tc.wantHost && b.Base != tc.wantHost {
						t.Errorf("%s detected with ref %q base %q, want %q",
							b.Kind, b.Ref, b.Base, tc.wantHost)
					}
				}
			}
			if !found {
				t.Errorf("detected %v, want a %s", got, tc.wantKind)
			}
		})
	}
}

// Supabase stays first when several are present, because it is the one this
// page probes most thoroughly.
func TestSupabaseWinsWhenAnAppUsesTwo(t *testing.T) {
	b := browserscan.DetectBackends(
		`createClient("https://abcdefghijklmnopqrst.supabase.co","sb_publishable_AAAAAAAAAAAA");
		 const pb=new PocketBase("https://x.fly.dev");`)
	if len(b) == 0 || b[0].Kind != "supabase" {
		t.Fatalf("got %v, want supabase first", b)
	}
}

// Nothing in the page means nothing detected, not a guess.
func TestAPageWithNoBackendDetectsNothing(t *testing.T) {
	if got := browserscan.DetectBackends(`<html><body>hello</body></html>`); len(got) != 0 {
		t.Errorf("detected %v in a page with no backend", got)
	}
}
