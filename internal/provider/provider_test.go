package provider

import (
	"strings"
	"testing"
)

// Detection decides what every later request asks and who it asks. Getting it
// wrong does not degrade a scan, it aims it at a stranger's project — so these
// cases are weighted towards what must NOT be detected.
//
// Keys here are shape-only and belong to nothing: CI scans committed content
// for credential shapes outside _test.go for exactly this reason.
const (
	fakeAIza  = "AIzaSyD" + "0123456789abcdefghijklmnopqrstu"
	fakeAnon  = "eyJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoiYW5vbiJ9.QUJDREVGR0hJSktMTU5PUA"
	someRef   = "abcdefghijklmnopqrst"
	otherRef  = "zyxwvutsrqponmlkjihg"
	fakePubKe = "sb_publishable_0123456789abcdefghij"
)

func detectOne(t *testing.T, name string, s Surface) (Detection, bool) {
	t.Helper()
	for _, d := range Detect(s) {
		if d.Provider == name {
			return d, true
		}
	}
	return Detection{}, false
}

func TestFirebaseNeedsCorroborationNotJustAKey(t *testing.T) {
	// THE false positive to avoid. Google issues browser keys in this shape for
	// Maps, YouTube and everything else; a detector that fires on the shape
	// reports Firebase on a large fraction of the web.
	// Spelled apiKey, because that is what the risk looks like: plenty of
	// non-Firebase libraries take a Google browser key under exactly that name,
	// so the field name is no more discriminating than the key shape. Written
	// with key: at first, which meant the regex never matched and this test
	// passed while asserting nothing -- confirmed by loosening the detector and
	// watching it stay green.
	maps := Surface{Site: "https://shop.example", Scripts: map[string]string{
		"https://shop.example/app.js": `const mapsConfig={apiKey:"` + fakeAIza +
			`",libraries:["places"],region:"DE"};`,
	}}
	if d, ok := detectOne(t, "firebase", maps); ok {
		t.Errorf("a Google Maps key was reported as Firebase (%s); the key shape is shared "+
			"across every Google browser API and proves nothing on its own", d.Reason)
	}

	// A real config: projectId beside apiKey.
	cfg := Surface{Site: "https://app.example", Scripts: map[string]string{
		"https://app.example/main.js": `const firebaseConfig={apiKey:"` + fakeAIza +
			`",authDomain:"demo-proj.firebaseapp.com",projectId:"demo-proj"};`,
	}}
	d, ok := detectOne(t, "firebase", cfg)
	if !ok {
		t.Fatal("a config carrying both projectId and apiKey was not detected")
	}
	if d.Project != "demo-proj" {
		t.Errorf("project %q", d.Project)
	}
	if d.Credential != fakeAIza {
		t.Errorf("credential not recovered")
	}

	// A minified bundle where only a Firebase-specific host survives. That host
	// belongs to no other product, so it corroborates on its own.
	rtdb := Surface{Site: "https://app.example", Scripts: map[string]string{
		"https://app.example/b.js": `fetch("https://myproj-default-rtdb.europe-west1.firebasedatabase.app/x.json")`,
	}}
	if d, ok := detectOne(t, "firebase", rtdb); !ok {
		t.Error("a Realtime Database host did not identify the backend")
	} else if d.Project != "myproj" {
		t.Errorf("project %q from an rtdb host", d.Project)
	}
}

func TestSupabaseIgnoresAHotlinkedAsset(t *testing.T) {
	// The mirror-image false positive, and one this project measured in the
	// field: sites whose only reference to supabase.co was an image served from
	// somebody else's storage bucket, several of them a hosting platform's own
	// logo. Scanning that project because a logo pointed at it is precisely the
	// mistake this tool exists not to make.
	hotlink := Surface{Site: "https://blog.example", HTML: `<html><body>
		<img src="https://` + otherRef + `.supabase.co/storage/v1/object/public/logos/logo.png">
		</body></html>`}
	if d, ok := detectOne(t, "supabase", hotlink); ok {
		t.Errorf("a hotlinked image identified somebody else's project as this site's "+
			"backend: %s (%s)", d.Project, d.Reason)
	}

	// An anon key names its own project in its claims, so key and identity
	// corroborate each other in one object.
	real := Surface{Site: "https://app.example", Scripts: map[string]string{
		"https://app.example/app.js": `createClient("https://` + someRef +
			`.supabase.co","` + fakeAnon + `")`,
	}}
	d, ok := detectOne(t, "supabase", real)
	if !ok {
		t.Fatal("an anon key in the bundle did not identify the backend")
	}
	if d.Project != someRef {
		t.Errorf("project %q", d.Project)
	}

	// An API call identifies a backend even with no key on this surface --
	// which is the login-wall case, where the key ships only after sign-in.
	api := Surface{Site: "https://app.example", Scripts: map[string]string{
		"https://app.example/a.js": `fetch("https://` + someRef + `.supabase.co/rest/v1/notes")`,
	}}
	if d, ok := detectOne(t, "supabase", api); !ok {
		t.Error("an API call to a project did not identify it")
	} else if d.Credential != "" {
		t.Error("a credential was reported where none was present")
	}
}

// Two backends in one application must both be reported. Picking a winner
// would hide the second, and "which one is primary" is not a question the
// evidence answers.
func TestBothBackendsAreReported(t *testing.T) {
	s := Surface{Site: "https://app.example", Scripts: map[string]string{
		"https://app.example/app.js": `createClient("https://` + someRef + `.supabase.co","` +
			fakeAnon + `");const firebaseConfig={apiKey:"` + fakeAIza + `",projectId:"demo-proj"};`,
	}}
	got := Detect(s)
	if len(got) != 2 {
		t.Fatalf("expected both backends, got %d: %+v", len(got), got)
	}
	// Sorted by provider name: reports get diffed between runs.
	if got[0].Provider != "firebase" || got[1].Provider != "supabase" {
		t.Errorf("order is not stable by name: %s, %s", got[0].Provider, got[1].Provider)
	}
}

// Nothing at all must produce nothing. A site that is not a BaaS application is
// the commonest input a broad scan sees, and the negative control this whole
// project was benchmarked on.
func TestPlainSiteDetectsNothing(t *testing.T) {
	s := Surface{Site: "https://news.example", HTML: `<html><head><title>News</title></head>
		<body><script src="/jquery.js"></script></body></html>`,
		Scripts: map[string]string{"https://news.example/jquery.js": "function $(s){return null}"}}
	if got := Detect(s); len(got) != 0 {
		t.Errorf("a plain site was identified as %+v", got)
	}
}

func TestRegistryIsStableAndPopulated(t *testing.T) {
	names := Registered()
	if len(names) < 2 {
		t.Fatalf("only %d detectors registered: %v", len(names), names)
	}
	if !strings.Contains(strings.Join(names, ","), "firebase") ||
		!strings.Contains(strings.Join(names, ","), "supabase") {
		t.Errorf("registry missing a backend: %v", names)
	}
	for i := 1; i < len(names); i++ {
		if names[i-1] > names[i] {
			t.Errorf("registry is not sorted, so output order depends on init order: %v", names)
		}
	}
}
