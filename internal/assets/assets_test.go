package assets

import "testing"

// The origin guard, asserted on its own so it cannot be softened by accident.
func TestScriptDiscoveryRefusesOtherOrigins(t *testing.T) {
	for _, ref := range []string{
		"https://cdn.example.invalid/x.js",
		"//cdn.example.invalid/x.js",
		"http://insecure.example.invalid/x.js",
	} {
		if got, ok := SameOrigin("https://app.example.com/", ref); ok {
			t.Errorf("%s resolved to %s and would be fetched; a hostile page could send "+
				"the scanner -- and the apikey header, which Go does not strip -- to any "+
				"address it names", ref, got)
		}
	}
	for _, ref := range []string{"script.js", "/assets/a.js", "./b/c.js", "https://app.example.com/d.js"} {
		if _, ok := SameOrigin("https://app.example.com/", ref); !ok {
			t.Errorf("%s is same-origin and was refused", ref)
		}
	}
}
