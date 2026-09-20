package provider

import (
	"strings"
	"testing"

	"github.com/eppser/unruly/scan"
)

// A second backend, written the way a contributor outside this repository
// would write one: a type, a Detect, an Assess, and nothing else.
//
// It exists to grade the seam rather than any backend. Every assertion below
// is about a decision the CORE was making on a provider's behalf, and each one
// was wrong for any backend that is not Firebase.
type fakeBackend struct{}

func (fakeBackend) Name() string { return "examplebase" }

func (fakeBackend) Measures() []Capability        { return append([]Capability(nil), allCapabilities...) }
func (fakeBackend) Cannot() map[Capability]string { return nil }

func (fakeBackend) APIBase(Detection) string { return "https://api.examplebase.test" }

func (fakeBackend) Detect(s Surface) (Detection, bool) {
	for _, body := range bodies(s) {
		if strings.Contains(body, "EXAMPLEBASE_PROJECT=") {
			return Detection{
				Provider: "examplebase", Project: "acme",
				Source: s.Site, Reason: "an EXAMPLEBASE_PROJECT declaration",
			}, true
		}
	}
	return Detection{}, false
}

func (fakeBackend) Stages(Detection, scan.Inputs) []scan.Stage { return nil }

// registerFake adds the backend for one test and removes it afterwards, so the
// registry the rest of the suite sees is unchanged.
func registerFake(t *testing.T) {
	t.Helper()
	Register(fakeBackend{})
	t.Cleanup(func() {
		mu.Lock()
		defer mu.Unlock()
		for i, d := range detectors {
			if d.Name() == "examplebase" {
				detectors = append(detectors[:i], detectors[i+1:]...)
				return
			}
		}
	})
}

// The address of a backend belongs to the backend.
func TestProviderDeclaresItsOwnAPIBase(t *testing.T) {
	registerFake(t)
	got := APIBase(Detection{Provider: "examplebase"})
	if got != "https://api.examplebase.test" {
		t.Errorf("APIBase = %q, want the provider's own origin", got)
	}
	// The specific wrong answer the core used to produce.
	if strings.Contains(got, "googleapis.com") {
		t.Errorf("APIBase = %q: derived from the provider NAME, so every probe "+
			"this backend makes goes to a host unrelated to the target", got)
	}
	if base := APIBase(Detection{Provider: "firebase"}); !strings.Contains(base, "firebase") {
		t.Errorf("firebase APIBase = %q", base)
	}
	// A provider that addresses everything absolutely says so by not
	// implementing Endpoint, and must not be given a guess.
	if base := APIBase(Detection{Provider: "supabase"}); base != "" {
		t.Errorf("supabase APIBase = %q, want empty rather than an invented origin", base)
	}
}

// Detection must find a second backend, and report both when both are present.
func TestDetectFindsARegisteredBackendAlongsideFirebase(t *testing.T) {
	registerFake(t)
	s := Surface{
		Site: "https://app.test",
		Scripts: map[string]string{"https://app.test/b.js": `
			const EXAMPLEBASE_PROJECT="acme";
			const firebaseConfig={apiKey:"AIzaSyFAKEfakefakefakefakefake0123",projectId:"acme-app"};`},
	}
	var names []string
	for _, d := range Detect(s) {
		names = append(names, d.Provider)
	}
	// Sorted by provider name, so a report of an unchanged site is identical
	// between runs.
	if strings.Join(names, ",") != "examplebase,firebase" {
		t.Errorf("Detect = %v, want both backends in name order", names)
	}
}
