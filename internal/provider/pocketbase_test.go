package provider

import (
	"github.com/eppser/unruly/internal/finding"
	"strings"
	"testing"
)

// A PocketBase application names its own backend in the bundle.
//
// There is no project ref to recognise and no key to find: a PocketBase
// deployment IS its origin, and the SDK is constructed with that origin as a
// literal. So detection reads the constructor, and the origin it yields is
// what every later request is addressed to.
func TestPocketBaseIsDetectedFromTheSDKConstructor(t *testing.T) {
	s := Surface{
		Site: "https://app.example.com",
		Scripts: map[string]string{
			"https://app.example.com/main.js": `import PocketBase from 'pocketbase';
			const pb = new PocketBase('https://pb.example.com');
			pb.collection('notes').getList(1, 50);`,
		},
	}
	got := Detect(s)
	var d Detection
	for _, x := range got {
		if x.Provider == "pocketbase" {
			d = x
		}
	}
	if d.Provider != "pocketbase" {
		t.Fatalf("not detected: %+v", got)
	}
	if d.Project != "https://pb.example.com" {
		t.Errorf("Project %q, want the full origin: for PocketBase the origin IS the "+
			"instance identity, and http:// and https:// are different deployments",
			d.Project)
	}
	if got := APIBase(d); got != "https://pb.example.com" {
		t.Errorf("APIBase %q, want the origin every request is addressed to", got)
	}
	if d.Source == "" || d.Reason == "" {
		t.Error("a detection must say where it came from and what made it positive, " +
			"so a reader can check it rather than take it")
	}
}

// A Supabase bundle must NOT be identified as PocketBase.
//
// Precision is the axis this project competes on, and a detector that fires on
// a neighbouring backend sends the whole scan to the wrong API.
func TestASupabaseBundleIsNotPocketBase(t *testing.T) {
	s := Surface{
		Site: "https://app.example.com",
		Scripts: map[string]string{
			"https://app.example.com/main.js": `import { createClient } from '@supabase/supabase-js';
			const supabase = createClient('https://abcdefghijklmnop.supabase.co', 'ey.J.k');
			supabase.from('notes').select('*');`,
		},
	}
	for _, d := range Detect(s) {
		if d.Provider == "pocketbase" {
			t.Errorf("a Supabase bundle was identified as PocketBase: %+v", d)
		}
	}
}

// A site with no backend at all yields nothing.
func TestAPlainSiteIsNotPocketBase(t *testing.T) {
	s := Surface{Site: "https://example.com", HTML: "<h1>hello</h1>"}
	for _, d := range Detect(s) {
		if d.Provider == "pocketbase" {
			t.Errorf("a plain site was identified as PocketBase: %+v", d)
		}
	}
}

// The word "pocketbase" appearing in prose is not a deployment.
//
// A blog post about PocketBase, or a dependency listed in a bundle comment, is
// exactly the sort of thing that produces a confident scan of a host that does
// not exist. The constructor with an origin is the evidence; the name alone is
// not.
func TestTheWordAloneIsNotADetection(t *testing.T) {
	s := Surface{
		Site: "https://blog.example.com",
		HTML: `<article>Why we migrated from PocketBase to Postgres</article>`,
		Scripts: map[string]string{
			"https://blog.example.com/a.js": `// pocketbase was considered here`,
		},
	}
	for _, d := range Detect(s) {
		if d.Provider == "pocketbase" {
			t.Errorf("prose mentioning the product was treated as a deployment: %+v", d)
		}
	}
}

// Two origins in one bundle resolve the same way every run.
//
// Detection order feeds report order, and eval-determinism grades byte
// identity, so the choice cannot depend on map iteration.
func TestDetectionIsDeterministicWithSeveralOrigins(t *testing.T) {
	s := Surface{
		Site: "https://app.example.com",
		Scripts: map[string]string{
			"https://app.example.com/b.js": `new PocketBase("https://zzz.example.com")`,
			"https://app.example.com/a.js": `new PocketBase("https://aaa.example.com")`,
		},
	}
	first := ""
	for i := 0; i < 20; i++ {
		var got string
		for _, d := range Detect(s) {
			if d.Provider == "pocketbase" {
				got = d.Project
			}
		}
		if i == 0 {
			first = got
			continue
		}
		if got != first {
			t.Fatalf("run %d chose %q, first run chose %q: detection depends on map order",
				i, got, first)
		}
	}
}

// A plaintext instance is addressed over plaintext.
//
// APIBase used to return "https://" + host, which silently rewrote every
// http:// deployment -- including the local lab on http://127.0.0.1:8090 --
// to a scheme it does not serve. Every probe would then fail to connect and
// the scan would report a backend it never reached.
func TestAPlaintextInstanceKeepsItsScheme(t *testing.T) {
	s := Surface{
		Site: "http://localhost:3000",
		Scripts: map[string]string{
			"http://localhost:3000/app.js": `const pb = new PocketBase("http://127.0.0.1:8090")`,
		},
	}
	var d Detection
	for _, x := range Detect(s) {
		if x.Provider == "pocketbase" {
			d = x
		}
	}
	if d.Provider == "" {
		t.Fatal("a plaintext PocketBase instance was not detected")
	}
	if got := APIBase(d); got != "http://127.0.0.1:8090" {
		t.Errorf("APIBase %q, want http://127.0.0.1:8090 with its scheme intact", got)
	}
}

// PocketBase usually serves the application itself, and then the SDK is
// constructed with a relative URL rather than an origin.
//
// Measured against PocketBase's own minified admin bundle, fetched from the
// running lab: it constructs its client as new PocketBase('${i}') -- a
// template literal, not a literal origin. The same shape appears as
// new PocketBase('/') and new PocketBase(window.location.origin) in
// applications PocketBase hosts.
//
// Requiring an absolute origin therefore missed what is plausibly the most
// common deployment shape, while still refusing to invent one. The evidence is
// the CONSTRUCTOR; when its argument is not an origin, the backend is whatever
// serves the application.
func TestAnApplicationServedByItsOwnPocketBaseIsDetected(t *testing.T) {
	for _, arg := range []string{"/", "", "${base}", "window.location.origin"} {
		t.Run("arg="+arg, func(t *testing.T) {
			s := Surface{
				Site: "https://app.example.com",
				Scripts: map[string]string{
					"https://app.example.com/main.js": "const pb = new PocketBase('" + arg + "')",
				},
			}
			var d Detection
			for _, x := range Detect(s) {
				if x.Provider == "pocketbase" {
					d = x
				}
			}
			if d.Provider == "" {
				t.Fatalf("a PocketBase-hosted application was not detected for arg %q", arg)
			}
			if d.Project != "https://app.example.com" {
				t.Errorf("Project %q, want the site: the constructor names no origin, so "+
					"the backend is whatever serves the application", d.Project)
			}
			if !strings.Contains(d.Reason, "serves") {
				t.Errorf("Reason %q does not say the origin was inferred from the site "+
					"rather than read from the bundle, so a reader cannot check it",
					d.Reason)
			}
		})
	}
}

// An absolute origin in the constructor still wins over the site.
func TestAnExplicitOriginBeatsTheSite(t *testing.T) {
	s := Surface{
		Site: "https://app.example.com",
		Scripts: map[string]string{
			"https://app.example.com/main.js": `new PocketBase("https://pb.example.com")`,
		},
	}
	var d Detection
	for _, x := range Detect(s) {
		if x.Provider == "pocketbase" {
			d = x
		}
	}
	if d.Project != "https://pb.example.com" {
		t.Errorf("Project %q, want the origin the constructor names", d.Project)
	}
}

// Inference must NOT rescue a non-detection.
//
// The constructor remains the evidence. Prose, a Supabase bundle and a plain
// site all have a Site to fall back on, and none of them may produce a
// detection -- otherwise the fallback turns every page into a PocketBase.
func TestInferenceDoesNotWeakenPrecision(t *testing.T) {
	cases := map[string]Surface{
		"prose": {Site: "https://blog.example.com",
			HTML: "<article>Why we left PocketBase</article>"},
		"supabase": {Site: "https://app.example.com", Scripts: map[string]string{
			"https://app.example.com/m.js": `createClient('https://abcdefghijklmnopqrst.supabase.co','k')`}},
		"plain": {Site: "https://example.com", HTML: "<h1>hi</h1>"},
	}
	for name, s := range cases {
		t.Run(name, func(t *testing.T) {
			for _, d := range Detect(s) {
				if d.Provider == "pocketbase" {
					t.Errorf("inference produced a detection with no constructor: %+v", d)
				}
			}
		})
	}
}

// PocketBase's limits were measured and written into
// docs/pocketbase-ground-truth.md, and were absent from the report a scan
// produces. This asserts each reaches a reader, and names what silence costs.
func TestPocketBaseDeclaresWhatItCannotMeasure(t *testing.T) {
	fs := NotMeasured(pocketbase{}, Detection{Provider: "pocketbase", Project: "http://p"})
	if len(fs) == 0 {
		t.Fatal("PocketBase declares no limits, so a report says nothing about the " +
			"surfaces nobody looked at -- while the repository documents them")
	}
	byCap := map[string]finding.Finding{}
	for _, f := range fs {
		byCap[f.Resource] = f
		if f.ID != "unruly-surface-not-assessed" {
			t.Errorf("%q has id %q; a limit must reuse the id the exit code already "+
				"treats as blindness", f.Resource, f.ID)
		}
		if f.Severity != finding.Info {
			t.Errorf("%q is severity %v; a scanner diagnostic must never reach a reader "+
				"filtering for things to fix", f.Resource, f.Severity)
		}
	}
	for _, want := range []struct{ capability, mechanism, cost string }{
		{"anonymous write", "404",
			"a fake-id probe cannot tell an open rule from a filtered one, so " +
				"'permitted' is never established without -write"},
		{"enumerating what exists", "401",
			"the candidate list IS the recall, so an absent collection was not " +
				"guessed rather than not there"},
		{"callable code", "hook",
			"a hook runs before the rules and can serve anything, so every rule in " +
				"the report can be correct while the data is public"},
		{"live subscriptions", "204",
			"subscription acceptance proves nothing because rules are enforced at " +
				"delivery, and this surface is not probed at all"},
	} {
		f, ok := byCap[want.capability]
		if !ok {
			t.Errorf("%q is not declared; %s", want.capability, want.cost)
			continue
		}
		if !strings.Contains(strings.ToLower(f.Description), want.mechanism) {
			t.Errorf("%q does not say WHY (%q missing): without the mechanism a reader "+
				"cannot judge whether it matters. %s", want.capability, want.mechanism, want.cost)
		}
	}
}

// Weak or default superuser credentials are NOT declared, and must not be.
// That check is unwritten work, not a property of the protocol: guessable
// credentials are measurable by anyone who writes the probe. Declaring it here
// would dress a gap in the WORK as a limit of the TARGET, and it would then
// read as permanently unfixable rather than as a to-do.
func TestPocketBaseDoesNotDeclareUnwrittenWorkAsALimit(t *testing.T) {
	for _, f := range NotMeasured(pocketbase{}, Detection{Provider: "pocketbase"}) {
		low := strings.ToLower(f.Resource + " " + f.Description)
		for _, forbidden := range []string{"superuser credential", "default password",
			"weak password", "guessable credential"} {
			if strings.Contains(low, forbidden) {
				t.Errorf("a declared limit mentions %q: that check is simply unwritten, "+
					"and calling it unmeasurable makes unfinished work look structural: %s",
					forbidden, f.Description)
			}
		}
	}
}
