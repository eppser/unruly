package provider

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"time"

	"github.com/eppser/unruly/internal/client"
	"testing"

	neonstage "github.com/eppser/unruly/backend/neon"
	"github.com/eppser/unruly/scan"
)

// Stages handed back by the seam must be able to RUN.
//
// The seam has three failure points and only the first two were guarded: a
// provider can declare stages, main can collect them, and the stages can then
// refuse to do anything. That is what happened here -- the backends were moved
// onto the shared client so the operator's -rate-limit and -timeout would
// bind, and a stage with no client now returns an error instead of guessing at
// defaults. Nothing supplied one through the seam, so every staged backend
// went quiet: detected, dispatched, and silent.
//
// The check is deliberately behavioural rather than structural. Asserting that
// a Client field is non-nil would pass a stage that holds a client and never
// uses it. Counting requests at the target is the thing an operator would
// notice was missing.
func TestStagesFromTheSeamActuallySendRequests(t *testing.T) {
	var seen int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&seen, 1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"items":[],"page":1,"perPage":1,"totalItems":0,"totalPages":0}`))
	}))
	defer srv.Close()

	stages := StagesFor(Detection{Provider: "pocketbase", Project: srv.URL}, scan.Inputs{
		Seeds:  []string{"widgets"},
		Client: testSeamClient(srv.URL),
	})
	if len(stages) == 0 {
		t.Fatal("the seam contributed no stages for a detected PocketBase instance")
	}
	st := &scan.State{Target: srv.URL}
	if _, err := scan.Pipeline(stages).Run(context.Background(), st); err != nil {
		t.Fatalf("pipeline: %v", err)
	}
	if atomic.LoadInt64(&seen) == 0 {
		t.Errorf("the seam produced %d stage(s) and sent no request. A backend that "+
			"is detected, dispatched and then silent reports nothing about a target "+
			"it found, which reads exactly like a clean result", len(stages))
	}
}

// Neon's stages are wired by the seam, and gated on having a credential.
//
// This one asserts WIRING rather than counting requests, and the reason is
// worth stating: APIBase returns an https origin, correctly -- the shared
// client offers no way to skip certificate verification and should not, so a
// plain-HTTP test server cannot be reached through it. That the stages
// actually send is covered by the transcript-replay evals in backend/neon,
// which drive them directly.
//
// The gate is the substance. Neon has no anonymous tier to compare against:
// without a bearer every name answers identically, so an escalation stage
// would present a refusal as a measurement.
func TestNeonStagesAreWiredAndGatedOnACredential(t *testing.T) {
	d := Detection{Provider: "neon", Project: "ep-x.apirest.eu-west-1.aws.neon.tech/neondb"}
	in := scan.Inputs{Seeds: []string{"widgets"}, Client: testSeamClient("https://x.invalid")}

	anon := StagesFor(d, in)
	if len(anon) != 1 {
		t.Fatalf("with no credential the seam contributed %d stage(s), want exactly 1 "+
			"(the reach check). Anything more would be measuring a surface that "+
			"answers every name the same way", len(anon))
	}
	if got := anon[0].Name(); got != "neon-reach" {
		t.Errorf("the sole uncredentialed stage is %q, want neon-reach: without one "+
			"the scan cannot tell an unassessed surface from a clean one", got)
	}

	in.Bearer = "a.b.c"
	authed := StagesFor(d, in)
	// Four: enumeration, reach, escalation, and a non-mutating write-tier
	// disclosure. The write stage is present with Consent=false so an omitted
	// tier cannot disappear; it sends nothing until the operator opts in.
	if len(authed) != 4 {
		t.Fatalf("with a credential the seam contributed %d stage(s), want 4", len(authed))
	}
	for _, st := range authed {
		if write, ok := st.(neonstage.WriteStage); ok && write.Consent {
			t.Fatal("the write stage received consent without -write -yes-i-own-this")
		}
	}

	in.Write = true
	consented := StagesFor(d, in)
	var names3 []string
	for _, st := range consented {
		names3 = append(names3, st.Name())
	}
	// 4 since enumeration joined. The write stage must still be LAST: a row it
	// adds would otherwise show up in the reads that precede it, which is not a
	// preference about tidiness -- it is why the read evidence can be trusted.
	if len(consented) != 4 || names3[len(names3)-1] != "neon-write" {
		t.Fatalf("with consent the seam contributed %v, want the write stage last: "+
			"it runs after the reads because a row it adds would otherwise show up "+
			"in them", names3)
	}
	var names []string
	for _, s := range authed {
		names = append(names, s.Name())
	}
	if names[0] != "neon-relations" {
		t.Errorf("stage order is %v; enumeration must run first so volunteered names "+
			"are probed in this invocation", names)
	}
	if names[1] != "neon-reach" || names[2] != "neon-escalation" {
		t.Errorf("stage order is %v, want reach then escalation after enumeration", names)
	}
}

func TestNeonNoResidueNeverAuthorisesTheWriteStage(t *testing.T) {
	d := Detection{Provider: "neon", Project: "ep-x.apirest.eu-west-1.aws.neon.tech/neondb"}
	stages := StagesFor(d, scan.Inputs{Seeds: []string{"widgets"}, Bearer: "a.b.c",
		Write: true, Controls: scan.Controls{Write: true, NoResidue: true},
		Client: testSeamClient("https://x.invalid")})
	for _, st := range stages {
		if write, ok := st.(neonstage.WriteStage); ok {
			if write.Consent {
				t.Fatal("-no-residue authorized a Neon stage that can leave an inserted row")
			}
			return
		}
	}
	t.Fatal("the refused write tier disappeared instead of being reported unmeasured")
}

// testSeamClient forwards every control an operator would.
func testSeamClient(base string) *client.Client {
	return client.New(client.Options{
		BaseURL:    base,
		RestPrefix: "/",
		Timeout:    5 * time.Second,
		UserAgent:  "unruly-test",
		Limiter:    client.NewLimiter(0),
	})
}

// The stages must be pointed at the REST prefix, not at the database root.
//
// APIBase returns origin + database, which is what the shared client hangs
// RestPrefix off. The Neon stages build their own URLs by appending a table
// name to Base, so handing them APIBase directly sent every request to
// <origin>/<db>/<table> -- a path that does not exist.
//
// Every offline eval missed this. They pass an httptest URL as Base and a
// transcript whose paths were recorded relative to a URL that ALREADY
// contained /rest/v1, so the prefix cancelled out on both sides. The bug only
// appears when something derives Base from a Detection, which is exactly what
// the seam does and no replay does.
func TestNeonStagesArePointedAtTheRestPrefix(t *testing.T) {
	d := Detection{Provider: "neon", Project: "ep-x.apirest.eu-west-1.aws.neon.tech/neondb"}
	stages := StagesFor(d, scan.Inputs{
		Seeds: []string{"widgets"}, Bearer: "a.b.c",
		Client: testSeamClient("https://x.invalid"),
	})
	if len(stages) == 0 {
		t.Fatal("no stages contributed")
	}
	want := APIBase(d) + "/rest/v1"
	for _, st := range stages {
		var base string
		switch v := st.(type) {
		case neonstage.ReachStage:
			base = v.Base
		case neonstage.EscalationStage:
			base = v.Base
		case neonstage.WriteStage:
			base = v.Base
		case neonstage.EnumerateStage:
			base = v.Base
		default:
			t.Fatalf("unexpected stage %T", st)
		}
		if base != want {
			t.Errorf("%s was given base %q, want %q. Appending a table name to the "+
				"database root asks for a path that is not there, so a live scan "+
				"finds nothing and reports the project clean", st.Name(), base, want)
		}
	}
}
