package eval_test

// Negative controls: hosts that are not Supabase.
//
// Every false positive found in the last three iterations was found by
// pointing the scanner at a host that answers uniformly, and every one was
// found by ACCIDENT — a catch-all edge host produced 706 invented relations
// and 1,412 findings, and the same host produced an open-signup finding
// against something with no auth server. This file makes that deliberate.
//
// The rule: against a target that is not Supabase, no finding above Info is
// correct, because there is nothing there to be vulnerable. Info findings are
// expected and are the point — they are how a scan says it could not assess a
// surface. A scanner that stays silent instead would be making the same claim
// as one that found nothing wrong.
//
//   make fixtures-notsupabase && UNRULY_LIVE=1 go test ./internal/eval -run NotSupabase -v

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/eppser/unruly/internal/client"
	"github.com/eppser/unruly/internal/enumerate"
	"github.com/eppser/unruly/internal/finding"
	"github.com/eppser/unruly/internal/probe"
	"github.com/eppser/unruly/internal/selfcheck"
	"github.com/eppser/unruly/internal/surface"
	"github.com/eppser/unruly/internal/wordlist"
)

// decoys are hosts a scan will plausibly be pointed at by mistake: a wrong
// port, a CDN in front of the origin, a staging URL that no longer resolves to
// the project.
var decoys = []struct{ name, url, why string }{
	{"spa", "http://127.0.0.1:54361",
		"a single-page app serving index.html for unknown routes, which is how " +
			"every React deployment is configured"},
	{"json200", "http://127.0.0.1:54362",
		"an API gateway answering 200 with JSON to every path"},
	{"deny", "http://127.0.0.1:54363",
		"a 401 wall; a 401 arrives before the schema is consulted and says nothing " +
			"about whether a relation exists"},
	{"broken", "http://127.0.0.1:54364",
		"an origin returning 500, which must read as could-not-measure"},
	{"throttle", "http://127.0.0.1:54365",
		"a host answering 429 to everything, as a rate-limited project or a WAF does"},
}

func decoyClient(t *testing.T, url string) *client.Client {
	t.Helper()
	if os.Getenv("UNRULY_LIVE") != "1" {
		t.Skip("set UNRULY_LIVE=1 to run live evals")
	}
	return client.New(client.Options{
		ProjectRef: "decoy", BaseURL: url, AnonKey: "eyJhbGciOiJIUzI1NiJ9.e30.x",
		Retries: 1,
	})
}

// scanDecoy runs the stages that make claims about a target and returns every
// finding they produce.
func scanDecoy(t *testing.T, url string) []finding.Finding {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	c := decoyClient(t, url)

	en := enumerate.Run(ctx, c, enumerate.Options{Seeds: wordlist.Relations()})
	var out []finding.Finding
	if f, ok := en.ControlFinding(c.RestBase()); ok {
		out = append(out, f)
	}
	sent, failed := c.Stats()
	sc := selfcheck.Run(ctx, c, selfcheck.Evidence{
		HintsObserved: en.HintsObserved, RelationsFound: len(en.Relations),
		ProbesDenied: en.Denied, ProbesTotal: en.SeedCount,
		RequestsSent: sent, RequestsFailed: failed,
	})
	out = append(out, sc.Findings...)

	pr := probe.Run(ctx, c, en.Names(), probe.Options{Write: true, SampleRows: 2})
	out = append(out, pr.Findings(c.RestBase(), false)...)

	sf := surface.Run(ctx, c, surface.Options{
		RoutineSeeds: wordlist.Routines(), FunctionSeeds: wordlist.Functions(),
		AllowInvoke: true, AllowFunctions: true,
	})
	out = append(out, sf.Findings...)
	return out
}

// TestNotSupabaseProducesNoVulnerabilityFindings is the precision test for
// targets that are not Supabase at all.
func TestNotSupabaseProducesNoVulnerabilityFindings(t *testing.T) {
	requireLiveEvals(t)
	for _, d := range decoys {
		t.Run(d.name, func(t *testing.T) {
			fs := scanDecoy(t, d.url)
			for _, f := range fs {
				if f.Severity > finding.Info {
					t.Errorf("%s (%s) is not Supabase, so %q at %s is a false positive: %s",
						d.name, d.why, f.ID, f.Severity, f.Description)
				}
			}
			t.Logf("%s: %d findings, all informational", d.name, len(fs))
		})
	}
}

// Silence would be the wrong kind of pass. A scan that reports nothing at all
// is indistinguishable from one that looked and found nothing wrong, which is
// the claim every surveyed tool makes falsely.
func TestNotSupabaseStillSaysItCouldNotLook(t *testing.T) {
	requireLiveEvals(t)
	for _, d := range decoys {
		t.Run(d.name, func(t *testing.T) {
			fs := scanDecoy(t, d.url)
			if len(fs) == 0 {
				t.Fatalf("%s produced no findings at all; an empty report is the same "+
					"thing a clean project produces", d.name)
			}
			var coverage int
			for _, f := range fs {
				switch f.ID {
				case "unruly-capability-degraded",
					"unruly-surface-not-assessed",
					"unruly-target-not-discriminating":
					coverage++
				}
			}
			if coverage == 0 {
				t.Errorf("%s produced %d findings but none of them say a surface could "+
					"not be assessed", d.name, len(fs))
			}
		})
	}
}

// The flaky host is the case the uniform decoys cannot reach: it behaves like
// PostgREST, so the control probe succeeds and the scan proceeds, and then it
// throttles half the relation probes. Nothing here is a false positive -- the
// relations it does report really do answer. What must not happen is silence
// about the half that was never measured.
func TestNotSupabaseThrottledTargetSaysTheListIsIncomplete(t *testing.T) {
	const flakyURL = "http://127.0.0.1:54366"
	if os.Getenv("UNRULY_LIVE") != "1" {
		t.Skip("set UNRULY_LIVE=1 to run live evals")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	c := decoyClient(t, flakyURL)

	en := enumerate.Run(ctx, c, enumerate.Options{Seeds: wordlist.Relations()})
	if !en.Discriminating {
		t.Fatal("the flaky host 404s the control name, so it discriminates and the " +
			"scan must proceed rather than refuse it")
	}
	if en.Unresolved == 0 {
		t.Fatal("half this host's paths answer 429; those probes must be counted")
	}
	if len(en.Relations) == 0 {
		t.Fatal("the unthrottled half must still be discovered")
	}
	f, ok := en.UnresolvedFinding(c.RestBase(), en.SeedCount)
	if !ok {
		t.Fatal("a scan that could not measure half its candidates must say so")
	}
	t.Logf("%d relations discovered, %d of %d probes unresolved",
		len(en.Relations), en.Unresolved, en.SeedCount)
	if f.Severity != finding.Info {
		t.Errorf("an incomplete scan is not a target vulnerability, got %s", f.Severity)
	}
}

// requireLiveEvals skips the PARENT, not the subtests.
//
// The gate used to live in the client helper, which runs inside t.Run — so
// every subtest skipped and the parent reported PASS in 0.00s. An audit found
// TestExitCodeUnmeasurableTargetsAreNotClean green in the offline CI job
// having executed nothing, which is the file's own description of "this
// project's entire thesis". A parent that passes because its children skipped
// is the same lie as a scan that reports clean because it could not look.
func requireLiveEvals(t *testing.T) {
	t.Helper()
	if os.Getenv("UNRULY_LIVE") != "1" {
		t.Skip("set UNRULY_LIVE=1 to run live evals")
	}
}

// A host that refuses everything must be abandoned quickly and reported
// honestly.
//
// Measured before the breaker existed: 2m6s and 1,827 requests against a
// fixture that answers 429 instantly, ending in 0 relations and every surface
// unassessed. Nothing was learned, and the report was shaped exactly like a
// clean project's -- absence of findings, which the reader has to notice is
// absence of measurement.
//
// Both halves are graded. Stopping fast without saying why would be worse than
// grinding: it would turn two minutes of honest failure into four seconds of
// silent failure.
func TestRefusingHostIsAbandonedQuicklyAndSaidSo(t *testing.T) {
	requireLiveEvals(t)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	c := client.New(client.Options{
		ProjectRef: "decoy", BaseURL: "http://127.0.0.1:54365",
		AnonKey: "eyJhbGciOiJIUzI1NiJ9.e30.x", Retries: 1,
	})

	// Not requireReachable: that helper counts 429 as unreachable, which is
	// right for every other fixture and wrong for the one whose entire purpose
	// is answering 429. But a fixture that is simply DOWN would also open the
	// breaker, on transport errors, and this test would pass without ever
	// measuring what it claims to. So establish that the host is up and
	// refusing, which is a different thing from absent.
	if probe := c.Do(ctx, "GET", "http://127.0.0.1:54365/", nil, nil); probe.Status != 429 {
		t.Skipf("FIXTURE UNREACHABLE: the throttle fixture answered status=%d err=%v, "+
			"not the 429 this test exists to measure", probe.Status, probe.Err)
	}

	// The whole plan, not one stage: enumeration alone stops early on its own
	// control probe, so it never reaches the refusal budget. The two minutes
	// this test exists to prevent were spent across every stage that followed.
	start := time.Now()
	en := enumerate.Run(ctx, c, enumerate.Options{Seeds: wordlist.Relations()})
	probe.Run(ctx, c, en.Names(), probe.Options{SampleRows: 2})
	surface.Run(ctx, c, surface.Options{
		RoutineSeeds: wordlist.Routines(), FunctionSeeds: wordlist.Functions(),
		AllowInvoke: true, AllowFunctions: true,
	})
	elapsed := time.Since(start)
	t.Logf("elapsed %s", elapsed)

	if !c.GaveUp() {
		t.Fatal("the host refused every request and the scan kept asking")
	}
	// The plan is thousands of probes. Anything near a minute means the
	// breaker is reporting rather than preventing.
	if elapsed > 30*time.Second {
		t.Errorf("enumeration took %s against a host that refuses everything", elapsed)
	}
	sent, _ := c.Stats()
	if sent > 400 {
		t.Errorf("sent %d requests into a wall; the budget is %d consecutive refusals",
			sent, 25)
	}
	if len(en.Relations) != 0 {
		t.Errorf("claimed %d relations from a host that answered 429 to everything",
			len(en.Relations))
	}

	// And the report must say it, at info -- this is a statement about the
	// scan, never about the target.
	f := finding.TargetRefused("http://127.0.0.1:54365", sent, "429 to everything")
	if f.ID != "unruly-target-refused" {
		t.Errorf("id = %q", f.ID)
	}
	if f.Severity != finding.Info {
		t.Errorf("severity %s: a scan diagnostic must never compete with a finding", f.Severity)
	}
	for _, must := range []string{"not a clean result", "absence of measurement"} {
		if !strings.Contains(f.Description, must) {
			t.Errorf("the finding does not say %q, so a reader can mistake it for clean", must)
		}
	}
}
