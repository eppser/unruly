package eval_test

import (
	"encoding/json"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
)

// Every replayable request must reproduce the finding that published it.
//
// "Proof-carrying: findings carry REAL sampled evidence and a replayable
// request, never a boolean" is a standing rule, and until now nothing checked
// the second half. eval-remediation executes the -fix output and requires the
// findings to close, which is why remediation has never drifted. Evidence had
// no equivalent, and on 2026-08-22 three of them had drifted:
//
//	the Neon write finding published a payload the probe had stopped sending
//	the Firestore evidence dropped the __name__ projection, so replaying it
//	  retrieved the field values the scan is documented never to retrieve
//	the GraphQL evidence hardcoded first: 3 whatever -sample was set to
//
// Each was found by reading. This runs them instead: take the command out of
// the report, execute it, and require the status the report claims. A command
// that does not reproduce its own finding is not evidence.
//
// Requests carrying a credential placeholder are executed with the fixture's
// key substituted. Requests naming a host this fixture does not serve are
// skipped and COUNTED -- a replay suite that quietly checks nothing is the
// vacuous check this repo keeps finding.
func TestReplayPublishedRequestsReproduceTheirFindings(t *testing.T) {
	key := os.Getenv("UNRULY_FIXTURE_KEY")
	if key == "" {
		t.Skip("UNRULY_FIXTURE_KEY required")
	}
	_, findings := scanLabWithFlags(t, "-invoke", "-write", "-yes-i-own-this")

	// Relations this scan WROTE to cannot have their earlier read evidence
	// replayed byte for byte, because the scan changed the thing it measured.
	//
	// Measured: the read of all_defaults_insertable found it empty, so
	// PostgREST answered 200 with no Content-Range; the write probe then
	// inserted a row, and by replay time the same command answers 206. The
	// finding was true when taken and the write finding is true, and together
	// they mean the row count moved.
	//
	// Derived from the REPORT rather than from a status pair. Treating 200 and
	// 206 as interchangeable would re-admit the exact drift this check was
	// built to catch -- the published read command omitting the Prefer header
	// the probe always sends, which is a 206/200 mismatch too, opposite
	// direction and entirely different cause.
	mutated := map[string]bool{}
	for _, f := range findings {
		id, _ := f["id"].(string)
		switch id {
		case "supabase-anon-insert-allowed", "supabase-anon-update-allowed",
			"supabase-anon-delete-allowed":
			if r, ok := f["resource"].(string); ok {
				mutated[r] = true
			}
		}
	}

	var replayed, skipped, checked, carried, unstated, templates, suggested, coverage, selfChanged int
	var unstatedIDs []string
	for _, f := range findings {
		ev, ok := f["evidence"].(map[string]any)
		if !ok {
			continue
		}
		req, _ := ev["request"].(string)
		if req == "" {
			continue
		}
		carried++
		if !strings.HasPrefix(strings.TrimSpace(req), "curl") ||
			!strings.Contains(req, "127.0.0.1") {
			skipped++
			continue
		}
		// A command carrying <placeholders> is a template: the operator fills
		// it in. It cannot reproduce anything, so it is not replayed -- and it
		// must not claim a status either, or the report states an answer its
		// own command cannot produce.
		if strings.Contains(req, "<") && strings.Contains(req, ">") {
			templates++
			if st, ok := statusOf(ev); ok && st != 0 {
				id, _ := f["id"].(string)
				t.Errorf("%s publishes a template command and claims it answered HTTP %d. "+
					"A reader who runs it gets something else and concludes the tool is "+
					"wrong about something it is right about.\n  %s", id, st, req)
			}
			continue
		}
		id, _ := f["id"].(string)
		got, err := replayStatus(t, req, key)
		if err != nil {
			t.Errorf("%s: its own published command does not run: %v\n  %s", id, err, req)
			continue
		}
		replayed++

		// A command that reaches nothing is not evidence. 000 is curl's answer
		// when the request never completed -- a malformed URL, a quote in the
		// wrong place, a host that is not there.
		if got == 0 {
			t.Errorf("%s: its own published command completed no request at all.\n  %s", id, req)
			continue
		}
		// An offer is not a record. A finding may print a command the scan did
		// not run -- the RPC-discovery finding prints a call the scanner
		// refuses to make -- and such a command must say so rather than claim
		// an answer nothing observed.
		if sug, _ := ev["suggested"].(bool); sug {
			suggested++
			if st, ok := statusOf(ev); ok && st != 0 {
				id, _ := f["id"].(string)
				t.Errorf("%s marks its command as suggested and still claims HTTP %d", id, st)
			}
			continue
		}
		// A request without the status it produced cannot be checked against
		// anything: replaying it proves the command runs, and running is not
		// reproducing. Measured on 2026-08-22: 51 findings published a command
		// and ONE said what it answered, so a deliberately mangled URL replayed
		// to a 404 and this check passed it.
		want, ok := statusOf(ev)
		if !ok || want == 0 {
			// A finding that reports an INABILITY to measure may have no
			// status: an endpoint that never answered produced none, and
			// inventing one would be the invention this check exists to catch.
			// A finding that CLAIMS something about the target may not: it saw
			// an answer, and the answer is the evidence.
			id, _ := f["id"].(string)
			if strings.HasPrefix(id, "unruly-surface-not-assessed") ||
				strings.HasPrefix(id, "unruly-checks-skipped") ||
				strings.HasPrefix(id, "unruly-capability-degraded") {
				coverage++
				continue
			}
			unstated++
			unstatedIDs = append(unstatedIDs, id)
			continue
		}
		{
			// Only the READ evidence is invalidated: the row count moved, so
			// 200-with-no-range becomes 206. A write finding's own status is
			// about the write and reproduces exactly, so it stays compared --
			// exempting every finding on a written relation would have dropped
			// the comparison from 31 to 11 and called that progress.
			id, _ := f["id"].(string)
			res, _ := f["resource"].(string)
			if id == "supabase-anon-read-exposed" && mutated[res] {
				selfChanged++
				continue
			}
			checked++
			if got != want {
				t.Errorf("%s: the report says HTTP %d and its own command returns HTTP %d. "+
					"A command that does not reproduce the finding is not evidence.\n  %s",
					id, want, got, req)
			}
		}
	}
	t.Logf("replayed %d of %d published request(s); %d stated a status to compare; "+
		"%d were templates, %d offers, %d coverage notes, %d on relations this scan "+
		"itself wrote to; %d addressed other hosts",
		replayed, carried, checked, templates, suggested, coverage, selfChanged, skipped)

	// A replay suite that grades a handful is the vacuous check this repo keeps
	// finding. The first version of THIS test required a status and so graded 1
	// request of 51, and passed.
	if (replayed+templates+suggested)*10 < carried*8 {
		t.Errorf("only %d of %d published requests were replayed; a check that skips most "+
			"of its subject reports confidence it has not earned", replayed, carried)
	}
	if unstated > 0 {
		t.Errorf("%d finding(s) published a command and did not say what it answered. "+
			"Replaying such a command proves it runs, and running is not reproducing: a "+
			"wrong URL answers 404 and passes. The status the scan observed IS part of "+
			"the evidence: %v", unstated, unstatedIDs)
	}
	if carried == 0 {
		t.Error("the scan published no replayable request at all against this fixture")
	}
}

func statusOf(ev map[string]any) (int, bool) {
	switch v := ev["status"].(type) {
	case float64:
		return int(v), true
	case string:
		n, err := strconv.Atoi(v)
		return n, err == nil
	}
	return 0, false
}

// replayStatus runs the published curl and returns the status it observed.
//
// The command is executed through sh with the placeholders the report uses
// bound to the fixture's own credential, which is what an operator following
// the report would do. -o /dev/null -w keeps the body out of the test log: the
// point is the status, and a fixture's rows do not belong in CI output.
func replayStatus(t *testing.T, req, key string) (int, error) {
	t.Helper()
	cmd := exec.Command("sh", "-c", req+` -o /dev/null -w '%{http_code}'`)
	cmd.Env = append(os.Environ(),
		"SUPABASE_ANON_KEY="+key, "ANON="+key, "APIKEY="+key, "KEY="+key)
	out, err := cmd.Output()
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(strings.TrimSpace(string(out)))
}

var _ = json.Marshal
