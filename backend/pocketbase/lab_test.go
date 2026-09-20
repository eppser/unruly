package pocketbase

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/eppser/unruly/scan"
)

// labs are the fixtures provisioned by fixtures/pocketbase/setup.sh.
//
// Skipped unless the instances are actually serving, because a test that
// silently passes when its fixture is down is the "not run counts as a pass"
// failure this project refuses everywhere else.
//
// THE PORTS ARE NOT HARD-CODED, and that is not a convenience. They were,
// and it cost a false pass: an ssh port-forward held 8090 on the machine
// this was developed on, setup.sh could not bind, and the whole graded suite
// ran against a stranger while reporting success. The tests now read the same
// variables setup.sh does, so "the fixtures" means the ones that were
// actually started.
var (
	vulnerable = "http://127.0.0.1:" + envOr("PB_VULN_PORT", "8090")
	hardened   = "http://127.0.0.1:" + envOr("PB_HARD_PORT", "8091")
)

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func requireLab(t *testing.T, base string) {
	t.Helper()
	if os.Getenv("UNRULY_PB_LAB") == "" {
		t.Skip("set UNRULY_PB_LAB=1 with the pocketbase lab serving")
	}
	c := &http.Client{Timeout: 2 * time.Second}
	resp, err := c.Get(base + "/api/health")
	if err != nil {
		t.Fatalf("lab at %s is not serving: %v", base, err)
	}
	defer func() { _ = resp.Body.Close() }()
	// A response is not enough: it has to be POCKETBASE responding. The old
	// check accepted any answer, and an unrelated service returning 404 on
	// /api/health satisfied it -- which is how this suite once graded a
	// stranger and passed.
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("%s answered /api/health with %d; something is on that port but it "+
			"is not a healthy PocketBase", base, resp.StatusCode)
	}
	var health struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&health); err != nil || health.Code != 200 {
		t.Fatalf("%s does not answer /api/health like PocketBase (decode err %v, code %d); "+
			"the fixture may not be what is listening", base, err, health.Code)
	}
}

// Recall: every collection the answer key says leaks rows must be found.
func TestTheProberAgreesWithTheLabAnswerKeyOnRecall(t *testing.T) {
	requireLab(t, vulnerable)
	// Measured and recorded in the lab README. open_files and open_write and
	// public_notes return rows to anyone; the rest do not.
	want := map[string]bool{
		"public_notes": true, "open_files": true, "open_write": true,
		"locked_notes": false, "locked_files": false, "open_create": false,
		// The default users collection: 200 with an EMPTY items array,
		// because id = @request.auth.id filters every row away. Reporting it
		// would be a false positive on every PocketBase install.
		"users": false,
		// list blocked, view open -- its exposure is not a list exposure.
		"view_only": false,
	}
	for name, exposed := range want {
		got := ReadState(context.Background(), pbTestClient(vulnerable), vulnerable, name)
		if !got.Reached {
			t.Errorf("%s: not reached (status %d); the fixture may have drifted",
				name, got.Status)
			continue
		}
		if got.Exposed != exposed {
			t.Errorf("%s: Exposed=%v want %v (status %d, %d rows)",
				name, got.Exposed, exposed, got.Status, len(got.Sample))
		}
		if exposed && len(got.Sample) == 0 {
			t.Errorf("%s: reported exposed with no sampled rows", name)
		}
	}
}

// Precision: the hardened instance must yield nothing at all.
func TestTheProberFindsNothingOnTheHardenedInstance(t *testing.T) {
	requireLab(t, hardened)
	for _, name := range []string{"public_notes", "locked_notes", "open_create",
		"open_write", "users"} {
		got := ReadState(context.Background(), pbTestClient(hardened), hardened, name)
		if got.Exposed {
			b, _ := json.Marshal(got.Sample)
			t.Errorf("%s: reported exposed on the HARDENED instance, where every rule "+
				"is null: %s", name, b)
		}
	}
}

// The 403 negative must hold where the answer key says the rule is null, and
// must NOT be claimed where the rule is an expression.
func TestDenialIsDetectedOnlyWhereTheRuleIsActuallyNull(t *testing.T) {
	requireLab(t, vulnerable)
	cases := map[string]bool{
		"locked_notes": true,  // every rule null -> 403
		"view_only":    true,  // updateRule null -> 403
		"open_write":   false, // updateRule "" -> 404, not denied
		"users":        false, // expression rule -> 404, NOT a denial
	}
	for name, denied := range cases {
		v := VerbState(context.Background(), pbTestClient(vulnerable), vulnerable, name, http.MethodPatch)
		if v.Denied != denied {
			t.Errorf("%s: Denied=%v want %v (status %d)", name, v.Denied, denied, v.Status)
		}
		if v.Permitted {
			t.Errorf("%s: Permitted was set from a status code alone", name)
		}
	}
}

// Escalation against the real lab: sign up, diff, clean up, verify.
//
// authed_only carries the rule @request.auth.id != "" and one row with a
// card-shaped value. Measured: anonymous sees 0 rows, a registered account
// sees 1. That difference is the whole finding, and it is invisible to any
// anonymous scan.
func TestEscalationAgainstTheRealLab(t *testing.T) {
	requireLab(t, vulnerable)

	st := &scan.State{Target: vulnerable}
	stage := EscalationStage{
		Client:      pbTestClient(vulnerable),
		Base:        vulnerable,
		Consent:     true,
		Collections: []string{"authed_only", "public_notes", "locked_notes"},
	}
	if _, err := (scan.Pipeline{stage}).Run(context.Background(), st); err != nil {
		t.Fatal(err)
	}

	var gains []string
	for _, f := range st.Findings() {
		switch f.ID {
		case "pocketbase-authenticated-escalation":
			gains = append(gains, f.Resource)
			if len(f.Evidence.Sample) == 0 {
				t.Errorf("%s: reported a gain with no rows", f.Resource)
			}
		case "unruly-surface-not-assessed":
			if f.Resource == "escalation:residue" {
				t.Error("the scan created an account it could not delete; the lab now " +
					"holds a real user this test put there")
			}
		}
	}
	if len(gains) != 1 || gains[0] != "authed_only" {
		t.Errorf("gains %v, want only [authed_only]: public_notes is readable to both "+
			"callers and reporting it would double-count the anonymous finding", gains)
	}
}
