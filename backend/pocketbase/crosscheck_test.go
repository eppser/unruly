package pocketbase

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/eppser/unruly/internal/exploit"
	"github.com/eppser/unruly/scan"
)

// Everything the scanner reports must be exploitable, and everything
// exploitable must be reported.
//
// The lab tests next door grade RECALL: given collections whose rules setup.sh
// set, does the prober name them. They cannot answer whether anybody could
// actually DO the thing a finding claims, because the scanner performs the
// retrieval they check. That is why both PocketBase findings sat at `pending`
// in docs/exploitability.md and why maxPendingExploits had to go from 5 to 7.
//
// This closes it. internal/exploit imports nothing from this package -- verify
// with `go list -deps` -- so when the two agree it is because the target
// behaves that way, not because they share an assumption. The answer key is
// transcribed from setup.sh rather than from scanner output, for the same
// reason.
func TestTheScannerAgreesWithAnIndependentExploit(t *testing.T) {
	requireLab(t, vulnerable)
	ctx := context.Background()

	key, err := exploit.LoadKey("../../fixtures/pocketbase/answer-key.yaml")
	if err != nil {
		t.Fatalf("answer key: %v", err)
	}

	// --- what an independent implementation could actually do ------------
	exploited := map[string]exploit.Outcome{} // collection -> outcome
	var created []struct{ id, token string }
	// Deleted at the end, not merely reported. An account this harness leaves
	// on the instance is residue, and the harness is held to the rule the
	// scanner is held to.
	t.Cleanup(func() {
		for _, c := range created {
			if c.token == "" {
				t.Errorf("account %s cannot be deleted: no token was returned, so this "+
					"cross-check left a user on the lab", c.id)
				continue
			}
			if err := exploit.PocketBaseDeleteAccount(ctx, vulnerable, c.id, c.token); err != nil {
				t.Errorf("account %s was not deleted: %v", c.id, err)
			}
		}
	})
	for _, e := range key.Exploits {
		switch e.Technique {
		case "read":
			exploited[e.Collection] = exploit.AnonRead(ctx, vulnerable, e.Collection)
		case "escalate":
			email := fmt.Sprintf("unruly-crosscheck-%s@example.invalid", e.Collection)
			o, id, tok := exploit.SignupEscalation(ctx, vulnerable, e.Collection, email, "probe-password-123")
			exploited[e.Collection] = o
			if id != "" {
				created = append(created, struct{ id, token string }{id, tok})
			}
		default:
			t.Fatalf("%s names technique %q, which this cross-check cannot run",
				e.ID, e.Technique)
		}
	}

	// --- what the scanner says -------------------------------------------
	names := []string{}
	for _, e := range key.Exploits {
		names = append(names, e.Collection)
	}
	for _, p := range key.Protected {
		names = append(names, p.Relation)
	}
	// BOTH stages, because the cross-check grades both findings. Running only
	// CollectionStage left the escalation half of the protected loop grading an
	// empty map -- a guard that cannot fire, which is the defect this test
	// exists to catch in the scanner.
	st := &scan.State{Target: vulnerable}
	if _, err := (scan.Pipeline{
		CollectionStage{Client: pbTestClient(vulnerable), Base: vulnerable, Collections: names},
		EscalationStage{Client: pbTestClient(vulnerable), Base: vulnerable, Consent: true, Collections: names},
	}).Run(ctx, st); err != nil {
		t.Fatalf("scan: %v", err)
	}
	// Both findings, not just the read one. The protected list guards a claim
	// about a collection, and either finding is a way of making that claim.
	reported := map[string]bool{}
	gains := map[string]bool{}
	for _, f := range st.Findings() {
		switch f.ID {
		case "pocketbase-anon-read-exposed":
			reported[f.Resource] = true
		case "pocketbase-authenticated-escalation":
			gains[f.Resource] = true
		}
	}

	// --- the two directions ----------------------------------------------
	for _, e := range key.Exploits {
		if e.Technique != "read" {
			continue
		}
		o := exploited[e.Collection]
		if o.Unmeasured {
			t.Logf("%s: could not be established either way (%s)", e.ID, o.Detail)
			continue
		}
		if o.Succeeded && !reported[e.Collection] {
			t.Errorf("%s: an independent implementation retrieved %d record(s) from %q "+
				"and the scanner did not report it. That is a false negative on the "+
				"exact claim this tool exists to make.", e.ID, o.RowsGot, e.Collection)
		}
		if !o.Succeeded && reported[e.Collection] {
			t.Errorf("%s: the scanner reports %q as anonymously readable and nothing "+
				"could be retrieved from it (%s). A finding nobody can act on is worse "+
				"than a missed one.", e.ID, e.Collection, o.Detail)
		}
	}

	// Protected collections must not be reported at all, by EITHER finding.
	//
	// open_create is the one this second check catches: its createRule is open
	// and every read rule is null, so it accepts records and returns none -- to
	// an anonymous caller and to a registered account alike. A prober that read
	// "a rule is open" as "somebody can read it" would report it as an
	// escalation gain, and until now nothing here would have objected.
	for _, p := range key.Protected {
		if reported[p.Relation] {
			t.Errorf("%q is reported as anonymously readable, and the key says it must "+
				"not be: %s", p.Relation, strings.TrimSpace(p.Why))
		}
		if gains[p.Relation] {
			t.Errorf("%q is reported as an escalation gain, and the key says it must "+
				"not be: %s", p.Relation, strings.TrimSpace(p.Why))
		}
	}

	// Anti-vacuous. If every exploit retrieved nothing AND the scanner reported
	// nothing, the two comparisons above are between empty sets and this test
	// passes while proving nothing -- which is the failure it exists to catch
	// in the scanner.
	var succeeded, unmeasured int
	for _, o := range exploited {
		switch {
		case o.Succeeded:
			succeeded++
		case o.Unmeasured:
			unmeasured++
		}
	}
	if succeeded == 0 {
		t.Fatalf("no exploit succeeded against the vulnerable lab (%d unmeasured of "+
			"%d): either the fixture is not the vulnerable one or the harness cannot "+
			"reach it, and agreement between two things that both did nothing is not "+
			"evidence", unmeasured, len(exploited))
	}
	if len(reported) == 0 {
		t.Fatal("the scanner reported no anonymously readable collection against the " +
			"deliberately vulnerable fixture, so the comparison above had nothing on " +
			"one side")
	}
	t.Logf("%d exploit(s) succeeded, %d collection(s) reported, %d unmeasured",
		succeeded, len(reported), unmeasured)
}
