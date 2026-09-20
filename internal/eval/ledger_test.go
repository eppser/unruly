package eval_test

import (
	"os"
	"sort"
	"strings"
	"testing"
)

// How many serious findings have no demonstration yet.
//
// A ratchet, not a target. Lowering it is the work; raising it is a decision
// somebody has to make on purpose and defend in review, which is the whole
// point -- the alternative is a critical shipping with nothing behind it and
// nothing anywhere saying so.
//
// Went 5 -> 7 to admit two PocketBase findings that were already shipping and
// were invisible to this test, then back to 5 once they were demonstrated:
// fixtures/pocketbase/answer-key.yaml, internal/exploit/pocketbase.go, and
// backend/pocketbase's cross-check, which runs both against the live lab and
// requires them to agree. That is the ratchet working in the direction it is
// meant to move.
//
// 5 -> 3 when firebase-storage-anon-read and firebase-function-public were
// demonstrated against the live lab. The count had been 3 for some time while
// this constant still said 5, which is slack: two demonstrations could have
// been lost with nothing failing. A ratchet that is not tightened when it
// falls is a ratchet only in the direction nobody travels.
//
// The three that remain are Supabase, each recorded in docs/exploitability.md
// with what is missing rather than left implied: a realtime subscription needs
// a fixture where REST refuses the relation, the management-token proof needs
// an owned account and a decision about what is safe to call, and the
// connection-string proof needs a fixture shipping a URI with a password.
// 3 -> 2 when supabase-realtime-anon-subscription was reclassified. Not a
// demonstration written: a reason corrected. It was recorded as pending on the
// grounds that no fixture existed with REST refusing the relation, and that is
// the condition for HIGH rather than the condition for the finding to fire at
// all. It cannot fire against Supabase, because the acknowledgement control
// short-circuits Run first, so there is deliberately nothing to demonstrate --
// which is what not-exploitable means here.
//
// Reclassifying is the one move that can shrink this number without work, so
// it is only honest with a tripwire: the ledger row names the live test that
// fails if the platform ever makes the finding reachable.
// BACK TO 2 ON 2026-08-24, which is where it started.
//
// It went 2 -> 3 -> 4 -> 5 as four application findings were added, each raise
// deliberate and annotated, and each carrying the same debt: the testbed
// exercised them but this ledger asks for an ANSWER KEY, not a test written by
// the same person as the check. That distinction is not theoretical -- six of
// this loop's own tests, fixtures and controls agreed with the code for the
// wrong reason and only breaking them found it.
//
// fixtures/application/answer-key.yaml and internal/exploit/application.go
// discharge all four: a fixture whose behaviour is declared in one place, a key
// transcribed from it by hand, and a second implementation of every technique
// that shares no line with the scanner. The two pending rows that remain are
// the ones that were here before this work started.
const maxPendingExploits = 2

// Every finding that can reach high or critical is classified for
// exploitability.
//
// "More accurate than the alternatives" is a claim about proof. Measured when
// this was written: 26 finding ids can reach high or critical, and 7 of them
// had a demonstration. The other 19 were not wrong -- several are exploitable
// by construction -- but nothing in the repository said which was which, so
// the claim covered all 26 and the evidence covered 7.
//
// This does not require an exploit for everything. It requires a decision
// about everything, recorded where the next person can read it.
func TestExploitabilityLedgerCoversEverySeriousFinding(t *testing.T) {
	serious := seriousFindingIDs(t)
	ledger := exploitabilityLedger(t)

	var missing, extra []string
	for id := range serious {
		if _, ok := ledger[id]; !ok {
			missing = append(missing, id)
		}
	}
	for id := range ledger {
		if !serious[id] {
			extra = append(extra, id)
		}
	}
	sort.Strings(missing)
	sort.Strings(extra)
	if len(missing) > 0 {
		t.Errorf("docs/exploitability.md does not say whether these can be demonstrated: "+
			"%v. A finding reported at high or critical asserts a stranger can do "+
			"something; unrecorded, that assertion has nothing behind it", missing)
	}
	if len(extra) > 0 {
		t.Errorf("docs/exploitability.md classifies %v, which no longer reach high or "+
			"critical: a ledger that outlives its findings stops being read", extra)
	}

	// A proven row has to point at something that exists, in either key. The
	// local fixture proves the techniques offline and the cloud project proves
	// them against the real product; a finding demonstrated by either has a
	// demonstration.
	var keys string
	//
	// fixtures/pocketbase joined the list when PocketBase's two findings were
	// demonstrated. Adding the key here is not a formality: this check is what
	// stops a `proven` row from being a claim somebody typed, and it fired
	// correctly when the rows were flipped before the key was wired in.
	//
	// fixtures/neon joined when the escalation was demonstrated by
	// internal/exploit/neon.go -- a second implementation of the Neon Auth
	// sequence that imports nothing from the scanner -- and backend/neon's
	// cross-check, which runs both against the live lab and requires them to
	// agree on the rows AND on the tables that must stay silent.
	for _, p := range []string{"../../fixtures/supabase-lab/answer-key.yaml",
		"../../fixtures/lab/answer-key.yaml", "../../fixtures/firebase-lab/answer-key.yaml",
		"../../fixtures/pocketbase/answer-key.yaml",
		"../../fixtures/neon/answer-key.yaml",
		// fixtures/application joined when the four application findings were
		// demonstrated by internal/exploit/application.go -- a second
		// implementation of each technique, written from that key and
		// importing nothing from internal/routes. Its cross-check requires
		// three things at once: every exploit demonstrated, every control
		// refused, and NO technique succeeding against an application with
		// nothing wrong with it. The third is what stops a demonstrator that
		// succeeds everywhere from reading as proof.
		"../../fixtures/application/answer-key.yaml"} {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatalf("reading %s: %v", p, err)
		}
		keys += string(b)
	}
	var unbacked []string
	pending := 0
	for id, status := range ledger {
		switch status {
		case "proven":
			if !strings.Contains(keys, id) {
				unbacked = append(unbacked, id)
			}
		case "pending":
			pending++
		}
	}
	sort.Strings(unbacked)
	if len(unbacked) > 0 {
		t.Errorf("%v are recorded as proven and no answer key exploits them: a ledger "+
			"that can claim proof without one is a worse document than no ledger",
			unbacked)
	}
	if pending > maxPendingExploits {
		t.Errorf("%d findings have no demonstration and the ratchet allows %d. Either "+
			"write the exploit or raise maxPendingExploits deliberately -- the count "+
			"is allowed to fall on its own and never to rise on its own",
			pending, maxPendingExploits)
	}
	t.Logf("%d serious findings: %d classified, %d still pending a demonstration",
		len(serious), len(ledger), pending)
}

// seriousFindingIDs are the ids docs/checks.md says can reach high or
// critical. That file is itself checked against the source, so this reads the
// severities the code actually assigns rather than a second copy of them.
func seriousFindingIDs(t *testing.T) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	for _, row := range markdownRows(t, "../../docs/checks.md") {
		if len(row) < 2 {
			continue
		}
		sev := strings.ToLower(row[1])
		if strings.Contains(sev, "high") || strings.Contains(sev, "critical") {
			out[row[0]] = true
		}
	}
	if len(out) == 0 {
		t.Fatal("no high or critical findings parsed out of docs/checks.md, so this test " +
			"would pass against an empty ledger")
	}
	return out
}

// exploitabilityLedger is id -> status.
func exploitabilityLedger(t *testing.T) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, row := range markdownRows(t, "../../docs/exploitability.md") {
		if len(row) < 3 {
			continue
		}
		status := strings.TrimSpace(row[1])
		switch status {
		case "proven", "not-exploitable", "pending":
		default:
			t.Errorf("%s has status %q; the three that mean something are proven, "+
				"not-exploitable and pending", row[0], status)
			continue
		}
		if strings.TrimSpace(row[2]) == "" {
			t.Errorf("%s carries no note: the status alone does not tell the next "+
				"person what to write or why there is nothing to write", row[0])
		}
		out[row[0]] = status
	}
	return out
}

// markdownRows returns the cells of every table row whose first cell is a
// backticked id.
func markdownRows(t *testing.T, path string) [][]string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	var out [][]string
	for _, line := range strings.Split(string(b), "\n") {
		if !strings.HasPrefix(line, "| `") {
			continue
		}
		cells := strings.Split(strings.Trim(line, "|"), "|")
		for i := range cells {
			cells[i] = strings.TrimSpace(cells[i])
		}
		cells[0] = strings.Trim(cells[0], "`")
		out = append(out, cells)
	}
	return out
}
