package finding

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestAgentOutputIsVersionedCompactAndSampleFree(t *testing.T) {
	f := fullFinding()
	f.Description = strings.Repeat("human explanation ", 80)
	f.Remediation = strings.Repeat("ALTER POLICY ... ", 80)
	f.Evidence.Sample = []map[string]any{{"email": "person@example.invalid"}}
	f.Evidence.Response = `{"token":"response-secret-must-not-enter-agent-output"}`

	var agent, full bytes.Buffer
	if err := (Writer{Out: &agent, Agent: true}).Write(f); err != nil {
		t.Fatal(err)
	}
	if err := (Writer{Out: &full, JSON: true}).Write(f); err != nil {
		t.Fatal(err)
	}
	var got AgentRecord
	if err := json.Unmarshal(agent.Bytes(), &got); err != nil {
		t.Fatalf("agent output is not JSON: %v", err)
	}
	if got.Schema != AgentSchema || got.Fingerprint != f.Fingerprint() {
		t.Fatalf("unstable agent identity: %+v", got)
	}
	if bytes.Contains(agent.Bytes(), []byte("person@example.invalid")) ||
		bytes.Contains(agent.Bytes(), []byte("response-secret-must-not-enter-agent-output")) ||
		bytes.Contains(agent.Bytes(), []byte("human explanation")) ||
		bytes.Contains(agent.Bytes(), []byte("ALTER POLICY")) {
		t.Fatalf("compact output carried samples or human prose: %s", agent.Bytes())
	}
	if agent.Len()*3 >= full.Len() {
		t.Errorf("agent output is not materially compact: agent=%d full=%d", agent.Len(), full.Len())
	}
	if got.Replay == nil || got.Replay.Performed {
		t.Fatal("a suggested replay was presented as a request the scanner performed")
	}
}

func TestAgentOutputDistinguishesCoverageFromFindings(t *testing.T) {
	coverage := (Finding{ID: "unruly-surface-not-assessed"}).agentRecord()
	result := (Finding{ID: "supabase-anon-read-exposed"}).agentRecord()
	if coverage.Type != "coverage" || result.Type != "finding" {
		t.Fatalf("coverage=%q finding=%q", coverage.Type, result.Type)
	}
}

func TestAgentReplayNeverCarriesCredentialsOrRequestBodies(t *testing.T) {
	secret := "eyJ-real-user-token"
	f := Finding{ID: "supabase-anon-read-exposed", Protocol: "postgrest",
		Evidence: Evidence{Request: "curl 'https://x.test/items?key=AIza-real&token=query-secret' " +
			"-H 'Authorization: Bearer " + secret + "' -H \"apikey: raw-project-key\" " +
			"--data-raw '{\"email\":\"private@example.test\"}'"}}
	r := f.agentRecord()
	if r.Replay == nil {
		t.Fatal("replay disappeared")
	}
	for _, leaked := range []string{secret, "AIza-real", "query-secret", "raw-project-key",
		"private@example.test"} {
		if strings.Contains(r.Replay.Command, leaked) {
			t.Fatalf("agent replay leaked %q: %s", leaked, r.Replay.Command)
		}
	}
	if !strings.Contains(r.Replay.Command, "<redacted>") {
		t.Fatalf("agent replay did not mark redactions: %s", r.Replay.Command)
	}
}
