package finding

import (
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"testing"
	"time"
)

// The JSON field names are a contract with every consumer, and nothing else in
// this repository defends them.
//
// The determinism eval compares two runs of the SAME binary, so renaming a
// struct tag stays perfectly deterministic and passes. The evals compare
// findings through Go structs, so a rename is invisible there too. A consumer
// filtering on .severity or reading .evidence.sample would break silently on
// the next release, and the release would be green.
//
// So the names are pinned here. Changing one is a breaking change for
// everything downstream; this test makes that a decision someone has to take
// deliberately in a diff, rather than a side effect of a refactor.

func fieldNames(t *testing.T, v any) []string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// fullFinding populates every ordinary field so omitempty hides nothing.
// Timestamp is the deliberate exception: default reports omit it to remain
// deterministic, and TestTimestampIsNotEmitted pins its opt-in wire name.
func fullFinding() Finding {
	return Finding{
		ID: "x", Name: "n", Severity: High, Protocol: "postgrest",
		Matched: "https://x", Resource: "r", Description: "d", Remediation: "fix",
		FixKind: FixSQL, Reference: []string{"https://ref"},
		Evidence: Evidence{
			Request: "curl", Suggested: true, Status: 200, Response: "[]", Rows: 1,
			Columns: []string{"c"}, Sample: []map[string]any{{"a": 1}}, Reason: "why",
			Classes: []string{"contact"},
		},
	}
}

func TestFindingJSONFieldNamesAreStable(t *testing.T) {
	want := []string{
		"description", "evidence", "fix_kind", "id", "matched", "name",
		"protocol", "reference", "remediation", "resource", "severity",
	}
	got := fieldNames(t, fullFinding())
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("the finding JSON schema changed, which breaks every consumer "+
			"parsing it\n  want: %v\n  got:  %v", want, got)
	}
}

func TestEvidenceJSONFieldNamesAreStable(t *testing.T) {
	want := []string{
		"classes", "columns", "reason", "request", "response", "rows", "sample", "status", "suggested",
	}
	got := fieldNames(t, fullFinding().Evidence)
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("the evidence JSON schema changed\n  want: %v\n  got:  %v", want, got)
	}
}

// Severity is the field consumers filter on to decide whether to fail a build.
// The wire values must not drift with the Go constant names.
func TestSeverityWireValuesAreStable(t *testing.T) {
	want := map[Severity]string{
		Critical: `"critical"`, High: `"high"`, Medium: `"medium"`,
		Low: `"low"`, Info: `"info"`,
	}
	for sev, expect := range want {
		b, err := json.Marshal(sev)
		if err != nil {
			t.Fatalf("marshal %v: %v", sev, err)
		}
		if string(b) != expect {
			t.Errorf("severity wire value changed: got %s, want %s", b, expect)
		}
	}
}

// Timestamp exists on the struct and is never set. If it ever is, every scan
// produces a different report and the determinism guarantee is gone -- so the
// determinism eval would catch it, but only for someone running fixtures. This
// catches it in the offline suite.
func TestTimestampIsNotEmitted(t *testing.T) {
	for _, name := range fieldNames(t, fullFinding()) {
		if name == "timestamp" {
			t.Fatal("timestamp is serialised; a per-run value makes two scans of an " +
				"unchanged target differ, which is the determinism guarantee gone")
		}
	}
	now := time.Now()
	f := fullFinding()
	f.Timestamp = &now
	var found bool
	for _, name := range fieldNames(t, f) {
		if name == "timestamp" {
			found = true
		}
	}
	if !found {
		t.Error("the field cannot be set at all, so it is dead weight in the struct " +
			"and should be removed rather than left as a trap")
	}
}

// -o used to REPLACE stdout. A run that wrote a file showed log lines and no
// findings, and capturing both renderings of ONE scan was impossible: two
// scans disagreed because a write probe adds a row between them.
func TestWritersFanOutToEveryDestination(t *testing.T) {
	var human, machine strings.Builder
	ws := Writers{
		{Out: &machine, JSON: true, NoColor: true},
		{Out: &human, NoColor: true},
	}
	if err := ws.Write(fullFinding()); err != nil {
		t.Fatalf("write: %v", err)
	}
	if machine.Len() == 0 || human.Len() == 0 {
		t.Fatalf("both destinations must receive the finding (machine=%d human=%d)",
			machine.Len(), human.Len())
	}
	if !strings.HasPrefix(strings.TrimSpace(machine.String()), "{") {
		t.Errorf("the JSON destination must get JSON, got %q", machine.String())
	}
	if strings.HasPrefix(strings.TrimSpace(human.String()), "{") {
		t.Errorf("the human destination must not get JSON, got %q", human.String())
	}
}

// A failure on one destination must not silently cost the other: a full disk
// should not make a scan stop printing.
func TestWritersKeepGoingAfterOneFails(t *testing.T) {
	var good strings.Builder
	ws := Writers{
		{Out: failingWriter{}, NoColor: true},
		{Out: &good, NoColor: true},
	}
	err := ws.Write(fullFinding())
	if err == nil {
		t.Error("the failure must be reported")
	}
	if good.Len() == 0 {
		t.Error("the working destination must still receive the finding")
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errWriteFailed }

var errWriteFailed = errors.New("disk full")
