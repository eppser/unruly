package eval_test

import (
	"encoding/json"
	"os"
	"os/exec"
	"sort"
	"strings"
	"testing"
)

// The seam an agent works through.
//
// unruly's scan path is deterministic and stays that way: no model runs inside
// it. That rule is about the ANALYSIS, not the INPUTS -- enumeration has
// always been seeded from two sources, a pinned wordlist and the application's
// own bundles, and neither is a measurement. A file between the two stages
// makes a third source possible without touching the first two: something
// outside unruly proposes names, unruly tests every one of them the same way,
// and every finding still carries a real response.
//
// This measures the case that motivates it. reporting.revenue_secrets exists
// in the fixture, is mentioned nowhere in the application, and is reachable by
// no wordlist unruly ships -- a scan finds every other relation in the schema
// and not that one. It is also the shape that matters most: the anonymous role
// holds NO privilege on it at all, so PostgREST answers 42501, and the only
// thing that proves it is there is the name.
func TestAnAgentSuppliedNameReachesARelationNothingElseFinds(t *testing.T) {
	requireLiveEvals(t)
	requireReachable(t, "http://127.0.0.1:54321")
	key := os.Getenv("UNRULY_FIXTURE_KEY")
	if key == "" {
		t.Skip("set UNRULY_FIXTURE_KEY")
	}
	const secret = "zq9f_x4tm7"

	// Control: everything unruly can reach on its own.
	control := scanResources(t, key, nil)
	if hasSubstring(control, secret) {
		t.Fatalf("the control scan already found %s, so this test cannot show that "+
			"the handoff added anything; pick a relation the wordlist misses", secret)
	}

	// The same scan, plus one name from outside.
	file := t.TempDir() + "/vocab.json"
	writeVocabFile(t, file, []string{secret})
	with := scanResources(t, key, []string{"-vocab", file})
	if !hasSubstring(with, secret) {
		t.Errorf("a name supplied through the vocabulary handoff did not reach the "+
			"scan: %s is absent from %d resources. The seam is the whole point -- "+
			"without it the schema an operator or an agent already knows about is "+
			"unreachable, and enumeration is capped by what unruly happens to ship",
			secret, len(with))
	}
}

// What the harvest found has to survive the round trip, or the file is a
// downgrade dressed as a feature: an agent that edits it would be handing back
// less than the scan started with.
func TestTheHarvestedVocabularyRoundTripsThroughAFile(t *testing.T) {
	requireLiveEvals(t)
	requireReachable(t, "http://127.0.0.1:54321")
	requireReachable(t, "http://127.0.0.1:54322")
	key := os.Getenv("UNRULY_FIXTURE_KEY")
	if key == "" {
		t.Skip("set UNRULY_FIXTURE_KEY")
	}

	// Harvest and stop. No backend credential is supplied, because reading an
	// application is not a scan of anything.
	file := t.TempDir() + "/vocab.json"
	out, err := exec.Command(buildScanner(t), "-s", "http://127.0.0.1:54322",
		"-emit-vocab", file, "-silent").CombinedOutput()
	if err != nil {
		t.Fatalf("harvesting to a file: %v\n%s", err, lastLines(out, 6))
	}
	b, err := os.ReadFile(file)
	if err != nil {
		t.Fatalf("the harvest wrote no file: %v", err)
	}
	var v struct {
		SchemaVersion int      `json:"schema_version"`
		Stage         string   `json:"stage"`
		Note          string   `json:"note"`
		Sources       []string `json:"sources"`
		Seeds         []string `json:"seeds"`
	}
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatalf("the handoff file is not JSON: %v", err)
	}
	if v.SchemaVersion == 0 || v.Stage != "vocabulary" {
		t.Errorf("the file does not identify itself (version %d, stage %q): a reader "+
			"cannot tell it from any other JSON unruly writes", v.SchemaVersion, v.Stage)
	}
	if v.Note == "" {
		t.Error("the file carries no note saying what it is for; its reader may be a model")
	}
	if len(v.Sources) == 0 {
		t.Error("no sources recorded, so nothing distinguishes a harvest that read the " +
			"whole application from one that read a 404 page")
	}
	if !containsString(v.Seeds, "leaky_credentials") {
		t.Errorf("the harvest did not carry the application's own vocabulary into the "+
			"file: %d seeds, none of them leaky_credentials", len(v.Seeds))
	}

	// A scan driven by the FILE must reach every RELATION a scan driven by the
	// SITE reaches. Anything less and the handoff loses vocabulary in transit.
	//
	// Relations only: the site run also probes application routes and reads
	// the page that ships a service_role key, and neither is vocabulary. A
	// file cannot carry them and is not claiming to.
	fromSite := scanRelations(t, key, []string{"-s", "http://127.0.0.1:54322"})
	fromFile := scanRelations(t, key, []string{"-vocab", file})
	var missing []string
	for _, r := range fromSite {
		if !containsString(fromFile, r) {
			missing = append(missing, r)
		}
	}
	if len(missing) > 0 {
		t.Errorf("scanning from the handoff file reached %d resources against the "+
			"site's %d and lost %v: the file has to carry the harvest, not summarise it",
			len(fromFile), len(fromSite), missing)
	}
}

// writeVocabFile writes the artifact an agent would hand back.
func writeVocabFile(t *testing.T, path string, seeds []string) {
	t.Helper()
	b, err := json.Marshal(map[string]any{
		"schema_version": 1,
		"stage":          "vocabulary",
		"seeds":          seeds,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatal(err)
	}
}

type reportLine struct {
	ID          string `json:"id"`
	Resource    string `json:"resource"`
	Description string `json:"description"`
}

// scanResources runs the fixture scan with extra arguments and returns every
// resource and description in the report -- descriptions included because the
// protected relations arrive as one finding listing many names.
func scanResources(t *testing.T, key string, extra []string) []string {
	t.Helper()
	var got []string
	for _, f := range scanFindings(t, key, extra) {
		got = append(got, f.Resource, f.Description)
	}
	sort.Strings(got)
	return got
}

// scanFindings runs the fixture scan and returns the report, line by line.
func scanFindings(t *testing.T, key string, extra []string) []reportLine {
	t.Helper()
	out := t.TempDir() + "/f.jsonl"
	args := append([]string{"-u", "http://127.0.0.1:54321", "-k", key,
		"-rest-prefix", "/", "-json", "-o", out, "-silent"}, extra...)
	cmd := exec.Command(buildScanner(t), args...)
	cmd.Env = append(os.Environ(), "SUPABASE_ANON_KEY=")
	if b, err := cmd.CombinedOutput(); err != nil && cmd.ProcessState.ExitCode() > 3 {
		t.Fatalf("scan failed: %v\n%s", err, lastLines(b, 8))
	}
	b, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("the scan wrote no report: %v", err)
	}
	var got []reportLine
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		if line == "" {
			continue
		}
		var f reportLine
		if err := json.Unmarshal([]byte(line), &f); err != nil {
			continue
		}
		got = append(got, f)
	}
	return got
}

// scanRelations is the subset of the report that names a relation.
func scanRelations(t *testing.T, key string, extra []string) []string {
	t.Helper()
	var out []string
	for _, f := range scanFindings(t, key, extra) {
		if strings.HasPrefix(f.ID, "supabase-anon-") {
			out = append(out, f.Resource)
		}
	}
	sort.Strings(out)
	return out
}

func hasSubstring(xs []string, want string) bool {
	for _, x := range xs {
		if strings.Contains(x, want) {
			return true
		}
	}
	return false
}

func containsString(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}
