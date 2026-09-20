package eval_test

// Determinism is the first requirement in this project's brief, and until now
// it was an argument rather than a measurement: no LLM in the scan path, sorted
// output, canonical IDs, pinned wordlists. Every one of those is true and none
// of them prove the whole is reproducible. Go randomises map iteration on every
// run precisely so that code which accidentally depends on it fails visibly,
// and this scanner builds sets in maps everywhere — vocabulary, read exposure,
// delivered relations, sensitive columns.
//
// TestLiveDeterminism already covers one stage: enumeration, from a fixed seed
// list, returning the same relations in the same order. That is the narrowest
// possible slice of the claim. It says nothing about the eleven stages that
// run after it, nor about the report assembly where ordering decisions
// actually get made.
//
// So the property is measured here the way a user would check it: run the
// binary twice with identical inputs and diff the bytes. Anything short of
// byte equality means two people scanning the same project can get reports
// that disagree, which makes every other guarantee here unfalsifiable.
//
//   make fixtures-reset && UNRULY_LIVE=1 go test ./internal/eval -run Determinism -v

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"testing"
)

// buildScanner compiles the CLI once per test binary. Testing the packages
// would miss exactly the layer this test exists for: ordering decisions made
// while assembling the report.
func buildScanner(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "unruly")
	cmd := exec.Command("go", "build", "-o", bin, "../../cmd/unruly")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build scanner: %v\n%s", err, out)
	}
	return bin
}

// This test was itself mutation-tested, and the first attempt was wrong in an
// instructive way. Swapping the first and last finding inside finding.Sort did
// NOT fail it, because that mutation is perfectly deterministic: every run
// produces the same wrong order, and the bytes still match. Byte-equality
// proves reproducibility, not correct ordering, and the two are independent
// properties. Ordering is covered by the unit tests in internal/finding.
//
// Replacing the sort with a map round-trip does fail it, on every run, with a
// diff pointing at the first differing line. That is the property this test
// actually holds.
//
// TestDeterminismRepeatedScansAreByteIdentical runs the same read-only scan
// several times and requires the JSON reports to be identical.
//
// Read-only on purpose: a write probe inserts and removes a row, so the row
// counts it reports legitimately differ between runs. That is the scan changing
// the target, not the scanner being unstable, and conflating the two would make
// this test either flaky or worthless.
func TestDeterminismRepeatedScansAreByteIdentical(t *testing.T) {
	if os.Getenv("UNRULY_LIVE") != "1" {
		t.Skip("set UNRULY_LIVE=1 to run live evals")
	}
	key := os.Getenv("UNRULY_FIXTURE_KEY")
	if key == "" {
		t.Skip("UNRULY_FIXTURE_KEY required")
	}
	bin := buildScanner(t)
	dir := t.TempDir()

	const labBaseURL = "http://127.0.0.1:54321"
	const runs = 3
	reports := make([][]byte, runs)
	for i := range reports {
		out := filepath.Join(dir, "run.json")
		cmd := exec.Command(bin,
			"-u", labBaseURL, "-k", key, "-rest-prefix", "/",
			"-j", "-o", out, "-silent", "-no-realtime")
		if err := cmd.Run(); err != nil {
			// A non-zero exit is normal: findings were reported.
			if _, statErr := os.Stat(out); statErr != nil {
				t.Fatalf("run %d produced no report: %v", i, err)
			}
		}
		b, err := os.ReadFile(out)
		if err != nil {
			t.Fatalf("run %d: %v", i, err)
		}
		if len(b) == 0 {
			t.Fatalf("run %d produced an empty report; an empty file compares "+
				"equal to another empty file and would pass this test vacuously", i)
		}
		reports[i] = b
		_ = os.Remove(out)
	}

	for i := 1; i < runs; i++ {
		if !bytes.Equal(reports[0], reports[i]) {
			t.Errorf("run 0 and run %d differ (%d vs %d bytes)\n%s",
				i, len(reports[0]), len(reports[i]), firstDiff(reports[0], reports[i]))
		}
	}
}

// firstDiff reports the first differing line, which is far more useful than a
// byte offset when the cause is usually an ordering slip.
func firstDiff(a, b []byte) string {
	al, bl := bytes.Split(a, []byte("\n")), bytes.Split(b, []byte("\n"))
	for i := 0; i < len(al) && i < len(bl); i++ {
		if !bytes.Equal(al[i], bl[i]) {
			return "first difference at line " + strconv.Itoa(i+1) + ":\n  A: " +
				truncate(string(al[i])) + "\n  B: " + truncate(string(bl[i]))
		}
	}
	return "reports share a common prefix but differ in length (" +
		strconv.Itoa(len(al)) + " vs " + strconv.Itoa(len(bl)) + " lines)"
}

func truncate(s string) string {
	if len(s) > 300 {
		return s[:300] + "..."
	}
	return s
}

// Determinism where the target answers NOTHING.
//
// The test above grades a healthy fixture, where every stage runs to completion
// and the request total is a fixed number. It has nothing to say about the
// second most common target in the world: one that refuses. A typo in the URL,
// a firewalled host, a project that was deleted -- all of them land here, and
// none of them were ever graded.
//
// They are not the same problem. Against a refused target the circuit breaker
// stops the scan partway, and WHERE it stops depends on how many requests were
// already in flight when the refusal budget ran out. Measured across five
// identical scans: 50, 61, 62, 63, 69 requests. So byte equality is the wrong
// assertion here -- it would be flaky, and "fixing" the flake would mean
// rounding off a number that is a true statement about what this tool sent to
// somebody else's host.
//
// The property that must hold is the one a reader depends on: the CONCLUSIONS
// are stable. Same findings, same ids, same severities, same order. The scan
// cost varies because the scan really did vary; what the scan CONCLUDED must
// not.
//
// No fixture, no docker, no credentials: port 1 on loopback refuses, and that
// is the whole setup.
func TestDeterminismHoldsWhenTheTargetRefuses(t *testing.T) {
	bin := buildScanner(t)
	dir := t.TempDir()

	const runs = 3
	reports := make([][]byte, runs)
	for i := range reports {
		out := filepath.Join(dir, "run"+strconv.Itoa(i)+".json")
		// -provider supabase, because this test is about the SUPABASE
		// pipeline's behaviour when a target refuses everything.
		//
		// A key alone no longer selects that pipeline: an anon key says what
		// the operator holds, not what the target runs, and treating it as
		// evidence sent 2,725 probe requests at a plain website. This fixture
		// is an unreachable port with nothing to identify it, so the scanner
		// is right to decline -- and the test has to say which pipeline it
		// means rather than rely on the gate being absent.
		cmd := exec.Command(bin, "-u", "http://127.0.0.1:1",
			"-k", "eyJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoiYW5vbiJ9.x",
			"-provider", "supabase",
			"-j", "-o", out, "-silent")
		cmd.Env = append(os.Environ(), "SUPABASE_ANON_KEY=")
		_ = cmd.Run()
		b, err := os.ReadFile(out)
		if err != nil {
			t.Fatalf("run %d produced no report: %v", i, err)
		}
		if len(bytes.TrimSpace(b)) == 0 {
			t.Fatal("a refused target produced an EMPTY report; silence is the one " +
				"answer this tool must never give, because it is indistinguishable " +
				"from a clean project")
		}
		// Normalise the one field that is legitimately timing-dependent, and
		// only that field -- a broad normalisation here would hide exactly the
		// instability this test exists to catch.
		reports[i] = normaliseRequestCount(b)
	}

	for i := 1; i < runs; i++ {
		if !bytes.Equal(reports[0], reports[i]) {
			t.Errorf("scan %d of a refused target concluded something different from "+
				"scan 0, so two people scanning the same dead host would file "+
				"different reports\n%s", i, firstDiff(reports[0], reports[i]))
		}
	}

	// And the report must SAY it was abandoned. Without this, a consumer reads
	// a short finding list from a scan that stopped early as a short finding
	// list from a project with little wrong with it -- the false-negative shape
	// this whole tool exists to refuse.
	if !bytes.Contains(reports[0], []byte("unruly-target-refused")) {
		t.Error("a scan the breaker abandoned did not emit unruly-target-refused, " +
			"so nothing in the machine-readable report distinguishes it from a " +
			"scan that ran to completion")
	}
}

// The request total, and nothing else.
//
// Two forms, because the number reaches the report twice: as a JSON field, and
// spelled out inside the findings that quote it ("using 61 requests", "every
// one of the first 88 requests was refused"). The first draft of this test
// normalised only the field and failed on the prose -- which is the test doing
// its job, and worth recording: a scan fact that appears in six places is a
// scan fact that has to be recognised in all six before anything can be said
// about stability.
//
// Both patterns are anchored on the word "requests" so neither can quietly
// normalise a row count, a relation count, or anything else a finding claims
// about the TARGET. Those must never be masked here.
var (
	requestField = regexp.MustCompile(`"requests":[0-9]+`)
	requestProse = regexp.MustCompile(`[0-9]+ requests`)
)

// normaliseRequestCount masks the scan-cost number wherever it appears, and
// masks nothing else. A first attempt used one pattern for both forms and
// matched any digits followed by a space -- which would have masked row counts
// and relation counts too, quietly turning this test into one that passes
// while the scanner reports a different number of exposed rows each run.
func normaliseRequestCount(b []byte) []byte {
	b = requestField.ReplaceAll(b, []byte(`"requests":N`))
	return requestProse.ReplaceAll(b, []byte("N requests"))
}
