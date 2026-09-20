package eval_test

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Flags that promise something, checked against what they do.
//
// Both of these were unexercised: neither appeared in any eval, so nothing
// would have noticed either becoming a no-op. They are grouped because they
// fail the same way — quietly, in the direction that looks like good news.

// -severity must never hide a finding at or above the threshold.
//
// The failure that matters is one-directional. Showing too much is noise;
// showing too little is a reader filtering to `high`, seeing an empty report,
// and concluding the project is clean. That is the false-clean this whole tool
// is built to refuse, delivered by its own output filter.
func TestSeverityFilterNeverHidesSomethingAboveIt(t *testing.T) {
	requireLiveEvals(t)
	requireReachable(t, "http://127.0.0.1:54321")
	key := os.Getenv("UNRULY_FIXTURE_KEY")
	if key == "" {
		t.Skip("set UNRULY_FIXTURE_KEY")
	}

	rank := map[string]int{"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
	counts := map[string]map[string]int{}
	for _, level := range []string{"info", "low", "medium", "high", "critical"} {
		out := filepath.Join(t.TempDir(), "scan.json")
		cmd := exec.Command(buildScanner(t), "-u", "http://127.0.0.1:54321", "-k", key,
			"-rest-prefix", "/", "-severity", level, "-j", "-o", out, "-silent")
		cmd.Env = append(os.Environ(), "SUPABASE_ANON_KEY=")
		_ = cmd.Run()

		b, err := os.ReadFile(out)
		if err != nil {
			t.Fatalf("-severity %s produced no report: %v", level, err)
		}
		got := map[string]int{}
		for _, line := range strings.Split(string(b), "\n") {
			if strings.TrimSpace(line) == "" {
				continue
			}
			var f struct{ Severity string }
			if json.Unmarshal([]byte(line), &f) != nil {
				t.Fatalf("report line is not JSON: %q", line)
			}
			got[f.Severity]++
			// The filter's one hard promise.
			if rank[f.Severity] < rank[level] {
				t.Errorf("-severity %s emitted a %s finding", level, f.Severity)
			}
		}
		counts[level] = got
	}

	// Monotonic: nothing at or above a level may be dropped by raising the
	// floor below it. An off-by-one here is invisible in any single run.
	for _, pair := range [][2]string{{"info", "low"}, {"low", "medium"},
		{"medium", "high"}, {"high", "critical"}} {
		lower, higher := counts[pair[0]], counts[pair[1]]
		for sev, n := range higher {
			if lower[sev] < n {
				t.Errorf("-severity %s reported %d %s findings but -severity %s reported "+
					"only %d: raising the floor must never reveal more",
					pair[1], n, sev, pair[0], lower[sev])
			}
		}
	}
	if counts["critical"]["critical"] == 0 {
		t.Fatal("the fixture has critical findings and none survived the filter, so " +
			"this test is measuring nothing")
	}
}

// -rate-limit must actually slow the scan down.
//
// It is the politeness control: the answer to "this tool is about to send
// thousands of requests at somebody's project". A flag that documents a limit
// and does not impose one is worse than no flag, because the operator believes
// they have throttled and has not.
func TestRateLimitIsActuallyImposed(t *testing.T) {
	requireLiveEvals(t)
	requireReachable(t, "http://127.0.0.1:54321")
	key := os.Getenv("UNRULY_FIXTURE_KEY")
	if key == "" {
		t.Skip("set UNRULY_FIXTURE_KEY")
	}

	const limit = 200
	out := filepath.Join(t.TempDir(), "scan.json")
	cmd := exec.Command(buildScanner(t), "-u", "http://127.0.0.1:54321", "-k", key,
		"-rest-prefix", "/", "-rate-limit", "200", "-j", "-o", out, "-silent")
	cmd.Env = append(os.Environ(), "SUPABASE_ANON_KEY=")
	start := time.Now()
	_ = cmd.Run()
	elapsed := time.Since(start)

	b, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("scan produced no report: %v", err)
	}
	var requests int
	for _, line := range strings.Split(string(b), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var f struct {
			ID       string
			Evidence struct {
				Sample []map[string]any
			}
		}
		if json.Unmarshal([]byte(line), &f) != nil {
			continue
		}
		if f.ID == "unruly-scan-summary" && len(f.Evidence.Sample) > 0 {
			if n, ok := f.Evidence.Sample[0]["requests"].(float64); ok {
				requests = int(n)
			}
		}
	}
	if requests < 500 {
		t.Fatalf("only %d requests were sent, which is too few for a rate to be "+
			"measured; this test would pass whatever the limiter did", requests)
	}

	// Generous, because this is a timing assertion and the point is the order
	// of magnitude: unlimited, the same scan finishes in well under a second.
	rate := float64(requests) / elapsed.Seconds()
	if rate > limit*1.5 {
		t.Errorf("%d requests in %s is %.0f/s against a limit of %d: the flag "+
			"documents a throttle it does not impose", requests, elapsed, rate, limit)
	}
	t.Logf("%d requests in %s = %.0f/s (limit %d)", requests, elapsed, rate, limit)
}

// A budget that binds must say what it cost, in relations rather than probes.
//
// The column budget is spent per RELATION, all or nothing: a relation is either
// classified or skipped entirely. So a budget too small to cover even one
// relation reports "0 of 1 column probes used" -- literally true, and it reads
// as though nothing was truncated. A coverage notice may read pessimistically
// or accurately, never optimistically, because the reader is deciding whether
// the severities below it are trustworthy.
//
// The column budget applies only under -measure. A normal scan retrieves rows
// and reads the columns off them, so there is nothing to budget; that is why an
// earlier version of this test found no notice and was measuring the wrong mode.
func TestColumnBudgetSaysWhatItCostInRelations(t *testing.T) {
	requireLiveEvals(t)
	requireReachable(t, "http://127.0.0.1:54321")
	key := os.Getenv("UNRULY_FIXTURE_KEY")
	if key == "" {
		t.Skip("set UNRULY_FIXTURE_KEY")
	}

	run := func(limit string) (reason string, present bool) {
		out := filepath.Join(t.TempDir(), "scan.json")
		cmd := exec.Command(buildScanner(t), "-u", "http://127.0.0.1:54321", "-k", key,
			"-rest-prefix", "/", "-measure", "-max-column-probes", limit,
			"-j", "-o", out, "-silent")
		cmd.Env = append(os.Environ(), "SUPABASE_ANON_KEY=")
		_ = cmd.Run()
		b, err := os.ReadFile(out)
		if err != nil {
			t.Fatalf("scan produced no report: %v", err)
		}
		for _, line := range strings.Split(string(b), "\n") {
			if strings.TrimSpace(line) == "" {
				continue
			}
			var f struct {
				Resource string
				Evidence struct{ Reason string }
			}
			if json.Unmarshal([]byte(line), &f) != nil {
				continue
			}
			if f.Resource == "sensitive-columns" {
				return f.Evidence.Reason, true
			}
		}
		return "", false
	}

	reason, ok := run("1")
	if !ok {
		t.Fatal("a budget of one probe cannot classify a single relation on this " +
			"fixture, and nothing said so: the severities below are a lower bound " +
			"and the report does not admit it")
	}
	// The number that matters is relations, not probes.
	if !strings.Contains(reason, "relation(s) left unclassified") {
		t.Errorf("the notice says %q, which reports probes spent rather than what "+
			"was not classified", reason)
	}
	if strings.HasPrefix(strings.TrimSpace(reason), "0 ") {
		t.Errorf("the notice opens with a zero (%q), which reads as 'nothing was "+
			"truncated' on a scan where everything was", reason)
	}

	// And a budget nothing exhausts must stay silent: a coverage notice on a
	// complete scan is noise, and noise is what stops the real ones being read.
	if r, ok := run("100000"); ok {
		t.Errorf("a budget that was never exhausted still reported %q", r)
	}
}

// The request count the README quotes for the fixture must be the truth.
//
// The front page said "roughly 3,800 requests" and called that "the number that
// is actually stable", while the scan had grown to 12,068 against the same
// target -- three times the traffic, in a tool whose own ethic is that an
// operator should know what it is about to send at somebody else's project.
//
// The live figure cannot be checked from a clone, so the README also quotes the
// FIXTURE figure, and this is what keeps that one honest. Tolerance is wide: the
// point is to catch a number that has drifted by a multiple, not to fail on the
// handful of requests a seed change moves.
func TestReadmeFixtureRequestCountIsCurrent(t *testing.T) {
	requireLiveEvals(t)
	requireReachable(t, "http://127.0.0.1:54321")
	key := os.Getenv("UNRULY_FIXTURE_KEY")
	if key == "" {
		t.Skip("set UNRULY_FIXTURE_KEY")
	}

	readme, err := os.ReadFile(filepath.Join("..", "..", "README.md"))
	if err != nil {
		t.Fatalf("README.md: %v", err)
	}
	claimed := regexp.MustCompile(`\*\*([0-9],[0-9]{3}|[0-9]{4})\s*\n?requests\*\* for the same`).
		FindSubmatch(readme)
	if claimed == nil {
		t.Skip("the README no longer quotes a fixture request count")
	}
	want, err := strconv.Atoi(strings.ReplaceAll(string(claimed[1]), ",", ""))
	if err != nil {
		t.Fatalf("unreadable count %q", claimed[1])
	}

	out := filepath.Join(t.TempDir(), "scan.json")
	cmd := exec.Command(buildScanner(t), "-u", "http://127.0.0.1:54321", "-k", key,
		"-rest-prefix", "/", "-measure", "-j", "-o", out, "-silent")
	cmd.Env = append(os.Environ(), "SUPABASE_ANON_KEY=")
	_ = cmd.Run()

	b, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("scan produced no report: %v", err)
	}
	var got int
	for _, line := range strings.Split(string(b), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var f struct {
			ID       string
			Evidence struct{ Sample []map[string]any }
		}
		if json.Unmarshal([]byte(line), &f) != nil || f.ID != "unruly-scan-summary" {
			continue
		}
		if len(f.Evidence.Sample) > 0 {
			if n, ok := f.Evidence.Sample[0]["requests"].(float64); ok {
				got = int(n)
			}
		}
	}
	if got == 0 {
		t.Fatal("the scan reported no request count, so this test measured nothing")
	}
	// Half to double: a multiple, not a rounding error.
	if got*2 < want || got > want*2 {
		t.Errorf("the README says the fixture scan is %d requests and it is %d. The "+
			"last time this drifted it reached three times the quoted figure while the "+
			"text still called the number stable.", want, got)
	}
	t.Logf("README says %d, measured %d", want, got)
}

// The RPC budget binds, and the help says what it counts.
//
// It counts NAMES, not requests, and each name costs up to two requests: at
// -max-rpc-probes 100, one schema sent 199. An operator setting a bound to
// limit what lands on somebody else's project is entitled to know the unit,
// which the help now states -- this tool spent a whole iteration fixing a
// README that understated its own traffic threefold, and a flag that
// understates it by two is the same error in a smaller place.
//
// Both halves are checked, because either alone is satisfiable by a no-op: the
// budget must actually reduce traffic when lowered, AND the traffic must stay
// within the multiple the help promises.
func TestRPCBudgetBindsAndTheHelpStatesItsUnit(t *testing.T) {
	requireLiveEvals(t)
	requireReachable(t, "http://127.0.0.1:54321")
	key := os.Getenv("UNRULY_FIXTURE_KEY")
	if key == "" {
		t.Skip("set UNRULY_FIXTURE_KEY")
	}

	routineRequests := func(budget string) int {
		out := filepath.Join(t.TempDir(), "scan.json")
		cmd := exec.Command(buildScanner(t), "-u", "http://127.0.0.1:54321", "-k", key,
			"-rest-prefix", "/", "-measure", "-max-rpc-probes", budget,
			"-j", "-o", out, "-silent")
		cmd.Env = append(os.Environ(), "SUPABASE_ANON_KEY=")
		_ = cmd.Run()
		b, err := os.ReadFile(out)
		if err != nil {
			t.Fatalf("scan produced no report: %v", err)
		}
		var total int
		for _, line := range strings.Split(string(b), "\n") {
			if strings.TrimSpace(line) == "" {
				continue
			}
			var f struct {
				ID       string
				Evidence struct{ Sample []map[string]any }
			}
			if json.Unmarshal([]byte(line), &f) != nil || f.ID != "unruly-scan-summary" {
				continue
			}
			if len(f.Evidence.Sample) > 0 {
				if n, ok := f.Evidence.Sample[0]["requests"].(float64); ok {
					total = int(n)
				}
			}
		}
		return total
	}

	small, large := routineRequests("100"), routineRequests("1200")
	if small == 0 || large == 0 {
		t.Fatal("no request count was reported, so this test measured nothing")
	}
	// Lowering the budget must remove real traffic. Without this, a budget that
	// is read and ignored passes every other assertion here.
	if small >= large {
		t.Errorf("-max-rpc-probes 100 sent %d requests and 1200 sent %d: the budget "+
			"does not bind", small, large)
	}
	// And the difference must be roughly the budget's own scale, not a rounding
	// error dressed up as a bound.
	if large-small < 1000 {
		t.Errorf("dropping the budget from 1200 to 100 removed only %d requests; the "+
			"flag is not bounding the stage it names", large-small)
	}

	// The help must name the unit. A bound whose unit is unstated is one an
	// operator will read as requests, because that is what they are trying to
	// limit.
	help, err := exec.Command(buildScanner(t), "-h").CombinedOutput()
	if err != nil && len(help) == 0 {
		t.Fatalf("reading -h: %v", err)
	}
	for _, must := range []string{"NAMES", "two requests"} {
		if !strings.Contains(string(help), must) {
			t.Errorf("the -max-rpc-probes help does not say %q, so its unit is left "+
				"to be guessed", must)
		}
	}
}

// -stats has to be able to change the output, and the only mode where it
// can is -silent.
//
// Measured before this was fixed, against a host answering nothing:
//
//	(no flags)       stats printed
//	-stats           stats printed -- identical
//	-silent          nothing
//	-silent -stats   NOTHING
//
// There was no combination in which the flag mattered. -silent sets
// gologger to LevelSilent, and the stats block logged at Info, so the
// flag's own output went into a void; without -silent the block printed
// regardless. A documented flag that cannot change what the tool does is
// a promise the tool does not keep, and it is the third one this project
// has found by exercising a flag rather than reading it.
//
// Both directions are asserted. Printing always would satisfy half of
// this test while destroying what -silent is for.
func TestStatsFlagIsTheOnlyWayToGetStatsUnderSilent(t *testing.T) {
	bin := buildScanner(t)
	key := "eyJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoiYW5vbiJ9.x"
	// A refused port: no fixture, no traffic to anyone, and the scan still
	// reaches its summary.
	run := func(args ...string) string {
		cmd := exec.Command(bin, append([]string{
			"-u", "http://127.0.0.1:1", "-k", key}, args...)...)
		cmd.Env = append(os.Environ(), "SUPABASE_ANON_KEY=", "NO_COLOR=1")
		var errb bytes.Buffer
		cmd.Stderr = &errb
		_ = cmd.Run()
		return errb.String()
	}
	const marker = "requests,"

	if got := run("-silent", "-stats"); !strings.Contains(got, marker) {
		t.Errorf("-silent -stats printed no statistics, so -stats cannot change "+
			"the output in any mode; stderr was:\n%s", got)
	}
	if got := run("-silent"); strings.Contains(got, marker) {
		t.Errorf("-silent alone printed statistics, so -stats is not what "+
			"produces them:\n%s", got)
	}
}
