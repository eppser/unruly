// Command benchmark scores unruly against the corpus.
//
// The corpus has had verified answer keys for a while and nothing had ever
// graded the SCANNER against them: verify.sh checks that the keys match the
// running stacks, which keeps the keys honest and says nothing about the tool.
// So "more accurate than the alternatives" was a claim with a corpus behind it
// and no measurement in between.
//
// This runs the real binary end to end -- the same argv an operator types --
// and derives what it found from the REPORT rather than from any internal
// stage. That distinction is the point: the fixture evals feed the probe stage
// a relation list and grade what it does with it, which measures probing and
// not discovery. Here the scanner has to find the relations itself, and a name
// it never recovered is a false negative exactly as an operator would
// experience it.
//
// Build-time only. Nothing here ships in the scanner.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/eppser/unruly/internal/eval"
)

func main() {
	var (
		binary = flag.String("unruly", "./unruly", "path to the scanner under test")
		corpus = flag.String("corpus", "benchmark/corpus", "corpus directory")
		out    = flag.String("out", "", "write a markdown report here")
		only   = flag.String("only", "", "score one project by directory name")
	)
	flag.Parse()

	projects, err := filepath.Glob(filepath.Join(*corpus, "*", "answer-key.yaml"))
	if err != nil || len(projects) == 0 {
		fmt.Fprintf(os.Stderr, "no answer keys under %s\n", *corpus)
		os.Exit(2)
	}
	sort.Strings(projects)

	var results []eval.Result
	var skipped []string
	for _, key := range projects {
		name := filepath.Base(filepath.Dir(key))
		if *only != "" && name != *only {
			continue
		}
		tgt, err := loadCorpusTarget(key)
		if err != nil {
			// Not every project in the corpus is a PostgREST project. The
			// Firebase one is graded by its own harness, against rules rather
			// than against relations, and refusing to score it here is
			// correct -- reporting it as a failure would be this tool saying
			// a target is broken because it is not the shape this tool reads.
			skipped = append(skipped, fmt.Sprintf("%s (%v)", name, err))
			continue
		}
		t0 := time.Now()
		stop, err := bringUp(filepath.Dir(key), tgt)
		progress(name, "bring-up", time.Since(t0), err)
		if err != nil {
			skipped = append(skipped, fmt.Sprintf("%s (%v)", name, err))
			continue
		}
		t0 = time.Now()
		obs, err := scan(*binary, tgt)
		progress(name, "scan", time.Since(t0), err)
		t0 = time.Now()
		stop()
		progress(name, "teardown", time.Since(t0), nil)
		if err != nil {
			// A project that is not up is NOT a project that scored zero.
			// Recording it as a failure would let a docker problem read as a
			// recall collapse, which is the same category error this scanner
			// refuses to make about its targets.
			skipped = append(skipped, fmt.Sprintf("%s (%v)", name, err))
			continue
		}
		graded := eval.Grade(tgt, obs)
		if want, ok := wantExit[tgt.Name]; ok {
			got := exitCodes[tgt.Name]
			score := eval.Score{Dimension: "exit-code"}
			if got == want {
				score.TruePos = []string{fmt.Sprintf("exit %d", got)}
			} else {
				score.FalseNeg = []string{fmt.Sprintf("exit %d, want %d", got, want)}
			}
			graded.Scores = append(graded.Scores, score)
		}
		if why := unstableKeys[tgt.Name]; why != "" {
			for i := range graded.Scores {
				switch graded.Scores[i].Dimension {
				case "relation-discovery", "read-exposure", "write-exposure",
					"protected-not-flagged":
					// protected-not-flagged too, and finding out why took a
					// measurement: the scan reported payment_cards and
					// user_credentials as exposed and the scorer called both
					// false alarms. They ARE exposed -- card numbers and
					// password hashes come back to an anonymous GET. The key
					// lists thirteen relations and asserts read_exposed on
					// none of them, so absence there means UNASSERTED, and
					// reading it as "asserted protected" invents a claim the
					// key declined to make.
					graded.Scores[i].Unstable = strings.TrimSpace(why)
				}
			}
		}
		if sampleKeys[tgt.Name] {
			// The key says its relation list is a sample of a larger schema,
			// so a name the scanner found and the key does not mention is a
			// correct find. Recall still means something -- everything the key
			// DOES name must be found -- and precision does not.
			for i := range graded.Scores {
				if graded.Scores[i].Dimension == "relation-discovery" ||
					graded.Scores[i].Dimension == "read-exposure" {
					graded.Scores[i].FalsePos = nil
					graded.Scores[i].Sampled = true
				}
			}
		}
		results = append(results, graded)
	}

	report := render(results, skipped, provenance())
	fmt.Print(report)
	if *out != "" {
		if err := os.WriteFile(*out, []byte(report), 0o644); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
	}
	for _, r := range results {
		if !r.Passed() {
			os.Exit(1)
		}
	}
}

// bringUp starts a project's stack and returns the function that stops it.
//
// One project at a time. They bind fixed host ports by design -- the answer
// keys record them -- so running two at once is a port collision that looks
// like a scan failure.
func bringUp(dir string, t *eval.Target) (func(), error) {
	compose := filepath.Join(dir, "docker-compose.yml")
	if _, err := os.Stat(compose); err != nil {
		return func() {}, fmt.Errorf("no compose file")
	}
	// Retried once, because tearing the previous project down is asynchronous
	// and these projects bind fixed host ports by design. Measured: 02, 04 and
	// 06 all reported "did not answer within 90s" on the first full run and
	// each answered in ONE second when started by hand -- the stacks were
	// fine, the port was still held. A benchmark that reports a docker race
	// as an unreachable target is measuring itself.
	var upErr error
	for attempt := 0; attempt < 2; attempt++ {
		out, err := exec.Command("docker", "compose", "-f", compose, "up", "-d",
			"--remove-orphans").CombinedOutput()
		if err == nil {
			upErr = nil
			break
		}
		upErr = fmt.Errorf("compose up: %s", lastLine(out))
		time.Sleep(5 * time.Second)
	}
	if upErr != nil {
		return func() {}, upErr
	}
	stop := func() {
		_ = exec.Command("docker", "compose", "-f", compose, "down", "-v",
			"--remove-orphans").Run()
		// Docker releases the port after the call returns, and the next
		// project wants the neighbouring one immediately.
		time.Sleep(2 * time.Second)
	}
	// Wait for the API rather than for the container: a Postgres that is
	// listening is not a PostgREST that has loaded its schema cache, and
	// scanning through that gap measures the wait rather than the scanner.
	// Redirects are NOT followed, and that is the whole of it. 02, 04 and 06
	// reported "did not answer within 90s" on two full runs and answered in
	// one second by hand -- the difference was that curl showed the 301 the
	// gateway returns and http.Get followed it somewhere that never resolved.
	// Any response at all means the stack is listening, which is the only
	// question being asked here.
	probe := &http.Client{
		Timeout: 5 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	budget := bringUpBudget()
	deadline := time.Now().Add(budget)
	for time.Now().Before(deadline) {
		resp, err := probe.Get(t.BaseURL + t.RestPrefix)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode < 500 || serves5xx[t.Name] {
				return stop, nil
			}
		}
		time.Sleep(time.Second)
	}
	stop()
	return func() {}, fmt.Errorf("%s did not answer within %s", t.BaseURL, budget)
}

// bringUpBudget is how long a corpus stack gets to start answering.
//
// Raisable, because the default is a guess about a machine. The comments in
// bringUp record two rounds of projects reported unreachable that answered in
// one second when started by hand, and a third happened on a laptop with eight
// unrelated containers already running. A budget that cannot be raised turns a
// busy machine into a missing row in the published scoreboard, which is worse
// than waiting.
//
// A junk value falls back rather than parsing to zero: a zero budget fails
// every project instantly and reads like a corpus-wide outage.
func bringUpBudget() time.Duration {
	const fallback = 180 * time.Second
	v := os.Getenv("UNRULY_BENCH_BRINGUP")
	if v == "" {
		return fallback
	}
	d, err := time.ParseDuration(v)
	if err != nil || d < time.Second {
		return fallback
	}
	return d
}

// loadCorpusTarget reads a corpus answer key into the shape the scorer grades.
//
// The two documents disagree about one word, and it matters. In the corpus a
// relation's `rows` is the TRUE count taken from psql inside the container --
// that is what makes the key checkable against the running stack. In
// internal/eval it is the count an ANONYMOUS caller can see, which is zero
// whenever row-level security filters everything. Both definitions are right
// for what they are for, and eval.Target.Validate rejects the corpus one
// outright: "rows set but read_exposed is false".
//
// Reconciled here rather than in either document. Loosening Validate would
// weaken the guard the fixture evals rely on, and rewriting the corpus keys
// would break verify.sh, which is the thing that keeps them honest.
func loadCorpusTarget(path string) (*eval.Target, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var k struct {
		Name                string `yaml:"name"`
		Backend             string `yaml:"backend"`
		ProjectRef          string `yaml:"project_ref"`
		BaseURL             string `yaml:"base_url"`
		Site                string `yaml:"site"`
		RestPrefix          string `yaml:"rest_prefix"`
		AnonKeyEnv          string `yaml:"anon_key_env"`
		AuthenticatedKeyEnv string `yaml:"authenticated_key_env"`
		Fixture             bool   `yaml:"fixture"`
		RelationsAreASample bool   `yaml:"relations_are_a_sample"`
		DiscoveryIsUnstable string `yaml:"discovery_is_unstable"`
		AnswersWith5xx      bool   `yaml:"answers_with_5xx"`
		Expect              struct {
			Relations []struct {
				Name             string   `yaml:"name"`
				Schema           string   `yaml:"schema"`
				Rows             int      `yaml:"rows"`
				ReadExposed      bool     `yaml:"read_exposed"`
				AuthedRead       *bool    `yaml:"authenticated_read_exposed"`
				InsertReachable  bool     `yaml:"insert_reachable"`
				SensitiveColumns []string `yaml:"sensitive_columns"`
				Classes          []string `yaml:"classes"`
			} `yaml:"relations"`
			Checks              []struct{} `yaml:"checks"`
			RelationsAreASample bool       `yaml:"relations_are_a_sample"`
			// A pointer, so a key can expect exit 0 -- a clean project -- and
			// be distinguished from a key that says nothing. The first version
			// used int and treated 0 as unset, which meant the one value a
			// hardened project would want to assert was the one it could not.
			ExitCode        *int     `yaml:"exit_code"`
			Routines        []string `yaml:"routines"`
			EscalationGains []string `yaml:"escalation_gains"`
			KeyInBundles    bool     `yaml:"key_in_bundles"`
		} `yaml:"expect"`
	}
	if err := yaml.Unmarshal(raw, &k); err != nil {
		return nil, err
	}
	t := &eval.Target{
		Name: k.Name, Backend: k.Backend, ProjectRef: k.ProjectRef, BaseURL: k.BaseURL, Site: k.Site,
		RestPrefix: k.RestPrefix, AnonKeyEnv: k.AnonKeyEnv,
		AuthenticatedKeyEnv: k.AuthenticatedKeyEnv, Fixture: k.Fixture,
	}
	// A backend this runner cannot grade must not be SCORED as though it had
	// nothing to find.
	//
	// observationsFrom switches on Supabase finding ids -- supabase-anon-read-
	// exposed and its siblings. A Firebase scan emits firebase-firestore-anon-
	// read, which nothing here reads, so ReadExposed comes back empty whatever
	// the scanner found. 14-firebase then scored 100% recall and 100%
	// precision on a denominator of ZERO across four dimensions: a Firebase
	// project on the scoreboard with full marks, having graded nothing.
	//
	// The first version of this refusal keyed on "declares expect.checks and
	// no expect.relations", which is a property 05-empty-project and
	// 06-unreachable share -- legitimately, because an empty project HAS no
	// relations and "nothing expected, nothing found" is a real result for it.
	// That rule dropped both from the scoreboard and moved three denominators.
	// Caught by reading the diff, which is the only reason it is not in the
	// committed numbers.
	//
	// The backend is what decides it, so the backend is what it asks.
	if b := t.BackendOrDefault(); b != "supabase" {
		return nil, fmt.Errorf("this runner grades %s findings and the target is %s; "+
			"scoring it would report 100%% of nothing", "supabase", b)
	}
	if k.Expect.RelationsAreASample || k.RelationsAreASample {
		sampleKeys[k.Name] = true
	}
	if k.DiscoveryIsUnstable != "" {
		unstableKeys[k.Name] = k.DiscoveryIsUnstable
	}
	if k.AnswersWith5xx {
		serves5xx[k.Name] = true
	}
	if k.Expect.ExitCode != nil {
		wantExit[k.Name] = *k.Expect.ExitCode
	}
	t.Expect.Routines = k.Expect.Routines
	// An escalation gain is a DELTA: invisible to anon, visible to the
	// authenticated identity this scan carries. Derived from the per-relation
	// facts rather than from the key's top-level list, because the two
	// disagree on 03-policy-shapes and the per-relation ones are what
	// verify.sh checks against the running stack.
	//
	// The disagreement is instructive. That key lists one gain, which is what
	// a FRESH signup gains; its per-relation fields record two, because the
	// identity the key designates already owns rows in an owner-scoped table.
	// Measured: with the designated key policy_owner_scoped returns 3 rows,
	// with an identity that owns nothing it returns 0. Both are correct
	// answers to different questions, and the scan was being asked one and
	// graded against the other.
	var derived []string
	for _, r := range k.Expect.Relations {
		if r.AuthedRead != nil && *r.AuthedRead && !r.ReadExposed {
			name := r.Name
			if r.Schema != "" && r.Schema != "public" {
				name = r.Schema + "." + r.Name
			}
			derived = append(derived, name)
		}
	}
	if len(derived) > 0 {
		t.Expect.EscalationGains = derived
	} else {
		t.Expect.EscalationGains = k.Expect.EscalationGains
	}
	t.Expect.KeyInBundles = k.Expect.KeyInBundles
	for _, r := range k.Expect.Relations {
		name := r.Name
		// The scanner qualifies a relation outside the default schema, and the
		// answer key names the schema separately. Comparing the two forms
		// without this reports every non-public relation as both missed and
		// invented at once.
		if r.Schema != "" && r.Schema != "public" {
			name = r.Schema + "." + r.Name
		}
		rows := 0
		if r.ReadExposed {
			rows = r.Rows
		}
		t.Expect.Relations = append(t.Expect.Relations, eval.Relation{
			Name: name, Rows: rows, ReadExposed: r.ReadExposed,
			InsertReachable: r.InsertReachable, SensitiveColumns: r.SensitiveColumns,
			// Carried through nil-preserving: a key that says nothing about
			// classes must not be scored on them, and an empty list must be
			// scored as "report none".
			Classes: r.Classes,
		})
	}
	return t, t.Validate()
}

// sampleKeys are the projects whose relation list is a sample of a larger
// schema. Precision cannot be scored against them: a relation the scanner
// found and the key does not mention is a correct find, not a false alarm.
var sampleKeys = map[string]bool{}

// unstableKeys are the projects where WHICH relations answer changes between
// identical runs, with the key's own reason. Recall over a fixed list there
// measures the target's rate limiter, not the scanner, so it is reported as
// unscorable rather than as a number somebody might quote.
var unstableKeys = map[string]string{}

// serves5xx are the projects whose origin answers 5xx as its normal state.
// Waiting for a healthy response there waits forever.
var serves5xx = map[string]bool{}

// wantExit is the exit code the scan must produce, where the key names one.
// The contract is 0 clean, 2 findings, 3 could-not-measure, and the third is
// the one a benchmark can otherwise never check: a target that cannot be
// examined produces no findings, which is indistinguishable in a report from
// a target that was examined and found sound.
var wantExit = map[string]int{}

// exitCodes records what each scan actually exited with.
var exitCodes = map[string]int{}

// scan runs the scanner the way an operator would and reads its report.
func scan(binary string, t *eval.Target) (eval.Observation, error) {
	key, err := t.AnonKey()
	if err != nil {
		return eval.Observation{}, err
	}
	dir, err := os.MkdirTemp("", "bench")
	if err != nil {
		return eval.Observation{}, err
	}
	defer os.RemoveAll(dir)
	report := filepath.Join(dir, "findings.jsonl")

	args := []string{"-base-url", t.BaseURL, "-k", key, "-json", "-o", report,
		"-silent", "-nc"}
	if t.RestPrefix != "" {
		args = append(args, "-rest-prefix", t.RestPrefix)
	}
	if t.Site != "" {
		args = append(args, "-s", t.Site)
	}
	// Corpus projects are ours by construction, which is what the fixture flag
	// in the key asserts. Write probing is what makes the write dimension
	// gradable at all, and it is refused on anything not marked.
	if t.Fixture {
		args = append(args, "-write", "-yes-i-own-this")
	}
	if authed := os.Getenv(t.AuthenticatedKeyEnv); authed != "" {
		args = append(args, "-user-jwt", authed)
	}
	cmd := exec.Command(binary, args...)
	cmd.Env = append(os.Environ(), "SUPABASE_ANON_KEY=", "SUPABASE_URL=")
	b, _ := cmd.CombinedOutput()
	exitCodes[t.Name] = cmd.ProcessState.ExitCode()
	if exitCodes[t.Name] > 3 {
		return eval.Observation{}, fmt.Errorf("scan failed: %s", lastLine(b))
	}
	raw, err := os.ReadFile(report)
	if err != nil {
		// A scan that could not look writes no findings, which is correct.
		// The exit code is what carries the answer in that case.
		return eval.Observation{}, nil
	}
	return observe(raw), nil
}

// observe derives what the scanner found from its own report.
func observe(raw []byte) eval.Observation {
	// Classes starts EMPTY AND NON-NIL. The scan ran, so it has made a
	// statement about what it found, and a run that reports no class at all
	// must score 0% recall rather than being skipped as "did not look". Nil
	// here would let the one dimension that grades the classifier disappear
	// exactly when the classifier produced nothing.
	o := eval.Observation{Rows: map[string]int{}, Classes: []string{}}
	seen := map[string]bool{}
	add := func(dst *[]string, name string) {
		if name != "" {
			*dst = append(*dst, name)
		}
	}
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		if line == "" {
			continue
		}
		var f struct {
			ID          string `json:"id"`
			Resource    string `json:"resource"`
			Description string `json:"description"`
			Evidence    struct {
				Rows    int      `json:"rows"`
				Classes []string `json:"classes"`
			} `json:"evidence"`
		}
		if json.Unmarshal([]byte(line), &f) != nil {
			continue
		}
		switch f.ID {
		case "supabase-anon-read-exposed":
			add(&o.ReadExposed, f.Resource)
			seen[f.Resource] = true
			if f.Evidence.Rows > 0 {
				o.Rows[f.Resource] = f.Evidence.Rows
			}
			for _, c := range f.Evidence.Classes {
				add(&o.Classes, f.Resource+":"+c)
			}
		// Firebase reaches the same dimensions under different ids. A
		// Firestore collection or an RTDB path is a relation for grading:
		// a name the scan either recovered or missed, and either read or
		// stayed silent about. Only the vocabulary differs.
		//
		// Without these, a Firebase scan graded as though it had found
		// nothing -- ReadExposed empty however much the scanner reported --
		// which is how 14-firebase scored 100% on a denominator of zero.
		case "firebase-firestore-anon-read", "firebase-rtdb-anon-read":
			add(&o.ReadExposed, f.Resource)
			seen[f.Resource] = true
			if f.Evidence.Rows > 0 {
				o.Rows[f.Resource] = f.Evidence.Rows
			}
		case "firebase-firestore-anon-write", "firebase-rtdb-anon-write":
			add(&o.InsertReachable, f.Resource)
			seen[f.Resource] = true
		case "firebase-firestore-authenticated-read":
			// The escalation dimension: readable to an account that signed
			// itself up, and not to a stranger.
			add(&o.EscalationGains, f.Resource)
			seen[f.Resource] = true
		case "supabase-anon-insert-allowed":
			add(&o.InsertReachable, f.Resource)
			seen[f.Resource] = true
		case "supabase-anon-update-allowed", "supabase-anon-delete-allowed":
			seen[f.Resource] = true
		case "supabase-authenticated-escalation":
			add(&o.EscalationGains, f.Resource)
			seen[f.Resource] = true
		case "supabase-rpc-discoverable", "supabase-rpc-returns-data",
			"supabase-anon-arbitrary-sql":
			add(&o.Routines, f.Resource)
		case "unruly-relations-protected":
			// The names are only in the prose. That is a real limitation of
			// the report as a machine artifact and it is noted here rather
			// than worked around silently: a consumer that wants the schema
			// has to parse an English sentence.
			for _, n := range protectedNames(f.Description) {
				seen[n] = true
			}
		}
	}
	for n := range seen {
		o.Relations = append(o.Relations, n)
	}
	sort.Strings(o.Relations)
	sort.Strings(o.ReadExposed)
	sort.Strings(o.InsertReachable)
	sort.Strings(o.EscalationGains)
	o.Routines = dedup(o.Routines)
	return o
}

// protectedNames pulls the relation list out of the inventory finding.
func protectedNames(desc string) []string {
	const open = "rather than dropped: "
	i := strings.Index(desc, open)
	if i < 0 {
		return nil
	}
	rest := desc[i+len(open):]
	if j := strings.Index(rest, ". "); j >= 0 {
		rest = rest[:j]
	}
	var out []string
	for _, n := range strings.Split(rest, ",") {
		if n = strings.TrimSpace(n); n != "" {
			out = append(out, n)
		}
	}
	return out
}

func dedup(xs []string) []string {
	sort.Strings(xs)
	out := xs[:0:0]
	for i, x := range xs {
		if i == 0 || xs[i-1] != x {
			out = append(out, x)
		}
	}
	return out
}

func lastLine(b []byte) string {
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	return lines[len(lines)-1]
}

// render writes the table an operator and a reviewer both read.
func render(results []eval.Result, skipped []string, prov string) string {
	var b strings.Builder
	b.WriteString("# Benchmark: unruly against the corpus\n\n")
	b.WriteString(prov)
	b.WriteString("Every number here is the END-TO-END scanner run as an operator runs\n")
	b.WriteString("it, graded against an answer key that was verified against the running\n")
	b.WriteString("stack rather than read off the DDL. Discovery is included: a relation\n")
	b.WriteString("the scan never recovered is a false negative here, which is the\n")
	b.WriteString("difference between this and the fixture evals.\n\n")
	b.WriteString("| project | dimension | recall | precision | missed | false alarms |\n")
	b.WriteString("|---|---|---|---|---|---|\n")

	totals := map[string]*eval.Score{}
	for _, r := range results {
		for _, s := range r.Scores {
			recall := fmt.Sprintf("%.0f%%", s.Recall()*100)
			precision := fmt.Sprintf("%.0f%%", s.Precision()*100)
			if s.Sampled {
				precision = "n/a (sample)"
			}
			if s.Unstable != "" {
				recall, precision = "n/a", "n/a"
			}
			fmt.Fprintf(&b, "| `%s` | %s | %s | %s | %s | %s |\n",
				r.Target, s.Dimension, recall, precision,
				list(s.FalseNeg), list(s.FalsePos))
			t := totals[s.Dimension]
			if t == nil {
				t = &eval.Score{Dimension: s.Dimension}
				totals[s.Dimension] = t
			}
			if s.Unstable != "" {
				continue // never folded into a total
			}
			t.TruePos = append(t.TruePos, s.TruePos...)
			if s.Sampled {
				t.Sampled = true
			}
			t.FalsePos = append(t.FalsePos, s.FalsePos...)
			t.FalseNeg = append(t.FalseNeg, s.FalseNeg...)
		}
	}

	b.WriteString("\n## Totals across the corpus\n\n")
	b.WriteString("| dimension | recall | precision | denominator |\n|---|---|---|---|\n")
	var names []string
	for d := range totals {
		names = append(names, d)
	}
	sort.Strings(names)
	for _, d := range names {
		t := totals[d]
		fmt.Fprintf(&b, "| %s | %.1f%% | %.1f%% | %d |\n", d,
			t.Recall()*100, t.Precision()*100, len(t.TruePos)+len(t.FalseNeg))
	}
	if len(skipped) > 0 {
		b.WriteString("\n## Not scored\n\n")
		b.WriteString("A project that did not come up is not a project that scored zero.\n\n")
		for _, s := range skipped {
			fmt.Fprintf(&b, "- %s\n", s)
		}
	}
	return b.String()
}

func list(xs []string) string {
	if len(xs) == 0 {
		return "—"
	}
	sort.Strings(xs)
	if len(xs) > 4 {
		return "`" + strings.Join(xs[:4], "`, `") + "` +" +
			fmt.Sprint(len(xs)-4) + " more"
	}
	return "`" + strings.Join(xs, "`, `") + "`"
}

// provenance says which scanner produced these numbers.
//
// benchmark/RESULTS.md is the evidence behind the README's accuracy claim and
// it carried no statement of what produced it: no commit, no Go version. The
// audit report has had that line since it existed, for the same reason a
// results table nobody can date is indistinguishable from a stale one -- this
// file was 62 scanner commits old when the gap was noticed, and nothing in it
// said so.
//
// Same shape as scripts/audit.sh's header on purpose: a reader comparing the
// two reports should not have to learn two formats.
func provenance() string {
	commit := gitLine("rev-parse", "--short", "HEAD")
	if commit == "" {
		commit = "unknown"
	}
	state := "clean"
	if gitLine("status", "--porcelain") != "" {
		state = "MODIFIED (results describe uncommitted code)"
	}
	return fmt.Sprintf("commit: `%s` (%s)\ngo: `%s`\n\n", commit, state, runtime.Version())
}

func gitLine(args ...string) string {
	out, err := exec.Command("git", args...).Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// progressTo writes one line per phase of one project.
//
// Diagnostic output only, and on stderr on purpose: the report on stdout is
// compared byte for byte between runs, and interleaving progress into it would
// make every run differ from every other. It exists because two full runs were
// lost to projects reported unreachable after five minutes that answered in ten
// seconds by hand, with no way to tell afterwards where the time had gone.
func progressTo(w io.Writer, project, phase string, took time.Duration, err error) {
	status := "ok"
	if err != nil {
		status = "FAILED: " + err.Error()
	}
	fmt.Fprintf(w, "[%-24s] %-9s %7s  %s\n", project, phase, took.Round(time.Millisecond*100), status)
}

func progress(project, phase string, took time.Duration, err error) {
	progressTo(os.Stderr, project, phase, took, err)
}
