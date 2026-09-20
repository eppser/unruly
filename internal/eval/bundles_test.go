package eval_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// -max-bundles must bound EVERY reader of the application's bundles.
//
// It bounded one of two. enumerate.Harvest was given the flag; discover.Run
// was not, and fell back to its own default of 10. Measured against a site
// serving twelve bundles:
//
//	-max-bundles 2    15 bundle fetches, 10 distinct   (b00..b09)
//	-max-bundles 12   25 bundle fetches, 12 distinct
//
// An operator who sets -max-bundles 2 is asking this tool to be gentle with
// somebody's CDN, and was getting five times what they asked for from a code
// path that never saw the number. The bound is not a performance knob; it is
// the promise on the front of the flag.
//
// Distinct bundles is the assertion, because that is what the flag says it
// counts. Two readers fetching the SAME two bundles honours it; one reader
// fetching ten does not.
func TestMaxBundlesBoundsEveryBundleReader(t *testing.T) {
	const served = 12
	var mu sync.Mutex
	seen := map[string]int{}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen[r.URL.Path]++
		mu.Unlock()
		if strings.HasSuffix(r.URL.Path, ".js") {
			// Enough shape to look like a real bundle: a token to harvest and
			// something that could be a Supabase URL, so neither reader decides
			// early that this file is uninteresting.
			fmt.Fprintf(w, "const t=%q; const q=%q;\n",
				"widget_"+strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/"), ".js"),
				"/rest/v1/widgets")
			return
		}
		var b strings.Builder
		for i := 0; i < served; i++ {
			fmt.Fprintf(&b, `<script src="/b%02d.js"></script>`, i)
		}
		fmt.Fprintf(w, "<html><head>%s</head><body>hi</body></html>", b.String())
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	bin := buildScanner(t)
	distinct := func(bound string) (int, int) {
		mu.Lock()
		seen = map[string]int{}
		mu.Unlock()
		cmd := exec.Command(bin, "-u", "http://127.0.0.1:1",
			"-k", "eyJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoiYW5vbiJ9.x",
			"-s", srv.URL, "-max-bundles", bound, "-silent", "-j",
			"-o", filepath.Join(t.TempDir(), "r.json"))
		cmd.Env = append(os.Environ(), "SUPABASE_ANON_KEY=")
		_ = cmd.Run()
		mu.Lock()
		defer mu.Unlock()
		var uniq, total int
		for p, n := range seen {
			// Only the bundles this page REFERENCES. Counting every .js path
			// would also count /main.js and friends, which route discovery
			// guesses at rather than reads from the page -- a different
			// subsystem with a different budget. The first version of this test
			// counted those and reported three bundles read against a bound of
			// two, which would have been a real-looking failure with nothing
			// behind it.
			if strings.HasPrefix(p, "/b") && strings.HasSuffix(p, ".js") {
				uniq++
				total += n
			}
		}
		return uniq, total
	}

	low, lowFetches := distinct("2")
	if low > 2 {
		t.Errorf("-max-bundles 2 read %d distinct bundles (%d fetches): some reader "+
			"is not bounded by the flag", low, lowFetches)
	}
	if low == 0 {
		t.Fatal("no bundles were read at all, so this test measured nothing")
	}
	// And it must still bind upward -- a reader that always reads two would
	// satisfy the assertion above while making the flag useless in the other
	// direction.
	high, _ := distinct("10")
	if high <= low {
		t.Errorf("-max-bundles 10 read %d distinct bundles and -max-bundles 2 read "+
			"%d: raising the bound changed nothing", high, low)
	}
}

// A -site that cannot be read must reach the REPORT, not just the terminal.
//
// Before this, one branch served three different situations and named the
// wrong cause in two of them. Pointed at a site that answered nothing, the
// scan printed:
//
//	[INF] harvesting vocabulary from http://127.0.0.1:1
//	[INF] 0 seeds harvested from 0 sources
//	[WRN] no -site supplied: enumeration falls back to the pinned wordlist
//
// telling the operator they had omitted the flag they had just used. And
// nothing at all reached the JSONL: relation recall silently dropped to
// whatever a pinned wordlist can guess, and the report that came out was
// shorter for a reason it did not record. A short report that reads like a
// clean one is the single failure this scanner exists to refuse, so this is
// not a logging nicety -- it is the same class as the false negatives the
// README criticises other tools for.
//
// Falling back is a CHOICE when no -site was given and a LOSS when one was, and
// only the loss is a finding.
func TestUnreadableApplicationIsReportedNotAssumedAbsent(t *testing.T) {
	bin := buildScanner(t)
	// -base-url with a project ref, not -u: a bare -u that is not a
	// .supabase.co host is PROMOTED to -site (main.go), so "-u without -s" is
	// not the no-site case at all -- it is the site-unreadable case wearing
	// different flags. Discovering that is why the second half of this test
	// exists; the first draft asserted the opposite and failed correctly.
	run := func(args ...string) (string, string) {
		out := filepath.Join(t.TempDir(), "r.json")
		cmd := exec.Command(bin, append([]string{
			"-p", "unrulyprobe", "-base-url", "http://127.0.0.1:1",
			"-k", "eyJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoiYW5vbiJ9.x",
			"-j", "-o", out}, args...)...)
		cmd.Env = append(os.Environ(), "SUPABASE_ANON_KEY=", "NO_COLOR=1")
		stderr, _ := cmd.CombinedOutput()
		b, err := os.ReadFile(out)
		if err != nil {
			t.Fatalf("no report written: %v", err)
		}
		return string(b), string(stderr)
	}

	// -site given, nothing answers.
	report, logs := run("-s", "http://127.0.0.1:1")
	if !strings.Contains(report, `"resource":"application"`) {
		t.Error("a -site that could not be read produced no finding: the scan lost " +
			"relation recall and the machine-readable report does not say so")
	}
	if strings.Contains(logs, "no -site supplied") {
		t.Error("the scan told the operator that no -site was supplied, in a run where " +
			"-site was supplied and the fetch failed: the diagnostic names the wrong cause")
	}

	// No -site at all: a choice the operator made, and not a finding about
	// anything. Without this half, emitting the finding unconditionally would
	// pass the assertions above while marking every siteless scan as blind.
	report, logs = run()
	if strings.Contains(report, `"resource":"application"`) {
		t.Error("a scan with no -site reported the application as unreadable; there was " +
			"no application to read, and this would put every siteless scan at exit 3")
	}
	if !strings.Contains(logs, "no -site supplied") {
		t.Error("a scan with no -site no longer says so, which is the one case where " +
			"that sentence is true")
	}
}
