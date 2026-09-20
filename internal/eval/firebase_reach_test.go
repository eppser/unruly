package eval_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// A capability the binary cannot reach is a capability nobody has.
//
// The Firebase checks were unit-tested and lab-graded for two iterations while
// no scan could run them: nothing connected discovery to the provider. That is
// the exact distinction this project draws elsewhere -- an emit site a test
// executes, on a path a scan cannot -- so it gets an end-to-end test that
// drives the compiled binary.
//
// Entirely offline: the Realtime Database origin comes from the application's
// own config, so a stub can stand in for it.
func TestFirebaseIsReachableFromTheCommandLine(t *testing.T) {
	rtdb := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasPrefix(r.URL.Path, "/public"):
			_, _ = w.Write([]byte(`{"alpha":true,"beta":true}`))
		default:
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"Permission denied"}`))
		}
	}))
	defer rtdb.Close()

	site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "app.js") {
			w.Header().Set("Content-Type", "application/javascript")
			// Shape only; the key belongs to nothing.
			fmt.Fprintf(w, `const firebaseConfig={apiKey:"AIzaSyD%s",`+
				`projectId:"stub-project",databaseURL:"%s"};`,
				"0123456789abcdefghijklmnopqrstu", rtdb.URL)
			return
		}
		fmt.Fprint(w, `<html><body><script src="/app.js"></script></body></html>`)
	}))
	defer site.Close()

	out := filepath.Join(t.TempDir(), "report.jsonl")
	cmd := exec.Command(buildScanner(t), "-u", site.URL, "-j", "-o", out, "-nc", "-timeout", "20")
	cmd.Env = append(os.Environ(), "SUPABASE_ANON_KEY=", "SUPABASE_URL=")
	stdout, _ := cmd.CombinedOutput()

	if !strings.Contains(string(stdout), "firebase backend detected") {
		t.Fatalf("the scan did not recognise a Firebase application:\n%s", stdout)
	}
	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("no report: %v", err)
	}
	var sawRTDB, sawBound bool
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		if line == "" {
			continue
		}
		var f struct {
			ID       string `json:"id"`
			Resource string `json:"resource"`
			Severity string `json:"severity"`
		}
		if json.Unmarshal([]byte(line), &f) != nil {
			continue
		}
		if f.ID == "firebase-rtdb-anon-read" && f.Resource == "/public" {
			sawRTDB = true
			if f.Severity != "high" {
				t.Errorf("a readable path is %s; the root is what rates critical", f.Severity)
			}
		}
		if f.ID == "unruly-surface-not-assessed" && strings.Contains(f.Resource, "firestore") {
			sawBound = true
		}
	}
	if !sawRTDB {
		t.Error("a world-readable Realtime Database path was not reported by the binary")
	}
	if !sawBound {
		t.Error("the scan did not record that Firestore recall is bounded, so a Firebase " +
			"report with no Firestore findings reads as a clean Firestore")
	}
	// The refused paths must not be reported: a denied path and a missing one
	// answer identically, so anything else would be invented.
	if strings.Contains(string(raw), `"resource":"/locked"`) {
		t.Error("a refused path was reported; 401 does not distinguish denied from absent")
	}
}

// Vocabulary harvested from the application must reach the candidate list, and
// knowing a name must not by itself produce a finding.
//
// Firestore and the Realtime Database have no discovery oracle, so the
// candidate list IS the recall. A pinned wordlist finds users and posts and
// misses everything domain-specific -- the failure that made eight Supabase
// scanners match 1 relation of 21. The name below appears in no wordlist and
// can only be found by reading the application.
//
// The second half is the control: a path named in the same bundle that is NOT
// readable must stay unreported. Knowing a name is not evidence about it.
func TestFirebaseUsesHarvestedVocabulary(t *testing.T) {
	const open, shut = "quarterly_forecast_v2", "payroll_ledger_v2"

	rtdb := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.HasPrefix(r.URL.Path, "/"+open) {
			_, _ = w.Write([]byte(`{"row1":true}`))
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"Permission denied"}`))
	}))
	defer rtdb.Close()

	site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "app.js") {
			w.Header().Set("Content-Type", "application/javascript")
			fmt.Fprintf(w, `const firebaseConfig={apiKey:"AIzaSyD%s",projectId:"stub-project",`+
				`databaseURL:"%s"};const a=ref(db,"%s");const b=ref(db,"%s");`,
				"0123456789abcdefghijklmnopqrstu", rtdb.URL, open, shut)
			return
		}
		fmt.Fprint(w, `<html><body><script src="/app.js"></script></body></html>`)
	}))
	defer site.Close()

	out := filepath.Join(t.TempDir(), "report.jsonl")
	cmd := exec.Command(buildScanner(t), "-u", site.URL, "-j", "-o", out, "-nc", "-timeout", "20")
	cmd.Env = append(os.Environ(), "SUPABASE_ANON_KEY=", "SUPABASE_URL=")
	if _, err := cmd.CombinedOutput(); err != nil {
		_ = err // a non-zero exit means findings, which is the expected case
	}
	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("no report: %v", err)
	}
	body := string(raw)
	if !strings.Contains(body, `"resource":"/`+open+`"`) {
		t.Errorf("%s is named only in the application's bundle and was not probed, so "+
			"harvested vocabulary is not reaching the candidate list:\n%s", open, body)
	}
	if strings.Contains(body, `"resource":"/`+shut+`"`) {
		t.Errorf("%s is named in the bundle but refuses anonymous reads, and was reported "+
			"anyway: knowing a name is not evidence about it", shut)
	}
}

// Every output the operator asked for must be produced, whichever backend the
// target turns out to be.
//
// The outputs were wired in one at a time at the end of the Supabase pipeline,
// so a Firebase-only application -- which returns earlier, at the
// no-Supabase-credential path -- lost them silently. -plain printed nothing and
// -html wrote no file at all: a shareable report requested and simply absent,
// with no error to notice. A user who cannot read the technical output was
// handed silence, which looks exactly like a clean project.
func TestEveryRequestedOutputIsProducedForAFirebaseTarget(t *testing.T) {
	requireLiveEvals(t)
	rtdb := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"public":{"a":1}}`)
	}))
	defer rtdb.Close()
	site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, ".js") {
			w.Header().Set("Content-Type", "application/javascript")
			fmt.Fprintf(w, `const firebaseConfig={apiKey:"AIzaSyD%s",`+
				`projectId:"stub-project",databaseURL:"%s"};`,
				"0123456789abcdefghijklmnopqrstu", rtdb.URL)
			return
		}
		fmt.Fprint(w, `<html><body><script src="/app.js"></script></body></html>`)
	}))
	defer site.Close()

	dir := t.TempDir()
	html := filepath.Join(dir, "report.html")
	csv := filepath.Join(dir, "report.csv")

	cmd := exec.Command(buildScanner(t), "-u", site.URL, "-html", html,
		"-csv", "-o", csv, "-plain", "-nc", "-timeout", "20")
	cmd.Env = append(os.Environ(), "SUPABASE_ANON_KEY=", "SUPABASE_URL=")
	out, _ := cmd.CombinedOutput()

	// -html: a file, containing the finding and the button the flag promises.
	b, err := os.ReadFile(html)
	if err != nil {
		t.Fatalf("-html produced no file for a Firebase target: %v", err)
	}
	for _, must := range []string{"firebase-rtdb-anon-read", "Copy all SQL"} {
		if !strings.Contains(string(b), must) {
			t.Errorf("the html report does not contain %q", must)
		}
	}

	// -csv: a header and at least one row.
	c, err := os.ReadFile(csv)
	if err != nil {
		t.Fatalf("-csv produced no file: %v", err)
	}
	if !strings.HasPrefix(string(c), "severity,id,") {
		t.Errorf("csv does not start with the header: %.60q", c)
	}
	if !strings.Contains(string(c), "firebase-rtdb-anon-read") {
		t.Error("the csv does not carry the finding")
	}

	// -plain: the non-technical answer, which is the whole reason that flag
	// exists. Silence here is indistinguishable from a clean project.
	if !strings.Contains(string(out), "Anyone on the internet") {
		t.Errorf("-plain rendered nothing for a Firebase target:\n%s", out)
	}

	// And the stored report must say how much was examined. Without it a report
	// with no exposures cannot be told from a scan that looked at nothing --
	// which is the entire reason the summary exists, and it was emitted only at
	// the end of the Supabase pipeline.
	if !strings.Contains(string(c), "unruly-scan-summary") {
		t.Error("the stored report carries no statement of what was examined")
	}
	// In this backend's own terms: 0 relations across 0 schemas would be
	// Supabase's vocabulary, and reads as 'nothing found' beside a critical
	// finding.
	if strings.Contains(string(c), "0 relations, 0 schemas") {
		t.Error("the summary describes a Firebase project in relational terms")
	}
}

// The two ways a scan can end with a credential it cannot use, told apart.
//
// One code path serves both: a Firebase-only application, where a provider
// assessed the project and can say how many names it asked about; and a
// SUPABASE application whose anon key was never found, where nothing was
// assessed at all. Emitting the provider summary for the second produced
//
//	0 names probed, 1 requests   {"backend":"","names":0}
//
// on a target carrying a critical finding: an empty backend name and a count
// that measures nothing, next to a result a reader would act on.
//
// Found by running -l over a list of targets, which is how an operator scans a
// portfolio and the mode that had never been exercised end to end.
func TestScanSummaryDistinguishesAssessedFromUnassessed(t *testing.T) {
	requireLiveEvals(t)
	requireReachable(t, "http://127.0.0.1:54322")

	out := filepath.Join(t.TempDir(), "scan.json")
	cmd := exec.Command(buildScanner(t), "-u", "http://127.0.0.1:54322",
		"-j", "-o", out, "-silent", "-nc")
	// The site fixture ships a service_role key and no anon key, so the scan
	// recognises the backend and cannot examine it.
	cmd.Env = append(os.Environ(), "SUPABASE_ANON_KEY=", "SUPABASE_URL=")
	_ = cmd.Run()

	b, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("scan produced no report: %v", err)
	}
	var sawCritical, sawNotAssessed bool
	for _, line := range strings.Split(string(b), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var f struct {
			ID, Severity, Name string
			Evidence           struct{ Reason string }
		}
		if json.Unmarshal([]byte(line), &f) != nil {
			t.Fatalf("report line is not JSON: %q", line)
		}
		if f.Severity == "critical" {
			sawCritical = true
		}
		if f.ID == "unruly-scan-summary" {
			// The provider summary must not appear: no provider ran.
			if strings.Contains(f.Evidence.Reason, "names probed") {
				t.Errorf("a provider summary was emitted for a scan where no provider "+
					"assessed anything: %q", f.Evidence.Reason)
			}
		}
		if f.ID == "unruly-surface-not-assessed" &&
			strings.Contains(f.Evidence.Reason, "no usable credential") {
			sawNotAssessed = true
		}
	}
	if !sawCritical {
		t.Fatal("the fixture ships a service_role key and no critical finding was " +
			"reported, so this test is not measuring the case it describes")
	}
	if !sawNotAssessed {
		t.Error("the backend was recognised and never examined, and the report does " +
			"not say so: one critical finding beside a silence reads as 'nothing else'")
	}
}
