package eval_test

import (
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// The grouped fix plan must EXECUTE, against the schema it was generated from.
//
// Every other remediation test grades templates or per-finding blocks. None
// took a plan built from a real scan and ran it, which is exactly how the
// following survived: the plan emitted
//
//	ALTER TABLE <relation> ENABLE ROW LEVEL SECURITY;
//
// for every exposed relation, and PostgREST exposes VIEWS as relations
// indistinguishably from tables. On a view that statement is not a no-op, it
// is an error:
//
//	ERROR: ALTER action ENABLE ROW SECURITY cannot be performed on
//	       relation "view_leak"
//	DETAIL: This operation is not supported for views.
//
// Measured on PostgreSQL 16.14 against a plan of 11,888 characters from a real
// scan of the lab: piped into psql with ON_ERROR_STOP it stopped there, which
// on an operator's terminal means a half-applied remediation and a project
// left in a state nobody chose.
//
// The fix is not to guess. A scan cannot see pg_class from outside, so the plan
// decides at run time and does the right thing for either kind.
func TestTheFixPlanExecutesAgainstTheSchemaItDescribes(t *testing.T) {
	requireLiveEvals(t)
	requireReachable(t, "http://127.0.0.1:54321")
	key := os.Getenv("UNRULY_FIXTURE_KEY")
	if key == "" {
		t.Skip("set UNRULY_FIXTURE_KEY")
	}

	// A scan of the lab, whose schema deliberately contains a leaky view.
	html := t.TempDir() + "/r.html"
	cmd := exec.Command(buildScanner(t), "-u", "http://127.0.0.1:54321", "-k", key,
		"-rest-prefix", "/", "-html", html, "-silent")
	cmd.Env = append(os.Environ(), "SUPABASE_ANON_KEY=")
	_ = cmd.Run()

	plan := sqlFromHTML(t, html)
	if !strings.Contains(plan, "view_leak") {
		t.Fatalf("the plan does not mention the leaky view, so this test is not "+
			"measuring what it claims; plan was %d chars", len(plan))
	}

	// Run it the way the README tells an operator to, and with ON_ERROR_STOP so
	// a failure anywhere is a failure here rather than a silent skip.
	//
	// Inside a transaction that is thrown away. The first version of this test
	// ran the plan for real and left the lab REMEDIATED: every other eval in
	// this group grades against the seed state, and two of them failed in the
	// audit that followed -- the redaction eval reported "leaky_credentials
	// produced no finding among 1", which is exactly what a hardened fixture
	// looks like. The plan still executes, every statement in it still has to
	// be accepted by the same PostgreSQL that serves the fixture, and nothing
	// survives the ROLLBACK. DDL is transactional in PostgreSQL, and the plan
	// emits only DO blocks and REVOKE, so there is nothing here that a
	// transaction cannot hold.
	psql := exec.Command("docker", "compose", "-f", "../../fixtures/lab/docker-compose.yml",
		"exec", "-T", "db", "psql", "-U", "postgres", "-d", "fixture", "-v", "ON_ERROR_STOP=1")
	psql.Stdin = strings.NewReader("BEGIN;\n" + plan + "\nROLLBACK;\n")
	out, err := psql.CombinedOutput()
	if err != nil {
		t.Errorf("the fix plan this tool tells operators to paste into psql does not "+
			"run against the database it was generated from: %v\n%s", err, lastLines(out, 6))
	}
	if strings.Contains(string(out), "ERROR:") {
		t.Errorf("the plan produced a database error:\n%s", lastLines(out, 6))
	}

	// And the lab is still vulnerable. Without this the ROLLBACK above is an
	// unchecked claim, and the failure it prevents is invisible here: it shows
	// up as some OTHER eval reporting that a leaky relation leaks nothing.
	req, err := http.NewRequest("GET", "http://127.0.0.1:54321/open_no_rls?select=id&limit=1", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("apikey", key)
	req.Header.Set("Authorization", "Bearer "+key)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("re-reading the fixture after the plan ran: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 || len(body) <= 2 {
		t.Errorf("the fixture no longer leaks open_no_rls after this test ran "+
			"(status %d, body %q): the plan was applied for real and every eval "+
			"grading the seed state will now fail for a reason none of them can see",
			resp.StatusCode, body)
	}
}

// sqlFromHTML pulls the copy-all block out of the report.
func sqlFromHTML(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading the report: %v", err)
	}
	s := string(b)
	const open = `<pre id="sql"`
	i := strings.Index(s, open)
	if i < 0 {
		t.Fatal("the report has no copy-all SQL block")
	}
	i = strings.Index(s[i:], ">") + i + 1
	j := strings.Index(s[i:], "</pre>")
	if j < 0 {
		t.Fatal("the copy-all block is not closed")
	}
	return unescapeHTML(s[i : i+j])
}

func unescapeHTML(s string) string {
	r := strings.NewReplacer("&lt;", "<", "&gt;", ">", "&quot;", `"`,
		"&#39;", "'", "&#34;", `"`, "&amp;", "&")
	return r.Replace(s)
}

func lastLines(b []byte, n int) string {
	ls := strings.Split(strings.TrimRight(string(b), "\n"), "\n")
	if len(ls) > n {
		ls = ls[len(ls)-n:]
	}
	return strings.Join(ls, "\n")
}
