package neonfixture

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// a recording /sql endpoint, so the tests grade what was SENT rather than
// what the package says it sends.
type sqlServer struct {
	*httptest.Server
	mu   sync.Mutex
	got  []sqlRequest
	rows func(sqlRequest) []map[string]any
}

// sent returns a copy of what the fixture was asked, so an assertion is never
// reading the slice a still-running handler may be appending to.
func (s *sqlServer) sent() []sqlRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]sqlRequest, len(s.got))
	copy(out, s.got)
	return out
}

type sqlRequest struct {
	Query  string `json:"query"`
	Params []any  `json:"params"`
	Conn   string `json:"-"`
}

func newSQLServer(t *testing.T, rows func(sqlRequest) []map[string]any) *sqlServer {
	t.Helper()
	s := &sqlServer{rows: rows}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var req sqlRequest
		_ = json.Unmarshal(body, &req)
		req.Conn = r.Header.Get("Neon-Connection-String")
		s.mu.Lock()
		s.got = append(s.got, req)
		s.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"rows": s.rows(req)})
	}))
	t.Cleanup(s.Close)
	return s
}

// point a Client at the test server without going through New, which derives
// https:// from the connection string.
func clientFor(s *sqlServer) *Client {
	c, _ := New("postgresql://u:p@example.invalid/db")
	c.endpoint = s.URL + "/sql"
	c.http = s.Client()
	return c
}

func countRows(n string) func(sqlRequest) []map[string]any {
	return func(sqlRequest) []map[string]any { return []map[string]any{{"n": n}} }
}

// The count has to be exact. pg_stat_user_tables.n_live_tup is an estimate the
// collector updates after the fact, so a fixture could read as restored while
// a probe row was still in it.
func TestCountsAsksForAnExactCount(t *testing.T) {
	s := newSQLServer(t, countRows("2"))
	got, err := clientFor(s).Counts(context.Background(), []string{"anon_readable"})
	if err != nil {
		t.Fatalf("Counts: %v", err)
	}
	if got["anon_readable"] != 2 {
		t.Errorf("count = %d, want 2", got["anon_readable"])
	}
	if len(s.sent()) != 1 {
		t.Fatalf("%d statement(s) sent, want 1", len(s.sent()))
	}
	q := strings.ToLower(s.sent()[0].Query)
	if !strings.Contains(q, "count(*)") {
		t.Errorf("the statement does not count rows: %q", s.sent()[0].Query)
	}
	if strings.Contains(q, "n_live_tup") || strings.Contains(q, "pg_stat") {
		t.Errorf("the statement reads the statistics view, which is an estimate: %q", s.sent()[0].Query)
	}
}

// Neon returns bigint as a JSON string. A count that came back malformed must
// be an error, not a zero: zero is a plausible row count and would read as an
// empty table rather than as a failure to look.
func TestAMalformedCountIsAnErrorNotAZero(t *testing.T) {
	s := newSQLServer(t, countRows("12abc"))
	if _, err := clientFor(s).Counts(context.Background(), []string{"anon_readable"}); err == nil {
		t.Fatal("a count of \"12abc\" was accepted; a malformed count must not be believed")
	}
}

// The guard has to hold BEFORE the request is built. A package that validates
// after sending has already sent it.
func TestAnIdentifierThatIsNotAPlainNameNeverReachesTheWire(t *testing.T) {
	for _, bad := range []string{
		`open_guestbook"; drop table rls_disabled; --`,
		"open guestbook",
		"OpenGuestbook",
		"",
		"1_table",
	} {
		s := newSQLServer(t, countRows("1"))
		if _, err := clientFor(s).Counts(context.Background(), []string{bad}); err == nil {
			t.Errorf("Counts(%q) was accepted as a table name", bad)
		}
		if len(s.sent()) != 0 {
			t.Errorf("Counts(%q) sent %d statement(s); the name must be refused before anything is built",
				bad, len(s.sent()))
		}
	}
}

// The marker is a value and must be bound, not interpolated -- otherwise a
// probe that wrote a quote cannot be cleaned up by the code that wrote it.
func TestDeleteMarkedBindsTheMarkerRatherThanInterpolatingIt(t *testing.T) {
	const marker = `unruly_write_probe' or '1'='1`
	s := newSQLServer(t, func(sqlRequest) []map[string]any {
		return []map[string]any{{"gone": "1"}, {"gone": "1"}}
	})
	n, err := clientFor(s).DeleteMarked(context.Background(), "open_guestbook", "message", marker)
	if err != nil {
		t.Fatalf("DeleteMarked: %v", err)
	}
	if n != 2 {
		t.Errorf("deleted %d row(s), want 2 -- the count comes from RETURNING, not from a guess", n)
	}
	if len(s.sent()) != 1 {
		t.Fatalf("%d statement(s) sent, want 1", len(s.sent()))
	}
	if strings.Contains(s.sent()[0].Query, marker) {
		t.Errorf("the marker was interpolated into the statement: %q", s.sent()[0].Query)
	}
	if len(s.sent()[0].Params) != 1 || s.sent()[0].Params[0] != marker {
		t.Errorf("params = %v, want the marker bound as the only parameter", s.sent()[0].Params)
	}
	if !strings.Contains(strings.ToLower(s.sent()[0].Query), "returning") {
		t.Errorf("without RETURNING the deleted count is unknown: %q", s.sent()[0].Query)
	}
}

// An empty marker matches every row or none depending on the operator, and
// this package deletes from a fixture whose contents are the ground truth.
func TestAnEmptyMarkerIsRefused(t *testing.T) {
	s := newSQLServer(t, countRows("1"))
	if _, err := clientFor(s).DeleteMarked(context.Background(), "open_guestbook", "message", ""); err == nil {
		t.Fatal("an empty marker was accepted")
	}
	if len(s.sent()) != 0 {
		t.Errorf("%d statement(s) sent on an empty marker", len(s.sent()))
	}
}

// Restoring a fixture means knowing everything that drifted, not the first
// thing that drifted.
func TestVerifyNamesEveryTableThatDrifted(t *testing.T) {
	counts := map[string]string{"anon_readable": "5", "open_guestbook": "9", "rls_disabled": "3"}
	s := newSQLServer(t, func(r sqlRequest) []map[string]any {
		for tbl, n := range counts {
			if strings.Contains(r.Query, `"`+tbl+`"`) {
				return []map[string]any{{"n": n}}
			}
		}
		return []map[string]any{{"n": "0"}}
	})
	err := clientFor(s).Verify(context.Background(), map[string]int{
		"anon_readable": 2, "open_guestbook": 1, "rls_disabled": 3,
	})
	if err == nil {
		t.Fatal("Verify passed a fixture with two drifted tables")
	}
	for _, want := range []string{"anon_readable", "open_guestbook"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the drift report does not name %s: %v", want, err)
		}
	}
	if strings.Contains(err.Error(), "rls_disabled") {
		t.Errorf("the drift report names rls_disabled, which matches: %v", err)
	}
}

// A server-side error must not read as an empty result.
func TestAPostgresErrorIsNotAnEmptyCount(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"message": `relation "open_guestbook" does not exist`, "code": "42P01",
		})
	}))
	t.Cleanup(s.Close)
	c, _ := New("postgresql://u:p@example.invalid/db")
	c.endpoint = s.URL + "/sql"
	c.http = s.Client()
	_, err := c.Counts(context.Background(), []string{"open_guestbook"})
	if err == nil {
		t.Fatal("a 42P01 was read as a successful count")
	}
	if !strings.Contains(err.Error(), "42P01") {
		t.Errorf("the error does not carry the Postgres code: %v", err)
	}
}

// The connection string is a credential. It travels in a header and must not
// appear in an error a test log or CI transcript would keep.
func TestErrorsDoNotQuoteTheConnectionString(t *testing.T) {
	const conn = "postgresql://owner:hunter2@ep-x.aws.neon.tech/neondb"
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("not json"))
	}))
	t.Cleanup(s.Close)
	c, _ := New(conn)
	c.endpoint = s.URL + "/sql"
	c.http = s.Client()
	_, err := c.Counts(context.Background(), []string{"open_guestbook"})
	if err == nil {
		t.Fatal("a 500 with a non-JSON body was accepted")
	}
	if strings.Contains(err.Error(), "hunter2") || strings.Contains(err.Error(), conn) {
		t.Errorf("the error carries the connection string: %v", err)
	}
}

// Seed is the single place the lab's known state is written down, so it has to
// fail loudly rather than return an empty map: a caller that verifies against
// nothing verifies nothing, and would report a drifted lab as a clean one.
func TestSeedReadsTheAnswerKeyAndRefusesAnEmptyOne(t *testing.T) {
	got, err := Seed("../../fixtures/neon/answer-key.yaml")
	if err != nil {
		t.Fatalf("reading the committed answer key: %v", err)
	}
	want := map[string]int{
		"anon_readable": 2, "open_guestbook": 1, "rls_disabled": 3, "rls_enforced": 2,
	}
	if len(got) != len(want) {
		t.Errorf("got %d seeded tables, want %d: %v", len(got), len(want), got)
	}
	for table, n := range want {
		if got[table] != n {
			t.Errorf("%s seeded %d, answer key says %d", table, n, got[table])
		}
	}

	dir := t.TempDir()
	empty := filepath.Join(dir, "no-seed.yaml")
	if err := os.WriteFile(empty, []byte("endpoint: https://example.invalid\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Seed(empty); err == nil {
		t.Error("a key with no fixture_seed returned no error; a caller would then " +
			"verify against an empty map, which every possible lab state satisfies")
	}
	if _, err := Seed(filepath.Join(dir, "absent.yaml")); err == nil {
		t.Error("a missing answer key returned no error")
	}
}

// The prune must be scoped, and must say so rather than doing something
// approximately right. An unscoped delete on neon_auth.session signs the owner
// out of their own project.
func TestPruneProbeSessionsRefusesAnUnscopedDelete(t *testing.T) {
	s := newSQLServer(t, func(sqlRequest) []map[string]any {
		return []map[string]any{{"id": "s1"}}
	})
	c := clientFor(s)
	ctx := context.Background()

	for _, tc := range []struct {
		name   string
		emails []string
	}{
		{name: "no accounts at all", emails: nil},
		{name: "an empty list", emails: []string{}},
		{name: "an empty address widens the filter", emails: []string{"a@example.com", ""}},
		{name: "whitespace is not an address", emails: []string{"   "}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := len(s.sent())
			if _, err := c.PruneProbeSessions(ctx, tc.emails); err == nil {
				t.Error("the prune was accepted; an unscoped delete on neon_auth.session " +
					"removes the owner's session along with the probes'")
			}
			if n := len(s.sent()) - before; n != 0 {
				t.Errorf("%d statement(s) were sent before the refusal: the check has to "+
					"happen before the request is built, not after", n)
			}
		})
	}
}

// And when it is scoped, it must bind the addresses as a parameter and filter
// on them -- not interpolate, and not delete unconditionally.
func TestPruneProbeSessionsIsScopedToTheNamedAccounts(t *testing.T) {
	s := newSQLServer(t, func(sqlRequest) []map[string]any {
		return []map[string]any{{"id": "s1"}, {"id": "s2"}}
	})
	c := clientFor(s)
	n, err := c.PruneProbeSessions(context.Background(), ProbeAccounts())
	if err != nil {
		t.Fatalf("prune: %v", err)
	}
	if n != 2 {
		t.Errorf("reported %d deleted, want 2: the count comes from RETURNING", n)
	}
	sent := s.sent()
	if len(sent) != 1 {
		t.Fatalf("%d statement(s) sent, want 1", len(sent))
	}
	q := strings.ToLower(sent[0].Query)
	if !strings.Contains(q, "delete from neon_auth.session") {
		t.Errorf("the statement does not delete sessions: %q", sent[0].Query)
	}
	if !strings.Contains(q, "where") || !strings.Contains(q, "email = any($1)") {
		t.Errorf("the delete is not filtered by the named accounts: %q", sent[0].Query)
	}
	if !strings.Contains(q, "returning") {
		t.Errorf("without RETURNING the deleted count is unknown: %q", sent[0].Query)
	}
	for _, e := range ProbeAccounts() {
		if strings.Contains(sent[0].Query, e) {
			t.Errorf("%s was interpolated into the statement rather than bound: %q",
				e, sent[0].Query)
		}
	}
	if len(sent[0].Params) != 1 {
		t.Errorf("params = %v, want the address list bound as the only parameter",
			sent[0].Params)
	}
}

// The list is the scope, so it must name real probe accounts and nothing that
// could ever be a person's address.
func TestProbeAccountsAreAllSyntheticAndDistinct(t *testing.T) {
	seen := map[string]bool{}
	for _, e := range ProbeAccounts() {
		if !strings.HasSuffix(e, "@example.com") {
			t.Errorf("%q is not on the reserved example.com domain, so it could belong "+
				"to somebody", e)
		}
		if !strings.HasPrefix(e, "unruly-") {
			t.Errorf("%q is not identifiably ours", e)
		}
		if seen[e] {
			t.Errorf("%q is listed twice", e)
		}
		seen[e] = true
	}
	if len(seen) == 0 {
		t.Fatal("no probe accounts listed; every prune would refuse and nothing " +
			"would ever be cleaned up")
	}
}

// Live prune, gated so it never runs by accident. `make neon-prune`.
//
// Sessions are the one part of the lab's auth state that grows: the probe
// ACCOUNTS are fixed addresses, so a repeat sign-up is refused and falls
// through to sign-in, but every sign-in writes a session row. Measured at 102
// before the first prune.
func TestPruneProbeSessionsAgainstTheLiveLab(t *testing.T) {
	if os.Getenv("UNRULY_PRUNE") != "1" {
		t.Skip("set UNRULY_PRUNE=1 (make neon-prune)")
	}
	conn := os.Getenv("NEON_DATABASE_URL")
	if conn == "" {
		t.Fatal("NEON_DATABASE_URL must be set; source .secrets/neon.env")
	}
	c, err := New(conn)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	// The fixture is the ground truth every Neon eval grades against, and a
	// prune has no business touching it. Verified either side rather than
	// asserted: this writes to the project, and the standing rule is that the
	// lab stays exactly as vulnerable as the answer key says.
	seed, err := Seed("../../fixtures/neon/answer-key.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Verify(ctx, seed); err != nil {
		t.Skipf("the lab has already drifted, so a prune cannot be shown to be "+
			"harmless here: %v", err)
	}
	n, err := c.PruneProbeSessions(ctx, ProbeAccounts())
	if err != nil {
		t.Fatalf("prune: %v", err)
	}
	t.Logf("pruned %d probe session(s)", n)
	if err := c.Verify(ctx, seed); err != nil {
		t.Errorf("the prune changed the fixture: %v", err)
	}
}
