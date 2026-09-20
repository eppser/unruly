// Package neonfixture verifies and restores the Neon lab fixture.
//
// It is not part of the scan path and nothing under cmd/ or backend/ imports
// it. The scanner reaches the lab as a stranger does, over the Data API with a
// token; this package reaches it as the OWNER, over Neon's SQL-over-HTTP
// endpoint, and exists for one reason: a write probe that cannot be undone is
// a write probe that cannot be run twice. The fixture's value is that its
// contents are known, so anything that inserts a row has to be able to take it
// back out.
//
// Two properties are structural rather than promised:
//
//   - No exported call accepts SQL. Every statement is built here from an
//     operation this package implements, so there is no argument a caller can
//     pass that becomes a statement -- DDL included. The lab's schema is the
//     ground truth and nothing here can alter it.
//   - Identifiers are validated against a conservative pattern before they are
//     interpolated. Values are never interpolated at all; they are bound.
//
// The owner connection string is read from NEON_DATABASE_URL by the caller and
// never logged: errors quote the server's message, not the request.
package neonfixture

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// identifier is deliberately narrower than Postgres allows. The fixture's
// tables are all lower_snake_case, and a pattern that admits exactly those
// cannot be talked into admitting a statement.
var identifier = regexp.MustCompile(`^[a-z_][a-z0-9_]*$`)

// A Client talks to one Neon branch as its owner.
type Client struct {
	endpoint string // https://<host>/sql
	conn     string // the owner connection string, sent as a header
	http     *http.Client
}

// New derives the SQL endpoint from a Postgres connection string.
//
// Neon serves SQL over HTTPS at /sql on the same host the driver would connect
// to, which is why this needs no Postgres driver and stays inside net/http.
func New(connString string) (*Client, error) {
	if connString == "" {
		return nil, fmt.Errorf("neonfixture: no connection string (set NEON_DATABASE_URL)")
	}
	u, err := url.Parse(connString)
	if err != nil {
		return nil, fmt.Errorf("neonfixture: connection string does not parse")
	}
	if u.Host == "" {
		return nil, fmt.Errorf("neonfixture: connection string carries no host")
	}
	return &Client{
		endpoint: "https://" + u.Host + "/sql",
		conn:     connString,
		http:     &http.Client{Timeout: 30 * time.Second},
	}, nil
}

// Counts returns the exact row count of each table.
//
// count(*), not pg_stat_user_tables.n_live_tup: the statistics view is an
// estimate maintained by the collector and lags a write by however long the
// autovacuum daemon takes to notice. An estimate that happens to match the
// expected count would report a fixture as restored before it was.
func (c *Client) Counts(ctx context.Context, tables []string) (map[string]int, error) {
	out := make(map[string]int, len(tables))
	for _, t := range tables {
		if !identifier.MatchString(t) {
			return nil, fmt.Errorf("neonfixture: %q is not a plain table name", t)
		}
		rows, err := c.query(ctx, `select count(*) as n from "`+t+`"`, nil)
		if err != nil {
			return nil, fmt.Errorf("counting %s: %w", t, err)
		}
		if len(rows) != 1 {
			return nil, fmt.Errorf("counting %s: %d rows from a count query", t, len(rows))
		}
		n, err := asInt(rows[0]["n"])
		if err != nil {
			return nil, fmt.Errorf("counting %s: %w", t, err)
		}
		out[t] = n
	}
	return out, nil
}

// DeleteMarked removes the rows a probe left behind and returns how many went.
//
// The marker is bound as a parameter, so a probe that wrote a string full of
// quotes is still deleted by the same call that wrote it.
func (c *Client) DeleteMarked(ctx context.Context, table, column, marker string) (int, error) {
	if !identifier.MatchString(table) {
		return 0, fmt.Errorf("neonfixture: %q is not a plain table name", table)
	}
	if !identifier.MatchString(column) {
		return 0, fmt.Errorf("neonfixture: %q is not a plain column name", column)
	}
	if marker == "" {
		return 0, fmt.Errorf("neonfixture: refusing to delete on an empty marker, which matches nothing or everything depending on the operator")
	}
	rows, err := c.query(ctx,
		`delete from "`+table+`" where "`+column+`" = $1 returning 1 as gone`,
		[]any{marker})
	if err != nil {
		return 0, err
	}
	return len(rows), nil
}

// Verify reports every table whose count differs from the fixture contract.
//
// It reports ALL the drift rather than the first, because a caller who has to
// restore a fixture wants the whole list in one pass.
func (c *Client) Verify(ctx context.Context, want map[string]int) error {
	tables := make([]string, 0, len(want))
	for t := range want {
		tables = append(tables, t)
	}
	sort.Strings(tables)
	got, err := c.Counts(ctx, tables)
	if err != nil {
		return err
	}
	var drift []string
	for _, t := range tables {
		if got[t] != want[t] {
			drift = append(drift, fmt.Sprintf("%s has %d row(s), the fixture contract says %d", t, got[t], want[t]))
		}
	}
	if len(drift) > 0 {
		return fmt.Errorf("the Neon fixture has drifted: %s", strings.Join(drift, "; "))
	}
	return nil
}

func (c *Client) query(ctx context.Context, sql string, params []any) ([]map[string]any, error) {
	if params == nil {
		params = []any{}
	}
	body, err := json.Marshal(map[string]any{"query": sql, "params": params})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Neon-Connection-String", c.conn)
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var out struct {
		Rows    []map[string]any `json:"rows"`
		Message string           `json:"message"`
		Code    string           `json:"code"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("HTTP %d: response is not JSON", resp.StatusCode)
	}
	if out.Message != "" {
		return nil, fmt.Errorf("HTTP %d: %s (%s)", resp.StatusCode, out.Message, out.Code)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return out.Rows, nil
}

// asInt copes with Neon returning bigint as a JSON string.
func asInt(v any) (int, error) {
	switch t := v.(type) {
	case string:
		// strconv, not Sscanf: Sscanf("%d") reads 12 out of "12abc" and
		// reports no error, so a count that came back malformed would be
		// silently believed.
		n, err := strconv.Atoi(t)
		if err != nil {
			return 0, fmt.Errorf("%q is not a number", t)
		}
		return n, nil
	case float64:
		return int(t), nil
	default:
		return 0, fmt.Errorf("count came back as %T", v)
	}
}

// Seed reads the fixture's expected row counts from the answer key.
//
// The counts used to be a literal in each test that needed them, which meant
// two files could agree with each other and both be wrong about the lab. A
// statement about the fixture's contents is ground truth, and ground truth
// belongs in the ground-truth file.
func Seed(answerKey string) (map[string]int, error) {
	b, err := os.ReadFile(answerKey)
	if err != nil {
		return nil, err
	}
	var doc struct {
		FixtureSeed map[string]int `yaml:"fixture_seed"`
	}
	if err := yaml.Unmarshal(b, &doc); err != nil {
		return nil, err
	}
	if len(doc.FixtureSeed) == 0 {
		return nil, fmt.Errorf("%s declares no fixture_seed: without it a caller cannot "+
			"tell a lab in its known state from one a probe has changed, and would grade "+
			"against whatever it happens to find", answerKey)
	}
	return doc.FixtureSeed, nil
}

// Drift reports how the lab differs from its answer key, or nil if it matches.
//
// A live eval grades recall and precision against a lab it assumes is in a
// known state. When that assumption is wrong -- a probe left a row behind, a
// seed row was deleted, someone changed a policy -- the eval does not measure
// the scanner, it measures the laboratory, and reports the difference as a
// regression in the scanner. Callers verify first and SKIP on drift, so the
// audit renders it as "not run" rather than as a pass or a failure. Absence of
// a finding is only evidence when the check could see.
//
// Read-only: it counts rows and changes nothing.
func Drift(ctx context.Context, connString, answerKey string) error {
	want, err := Seed(answerKey)
	if err != nil {
		return err
	}
	c, err := New(connString)
	if err != nil {
		return err
	}
	return c.Verify(ctx, want)
}

// PruneProbeSessions deletes the Neon Auth sessions belonging to the named
// probe accounts, and returns how many it removed.
//
// The evals sign in on every run. Neon Auth writes a session row each time and
// nothing removes them: measured at 102 rows against six probe accounts, which
// is residue this project would report as a finding if it found it in someone
// else's project. The users themselves do not accumulate -- the evals use
// fixed addresses, so a repeat sign-up is refused and falls through to sign-in
// -- so sessions are the only part that grows.
//
// Scoped by email, and refuses an empty list. A prune that deletes every
// session would sign the OWNER out of their own console, and "delete all rows
// where the filter happened to match nothing" is the shape of the accidents
// this tool exists to find.
func (c *Client) PruneProbeSessions(ctx context.Context, emails []string) (int, error) {
	if len(emails) == 0 {
		return 0, fmt.Errorf("no probe accounts named: an unscoped prune would delete " +
			"every session in the project, including the owner's")
	}
	for _, e := range emails {
		if strings.TrimSpace(e) == "" {
			return 0, fmt.Errorf("an empty address is not a probe account; it would " +
				"widen the filter rather than narrow it")
		}
	}
	rows, err := c.query(ctx,
		`delete from neon_auth.session where "userId" in `+
			`(select id from neon_auth."user" where email = any($1)) returning id`,
		[]any{emails})
	if err != nil {
		return 0, err
	}
	return len(rows), nil
}

// ProbeAccounts are the addresses the live evals sign in as. Listed here so a
// prune is scoped to exactly these and never to "everything that looks like a
// test", which would eventually match a real account.
func ProbeAccounts() []string {
	return []string{
		"unruly-cli@example.com",
		"unruly-crosscheck@example.com",
		"unruly-e2e@example.com",
		"unruly-exploit@example.com",
		"unruly-recorder@example.com",
		"unruly-replay@example.com",
	}
}
