package surface

import (
	"context"
	"encoding/json"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"github.com/eppser/unruly/internal/client"
	"github.com/eppser/unruly/internal/finding"
)

// Arbitrary SQL execution: the only route from an anon key to DDL.
//
// PostgREST exposes no endpoint for DROP, so "can a stranger drop my database"
// is not a question about the REST API. It is a question about whether any
// routine takes SQL as an argument and runs it. Those exist in real projects:
// somebody adds exec_sql or run_sql for a migration or an admin page, marks it
// SECURITY DEFINER so it works, and grants EXECUTE to anon because that is what
// makes the call succeed from the browser. SECURITY DEFINER runs as the owner,
// so whatever the owner may do the caller may now do -- which includes DROP.
//
// The probe never sends DDL. It sends a statement whose ANSWER proves execution
// and whose effect is nothing:
//
//	GET /rest/v1/rpc/exec_sql?query=SELECT 6*7 AS unruly_probe
//	-> 200 [{"unruly_probe": 42}]
//
// Two properties make that safe and sound. GET is served by PostgREST inside a
// READ-ONLY transaction -- measured in this repo against a deliberately
// side-effecting routine, which answers 405 25006 over GET and writes a row
// over POST -- so even a destructive argument could not commit. And the
// arithmetic is the discriminator: a routine that merely ECHOES its argument
// returns the string, not 42, so the value proves the SQL ran rather than
// round-tripped. Measured on fixtures/lab, where exec_sql returns 42 and
// run_sql (same shape, EXECUTE not granted) answers 42501.
//
// Reporting is deliberately about capability, not damage: the finding says DROP
// is implied and states that it was not attempted.

// sqlExecutorNames are routine names that take SQL and run it. Pinned, because
// a scanner that guesses here calls arbitrary functions with arbitrary
// arguments -- and the deterministic rule is that the tool only ever probes
// names it was built to recognise.
var sqlExecutorNames = regexp.MustCompile(
	`(?i)^(exec|execute|run|eval|query|sql)(_?(sql|query|statement|stmt|raw|ddl|cmd))?$|` +
		`^(raw|admin|debug|dev|internal)_?(sql|query|exec|execute)$|` +
		`^sql_?(exec|execute|run|query)$`)

// sqlExecutorParams are the argument names such a routine uses. PostgREST does
// not disclose a function's signature: calling with an unknown parameter
// answers PGRST202 with a null hint, unlike the relation oracle, which names
// what you meant. Measured on the fixture. So the parameter has to be guessed
// from a short pinned list, and each miss costs one read-only request.
var sqlExecutorParams = []string{
	"query", "sql", "statement", "stmt", "q", "cmd", "command",
	"sql_query", "query_text", "expr",
}

// sqlProbeStatement returns 42 when executed and the literal text when echoed.
const sqlProbeStatement = "SELECT 6*7 AS unruly_probe"

// probeSQLExecution tries to prove that a discovered routine runs caller SQL.
//
// It returns the finding and the number of requests spent. A routine whose name
// does not match is never called at all.
func probeSQLExecution(ctx context.Context, c *client.Client, name, schema string, params []string) (*finding.Finding, int) {
	bare := name
	if i := strings.LastIndex(bare, "."); i >= 0 {
		bare = bare[i+1:]
	}
	if !sqlExecutorNames.MatchString(bare) {
		return nil, 0
	}

	reqs := 0
	for _, param := range params {
		u := c.RPCURL(name) + "?" + param + "=" + url.QueryEscape(sqlProbeStatement)
		resp := c.Get(ctx, u, nil)
		reqs++
		if resp.Err != nil || resp.Status != 200 {
			continue
		}
		if !executedTheStatement(resp.Body) {
			// It answered, but with something other than the arithmetic: an
			// echo, a fixed value, an empty set. Not proof, and not reported.
			continue
		}
		f := arbitrarySQLFinding(c, name, param, schema, string(resp.Body))
		return &f, reqs
	}
	return nil, reqs
}

// executedTheStatement checks for the ANSWER, not for a 200.
//
// A routine that returns its argument unchanged also answers 200, and a
// scanner that accepted that would report every echo helper as remote code
// execution. 42 can only come from evaluating the expression.
func executedTheStatement(body []byte) bool {
	var rows []map[string]any
	if json.Unmarshal(body, &rows) == nil {
		for _, r := range rows {
			if v, ok := r["unruly_probe"]; ok && isFortyTwo(v) {
				return true
			}
		}
		return false
	}
	var one map[string]any
	if json.Unmarshal(body, &one) == nil {
		if v, ok := one["unruly_probe"]; ok && isFortyTwo(v) {
			return true
		}
	}
	return false
}

func isFortyTwo(v any) bool {
	switch n := v.(type) {
	case float64:
		return n == 42
	case string:
		return n == "42"
	}
	return false
}

func arbitrarySQLFinding(c *client.Client, name, param, schema, body string) finding.Finding {
	qualified := name
	if schema != "" && !strings.Contains(name, ".") {
		qualified = schema + "." + name
	}
	if len(body) > 200 {
		body = body[:200] + "…"
	}
	return finding.Finding{
		ID:       "supabase-anon-arbitrary-sql",
		Name:     "A routine executes SQL supplied by the caller",
		Severity: finding.Critical,
		Protocol: "postgrest",
		Matched:  c.RPCURL(name),
		Resource: qualified,
		Description: "The routine " + qualified + " took a SQL statement as its \"" + param +
			"\" argument and executed it, returning the computed answer rather than the text " +
			"it was given. Anyone holding the public anon key can run statements of their " +
			"choosing against this database. If the routine is SECURITY DEFINER -- which is " +
			"usually why it was granted to anon in the first place -- they run as its owner, " +
			"and DROP TABLE and DROP DATABASE are inside that authority. Row-level security " +
			"is not a control here: policies apply to the REST API, not to SQL executed " +
			"through a function.\n\nThis scan did NOT attempt any of that. It sent " +
			sqlProbeStatement + " over GET, which PostgREST runs inside a read-only " +
			"transaction, so nothing it sent could have written or dropped anything. The " +
			"capability is the finding; exercising it is not the scanner's business.",
		Remediation: "-- Take the grant away first; it is the part that makes this reachable.\n" +
			"REVOKE EXECUTE ON FUNCTION " + qualified + " FROM anon, authenticated, PUBLIC;\n" +
			"-- Then decide whether the routine should exist at all. A function that\n" +
			"-- executes caller-supplied SQL cannot be made safe by input validation --\n" +
			"-- the argument IS the program. Replace it with functions that take\n" +
			"-- parameters and run fixed statements:\n" +
			"-- DROP FUNCTION " + qualified + ";\n" +
			"-- Check what else is reachable the same way:\n" +
			"SELECT n.nspname, p.proname, p.prosecdef, pg_get_userbyid(p.proowner) AS owner " +
			"FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace " +
			"WHERE has_function_privilege('anon', p.oid, 'EXECUTE') AND n.nspname NOT IN " +
			"('pg_catalog', 'information_schema');",
		Reference: []string{
			"https://supabase.com/docs/guides/database/functions#security-definer-vs-invoker",
		},
		Evidence: finding.Evidence{
			Request: "curl -sS '" + c.RPCURL(name) + "?" + param + "=" +
				url.QueryEscape(sqlProbeStatement) + "' -H 'apikey: $SUPABASE_ANON_KEY'",
			Status:   200,
			Response: body,
			Reason: "the routine returned the computed value 42 rather than the text of the " +
				"statement, so the SQL was executed and not echoed",
		},
	}
}

// sqlExecutorCandidates are probed by name even when discovery did not find
// them.
//
// Routine discovery is seeded from vocabulary harvested out of the target's own
// application, and a maintenance helper nobody links to from the browser is
// exactly the kind of name that harvest never sees -- so hooking this check to
// discovered names only would miss the case it exists for. These are few,
// well-known and pinned, and calling a name that does not exist costs one 404.
//
// Pinned rather than generated: the deterministic rule for this scanner is that
// it only ever calls names it was built to recognise.
var sqlExecutorCandidates = []string{
	"exec_sql", "execute_sql", "run_sql", "sql_exec", "sql_query", "raw_sql",
	"admin_sql", "admin_query", "run_query", "execute_query", "eval_sql",
	"exec", "execute", "query", "sql", "eval",
}

// primaryParams are tried for a name that was merely guessed. The full list is
// reserved for routines discovery actually found, which are few.
//
// The asymmetry is the budget. Every candidate name costs one request per
// parameter tried, and existence is NOT decidable first: a wrong parameter and
// a missing function both answer PGRST202 with the same message, measured on
// the fixture against exec_sql (exists), run_sql (exists, no grant) and a name
// that does not exist. Without that oracle the sweep is names x parameters, so
// 16 x 3 is spent blind and the 10-parameter list is spent only where a real
// routine name is already known.
var primaryParams = []string{"query", "sql", "statement"}

// sqlExecutionFindings probes discovered routines that match, plus the pinned
// candidate names, and returns the findings with the requests spent.
func sqlExecutionFindings(ctx context.Context, c *client.Client, discovered []string, schema string) ([]finding.Finding, int) {
	seen := map[string]bool{}
	var out []finding.Finding
	reqs := 0

	sorted := append([]string{}, discovered...)
	sort.Strings(sorted) // determinism: never depend on discovery order
	for _, n := range sorted {
		if seen[n] {
			continue
		}
		seen[n] = true
		f, spent := probeSQLExecution(ctx, c, n, schema, sqlExecutorParams)
		reqs += spent
		if f != nil {
			out = append(out, *f)
		}
	}
	for _, n := range sqlExecutorCandidates {
		if seen[n] {
			continue
		}
		seen[n] = true
		f, spent := probeSQLExecution(ctx, c, n, schema, primaryParams)
		reqs += spent
		if f != nil {
			out = append(out, *f)
		}
	}
	return out, reqs
}
