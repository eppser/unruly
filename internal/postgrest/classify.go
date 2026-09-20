// Package postgrest encodes PostgREST/PostgreSQL response semantics.
//
// This is the correctness core of unruly. Every scanner surveyed in the
// prior research fails here, and always in the same direction: a silent false
// negative that reports a vulnerable database as clean.
//
// Observed failure modes in existing tools:
//
//	206 Partial Content  a counted read. Tools matching only 200 miss every
//	                     readable table when Prefer:count=exact is set.
//	204 No Content       a successful write. One tool classifies this as
//	                     "possible" rather than "allowed", under-reporting.
//	404 Not Found        the table does not exist. One tool reports this as
//	                     "SECURE", which is false assurance.
//	200 + range */0      the table EXISTS but RLS filtered every row. This is
//	                     not the same as 404 and must never be conflated.
package postgrest

import (
	"net/http"
	"regexp"
	"strconv"
	"strings"
)

// ReadState is the outcome of an anonymous read probe against one relation.
type ReadState int

const (
	ReadUnknown  ReadState = iota
	ReadExposed            // rows were returned: real data is anonymously readable
	ReadEmpty              // relation exists, RLS filtered every row (or it is genuinely empty)
	ReadDenied             // 401/403: the role cannot reach the relation at all
	ReadNotFound           // relation does not exist in the exposed schema
)

func (r ReadState) String() string {
	switch r {
	case ReadExposed:
		return "exposed"
	case ReadEmpty:
		return "empty-or-filtered"
	case ReadDenied:
		return "denied"
	case ReadNotFound:
		return "not-found"
	}
	return "unknown"
}

// WriteState is the outcome of an anonymous write probe against one relation.
type WriteState int

const (
	WriteUnknown    WriteState = iota
	WriteReached               // the request passed RLS and reached the table
	WriteBlockedRLS            // RLS or GRANT rejected the request
	WriteInconclusive
)

func (w WriteState) String() string {
	switch w {
	case WriteReached:
		return "reached"
	case WriteBlockedRLS:
		return "blocked"
	case WriteInconclusive:
		return "inconclusive"
	}
	return "unknown"
}

// PostgreSQL SQLSTATE / PostgREST codes that prove a write request passed RLS
// and was rejected later, by the schema itself. Reaching the schema is the
// proof of write access: RLS would have stopped it earlier.
var reachedCodes = map[string]string{
	"23502": "not-null constraint",    // null value in required column
	"23503": "foreign key constraint", //
	"23505": "unique constraint",      //
	"23514": "check constraint",       //
	"22P02": "invalid input syntax",   // type cast failure
	"42703": "undefined column",       // column does not exist
}

// Codes decided BEFORE row-level security is consulted. They prove nothing
// about write access and must never be read as it. Measured: an unknown-column
// INSERT returns PGRST204 identically for an RLS-protected relation and a
// wide-open one, because PostgREST rejects the column against its own schema
// cache first. Treating PGRST204 as "reached" is the same class of error as the
// zero-match DELETE probe.
//
// 428C9 is the one raised by PostgreSQL rather than PostgREST, during statement
// rewriting, which still precedes any policy check. It surfaced as
// "unrecognised response 400 428C9" on a -no-residue scan of the reference
// target, and that scan is also the evidence that it does not discriminate:
//
//	signatory_submissions  428C9   anon-INSERT-reachable per ground truth
//	survival_series        428C9   NOT reachable
//	exploit_rate_series    428C9   NOT reachable
//	zero_day_series        428C9   NOT reachable
//
// The same code for both answers, so it is worth exactly nothing as a verdict.
// It is listed here to say so in the report instead of shrugging.
var preFlightCodes = map[string]string{
	"PGRST204": "column not in PostgREST schema cache (rejected before SQL)",
	"PGRST102": "invalid request body (rejected before SQL)",
	"428C9": "the sampled row carries a GENERATED ALWAYS column, which PostgreSQL " +
		"rejects while rewriting the statement, before any policy is evaluated " +
		"(observed identically on writable and protected relations)",
}

// Codes that prove the request was stopped by the security layer.
var blockedCodes = map[string]string{
	"42501": "insufficient privilege / row-level security policy",
}

// Body is the decoded PostgREST error envelope. All fields are optional.
type Body struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Details string `json:"details"`
	Hint    string `json:"hint"`
}

// ClassifyRead maps an HTTP status plus Content-Range into a ReadState and a
// row count. rangeHeader is the raw Content-Range value, e.g. "0-0/124" when
// rows exist or "*/0" when RLS filtered everything.
//
// Callers must send Prefer: count=exact for the count to be meaningful.
func ClassifyRead(status int, rangeHeader string, bodyLen int) (ReadState, int) {
	switch status {
	case http.StatusOK, http.StatusPartialContent: // 200, 206
		n, ok := parseRangeTotal(rangeHeader)
		if !ok {
			// No count requested or header absent: fall back to payload shape.
			// "[]" is 2 bytes and means zero rows.
			if bodyLen > 2 {
				return ReadExposed, -1
			}
			return ReadEmpty, 0
		}
		if n > 0 {
			return ReadExposed, n
		}
		return ReadEmpty, 0
	case http.StatusUnauthorized, http.StatusForbidden: // 401, 403
		return ReadDenied, 0
	case http.StatusNotFound: // 404
		return ReadNotFound, 0
	}
	return ReadUnknown, 0
}

// classifyCode maps a PostgREST or PostgreSQL error code to a write verdict,
// independently of which verb produced it.
//
// Shared by ClassifyWrite and ClassifyAffected. When ClassifyAffected was added
// it copied these three lookups, and the copy is what the mutation suite
// noticed: a mutation targeting the 42501 branch matched two places and was
// refused for applying ambiguously. That refusal was right for a better reason
// than duplication -- with two copies, a mutation of one is still killed by the
// other's tests, so the suite reports a decision as verified when only half of
// it is. One site means one decision, checked once, for every verb.
func classifyCode(b Body) (WriteState, string, bool) {
	if reason, ok := preFlightCodes[b.Code]; ok {
		return WriteInconclusive, reason, true
	}
	if reason, ok := blockedCodes[b.Code]; ok {
		return WriteBlockedRLS, reason, true
	}
	if reason, ok := reachedCodes[b.Code]; ok {
		return WriteReached, "passed RLS, rejected by " + reason, true
	}
	return WriteUnknown, "", false
}

// ClassifyWrite maps a write probe response into a WriteState plus the reason.
//
// Only INSERT is a sound discriminator. A zero-match DELETE or PATCH returns
// 204 whether or not the role has write access, because RLS silently filters
// the candidate rows to zero rather than raising an error. Probing writes that
// way produces a 100% false-positive rate; ClassifyWrite is therefore only
// meaningful for INSERT probes, and Probe enforces that.
func ClassifyWrite(status int, b Body) (WriteState, string) {
	switch status {
	case http.StatusOK, http.StatusCreated, http.StatusNoContent, http.StatusPartialContent:
		return WriteReached, "write succeeded"
	}
	if state, reason, ok := classifyCode(b); ok {
		return state, reason
	}
	if status == http.StatusUnauthorized || status == http.StatusForbidden {
		return WriteBlockedRLS, "rejected with HTTP " + strconv.Itoa(status)
	}
	if status == http.StatusNotFound {
		return WriteInconclusive, "relation not found"
	}
	return WriteInconclusive, "unrecognised response " + strconv.Itoa(status) + " " + b.Code
}

// ClassifyAffected maps an UPDATE or DELETE that requested an exact count.
//
// This is what makes UPDATE testable at all. The zero-match PATCH is unsound
// because RLS filters candidate rows to zero rather than erroring, so a
// protected relation and an open one both answer 204 -- the false-positive
// design this scanner exists to avoid. But 204 is not the whole response. With
// Prefer: count=exact, PostgREST reports how many rows the statement actually
// touched, and THAT discriminates. Measured on the exploit lab:
//
//	policy FOR ALL TO anon        PATCH -> 204  Content-Range: 0-0/1
//	policy SELECT, INSERT only    PATCH -> 204  Content-Range: */0
//
// Same status, opposite verdicts, told apart by a header. The caller is
// responsible for sending a body that changes nothing (a column set to its
// current value), so a positive answer costs the target no data.
//
// rangeHeader is the raw Content-Range. A missing or unparseable count is
// inconclusive rather than negative: without the number, 204 means only that
// the statement ran, which is exactly the ambiguity this function exists to
// resolve.
func ClassifyAffected(status int, rangeHeader string, b Body) (WriteState, string) {
	// A constraint rejection could only happen for rows the security layer had
	// already admitted -- same reasoning as the INSERT probe, and the basis of
	// the collision variant: an UPDATE that would duplicate a unique key aborts
	// before writing anything.
	if state, reason, ok := classifyCode(b); ok {
		return state, reason
	}
	switch status {
	case http.StatusOK, http.StatusNoContent, http.StatusPartialContent:
		n, ok := parseRangeTotal(rangeHeader)
		if !ok {
			return WriteInconclusive, "the response carried no usable row count (" +
				"Content-Range: " + rangeHeader + "), and a bare 204 is returned whether " +
				"or not the role may write"
		}
		if n > 0 {
			return WriteReached, "the statement affected " + strconv.Itoa(n) +
				" row(s), so the security layer admitted them"
		}
		return WriteBlockedRLS, "the statement affected 0 rows: row-level security " +
			"filtered every candidate row"
	}
	if status == http.StatusUnauthorized || status == http.StatusForbidden {
		return WriteBlockedRLS, "rejected with HTTP " + strconv.Itoa(status)
	}
	if status == http.StatusNotFound {
		return WriteInconclusive, "relation not found"
	}
	return WriteInconclusive, "unrecognised response " + strconv.Itoa(status) + " " + b.Code
}

// parseRangeTotal extracts the total from a Content-Range value.
// "0-0/124" -> 124, true.  "*/0" -> 0, true.  "" or "0-0/*" -> 0, false.
func parseRangeTotal(v string) (int, bool) {
	i := strings.LastIndex(v, "/")
	if i < 0 {
		return 0, false
	}
	tail := strings.TrimSpace(v[i+1:])
	if tail == "" || tail == "*" {
		return 0, false
	}
	n, err := strconv.Atoi(tail)
	if err != nil {
		return 0, false
	}
	return n, true
}

// hintPrefix is how PostgREST volunteers a real relation name when the
// requested one is a near miss. This is the enumeration oracle: it leaks
// schema names that no generic wordlist would ever contain.
const hintPrefix = "Perhaps you meant the table "

// fnHintPrefix is the same oracle for functions. It recovers RPC names,
// including SECURITY DEFINER functions used as admin backdoors. Note the
// asymmetry that makes it usable: calling the EXACT name with wrong arguments
// returns hint:null, while a near-miss name volunteers the real one. So
// enumeration probes deliberate near-misses.
const fnHintPrefix = "Perhaps you meant to call the function "

// safeIdentifier is the character set a name recovered from a TARGET may use.
//
// Everything the hint oracle returns is chosen by the host being scanned. That
// host is untrusted by definition -- it is the thing under examination -- and
// the names it supplies flow into two places that matter:
//
//   - a URL, where ? & # or / change which request is sent
//   - the -fix remediation, which exists to be pasted into a SQL console
//
// Measured before this existed. A hint reading
//
//	Perhaps you meant the table 'public.users; DROP TABLE audit_log; --'
//
// was accepted verbatim and would have been emitted as
//
//	ALTER TABLE users; DROP TABLE audit_log; -- ENABLE ROW LEVEL SECURITY;
//
// so a hostile host could get arbitrary SQL run by the person scanning it.
// Two others got through: a name carrying ?select=*&limit=999999, and one
// using ../ to escape the PostgREST path onto other endpoints.
//
// The set is deliberately narrower than Postgres allows. A quoted identifier
// may contain spaces and punctuation, so a table called "my table" is now
// skipped -- a real if rare false negative, taken knowingly, because the
// alternative is executing whatever a scanned host asks for. 63 is Postgres's
// own identifier limit.
// Any alphabet, no punctuation. The set was [A-Za-z0-9_$], which refused
// every name a non-English schema volunteers -- and the oracle is precisely
// the mechanism that reaches names no wordlist holds. Measured on the
// benchmark corpus: bestellungen draws a hint naming bestellübersicht and
// benutzer draws benutzer_顧客_данные, and both were discarded after the
// target had handed them over.
//
// What the guard is FOR is unchanged: the string comes from a scanned host
// and goes into a URL path. Letters and digits in any script are allowed;
// spaces, quotes, dots, slashes, query strings and semicolons are not, which
// is what stopped ?select=*&limit=999999 and ../ when they were really sent.
// A quoted Postgres identifier may contain a space, so "my table" is still
// skipped -- a real if rare false negative, taken knowingly.
var safeIdentifier = regexp.MustCompile(`^[\p{L}\p{N}_$]+$`)

// maxIdentifierBytes is Postgres's own limit, NAMEDATALEN-1. Counted in bytes
// rather than characters because that is how Postgres counts: thirty CJK
// characters are ninety bytes and cannot be a table name, so asking for one
// spends a request on an impossibility.
const maxIdentifierBytes = 63

// HintedRelation extracts a real relation name from a PostgREST 404 hint.
// Input:  "Perhaps you meant the table 'public.signatory_submissions'"
// Output: "signatory_submissions", true
func HintedRelation(hint string) (string, bool) {
	i := strings.Index(hint, hintPrefix)
	if i < 0 {
		return "", false
	}
	rest := hint[i+len(hintPrefix):]
	start := strings.IndexByte(rest, '\'')
	if start < 0 {
		return "", false
	}
	rest = rest[start+1:]
	end := strings.IndexByte(rest, '\'')
	if end < 0 {
		return "", false
	}
	name := rest[:end]
	// Strip the schema qualifier: "public.foo" -> "foo".
	if dot := strings.LastIndex(name, "."); dot >= 0 {
		name = name[dot+1:]
	}
	if !safeIdentifier.MatchString(name) || len(name) > maxIdentifierBytes {
		return "", false
	}
	return name, true
}

// HintedFunction extracts a real routine name from a PostgREST 404 hint.
// Input:  "Perhaps you meant to call the function public.admin_list_submissions"
// Output: "admin_list_submissions", true
func HintedFunction(hint string) (string, bool) {
	i := strings.Index(hint, fnHintPrefix)
	if i < 0 {
		return "", false
	}
	name := strings.TrimSpace(hint[i+len(fnHintPrefix):])
	// The hint is unquoted, so stop at the first separator.
	if j := strings.IndexAny(name, " (\t\n'\""); j >= 0 {
		name = name[:j]
	}
	if dot := strings.LastIndex(name, "."); dot >= 0 {
		name = name[dot+1:]
	}
	if !safeIdentifier.MatchString(name) {
		return "", false
	}
	return name, true
}
