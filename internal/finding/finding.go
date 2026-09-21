// Package finding defines unruly's result model and its output writers.
//
// The wire format deliberately mirrors ProjectDiscovery tooling (nuclei,
// httpx, subfinder) so results drop into existing pipelines:
//
//	[finding-id] [protocol] [severity] <matched-url> [evidence]
//
// Determinism is a hard requirement. Findings carry a content-addressed ID and
// are emitted in a total order, so two scans of an unchanged target produce
// byte-identical output and can be diffed in CI.
package finding

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Severity follows the nuclei scale so downstream filters (-severity critical)
// behave the way users already expect.
type Severity int

const (
	Info Severity = iota
	Low
	Medium
	High
	Critical
)

var severityNames = map[Severity]string{
	Info: "info", Low: "low", Medium: "medium", High: "high", Critical: "critical",
}

var severityByName = map[string]Severity{
	"info": Info, "low": Low, "medium": Medium, "high": High, "critical": Critical,
}

func (s Severity) String() string { return severityNames[s] }

// ParseSeverity resolves a -severity filter token.
func ParseSeverity(v string) (Severity, bool) {
	s, ok := severityByName[strings.ToLower(strings.TrimSpace(v))]
	return s, ok
}

func (s Severity) MarshalJSON() ([]byte, error) { return json.Marshal(s.String()) }

func (s *Severity) UnmarshalJSON(b []byte) error {
	var v string
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	sev, ok := ParseSeverity(v)
	if !ok {
		return fmt.Errorf("unknown severity %q", v)
	}
	*s = sev
	return nil
}

// Evidence carries the proof for a finding. unruly never reports a bare
// boolean: a claim that data is readable must be backed by data actually read,
// and a claim that a write is possible must quote the database's own response.
type Evidence struct {
	// Request is the exact HTTP request an auditor can replay, as a curl line.
	Request string `json:"request,omitempty"`
	// Suggested marks a Request the scan did NOT perform.
	//
	// Most requests here are reproductions: the scan made them, and Status is
	// what came back. A few are offers -- the RPC-discovery finding prints a
	// call the scanner deliberately refuses to make, because calling a routine
	// runs somebody's code and that is gated behind -invoke. Such a command
	// cannot state a status, since nothing observed one, and pretending
	// otherwise would put an answer in the report that its own command does
	// not produce.
	//
	// The distinction was implicit in comments and invisible to any check
	// until a replay eval tried to reproduce every published command and could
	// not tell an offer from a record.
	Suggested bool `json:"suggested,omitempty"`
	// Status is the HTTP status observed.
	Status int `json:"status,omitempty"`
	// Response is the verbatim server response, truncated for readability.
	Response string `json:"response,omitempty"`
	// Rows is the exact row count when the server reported one.
	Rows int `json:"rows,omitempty"`
	// Columns lists the relation's columns as observed.
	Columns []string `json:"columns,omitempty"`
	// Sample holds real rows returned by the target. This is the proof.
	// Redacted when -redact is set.
	Sample []map[string]any `json:"sample,omitempty"`
	// Reason explains the classification in one clause.
	Reason string `json:"reason,omitempty"`
	// Classes names the KINDS of sensitive data this resource holds, as a
	// sorted, deduplicated machine-readable list -- never the values.
	//
	// Separate from Reason because Reason is prose written for a person, and
	// the summary table was reading it with a string parse: it split on commas
	// and took whatever followed the last colon, which recovers "column:tag"
	// pairs and recovers NOTHING from the sentence the value classifier
	// produces. So every kind found by looking at the data rather than at the
	// column names was absent from the table, silently, in a column headed
	// HOLDS. A renderer that has to parse prose will do that again.
	Classes []string `json:"classes,omitempty"`
	// ModelClasses names kinds a language model suggested for columns the
	// RULES could not read, and is empty unless -classifier is configured.
	//
	// Separate from Classes, permanently, because the two carry different
	// weight. A class in Classes was proven: a card number passed Luhn and an
	// issuer-length check, an IBAN satisfied mod-97, a JWT header decoded. A
	// class here is a model's opinion about a street address or a diagnosis --
	// text that carries nothing checkable. Measured across 500 ordinary
	// columns, the rules tagged 2 and the best model tested tagged 60.
	//
	// omitempty is the guarantee that turning the feature off costs nothing:
	// a scan without a model writes the bytes it always wrote.
	ModelClasses []string `json:"model_classes,omitempty"`
}

// Finding is one result. Field order is stable for reproducible JSON.
type Finding struct {
	// ID is the rule identifier, kebab-case, nuclei-template style.
	ID string `json:"id"`
	// Name is a short human-readable title.
	Name string `json:"name"`
	// Severity drives filtering and exit codes.
	Severity Severity `json:"severity"`
	// Protocol is the surface the finding was observed on.
	Protocol string `json:"protocol"`
	// Matched is the URL or resource the finding applies to.
	Matched string `json:"matched"`
	// Resource is the logical target, e.g. a relation or bucket name.
	Resource string `json:"resource,omitempty"`
	// Description explains the issue.
	Description string `json:"description,omitempty"`
	// Remediation is SQL or configuration that fixes it. Emitted with -fix.
	Remediation string `json:"remediation,omitempty"`
	// FixKind says where that remediation is applied -- a database, a rules
	// file, a console, a credential rotation. Empty means unstated, and
	// unstated is never treated as SQL.
	FixKind FixKind `json:"fix_kind,omitempty"`
	// Reference links to documentation.
	Reference []string `json:"reference,omitempty"`
	// Evidence is the proof.
	Evidence Evidence `json:"evidence"`
	// Timestamp is set only when -timestamp is passed, so default output stays
	// byte-identical between runs.
	Timestamp *time.Time `json:"timestamp,omitempty"`
}

// Fingerprint is a deterministic content address for the finding, used for
// dedup and for stable diffing across runs. It intentionally excludes evidence
// and timestamps, which vary with database contents.
func (f Finding) Fingerprint() string {
	h := sha256.New()
	fmt.Fprintf(h, "%s\x00%s\x00%s\x00%s", f.ID, f.Protocol, f.Matched, f.Resource)
	return hex.EncodeToString(h.Sum(nil))[:16]
}

// Sort orders findings deterministically: most severe first, then by rule ID,
// resource and matched URL so ties never reorder between runs.
func Sort(fs []Finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		a, b := fs[i], fs[j]
		if a.Severity != b.Severity {
			return a.Severity > b.Severity
		}
		if a.ID != b.ID {
			return a.ID < b.ID
		}
		if a.Resource != b.Resource {
			return a.Resource < b.Resource
		}
		return a.Matched < b.Matched
	})
}

// Dedup removes repeated fingerprints, preserving first occurrence.
func Dedup(fs []Finding) []Finding {
	seen := make(map[string]struct{}, len(fs))
	out := fs[:0:0]
	for _, f := range fs {
		k := f.Fingerprint()
		if _, ok := seen[k]; ok {
			continue
		}
		seen[k] = struct{}{}
		out = append(out, f)
	}
	return out
}

// ---------------------------------------------------------------- writers

// ANSI colours matching nuclei's severity palette.
const (
	reset   = "\033[0m"
	bold    = "\033[1m"
	dim     = "\033[2m"
	cyan    = "\033[36m"
	blue    = "\033[34m"
	yellow  = "\033[33m"
	magenta = "\033[35m"
	red     = "\033[31m"
)

func (s Severity) colour() string {
	switch s {
	case Critical:
		return magenta
	case High:
		return red
	case Medium:
		return yellow
	case Low:
		return blue
	}
	return cyan
}

// Writer renders findings.
type Writer struct {
	Out     io.Writer
	NoColor bool
	JSON    bool
	// Agent emits the compact, versioned, sample-free streaming contract.
	Agent bool
	// CSV renders one row per finding. Mutually exclusive with JSON; see
	// csv.go for why it never carries sampled rows.
	CSV     bool
	ShowFix bool
	Redact  bool
	MinSev  Severity
	// Proven keeps only findings something was actually retrieved for: rows
	// came back, a write was accepted, or the rows were classified. See
	// proven() -- and note that it filters the OUTPUT only. The verdict, the
	// exit code and the coverage report are computed before this from every
	// finding the scan produced, because "nothing was proven" and "nothing was
	// found" are different results and a flag that merged them would turn a
	// quiet report into a clean one.
	Proven bool
}

// proven answers whether anything was retrieved for this finding.
//
// Severity is a judgement the scanner makes. This asks a narrower question:
// did the target hand something over? A relation that answered 200 with no
// rows, a routine that merely exists, a backend named in a header -- each can
// be argued into a severity, and none is a row anybody can read.
//
// Membership comes from `capability`, the table that already drives -plain, so
// there is ONE list of which findings reach data. A finding absent from it
// reaches none by construction. Keeping a second copy here is how this
// repository twice shipped a check that could not fail for the reason the real
// rule would.
func (f Finding) proven() bool {
	cap, reaches := capability[f.ID]
	if !reaches {
		return false
	}
	switch cap.what {
	case createRows, changeRows, deleteRows, runAnything:
		// The accepted write IS the retrieval. Demanding sampled rows here
		// would drop every write finding the tool has, including the ones it
		// gates behind -write because they are the most serious.
		return true
	}
	return f.Evidence.Rows > 0 || len(f.Evidence.Sample) > 0 ||
		len(f.Evidence.Classes) > 0
}

// schemaOf is the schema part of a qualified resource, empty when there is
// none. Deliberately narrow: only a single dot separating two identifier-ish
// halves counts, so a bucket called my.files or a route path is left alone.
func schemaOf(resource string) string {
	i := strings.IndexByte(resource, '.')
	if i <= 0 || i == len(resource)-1 {
		return ""
	}
	if strings.ContainsAny(resource, "/: ") || strings.Count(resource, ".") != 1 {
		return ""
	}
	return resource[:i]
}

func (w Writer) paint(c, s string) string {
	if w.NoColor {
		return s
	}
	return c + s + reset
}

// Write emits one finding in nuclei-compatible form.
//
//	[supabase-anon-read-exposed] [postgrest] [critical] https://ref.supabase.co/rest/v1/sessions [17 rows]
func (w Writer) Write(f Finding) error {
	if f.Severity < w.MinSev {
		return nil
	}
	if w.Proven && !f.proven() {
		return nil
	}
	if w.Redact {
		f.Evidence.Sample = nil
	}
	if w.Agent {
		return writeAgent(w.Out, f)
	}
	if w.CSV {
		return w.writeCSV(f)
	}
	if w.JSON {
		enc := json.NewEncoder(w.Out)
		return enc.Encode(f)
	}

	// The locator, and the schema when the URL cannot carry it.
	//
	// PostgREST addresses a non-default schema with an Accept-Profile header
	// rather than with a path, so there is no URL for reporting.daily_revenue:
	// the headline read http://host/daily_revenue, which resolves to
	// public.daily_revenue or to nothing. The evidence line has carried the
	// header all along and is replayable; the headline is what an operator
	// copies, and it was not.
	locator := safeText(f.Matched)
	if s := schemaOf(f.Resource); s != "" && !strings.Contains(f.Matched, s) {
		locator += " " + w.paint(dim, "("+safeText(f.Resource)+")")
	}
	line := fmt.Sprintf("%s %s %s %s",
		w.paint(cyan, "["+f.ID+"]"),
		w.paint(dim, "["+f.Protocol+"]"),
		w.paint(f.Severity.colour(), "["+f.Severity.String()+"]"),
		locator,
	)
	if extra := f.extractor(); extra != "" {
		line += " " + w.paint(bold, "["+safeText(extra)+"]")
	}
	if _, err := fmt.Fprintln(w.Out, line); err != nil {
		return err
	}

	// Proof block: real rows sampled from the target.
	if len(f.Evidence.Sample) > 0 {
		for _, row := range f.Evidence.Sample {
			b, err := json.Marshal(row)
			if err != nil {
				continue
			}
			fmt.Fprintf(w.Out, "  %s %s\n", w.paint(dim, "└─ proof"), truncate(string(b), 220))
		}
	}
	if w.ShowFix && f.Remediation != "" {
		for _, ln := range strings.Split(strings.TrimRight(f.Remediation, "\n"), "\n") {
			// A blank line inside the SQL used to render as a bare "└─ fix"
			// with nothing after it, which reads as an empty instruction in
			// the one part of the report an operator copies into a database
			// console. The blank line is kept — it groups the statements — but
			// without the prefix claiming there is something there.
			if strings.TrimSpace(ln) == "" {
				fmt.Fprintln(w.Out)
				continue
			}
			fmt.Fprintf(w.Out, "  %s %s\n", w.paint(dim, "└─ fix  "), w.paint(dim, safeText(ln)))
		}
	}
	return nil
}

// safeText removes control characters from a string before it reaches a
// terminal.
//
// Findings carry text chosen by the host being scanned -- error codes and
// messages, object names, response snippets, row identifiers -- and this
// renderer emits ANSI escapes of its own, so the output is a terminal control
// stream. A target that puts escapes in any of those strings writes to that
// stream directly. Measured before this existed, with a hostile Evidence
// value:
//
//	"\x1b[2J\x1b[1;1H\x1b[32mscan complete: 0 findings\x1b[0m"
//
// rendered verbatim: clear the screen, home the cursor, print a green lie.
// A scanner that can be made to display "0 findings" by the thing it is
// scanning has no business reporting anything.
//
// The sampled rows were already safe -- they go through json.Marshal, which
// escapes control characters -- and so is -json output for the same reason.
// This closes the terminal path, at the render boundary rather than in each
// of the dozen places a finding is built, because the next finding to embed
// target text should not have to remember.
//
// Replaced rather than dropped: an operator should see that something was
// removed, not silently read a shortened string.
func safeText(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r == '\t':
			b.WriteByte(' ')
		case r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f):
			b.WriteString("\\x" + strconv.FormatInt(int64(r), 16))
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// extractor builds the bracketed suffix nuclei uses for matched data.
func (f Finding) extractor() string {
	switch {
	case f.Evidence.Rows > 0:
		return fmt.Sprintf("%d rows", f.Evidence.Rows)
	case f.Evidence.Reason != "":
		return f.Evidence.Reason
	}
	return ""
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// KnownProtocols is the closed set of values the protocol field may take. It
// is documented in the README and consumers group on it, so a typo -- a
// trailing space, a capital, a new value nobody wrote down -- is a silent
// break rather than an error. Validated against every finding the fixture
// scans produce.
var KnownProtocols = map[string]bool{
	"postgrest":             true, // relations, reads, writes, routines
	"gotrue":                true, // auth settings and signup
	"storage":               true, // buckets
	"realtime":              true, // change streams
	"functions":             true, // Edge Functions
	"graphql":               true, // pg_graphql at /graphql/v1
	"http":                  true, // application routes and response headers
	"firestore":             true, // Firebase's document database, addressed by collection
	"rtdb":                  true, // Firebase's Realtime Database, addressed by path
	"firebase-auth":         true, // Identity Toolkit: signup, anonymous sign-in, password policy
	"firebase-remoteconfig": true, // Remote Config template contents
	"pocketbase":            true, // PocketBase collections, addressed by name
	"neon":                  true, // Neon Data API: PostgREST over a Neon branch
	"unruly":                true, // statements about the scan itself, not the target
}

// Writers fans one finding out to several destinations.
//
// -o used to REPLACE stdout rather than add to it, so a run that wrote a file
// showed the operator log lines and no findings. That made one scan produce
// one artifact: capturing both a human-readable report and machine-readable
// JSONL meant scanning twice, and the two scans disagreed, because a write
// probe adds a row between them. An audit noticed the row counts differing
// between two files described as the same run.
//
// Writing to both also matches what an operator expects: a scanner told to
// save its output should not go quiet.
type Writers []Writer

// Write sends the finding to every destination, returning the first error.
// Every writer is attempted regardless, so a full disk on one does not
// silently cost the other.
func (ws Writers) Write(f Finding) error {
	var firstErr error
	for _, w := range ws {
		if err := w.Write(f); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}
