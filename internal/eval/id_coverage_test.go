package eval_test

// Which checks have never fired?
//
// A scanner accumulates checks faster than it accumulates evidence that they
// work. The Realtime probe spent several iterations reporting nothing at all,
// and read as "the target is clean" rather than "this check is inert" — the
// same ambiguity this project exists to remove, sitting inside the project.
//
// An audit across all four eval targets found that 8 of 21 finding IDs had
// ever been emitted by a real scan. The other 13 were reachable only in
// principle. That is not a bug per se: a well-configured target legitimately
// produces no storage-bucket finding. But it means the emitting path has never
// executed, and a branch that has never executed is not known to work.
//
// So every finding ID must be named by at least one test. Naming it is not the
// point; the point is that writing such a test forces the emitting path to be
// exercised with an input that makes it fire.
//
// An audit found the hole in that reasoning: this rule is TEXTUAL. It greps
// string literals out of *_test.go, so it is satisfied by an id appearing
// anywhere in any test — including a hand-built struct in a sorting test that
// never calls the code emitting it. The rule was satisfiable by a comment.
//
// cmd/coveraudit closes that: it reads a coverage profile and requires the
// emit site itself to have executed. Both are kept, because they answer
// different questions. This one is cheap, runs offline, and catches a finding
// with no test at all. That one needs every fixture up and says whether the
// test does anything.
//
// Neither proves a real scan can REACH the finding: a unit test that calls the
// constructor directly covers the emit site while the path to it stays
// unreachable. Demonstrated while building the audit — guarding the storage
// write call with `&& false` left the emit site covered, because
// TestStorageWriteFindingID builds that finding itself. That gap is what the
// exploitability cross-check is for. The allowlist below is the debt
// that predates this rule. It may shrink and must never grow.

import (
	"fmt"
	"github.com/eppser/unruly/internal/finding"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// Matches any canonical finding id, not just the supabase-prefixed ones.
//
// The previous pattern was `"(supabase|unruly)-..."`, which silently
// excluded app-route-auth-inconsistency — a finding the scanner has emitted
// all along, from internal/routes. So the audit that exists to guarantee every
// check is tested had a check it could not see, and the budget of zero it
// enforces was zero out of a set that was quietly one short. Found by the
// documentation test disagreeing with it, which is the argument for having two
// checks that must agree rather than one that is trusted.
// Widening it again to include firebase- closed a second instance of the same
// hole: every Firebase finding was exempt from both this test and the
// documentation one, so those checks reported a clean sweep over a set that
// did not contain them. That widening needs findingIDs below, because the
// protocol namespace overlaps this one -- "firebase-auth" is a protocol, not a
// finding, and the regexp alone cannot tell them apart.
var reFindingID = regexp.MustCompile(`"((?:supabase|unruly|app|firebase)-[a-z0-9-]+)"`)

// findingIDsIn returns the ids in one Go file, reading STRING LITERALS rather
// than raw bytes.
//
// It used to scan the file as text, which meant a quoted id inside a COMMENT
// counted as one the scanner emits. That is not a hypothetical: explaining this
// very trap in a comment was enough to fail the audit, and the same trap --
// a literal that merely looks like a finding id -- has now cost three separate
// fixes. Parsing is both stricter and simpler than teaching a regexp about
// comments, and it cannot drift from what the compiler sees.
func findingIDsIn(path string) ([]string, error) {
	f, err := parser.ParseFile(token.NewFileSet(), path, nil, 0) // 0: comments dropped
	if err != nil {
		return nil, err
	}
	var out []string
	ast.Inspect(f, func(n ast.Node) bool {
		lit, ok := n.(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return true
		}
		v, err := strconv.Unquote(lit.Value)
		if err != nil {
			return true
		}
		out = append(out, findingIDs(`"`+v+`"`)...)
		return true
	})
	return out, nil
}

// findingIDs returns the ids in src, minus the string literals that only look
// like ids. A value in finding.KnownProtocols is a protocol -- consumers group
// on it -- and no finding is ever named after one.
func findingIDs(src string) []string {
	var out []string
	for _, m := range reFindingID.FindAllStringSubmatch(src, -1) {
		if finding.KnownProtocols[m[1]] {
			continue
		}
		out = append(out, m[1])
	}
	return out
}

var reProtocol = regexp.MustCompile(`Protocol:\s*"([^"]*)"`)

// unverifiedIDs are finding IDs whose positive path no test exercises yet.
// Each entry is a check that, if it silently stopped working, no test in this
// repository would notice. Remove entries by writing the test, never by
// deleting the requirement.
var unverifiedIDs = map[string]string{}

// collectIDs returns every finding ID literal found under root, split by
// whether it appeared in a test file.
func collectIDs(t *testing.T, root string) (prod, tested map[string]bool) {
	t.Helper()
	prod, tested = map[string]bool{}, map[string]bool{}
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(path, ".go") {
			return err
		}
		// This file names every ID twice over -- once in the allowlist, once
		// in the regexp's own test data. Counting itself would make the audit
		// report full coverage the moment it was written, which is exactly the
		// failure mode it exists to catch.
		if filepath.Base(path) == "id_coverage_test.go" {
			return nil
		}
		into := prod
		if strings.HasSuffix(path, "_test.go") {
			into = tested
		}
		ids, err := findingIDsIn(path)
		if err != nil {
			return err
		}
		for _, id := range ids {
			into[id] = true
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}
	return prod, tested
}

// TestEveryFindingIDIsNamedByATest fails when a check exists that no test
// exercises, which is the state a check silently decays into.
func TestEveryFindingIDIsNamedByATest(t *testing.T) {
	prod, tested := collectIDs(t, filepath.Join("..", ".."))

	var missing []string
	for id := range prod {
		if tested[id] || unverifiedIDs[id] != "" {
			continue
		}
		missing = append(missing, id)
	}
	sort.Strings(missing)
	for _, id := range missing {
		t.Errorf("finding %q is emitted by the scanner and named by no test: if it "+
			"stopped working, nothing here would notice", id)
	}

	// The allowlist must shrink. An entry for an ID that no longer exists, or
	// that has since been covered, is stale bookkeeping that hides the next
	// real gap.
	for id, why := range unverifiedIDs {
		switch {
		case !prod[id]:
			t.Errorf("allowlist names %q which the scanner no longer emits; remove it", id)
		case tested[id]:
			t.Errorf("allowlist names %q but a test now covers it; remove the entry "+
				"(recorded reason: %s)", id, why)
		}
	}
}

// TestUnverifiedCheckCountIsBounded turns the debt into a number that has to be
// argued down rather than a list that quietly grows.
func TestUnverifiedCheckCountIsBounded(t *testing.T) {
	const budget = 0
	if n := len(unverifiedIDs); n > budget {
		t.Fatalf("%d finding IDs have no positive-path test, budget is %d; lower the "+
			"budget when you close one, never raise it", n, budget)
	}
	if n := len(unverifiedIDs); n < budget {
		t.Logf("%d unverified checks remain, below the budget of %d -- lower the budget "+
			"to %d to lock the progress in", n, budget, n)
	}
}

// TestEveryFindingUsesAKnownProtocol closes the other half of the schema
// contract. The field names are pinned in internal/finding; this pins the
// values of the one field consumers group on.
func TestEveryFindingUsesAKnownProtocol(t *testing.T) {
	prod, _ := collectIDs(t, filepath.Join("..", ".."))
	if len(prod) == 0 {
		t.Fatal("no finding ids collected; nothing was asserted")
	}
	// Protocols are literals next to the ids, so the same walk finds them.
	protos := map[string]bool{}
	err := filepath.Walk(filepath.Join("..", ".."), func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(path, ".go") ||
			strings.HasSuffix(path, "_test.go") {
			return err
		}
		b, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		for _, m := range reProtocol.FindAllStringSubmatch(string(b), -1) {
			protos[m[1]] = true
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	if len(protos) == 0 {
		t.Fatal("no protocol literals found; the extractor stopped matching")
	}
	for p := range protos {
		if !finding.KnownProtocols[p] {
			t.Errorf("finding uses protocol %q, which is not in finding.KnownProtocols "+
				"and is not documented; consumers group on this field", p)
		}
	}
}

// TestEveryFindingIDIsDocumented pins the check list to the code.
//
// The README's list of checks drifted four times over this project's life,
// each time describing the tool as it had been when somebody last remembered
// to edit it. Two criticals — a routine returning rows, and an anonymously
// writable storage bucket — shipped while absent from it. For a document about
// a security tool that is the same class of problem as a stale safety control,
// which this project has already learned twice.
//
// docs/checks.md is therefore not prose about the tool: it is a table keyed by
// canonical id, and this test requires the two sets to match exactly. A
// finding added without a line fails; a line for a finding that no longer
// exists fails too, because stale documentation is what hid the last drift.
func TestEveryFindingIDIsDocumented(t *testing.T) {
	prod, _ := collectIDs(t, filepath.Join("..", ".."))
	b, err := os.ReadFile(filepath.Join("..", "..", "docs", "checks.md"))
	if err != nil {
		t.Fatalf("docs/checks.md: %v", err)
	}
	doc := string(b)

	documented := map[string]bool{}
	for _, m := range regexp.MustCompile("`((?:supabase|unruly|app|firebase)-[a-z0-9-]+)`").
		FindAllStringSubmatch(doc, -1) {
		documented[m[1]] = true
	}

	var missing, stale []string
	for id := range prod {
		if !documented[id] {
			missing = append(missing, id)
		}
	}
	for id := range documented {
		if !prod[id] {
			stale = append(stale, id)
		}
	}
	sort.Strings(missing)
	sort.Strings(stale)
	for _, id := range missing {
		t.Errorf("%q is emitted by the scanner and absent from docs/checks.md", id)
	}
	for _, id := range stale {
		t.Errorf("docs/checks.md documents %q, which the scanner no longer emits", id)
	}
}

// severityParameterised are findings whose severity is decided by the caller
// and passed in, so it cannot be read from the constructor.
//
// Listed rather than skipped silently: an exception nobody can see is how the
// last blind spot in this audit survived. Both are documented with their range
// in docs/checks.md and covered by tests in their own packages.
var severityParameterised = map[string]string{
	"supabase-rpc-discoverable": "severity is chosen by the caller from the routine name",
	"unruly-intent-violation":   "severity follows whether reality is more permissive or more restrictive than intent",
	"unruly-checks-skipped": "built by finding.Coverage, which takes no severity " +
		"decision at the call site",
}

var (
	reFuncStart = regexp.MustCompile(`(?m)^func [^\n]*\{`)
	reSevConst  = regexp.MustCompile(`finding\.(Critical|High|Medium|Low|Info)\b`)
	reIDInBody  = regexp.MustCompile(`ID:\s*"([a-z][a-z0-9-]+)"`)
)

// TestDocumentedSeverityMatchesTheCode is the second half of the docs
// contract. docs/checks.md already has to name every finding; this requires it
// to name every severity that finding can actually take.
//
// A document that understates a severity is worse than one that omits the
// finding: the reader sees "medium", deprioritises it, and never learns the
// same check reports critical under other conditions. Measured when this was
// written — the table said supabase-edge-function-no-jwt was medium while the
// code emits high for a privileged-looking name.
func TestDocumentedSeverityMatchesTheCode(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "docs", "checks.md"))
	if err != nil {
		t.Fatalf("docs/checks.md: %v", err)
	}
	// Tolerant of whitespace, because the strict form silently skipped a row
	// that had been reformatted: `|`id`| info |` did not match, the severity
	// check `continue`d, and a critical finding could be documented as info
	// with the suite green. An audit demonstrated exactly that.
	reRow := regexp.MustCompile("^\\s*\\|\\s*`([a-z][a-z0-9-]+)`\\s*\\|(.*)$")
	rows := map[string]string{}
	for _, line := range strings.Split(string(b), "\n") {
		if m := reRow.FindStringSubmatch(line); m != nil {
			rows[m[1]] = strings.ToLower(m[2])
		}
	}
	// An id that is documented but whose row could not be parsed is a hole
	// this test would otherwise pass over in silence.
	documentedAnywhere := map[string]bool{}
	for _, m := range regexp.MustCompile("`((?:supabase|unruly|app)-[a-z0-9-]+)`").
		FindAllStringSubmatch(string(b), -1) {
		documentedAnywhere[m[1]] = true
	}
	for id := range documentedAnywhere {
		if _, ok := rows[id]; !ok {
			t.Errorf("%q appears in docs/checks.md but not as a parseable table row, so "+
				"its severity cannot be checked against the code", id)
		}
	}

	emitted := severitiesByID(t, filepath.Join("..", ".."))
	if len(emitted) == 0 {
		t.Fatal("no severities extracted; the analyser stopped matching")
	}
	for id, sevs := range emitted {
		if why, ok := severityParameterised[id]; ok {
			t.Logf("%s: severity not readable from the constructor (%s)", id, why)
			continue
		}
		row, documented := rows[id]
		if !documented {
			continue // the other test reports undocumented ids
		}
		for _, sev := range sevs {
			if !strings.Contains(row, strings.ToLower(sev)) {
				t.Errorf("%s can be emitted at %s and docs/checks.md does not say so; "+
					"a reader who sees only the lower severity will deprioritise it",
					id, strings.ToLower(sev))
			}
		}
	}
}

// severitiesByID reports, per finding id, every severity assigned inside the
// same finding.Finding literal.
//
// Parsed with go/ast rather than scanned with regexps, after an audit defeated
// two successive text-based versions. The first read the enclosing FUNCTION,
// so a finding built inline in a large one was credited with every severity
// that function mentioned. The second matched braces by counting them, with
// no awareness of strings — putting "}}" in a Name field above the ID field
// truncated the literal, produced no id, and removed the finding from the
// audit entirely. Both mutations compiled, passed gofmt, and left the suite
// green.
//
// A parser does not have that class of failure. It also removes an unwritten
// rule the brace-counter imposed: that ID must be the first field.
func severitiesByID(t *testing.T, root string) map[string][]string {
	t.Helper()
	out := map[string]map[string]bool{}
	add := func(id, sev string) {
		if out[id] == nil {
			out[id] = map[string]bool{}
		}
		out[id][sev] = true
	}

	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err == nil && info.IsDir() && nestedModule(root, path) {
			return filepath.SkipDir
		}
		if err != nil || info.IsDir() || !strings.HasSuffix(path, ".go") ||
			strings.HasSuffix(path, "_test.go") {
			return err
		}
		fset := token.NewFileSet()
		file, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			return fmt.Errorf("%s: %w", path, perr)
		}
		ast.Inspect(file, func(n ast.Node) bool {
			lit, ok := n.(*ast.CompositeLit)
			if !ok || !isFindingLiteral(lit) {
				return true
			}
			ids, sevs := literalIDsAndSeverities(file, lit)
			if len(ids) == 0 {
				// A constructor that selects both together, in one statement:
				//
				//	sev, id = finding.Critical, "supabase-historic-…"
				//
				// Pairing them is exact. The cross-product fallback below
				// would attribute all three severities to all three ids and
				// demand documentation that is simply wrong.
				if paired := pairedIDSeverities(file, lit); len(paired) > 0 {
					for id, sev := range paired {
						add(id, sev)
					}
					return true
				}
				// The id comes from a variable. Fall back to the enclosing
				// function, which over-reports rather than under-reports: an
				// over-report demands documentation that may already exist,
				// while an under-report hides a finding nobody checks.
				ids = enclosingFunctionIDs(file, lit)
			}
			for _, id := range ids {
				for _, sev := range sevs {
					add(id, sev)
				}
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	res := map[string][]string{}
	for id, set := range out {
		for sev := range set {
			res[id] = append(res[id], sev)
		}
		sort.Strings(res[id])
	}
	return res
}

// pairedIDSeverities finds `sev, id = finding.X, "some-finding-id"` style
// assignments in the function containing the literal, and pairs each id with
// the severity assigned alongside it.
func pairedIDSeverities(file *ast.File, lit *ast.CompositeLit) map[string]string {
	fn := enclosingFunc(file, lit)
	if fn == nil {
		return nil
	}
	out := map[string]string{}
	ast.Inspect(fn, func(n ast.Node) bool {
		as, ok := n.(*ast.AssignStmt)
		if !ok || len(as.Rhs) < 2 {
			return true
		}
		var id, sev string
		for _, r := range as.Rhs {
			switch v := r.(type) {
			case *ast.BasicLit:
				if v.Kind == token.STRING {
					if u, err := strconv.Unquote(v.Value); err == nil &&
						reFindingID.MatchString(strconv.Quote(u)) {
						id = u
					}
				}
			case *ast.SelectorExpr:
				if pkg, ok := v.X.(*ast.Ident); ok && pkg.Name == "finding" {
					switch v.Sel.Name {
					case "Critical", "High", "Medium", "Low", "Info":
						sev = v.Sel.Name
					}
				}
			}
		}
		if id != "" && sev != "" {
			out[id] = sev
		}
		return true
	})
	return out
}

func isFindingLiteral(lit *ast.CompositeLit) bool {
	sel, ok := lit.Type.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "Finding" {
		return false
	}
	pkg, ok := sel.X.(*ast.Ident)
	return ok && pkg.Name == "finding"
}

// literalIDsAndSeverities reads the ID and Severity fields of one literal.
func literalIDsAndSeverities(file *ast.File, lit *ast.CompositeLit) (ids, sevs []string) {
	for _, el := range lit.Elts {
		kv, ok := el.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		key, ok := kv.Key.(*ast.Ident)
		if !ok {
			continue
		}
		switch key.Name {
		case "ID":
			if bl, ok := kv.Value.(*ast.BasicLit); ok && bl.Kind == token.STRING {
				if v, err := strconv.Unquote(bl.Value); err == nil {
					ids = append(ids, v)
				}
			}
		case "Severity":
			ast.Inspect(kv.Value, func(n ast.Node) bool {
				if sel, ok := n.(*ast.SelectorExpr); ok {
					if pkg, ok := sel.X.(*ast.Ident); ok && pkg.Name == "finding" {
						sevs = append(sevs, sel.Sel.Name)
					}
				}
				return true
			})
		}
	}
	// A severity computed above the literal and passed by name — the shape
	// most constructors use:
	//
	//	sev := finding.High
	//	if len(rel.Sensitive) > 0 { sev = finding.Critical }
	//	return finding.Finding{ ID: "…", Severity: sev, … }
	//
	// Fourteen of twenty-six findings look like this. The first go/ast version
	// of this file returned nothing for them and the suite stayed green, which
	// made the analyser far weaker than the regexp it replaced while looking
	// stricter — the exact silent under-report it was rewritten to prevent.
	if len(sevs) == 0 {
		sevs = enclosingFunctionSeverities(file, lit)
	}
	return ids, sevs
}

// enclosingFunctionSeverities collects every finding.<Severity> named in the
// function containing the literal.
//
// Over-reports by design: a constructor choosing between High and Critical
// yields both, so the documentation must list both. An over-report demands
// documentation that may already be true; an under-report hides a severity the
// code can actually emit, and a reader who sees only the lower one
// deprioritises it.
func enclosingFunctionSeverities(file *ast.File, lit *ast.CompositeLit) []string {
	fn := enclosingFunc(file, lit)
	if fn == nil {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	ast.Inspect(fn, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		pkg, ok := sel.X.(*ast.Ident)
		if !ok || pkg.Name != "finding" {
			return true
		}
		switch sel.Sel.Name {
		case "Critical", "High", "Medium", "Low", "Info":
			if !seen[sel.Sel.Name] {
				seen[sel.Sel.Name] = true
				out = append(out, sel.Sel.Name)
			}
		}
		return true
	})
	return out
}

// enclosingFunc returns the function declaration containing a node.
func enclosingFunc(file *ast.File, n ast.Node) *ast.FuncDecl {
	for _, d := range file.Decls {
		f, ok := d.(*ast.FuncDecl)
		if !ok || f.Body == nil {
			continue
		}
		if f.Pos() <= n.Pos() && n.End() <= f.End() {
			return f
		}
	}
	return nil
}

// enclosingFunctionIDs returns the finding ids named anywhere in the function
// containing the literal, for the case where ID is assigned from a variable.
func enclosingFunctionIDs(file *ast.File, lit *ast.CompositeLit) []string {
	fn := enclosingFunc(file, lit)
	if fn == nil {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	ast.Inspect(fn, func(n ast.Node) bool {
		bl, ok := n.(*ast.BasicLit)
		if !ok || bl.Kind != token.STRING {
			return true
		}
		v, err := strconv.Unquote(bl.Value)
		if err != nil || !reFindingID.MatchString(strconv.Quote(v)) {
			return true
		}
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
		return true
	})
	return out
}
