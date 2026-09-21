package eval_test

// Every stage must honour the controls that protect the target.
//
// Three times now a stage has been added that quietly bypassed one:
//
//	vocabulary harvesting   built its own HTTP client, never called
//	                        Limiter.Wait, so -rate-limit did not cover it
//	the preview sweep       same, found the same way
//	the preview sweep       declared Options.Timeout, never passed it to
//	                        discover, so -timeout did not bind it either
//
// Each was found by an audit or by writing a test months late, and each is the
// same shape: a control exists, a new stage does not reach it, and nothing
// says so because Go is perfectly happy with a struct field nobody reads.
//
// These tests make that a build failure instead of a discovery. They are
// deliberately structural rather than behavioural — the behavioural tests
// (server-side pacing, server-side timeout) exist per package and are better
// evidence, but they only cover stages somebody remembered to write them for.

import (
	"fmt"

	"github.com/eppser/unruly/internal/emitsites"
	"github.com/eppser/unruly/internal/provider"
	"github.com/eppser/unruly/internal/testrec"
	"github.com/eppser/unruly/internal/wordlist"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// controlFields are the Options fields whose whole purpose is to be passed on.
// A stage that declares one and never reads it has a control in name only.
// controlFields are the options that are promises to somebody else's
// infrastructure rather than tuning hints, which is why forgetting to pass one
// is a bug and not a preference.
//
// UserAgent identifies the scan to the site being read -- it is how the owner
// of a host finds out who is making these requests, and the remediation text
// on unruly-surface-not-assessed tells operators to point it at a page or
// mailbox they control. MaxBundles bounds what this tool fetches from
// somebody else's CDN; cmd/unruly/discovery.go calls it "a promise about what
// this tool does to somebody else's CDN, not a tuning hint" because discovery
// once used its own default of 10 and a scan told to read two bundles read
// ten.
//
// Concurrency, MaxPages and MaxSeeds were measured against the same rule and
// every call site already passes them, but they are left out: they bound
// effort rather than naming the scanner or capping third-party fetches, and a
// future caller taking a package default for one is not obviously wrong.
var controlFields = []string{"Limiter", "Timeout", "UserAgent", "MaxBundles"}

// TestDeclaredControlsAreUsed fails when a package declares a control field
// and never reads it.
func TestDeclaredControlsAreUsed(t *testing.T) {
	root := filepath.Join("..", "..", "internal")
	dirs := map[string]bool{}
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err == nil && info.IsDir() {
			dirs[path] = true
		}
		return err
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}

	var checked int
	for dir := range dirs {
		fset := token.NewFileSet()
		pkgs, perr := parser.ParseDir(fset, dir, func(fi os.FileInfo) bool {
			return !strings.HasSuffix(fi.Name(), "_test.go")
		}, 0)
		if perr != nil {
			t.Fatalf("%s: %v", dir, perr)
		}
		for name, pkg := range pkgs {
			declared := declaredControlFields(pkg)
			if len(declared) == 0 {
				continue
			}
			used := selectedFieldNames(pkg)
			for _, f := range declared {
				checked++
				if !used[f] {
					t.Errorf("package %s declares Options.%s and never reads it: the "+
						"control is present in the API and absent from the behaviour, "+
						"which is how -rate-limit and -timeout each came to skip a stage",
						name, f)
				}
			}
		}
	}
	if checked == 0 {
		t.Fatal("no control fields found; the analyser stopped matching")
	}
	t.Logf("%d declared control fields, all read", checked)
}

// TestStagesWithTheirOwnClientPaceThemselves fails when a package builds an
// http.Client and never waits on a limiter.
//
// internal/client is exempt: it IS the shared client, and the limiter lives
// inside it.
func TestStagesWithTheirOwnClientPaceThemselves(t *testing.T) {
	// Every tree that can hold a stage. "Any stage that builds its own client"
	// is not a statement about one directory, and backend/ was missing from
	// this list while holding two backends that do exactly that -- the control
	// read as green because it was not looking.
	roots := []string{
		filepath.Join("..", "..", "internal"),
		filepath.Join("..", "..", "cmd"),
		filepath.Join("..", "..", "backend"),
	}
	var offenders []string
	walk := func(root string) error {
		return filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() || !strings.HasSuffix(path, ".go") ||
				strings.HasSuffix(path, "_test.go") {
				return err
			}
			if exempt, why := clientExemption(filepath.ToSlash(path)); exempt {
				t.Logf("exempt: %s — %s", path, why)
				return nil
			}
			b, readErr := os.ReadFile(path)
			if readErr != nil {
				return readErr
			}
			src := string(b)
			if !strings.Contains(src, "http.Client{") {
				return nil
			}
			if !strings.Contains(src, ".Wait(") {
				offenders = append(offenders, strings.TrimPrefix(filepath.ToSlash(path), "../../"))
			}
			return nil
		})
	}

	for _, root := range roots {
		if err := walk(root); err != nil {
			t.Fatalf("walking %s: %v", root, err)
		}
	}
	sort.Strings(offenders)
	for _, o := range offenders {
		t.Errorf("%s builds its own http.Client and never waits on a limiter; traffic "+
			"from this stage is not covered by -rate-limit", o)
	}
}

// clientExemption names the packages allowed to build their own HTTP client
// without a limiter, and why. Listed rather than silently skipped: an
// exception nobody can see is how the last blind spot in an audit here
// survived.
func clientExemption(path string) (bool, string) {
	switch {
	case strings.Contains(path, "internal/client/"):
		return true, "it IS the shared client; the limiter lives inside it"
	case strings.Contains(path, "cmd/benchmark/"):
		// Its only client is a readiness probe against a docker stack this
		// command started seconds earlier on loopback -- one GET per second
		// until the port answers. The scan itself is the SCANNER's traffic,
		// issued by the binary under test through its own limiter, which is
		// the thing being measured.
		return true, "build-time only; its client waits for a local fixture it " +
			"started, and the graded traffic is the scanner's own"
	case strings.Contains(path, "internal/semantic/"):
		// Its endpoint is a model server the OPERATOR is running, configured
		// by them and usually on loopback. -rate-limit exists to pace what a
		// scan sends at somebody else's project; this sends nothing at
		// anybody's, and pacing it would only slow the operator's own
		// hardware. The request volume is bounded by the number of columns the
		// rules could not classify, not by a wordlist.
		return true, "the endpoint is the operator's own model server, not a scanned target"
	case strings.Contains(path, "cmd/estate/"):
		// Not a stage, and never aimed at a scanned project. It summarises
		// reports a scan already wrote, and its single request goes to
		// api.supabase.com to ask the OPERATOR'S OWN account which region each
		// of their projects sits in -- the one authoritative source, since
		// Supabase returns no region header and the Cloudflare colo that
		// answers is a different fact from where the data lives. -rate-limit
		// paces what a scan sends at somebody else's project; this sends
		// nothing at anybody's.
		return true, "report tooling, not a stage; its only request asks the " +
			"operator's own account where their projects live"
	case strings.Contains(path, "internal/neonfixture/"):
		// Not a stage, and not aimed at a target. It speaks to a database the
		// OPERATOR owns, over Neon's SQL-over-HTTP endpoint, with the owner's
		// connection string; nothing under cmd/ or backend/ imports it. Its
		// whole reason for existing is to put a lab fixture back the way it
		// was after a write probe. -rate-limit paces what a scan sends at
		// somebody else's project, and this sends nothing at anybody else's.
		return true, "lab tooling, not a stage; it talks only to a database the " +
			"operator owns and the scan path never calls it"
	case strings.Contains(path, "internal/neonauth/"):
		// Not a stage. It authenticates against a lab the operator owns, to
		// establish ground truth and record transcripts; the scan path never
		// calls it. Its traffic is three requests against one host, and that
		// host is never a scan target.
		return true, "lab tooling, not a stage; the scan path never calls it"
	case strings.Contains(path, "internal/exploit/"):
		// go list -deps ./internal/exploit returns only itself, stdlib and
		// yaml. Importing internal/client to satisfy this check would trade
		// the independence two audits verified for a structural nicety, and
		// the independence is the reason the harness's agreement with the
		// scanner means anything.
		//
		// The traffic is bounded by the answer key rather than by a wordlist:
		// one request per exploit, fourteen against the reference lab, against
		// a project the operator owns and is deliberately attacking.
		return true, "it must import nothing from the scanner; its volume is " +
			"bounded by the answer key, not by a wordlist"
	}
	return false, ""
}

func declaredControlFields(pkg *ast.Package) []string {
	var out []string
	for _, file := range pkg.Files {
		ast.Inspect(file, func(n ast.Node) bool {
			ts, ok := n.(*ast.TypeSpec)
			if !ok || ts.Name.Name != "Options" {
				return true
			}
			st, ok := ts.Type.(*ast.StructType)
			if !ok {
				return true
			}
			for _, f := range st.Fields.List {
				for _, nm := range f.Names {
					for _, c := range controlFields {
						if nm.Name == c {
							out = append(out, c)
						}
					}
				}
			}
			return true
		})
	}
	sort.Strings(out)
	return out
}

// selectedFieldNames collects every x.Field reference in the package, which is
// how an Options field is read — EXCLUDING the Options declaration itself.
//
// The first version did not exclude it, and the field declaration
//
//	Limiter *client.Limiter
//
// is itself a selector expression whose Sel.Name is "Limiter". So the type
// reference counted as a use and the check could not see a limiter that was
// declared and never passed — one of the three bugs it was written to catch.
// Replaying all three against it is the only reason that surfaced.
func selectedFieldNames(pkg *ast.Package) map[string]bool {
	out := map[string]bool{}
	for _, file := range pkg.Files {
		ast.Inspect(file, func(n ast.Node) bool {
			if ts, ok := n.(*ast.TypeSpec); ok && ts.Name.Name == "Options" {
				return false // the declaration is not a use
			}
			if sel, ok := n.(*ast.SelectorExpr); ok {
				out[sel.Sel.Name] = true
			}
			return true
		})
	}
	return out
}

// The GitHub workflow and `make ci` must agree on what runs.
//
// They had drifted: `make lint` and `make eval-coverage` were in the Makefile
// target and absent from the workflow, so a push ran a strictly smaller suite
// than a developer typing `make ci` — and the coverage audit, which exists to
// catch a check nobody tests, was itself not running where it would matter
// most.
//
// The same shape as docs/checks.md drifting from the code: two descriptions of
// one thing, with nothing requiring them to match.
func TestWorkflowCoversEveryCITarget(t *testing.T) {
	wf, err := os.ReadFile(filepath.Join("..", "..", ".github", "workflows", "ci.yml"))
	if err != nil {
		t.Skipf("no workflow file: %v", err)
	}
	mk, err := os.ReadFile(filepath.Join("..", "..", "Makefile"))
	if err != nil {
		t.Fatalf("Makefile: %v", err)
	}

	// Only `run:` lines count. A target named in a COMMENT explaining why it
	// is excluded is not a target that runs, and counting it was the first
	// mistake made comparing these two.
	inWorkflow := map[string]bool{}
	for _, line := range strings.Split(string(wf), "\n") {
		t := strings.TrimSpace(line)
		if !strings.HasPrefix(t, "run:") {
			continue
		}
		for _, f := range strings.Fields(strings.TrimPrefix(t, "run:")) {
			inWorkflow[f] = true
		}
	}

	var ciLine string
	for _, line := range strings.Split(string(mk), "\n") {
		if strings.HasPrefix(line, "ci:") {
			ciLine = line
			break
		}
	}
	if ciLine == "" {
		t.Fatal("no ci: target in the Makefile")
	}
	if i := strings.Index(ciLine, "##"); i >= 0 {
		ciLine = ciLine[:i]
	}

	var missing []string
	for _, target := range strings.Fields(strings.TrimPrefix(ciLine, "ci:")) {
		if !inWorkflow[target] {
			missing = append(missing, target)
		}
	}
	sort.Strings(missing)
	for _, m := range missing {
		t.Errorf("`make ci` runs %q and the GitHub workflow does not: a push would run a "+
			"smaller suite than a developer typing make ci", m)
	}
}

// TestWritingStagesHonourNoResidue fails when a stage that can create a row is
// gated on -write alone.
//
// -write and -no-residue answer different questions. -write is consent: may
// this scan send mutating requests at all. -no-residue is a limit on what may
// be left behind afterwards. A stage that checks only the first satisfies
// consent while breaking the promise.
//
// This is not hypothetical and it is not a style rule. The Realtime delivery
// probe was gated on o.write and installed a Trigger that INSERTs a row, so a
// -no-residue scan of the exploit lab still ended with one more row than it
// started with, after the probe stage's own residue bug had already been
// fixed. The scanner reported no residue finding, because the stage that
// created the row was not the stage that checks for residue.
//
// The check is structural: every assignment that installs a row-creating
// callback must sit inside a condition that mentions noResidue.
func TestWritingStagesHonourNoResidue(t *testing.T) {
	src, err := os.ReadFile(filepath.Join("..", "..", "cmd", "unruly", "main.go"))
	if err != nil {
		t.Fatalf("read main.go: %v", err)
	}
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "main.go", src, 0)
	if err != nil {
		t.Fatalf("parse main.go: %v", err)
	}

	// Callbacks whose invocation writes to the target.
	writingCallbacks := map[string]bool{"Trigger": true}

	var offenders []string
	// Walk if-statements, and for each, record whether its condition mentions
	// noResidue before descending into the body.
	var walk func(n ast.Node, guarded bool)
	walk = func(n ast.Node, guarded bool) {
		if n == nil {
			return
		}
		switch v := n.(type) {
		case *ast.IfStmt:
			g := guarded || strings.Contains(exprText(fset, src, v.Cond), "noResidue")
			ast.Inspect(v.Body, func(m ast.Node) bool {
				if inner, ok := m.(*ast.IfStmt); ok && inner != v {
					walk(inner, g)
					return false
				}
				if as, ok := m.(*ast.AssignStmt); ok && !g {
					for _, lhs := range as.Lhs {
						if sel, ok := lhs.(*ast.SelectorExpr); ok && writingCallbacks[sel.Sel.Name] {
							offenders = append(offenders,
								fset.Position(as.Pos()).String()+": "+sel.Sel.Name)
						}
					}
				}
				return true
			})
			return
		}
		ast.Inspect(n, func(m ast.Node) bool {
			if ifs, ok := m.(*ast.IfStmt); ok {
				walk(ifs, guarded)
				return false
			}
			return true
		})
	}
	for _, d := range f.Decls {
		walk(d, false)
	}

	sort.Strings(offenders)
	if len(offenders) > 0 {
		t.Errorf("a row-creating callback is installed without checking noResidue, so "+
			"-no-residue will leave rows on the target:\n  %s", strings.Join(offenders, "\n  "))
	}
}

// exprText recovers the source text of an expression.
func exprText(fset *token.FileSet, src []byte, e ast.Expr) string {
	return string(src[fset.Position(e.Pos()).Offset:fset.Position(e.End()).Offset])
}

// writeExemptPackages are packages that issue a mutating request but cannot
// leave anything behind, with the reason each is safe. The map is the point:
// adding a package here is a deliberate claim somebody can check, whereas
// omitting a package from a hand-written list of things to test is invisible.
var writeExemptPackages = map[string]string{
	"semantic": "its POST goes to a language model the OPERATOR is running, carries " +
		"only a column name and the values the scan already retrieved, and asks for one " +
		"token back. -no-residue is a promise about the TARGET, and this request never " +
		"reaches it. Nothing is created anywhere: the endpoint is stateless inference, " +
		"so there is no artefact to delete and none to report.",
	"selfcheck": "writes only to a relation whose name cannot exist, so no row can " +
		"be created regardless of the target's schema",
	"exploit": "the independent exploit harness, run only by an operator who asked " +
		"for exploitation explicitly; it is not part of a scan",
	"mailbox": "its POST creates an inbox on the OPERATOR's own mail service, never " +
		"on the target, and -no-residue is a promise about the target. The inbox is " +
		"still an artefact this tool created, so it is deleted in a defer and a failed " +
		"deletion is reported rather than swallowed. The stronger guarantee -- that " +
		"-no-residue opens no mailbox AT ALL, because opening one is only ever a " +
		"prelude to registering an account -- is held by TestNoResidueOpensNoMailbox " +
		"in internal/escalate, which is where the decision is actually made.",
	"neonfixture": "it exists to REMOVE residue rather than leave it, and its POST is " +
		"not a write in the sense this flag means: Neon carries SQL over HTTP, so every " +
		"statement travels as a POST -- including the count(*) that verifies a fixture. " +
		"The only mutating statement the package can build is a DELETE of rows carrying " +
		"a marker the caller passed, against the operator's own database. No argument " +
		"makes it write to a scan target, because it never addresses one: the endpoint " +
		"is derived from the owner connection string, not from anything a scan discovered.",
	"neonauth": "its POSTs create an account on Neon Auth, and that account IS an " +
		"artefact -- the exemption is not a claim that nothing is left behind. It is " +
		"a claim about WHERE: -no-residue is a promise about the scan target, and " +
		"this package is never pointed at one. It authenticates against a lab the " +
		"operator owns in order to establish ground truth and record transcripts, " +
		"and the scan path does not call it. Accounts are STABLE and named -- one " +
		"each for the recorder, the exploit harness and the cross-check -- and are " +
		"reused rather than churned, so the residue is three known rows listed in " +
		"fixtures/neon/README.md, not an unbounded trail.",
	"graphql": "POST is GraphQL's transport for READS -- every query this package sends " +
		"is the same read the REST pass already made, and it never sends a mutation. " +
		"An exemption is per-package, so this one cannot notice if that changes; " +
		"TestGraphQLSendsOnlyQueries in internal/graphql is what actually holds it, " +
		"by asserting the wire format of every request.",
}

// TestEveryWritingPackageHonoursNoResidue fails when a package issues a
// mutating request without offering a way to decline it.
//
// This replaces a narrower test that looked for assignments to a callback
// named Trigger in main.go. It passed while -no-residue was being ignored by
// TWO other stages, because they did not go through a callback and were not in
// main.go: the storage probe uploaded an object to every writable bucket, and
// the route probe POSTed to every discovered application route. NoResidue
// reached exactly one package of the four that write.
//
// A test that enumerates the cases somebody already thought of cannot find the
// case they did not. This one starts from the mutating requests themselves.
func TestEveryWritingPackageHonoursNoResidue(t *testing.T) {
	root := filepath.Join("..", "..", "internal")
	mutating := map[string]string{}  // package -> first mutating call seen
	candidate := map[string]string{} // package -> verb literal, before the capability filter
	canRequest := map[string]bool{}  // package -> can reach the HTTP layer at all
	hasField := map[string]bool{}

	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(path, ".go") ||
			strings.HasSuffix(path, "_test.go") {
			return err
		}
		src, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, path, src, 0)
		if err != nil {
			return nil
		}
		pkg := f.Name.Name

		// A package can only ISSUE a request if it can reach the HTTP layer.
		// Without this the rule matched any string literal spelled like a verb,
		// so a summary sentence naming DELETE put internal/finding -- which
		// imports fmt and strings and cannot open a socket -- on the list of
		// packages that write to the target. Exempting it would have been the
		// quick fix and the wrong one: the exemption list is where a check goes
		// to stop meaning anything, and the defect was in the question.
		//
		// Per PACKAGE, not per file. The first attempt tested the file holding
		// the literal, which dropped internal/exploit: its verb strings live in
		// techniques.go while the transport lives in exploit.go, so the check
		// went quiet about a package that really does write to targets. A
		// narrower question is not automatically a better one.
		for _, imp := range f.Imports {
			path := strings.Trim(imp.Path.Value, `"`)
			if path == "net/http" || strings.Contains(path, "/internal/client") {
				canRequest[pkg] = true
			}
		}

		ast.Inspect(f, func(n ast.Node) bool {
			switch v := n.(type) {
			case *ast.BasicLit:
				// A method name passed to a request helper.
				for _, m := range []string{`"POST"`, `"PUT"`, `"PATCH"`, `"DELETE"`} {
					if v.Value == m {
						if _, seen := candidate[pkg]; !seen {
							candidate[pkg] = fset.Position(v.Pos()).String() + " " + v.Value
						}
					}
				}
			case *ast.SelectorExpr:
				// http.MethodPost and friends.
				if strings.HasPrefix(v.Sel.Name, "Method") &&
					v.Sel.Name != "MethodGet" && v.Sel.Name != "MethodHead" {
					if id, ok := v.X.(*ast.Ident); ok && id.Name == "http" {
						if _, seen := candidate[pkg]; !seen {
							candidate[pkg] = fset.Position(v.Pos()).String() + " http." + v.Sel.Name
						}
					}
				}
			case *ast.Field:
				for _, name := range v.Names {
					if name.Name == "NoResidue" {
						hasField[pkg] = true
					}
				}
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	for pkg, where := range candidate {
		if canRequest[pkg] {
			mutating[pkg] = where
		}
	}
	if len(mutating) == 0 {
		t.Fatal("found no mutating requests anywhere, so this test is measuring nothing")
	}

	var offenders []string
	for pkg, where := range mutating {
		if _, exempt := writeExemptPackages[pkg]; exempt || hasField[pkg] {
			continue
		}
		offenders = append(offenders, pkg+" ("+where+")")
	}
	sort.Strings(offenders)
	if len(offenders) > 0 {
		t.Errorf("these packages issue a mutating request but have no NoResidue option, "+
			"so -no-residue does not cover them and the flag promises more than it "+
			"delivers:\n  %s\n\nEither honour the flag or add the package to "+
			"writeExemptPackages with the reason it cannot leave anything behind.",
			strings.Join(offenders, "\n  "))
	}

	// An exemption for a package that no longer writes is stale, and a stale
	// exemption is how a real gap gets waved through later.
	for pkg := range writeExemptPackages {
		if _, writes := mutating[pkg]; !writes {
			t.Errorf("package %q is exempted from -no-residue but issues no mutating "+
				"request; remove the exemption so it cannot cover a future one", pkg)
		}
	}
}

// TestNoBareCounterInsideAnHTTPHandler fails when a test increments a variable
// declared outside an httptest handler.
//
// The handler runs on one goroutine per connection and these tests probe
// concurrently, so `n++` there is a data race. `go test` is perfectly happy
// with it and -race only catches it when two requests actually overlap, which
// they do not reliably do -- one instance survived every race run in this
// project until an audit that kept its logs happened to catch it.
//
// This exists because the same bug was then written AGAIN, one iteration after
// being fixed, in a test whose whole subject was concurrent probing. A pattern
// that recurs that fast is not a lapse of attention to be resolved by paying
// more attention; it needs to be a build failure.
//
// Deliberately narrow: only ++ and -- on a free variable. `append` under a
// mutex is a normal, correct pattern in these tests and is not flagged, and an
// atomic counter reads as .Add(1) rather than ++ so it passes naturally.
func TestNoBareCounterInsideAnHTTPHandler(t *testing.T) {
	root := filepath.Join("..", "..", "internal")
	var offenders []string

	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(path, "_test.go") {
			return err
		}
		src, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		fset := token.NewFileSet()
		f, parseErr := parser.ParseFile(fset, path, src, 0)
		if parseErr != nil {
			return nil
		}

		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || !isHTTPTestServer(call) {
				return true
			}
			// Names bound inside the closure are safe; only free variables are
			// shared with the test goroutine.
			ast.Inspect(call, func(m ast.Node) bool {
				fn, ok := m.(*ast.FuncLit)
				if !ok {
					return true
				}
				local := map[string]bool{}
				for _, p := range fn.Type.Params.List {
					for _, nm := range p.Names {
						local[nm.Name] = true
					}
				}
				ast.Inspect(fn.Body, func(k ast.Node) bool {
					switch v := k.(type) {
					case *ast.AssignStmt:
						if v.Tok == token.DEFINE {
							for _, lhs := range v.Lhs {
								if id, ok := lhs.(*ast.Ident); ok {
									local[id.Name] = true
								}
							}
						}
					case *ast.IncDecStmt:
						if id, ok := v.X.(*ast.Ident); ok && !local[id.Name] {
							offenders = append(offenders,
								fset.Position(v.Pos()).String()+": "+id.Name+
									tokenString(v.Tok))
						}
					}
					return true
				})
				return true
			})
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}

	sort.Strings(offenders)
	if len(offenders) > 0 {
		t.Errorf("a variable declared outside an HTTP handler is incremented inside it, "+
			"which is a data race the race detector catches only when requests "+
			"overlap:\n  %s\n\nUse sync/atomic (`var n atomic.Int64` … `n.Add(1)`).",
			strings.Join(offenders, "\n  "))
	}
}

func isHTTPTestServer(call *ast.CallExpr) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	pkg, ok := sel.X.(*ast.Ident)
	return ok && pkg.Name == "httptest" &&
		(sel.Sel.Name == "NewServer" || sel.Sel.Name == "NewUnstartedServer" ||
			sel.Sel.Name == "NewTLSServer")
}

func tokenString(t token.Token) string {
	if t == token.INC {
		return "++"
	}
	return "--"
}

// TestEveryEvalTestIsSelectedByAMakeTarget fails when a FIXTURE-BACKED test is
// not matched by any `-run` pattern in the Makefile.
//
// Go's -run takes a regexp, and a test whose name does not match is not
// skipped -- it is never mentioned at all. A fixture-backed test also skips
// under the plain unfiltered suite, because that runs without the fixture
// credentials. Between the two, such a test can be written, pass locally with
// `go test -run TheName`, and then never execute again anywhere, while the
// target meant to cover it reports success. `make eval-fixtures` did exactly
// that for a new multi-schema test.
//
// Only fixture-backed tests are checked. Everything else runs under the
// unfiltered `go test ./...`, so an unmatched name there is harmless -- and
// flagging them would have demanded renaming thirty tests that are fine, which
// the first version of this did.
func TestEveryEvalTestIsSelectedByAMakeTarget(t *testing.T) {
	mk, err := os.ReadFile(filepath.Join("..", "..", "Makefile"))
	if err != nil {
		t.Fatalf("read Makefile: %v", err)
	}
	// Every -run pattern the Makefile applies to ./internal/eval.
	var patterns []*regexp.Regexp
	for _, m := range regexp.MustCompile(`-run '([^']+)'`).FindAllStringSubmatch(string(mk), -1) {
		re, err := regexp.Compile(m[1])
		if err != nil {
			t.Fatalf("Makefile -run pattern %q does not compile: %v", m[1], err)
		}
		patterns = append(patterns, re)
	}
	if len(patterns) == 0 {
		t.Fatal("no -run patterns found in the Makefile; this test would pass vacuously")
	}

	// Every Test function declared in this package.
	var names []string
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	fset := token.NewFileSet()
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		src, readErr := os.ReadFile(e.Name())
		if readErr != nil {
			t.Fatalf("read %s: %v", e.Name(), readErr)
		}
		f, parseErr := parser.ParseFile(fset, e.Name(), src, 0)
		if parseErr != nil {
			continue
		}
		for _, d := range f.Decls {
			fn, ok := d.(*ast.FuncDecl)
			if !ok || fn.Recv != nil || !strings.HasPrefix(fn.Name.Name, "Test") {
				continue
			}
			// Fixture-backed means it takes its client from one of the loaders,
			// which skip without the credentials the Makefile targets supply.
			var fixtureBacked bool
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				id, ok := n.(*ast.Ident)
				if !ok {
					return true
				}
				switch id.Name {
				case "loadFixture", "loadHardened", "loadMatrix", "loadEdge":
					fixtureBacked = true
				}
				return true
			})
			if fixtureBacked {
				names = append(names, fn.Name.Name)
			}
		}
	}
	if len(names) == 0 {
		t.Fatal("no fixture-backed tests found; the extractor stopped matching")
	}

	var orphans []string
	for _, n := range names {
		matched := false
		for _, re := range patterns {
			if re.MatchString(n) {
				matched = true
				break
			}
		}
		if !matched {
			orphans = append(orphans, n)
		}
	}
	sort.Strings(orphans)
	if len(orphans) > 0 {
		t.Errorf("these tests are not selected by any Makefile -run pattern, so they never "+
			"execute in the suite while it reports success:\n  %s\n\nRename them to match an "+
			"existing pattern, or widen the pattern in the Makefile.",
			strings.Join(orphans, "\n  "))
	}
}

// TestPerSchemaLoopScansRelationsAndRoutines pins what the multi-schema pass
// actually does, in main.go, rather than what its packages are capable of.
//
// The package-level tests call surface.Routines and probe.Run directly, so
// they pass whether or not the scanner ever invokes them for an extra schema.
// A mutation that disabled routine discovery inside main.go's loop survived
// every one of them -- the emit-site-versus-reachability distinction this
// project keeps rediscovering, arriving here through the orchestration layer.
func TestPerSchemaLoopScansRelationsAndRoutines(t *testing.T) {
	src, err := os.ReadFile(filepath.Join("..", "..", "cmd", "unruly", "main.go"))
	if err != nil {
		t.Fatalf("read main.go: %v", err)
	}
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "main.go", src, 0)
	if err != nil {
		t.Fatalf("parse main.go: %v", err)
	}

	want := map[string]string{
		"enumerate.Run":    "relation names in the extra schema",
		"probe.Run":        "read and write exposure of those relations",
		"surface.Routines": "routines, which are per-schema and whose hint oracle works there",
		"schemas.Discover": "which schemas are exposed at all",
	}
	got := map[string]bool{}

	var inLoop func(ast.Node)
	inLoop = func(n ast.Node) {
		ast.Inspect(n, func(m ast.Node) bool {
			call, ok := m.(*ast.CallExpr)
			if !ok {
				return true
			}
			if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
				if pkg, ok := sel.X.(*ast.Ident); ok {
					got[pkg.Name+"."+sel.Sel.Name] = true
				}
			}
			return true
		})
	}

	// Parsed across main.go AND the ported schemas stage.
	//
	// The multi-schema pass moved to backend/supabase and this half of the
	// guard went blind to it, reporting that the scanner never calls
	// schemas.Discover or probe.Run when it does -- just not from main any
	// more. Sixth occurrence in this rebuild of a check scoped to one FILE
	// silently ceasing to check.
	stageSrc := filepath.Join("..", "..", "backend", "supabase", "schemas_stage.go")
	pf, err := parser.ParseFile(token.NewFileSet(), stageSrc, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", stageSrc, err)
	}
	for _, src := range []*ast.File{f, pf} {
		ast.Inspect(src, func(n ast.Node) bool {
			rng, ok := n.(*ast.RangeStmt)
			if !ok {
				return true
			}
			// main ranged over sch.Extra; the stage ranges over its own
			// discover result. Both are the list of extra exposed schemas.
			sel, ok := rng.X.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "Extra" {
				return true
			}
			inLoop(rng.Body)
			return true
		})
		// schemas.Discover is outside the loop, by construction.
		inLoop(src)
	}

	for call, why := range want {
		if !got[call] {
			t.Errorf("the multi-schema pass never calls %s, so it does not establish %s. "+
				"A package being able to do this is not the same as the scanner doing it.",
				call, why)
		}
	}

	// Presence of the call is not enough. A mutation that kept
	// `escalate.Compare` but ranged over an empty slice instead of the
	// collected per-schema results passed the check above while doing nothing,
	// so the LOOP is what gets pinned: it must iterate schemaScans, the
	// variable the per-schema pass fills in.
	// Parsed across main.go AND the ported stages, not main.go alone.
	//
	// The realtime pass moved to backend/supabase and this guard went blind to
	// it -- the fifth time in this rebuild that a check scoped to one FILE
	// stopped checking when its subject was refactored elsewhere. What it
	// pins is a behaviour ("the per-schema loop actually calls this"), so it
	// has to look wherever that behaviour now lives.
	overSchemas := map[string]bool{}
	sources := []*ast.File{f}
	for _, extra := range []string{
		filepath.Join("..", "..", "backend", "supabase", "realtime_stage.go"),
		// Added when the elevated pass moved out of scanTarget. The guard
		// checks a LOOP over the exposed schemas exists; it does not care
		// which file holds it, but it can only see files it parses -- so a
		// port silently blinds it unless the new file is named here.
		filepath.Join("..", "..", "backend", "supabase", "escalation_stage.go"),
	} {
		fs2 := token.NewFileSet()
		pf, err := parser.ParseFile(fs2, extra, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", extra, err)
		}
		sources = append(sources, pf)
	}
	for _, src := range sources {
		ast.Inspect(src, func(n ast.Node) bool {
			rng, ok := n.(*ast.RangeStmt)
			if !ok {
				return true
			}
			// The collected per-schema results, whatever they are currently
			// called. main used to range over a local `schemaScans`; the ported
			// stages ranged over their own `Schemas` field; both now read the
			// published artifact and range over `schemas.Scans`.
			//
			// Three spellings for one thing, and each rename silently disarmed
			// this check until the rename also broke the build. Matching on the
			// SET of accepted names keeps the guarantee -- some loop over the
			// discovered schemas calls these functions -- without pinning it to
			// one variable name.
			overPerSchema := map[string]bool{"schemaScans": true, "Schemas": true, "Scans": true}
			switch x := rng.X.(type) {
			case *ast.Ident:
				if !overPerSchema[x.Name] {
					return true
				}
			case *ast.SelectorExpr:
				if !overPerSchema[x.Sel.Name] {
					return true
				}
			default:
				return true
			}
			ast.Inspect(rng.Body, func(m ast.Node) bool {
				call, ok := m.(*ast.CallExpr)
				if !ok {
					return true
				}
				if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
					if pkg, ok := sel.X.(*ast.Ident); ok {
						overSchemas[pkg.Name+"."+sel.Sel.Name] = true
					}
				}
				return true
			})
			return true
		})
	}
	for call, why := range map[string]string{
		"escalate.Compare": "the elevated pass would stay narrower than the anonymous one, " +
			"which is the wrong way round: its whole point is that the authenticated role sees more",
		"realtime.Run": "a table in that schema could be streaming every INSERT, UPDATE and " +
			"DELETE to anonymous listeners while the scan never subscribed. Measured on the " +
			"lab: a payload for reporting.metrics was delivered to an anonymous subscriber",
	} {
		if !overSchemas[call] {
			t.Errorf("no loop over the discovered schemas calls %s, so %s", call, why)
		}
	}
}

// TestExplicitSiteIsNotDiscarded pins the flag bug that hid a critical.
//
// The per-target loop reset site to "" and re-derived it from the target, so
// `-target <api> -site <app>` silently scanned the API origin for disclosure
// and never fetched the application. The consequence was not a wrong message:
// it was silence where a service_role key was being served.
//
// The reset itself is still needed -- a target LIST must have each entry
// discover its own site -- so the check is that it is conditional, not absent.
func TestExplicitSiteIsNotDiscarded(t *testing.T) {
	src, err := os.ReadFile(filepath.Join("..", "..", "cmd", "unruly", "main.go"))
	if err != nil {
		t.Fatalf("read main.go: %v", err)
	}
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "main.go", src, 0)
	if err != nil {
		t.Fatalf("parse main.go: %v", err)
	}

	var guarded, found bool
	var walk func(n ast.Node, inGuard bool)
	walk = func(n ast.Node, inGuard bool) {
		ast.Inspect(n, func(m ast.Node) bool {
			if ifs, ok := m.(*ast.IfStmt); ok && ifs != n {
				cond := string(src[fset.Position(ifs.Cond.Pos()).Offset:fset.Position(ifs.Cond.End()).Offset])
				walk(ifs.Body, inGuard || strings.Contains(cond, "explicitSite"))
				return false
			}
			as, ok := m.(*ast.AssignStmt)
			if !ok || len(as.Lhs) != 1 || len(as.Rhs) != 1 {
				return true
			}
			sel, ok := as.Lhs[0].(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "site" {
				return true
			}
			lit, ok := as.Rhs[0].(*ast.BasicLit)
			if !ok || lit.Value != `""` {
				return true
			}
			found = true
			if inGuard {
				guarded = true
			}
			return true
		})
	}
	for _, d := range f.Decls {
		walk(d, false)
	}

	if !found {
		t.Skip("no site reset in main.go; the shape this guards has changed")
	}
	if !guarded {
		t.Error("site is reset to \"\" outside any explicitSite check, so `-target <api> " +
			"-site <app>` discards the operator's own instruction and the application is " +
			"never inspected for disclosure")
	}
}

// TestReadmeCountsMatchReality fails when a number the README states about
// this repository stops being true.
//
// The README's list of checks drifted four times over this project's life, and
// a sweep of its factual claims found three more: it said every remediation
// carries a commented worked example (four of fourteen do), it described an
// audit of "21 finding IDs" when there are 29, and it claimed six negative
// controls when there are five. None of those are typos -- each was true when
// written and quietly stopped being so.
//
// Prose cannot be pinned, but counts can, and counts are what drift. Numbers
// that name a thing this repository contains are checked against the thing.
func TestReadmeCountsMatchReality(t *testing.T) {
	readme, err := os.ReadFile(filepath.Join("..", "..", "README.md"))
	if err != nil {
		t.Fatalf("read README: %v", err)
	}
	text := string(readme)

	// Negative-control hosts, counted from the compose file that defines them.
	compose, err := os.ReadFile(filepath.Join("..", "..", "fixtures", "notsupabase", "docker-compose.yml"))
	if err != nil {
		t.Fatalf("read notsupabase compose: %v", err)
	}
	hosts := len(regexp.MustCompile(`(?m)^  [a-z][a-z-]*:$`).FindAllString(string(compose), -1))
	if hosts == 0 {
		t.Fatal("no services parsed from the notsupabase fixture; the extractor stopped matching")
	}
	if want := numberWord(hosts) + " negative"; !strings.Contains(strings.ToLower(text), strings.ToLower(want)) {
		t.Errorf("the fixture defines %d negative controls; the README does not say %q",
			hosts, want)
	}

	// Firestore candidates, counted from the lists themselves.
	//
	// This number was 719 in the README, in the -vocab-only flag help and in
	// two source comments. It was TRUE when measured and relations.txt has
	// grown since -- the same drift this test exists for, in a claim the test
	// did not yet cover. It is load-bearing: -vocab-only's justification is
	// that an operator should not pay for N metered reads on their own
	// project, so N being wrong undermines the reason the flag exists.
	//
	// No extractor, so nothing can silently stop matching: the count comes
	// from the same call the scan makes.
	candidates := len(wordlist.Merge(wordlist.Collections(), wordlist.Relations()))
	// Read the number IN ITS ROLE, not anywhere in the file.
	//
	// The first version of this check was strings.Contains(text, "884"), which
	// passed after one sentence was reverted to 719 because the other still
	// said 884. A containment check over a whole document is satisfied by any
	// mention, so it graded nothing -- the same "passes for the wrong reason"
	// shape this file exists to catch.
	for _, probe := range []struct{ what, path, pattern string }{
		{"README", "README.md", `scan asks about (\d+)\s*\n?conventional names`},
		{"README", "README.md", `you stop paying\s*\n?for (\d+) guesses`},
		{"-vocab-only help", filepath.Join("cmd", "unruly", "main.go"), `pay for (\d+) guesses`},
	} {
		b, err := os.ReadFile(filepath.Join("..", "..", probe.path))
		if err != nil {
			t.Fatalf("read %s: %v", probe.path, err)
		}
		m := regexp.MustCompile(probe.pattern).FindStringSubmatch(string(b))
		if m == nil {
			t.Fatalf("%s: the candidate-count sentence no longer matches %q, so this "+
				"check grades nothing; move the check with the prose",
				probe.what, probe.pattern)
		}
		if m[1] != strconv.Itoa(candidates) {
			t.Errorf("%s says %s Firestore candidates; the pinned lists hold %d. "+
				"-vocab-only's justification is that an operator should not pay for N "+
				"metered reads on their own project, so N has to be N",
				probe.what, m[1], candidates)
		}
	}

	// Documented finding ids, counted from the table that documents them.
	checks, err := os.ReadFile(filepath.Join("..", "..", "docs", "checks.md"))
	if err != nil {
		t.Fatalf("read checks.md: %v", err)
	}
	// Anchored on the finding-id PREFIXES rather than on "a backtick-quoted
	// word at the start of a row". checks.md also documents the data-class
	// vocabulary as a table -- `credential`, `government-id`, `location` --
	// and the looser pattern counted those seven as finding ids, so
	// documenting the classifier moved a number that has nothing to do with
	// the classifier. A new backend adds its prefix here.
	ids := len(regexp.MustCompile("(?m)^\\| `(unruly|supabase|firebase|neon|pocketbase|app)-[a-z0-9-]+`").
		FindAllString(string(checks), -1))
	if ids == 0 {
		t.Fatal("no ids parsed from checks.md")
	}
	if !strings.Contains(text, fmt.Sprintf("all %d IDs", ids)) {
		t.Errorf("checks.md documents %d finding ids; the README's sweep claim does not "+
			"say \"all %d IDs\"", ids, ids)
	}

	// The mutation count in the auditors' document, against the harness that
	// defines it. This drifted from 24 to 51 unnoticed -- in the one document
	// written for somebody with no reason to trust this code, understating the
	// evidence offered to them.
	mutate, err := os.ReadFile(filepath.Join("..", "..", "scripts", "mutate.py"))
	if err != nil {
		t.Fatalf("read mutate.py: %v", err)
	}
	muts := len(regexp.MustCompile(`(?m)^    \($`).FindAllString(string(mutate), -1))
	if muts == 0 {
		t.Fatal("no mutations parsed from mutate.py; the extractor stopped matching")
	}
	auditing, err := os.ReadFile(filepath.Join("..", "..", "docs", "auditing.md"))
	if err != nil {
		t.Fatalf("read auditing.md: %v", err)
	}
	if !strings.Contains(string(auditing), fmt.Sprintf("%d mutations", muts)) {
		t.Errorf("mutate.py defines %d mutations; docs/auditing.md does not say "+
			"%q", muts, fmt.Sprintf("%d mutations", muts))
	}
}

// numberWord spells small counts the way the README writes them.
func numberWord(n int) string {
	words := []string{"zero", "one", "two", "three", "four", "five", "six",
		"seven", "eight", "nine", "ten"}
	if n < len(words) {
		return words[n]
	}
	return fmt.Sprint(n)
}

// Credential shapes belong in internal/creds, and nowhere else.
//
// They were defined in two packages. internal/discover scanned the live site
// and its bundles; internal/history scanned public archives; each carried its
// own copies. Two shapes were then added -- Postgres connection strings and
// Management API tokens -- and reached only the first. So the one channel
// where a "removed" secret demonstrably still works, a public archive, was not
// looked at for either of the two worst credentials this scanner knows about.
//
// Nothing was wrong with the archive code. It simply did not know the patterns
// had grown, and no test could notice, because both packages were internally
// consistent. A comment saying "keep these in sync" would have been the same
// defect with a note attached.
func TestCredentialPatternsLiveInOneP1ace(t *testing.T) {
	// Both trees. The rule is that NO package defines these, and scoping the
	// walk to internal/ made it quietly weaker than it reads -- a pattern
	// added under cmd/ would have been invisible. Nothing violates it today;
	// this keeps that true after the next time code moves between the two,
	// which it has three times this week.
	roots := []string{filepath.Join("..", "..", "internal"), filepath.Join("..", "..", "cmd")}
	markers := []string{"eyJ", "sb_secret_", "sb_publishable_", "sbp_", "postgres://"}
	// Substring-matching a JWT claim is the same defect one layer up, and it
	// caused a real false negative: `"role":"service_role"` does not match
	// {"role": "service_role"}, so a key with ordinary JSON whitespace was
	// invisible to the channels that read pages and archives.
	claimMarkers := []string{`"role":"`, `"ref":"`}

	var offenders []string
	var scanned int
	walk := func(root string) error {
		return filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") {
				return err
			}
			if strings.HasSuffix(path, "_test.go") || strings.Contains(path, "internal/creds") {
				return nil
			}
			body, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			scanned++
			for i, line := range strings.Split(string(body), "\n") {
				if !strings.Contains(line, "regexp.MustCompile") {
					continue
				}
				for _, m := range markers {
					if strings.Contains(line, m) {
						offenders = append(offenders,
							fmt.Sprintf("%s:%d defines a %q pattern", filepath.Base(path), i+1, m))
					}
				}
			}
			for i, line := range strings.Split(string(body), "\n") {
				if !strings.Contains(line, "strings.Contains") {
					continue
				}
				for _, m := range claimMarkers {
					if strings.Contains(line, m) {
						offenders = append(offenders, fmt.Sprintf(
							"%s:%d reads a JWT claim by substring match (%s)",
							filepath.Base(path), i+1, m))
					}
				}
			}
			return nil
		})
	}
	for _, root := range roots {
		if err := walk(root); err != nil {
			t.Fatalf("walking %s: %v", root, err)
		}
	}
	if scanned < 10 {
		t.Fatalf("only %d files scanned; the walk is not reaching the packages", scanned)
	}
	for _, o := range offenders {
		t.Errorf("%s. Every channel that reads application content must see the same "+
			"credential set, or a shape added in one place silently misses the others -- "+
			"which is how archives went unchecked for connection strings and Management "+
			"API tokens. Put it in internal/creds.", o)
	}
}

// Every probe.Run in the program must inherit -measure.
//
// It did not, and the consequence was the worst this project has produced.
// Measure mode was wired into the default-schema probe and not into the one
// that runs for every ADDITIONAL exposed schema. Pointed at a third-party site
// during a measurement study -- the exact setting where "this scan retrieves
// no data" is the entire basis for scanning at all -- the scanner pulled real
// rows out of somebody's database: avatar_url, bio, college.
//
// It was caught by an independent assertion in the measurement harness, which
// refused to write the record, not by anything in this repository. That is the
// only reason it is a bug rather than an incident.
//
// This is the recurring shape here: a control is added, a parallel stage does
// not inherit it, and every test passes because the stage that WAS wired up
// behaves perfectly. -no-residue did it twice. Structural tests are the answer
// because they check the wiring rather than the behaviour of one path.
func TestEveryProbeRunInheritsMeasure(t *testing.T) {
	// Every construction of probe.Options in the shipped source, wherever it
	// lives -- not just the ones in main.go.
	//
	// This guard used to read main.go alone, and that location-shaped scope
	// failed twice for the same reason. internal/escalate built probe.Options
	// without Measure and was never checked at all, so a scan run with
	// -measure and a -user-jwt retrieved rows through the escalation compare,
	// which is the single thing that mode exists to make impossible. Then
	// porting the probing stage to backend/supabase moved a call out of the
	// file the guard was watching, and it went quiet again.
	//
	// A guard that watches a place goes silent exactly when the code moves.
	// This one watches the behaviour instead.
	var files []string
	for _, root := range []string{"cmd", "backend", "internal"} {
		err := filepath.WalkDir(filepath.Join("..", "..", root),
			func(path string, d fs.DirEntry, err error) error {
				if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") ||
					strings.HasSuffix(path, "_test.go") {
					return err
				}
				// internal/probe DEFINES Options; its own defaults are not a
				// call site and its tests cover them.
				if strings.Contains(path, filepath.Join("internal", "probe")) {
					return nil
				}
				files = append(files, path)
				return nil
			})
		if err != nil {
			t.Fatalf("walk %s: %v", root, err)
		}
	}
	sort.Strings(files)

	var sites int
	for _, path := range files {
		src, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		body := string(src)
		for i := 0; ; {
			j := strings.Index(body[i:], "probe.Options{")
			if j < 0 {
				break
			}
			open := i + j + len("probe.Options{") - 1
			block, ok := braced(body, open)
			if !ok {
				t.Fatalf("%s: unterminated probe.Options at offset %d", path, open)
			}
			sites++
			if !strings.Contains(block, "Measure:") {
				line := 1 + strings.Count(body[:open], "\n")
				t.Errorf("%s:%d constructs probe.Options without Measure. In -measure "+
					"mode this path retrieves rows from the target, which is the one "+
					"thing that mode exists to make impossible:\n%s", path, line, block)
			}
			i = open + len(block)
		}
	}
	// The floor is the anti-vacuous check: if the extractor stops matching --
	// because the construction was renamed, wrapped or moved again -- this
	// test would pass by checking nothing, which is the failure mode it is
	// meant to prevent in the code it watches.
	if sites < 3 {
		t.Fatalf("found %d probe.Options constructions across %d files; the extractor "+
			"stopped matching and this test would pass by checking nothing", sites, len(files))
	}
	t.Logf("%d probe.Options constructions checked across %d files", sites, len(files))
}

// braced returns the {...} block beginning at the brace at index open.
func braced(s string, open int) (string, bool) {
	depth := 0
	for i := open; i < len(s); i++ {
		switch s[i] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return s[open : i+1], true
			}
		}
	}
	return "", false
}

// A stage that runs twice must be configured the same way both times.
//
// This generalises the defect that let -measure leak. The scanner runs several
// stages once for the default schema and again for every additional exposed
// schema, and each repetition constructs its own Options. Add a field, wire it
// into the first construction, and every test still passes -- because the path
// that WAS wired up behaves perfectly. The second path silently keeps the zero
// value, which for a safety control means "off".
//
// It has happened three times: -no-residue twice, -measure once, the last of
// which retrieved a stranger's rows during a study that promised not to.
//
// So the wiring itself is checked. Any Options type constructed more than once
// in main.go must name the same fields each time, with two exemptions:
//
//	Schema        differs by construction; that is what makes it a second pass
//	surface       the per-schema call is Routines(), not Run(): storage and
//	              Edge Functions are project-wide and deliberately not repeated
func TestRepeatedStagesAreConfiguredIdentically(t *testing.T) {
	// main.go AND the ported stages. A pass that runs its package twice used to
	// do so from two literals in main.go; as those passes moved behind the seam
	// the pairs moved with them -- EnumerateStage now holds both
	// enumerate.Options constructions. Reading only main.go left this comparing
	// one type and about to compare none, which is why the floor below fails
	// loudly instead of passing quietly.
	var src []byte
	stageFiles, _ := filepath.Glob(filepath.Join("..", "..", "backend", "supabase", "*_stage.go"))
	var err error
	for _, f := range append([]string{filepath.Join("..", "..", "cmd", "unruly", "main.go")}, stageFiles...) {
		b, rerr := os.ReadFile(f)
		if rerr != nil {
			t.Fatalf("read %s: %v", f, rerr)
		}
		src = append(src, b...)
	}
	_ = err
	if err != nil {
		t.Fatalf("read main.go: %v", err)
	}
	body := string(src)

	// Options types whose repetitions legitimately differ, with the reason.
	exempt := map[string]string{
		"surface": "the per-schema call is Routines(), which deliberately omits the " +
			"project-wide storage and Edge Function options",
	}

	type inst struct {
		line   int
		fields map[string]bool
	}
	found := map[string][]inst{}
	open := regexp.MustCompile(`(\w+)\.Options\{`)
	field := regexp.MustCompile(`\b([A-Z]\w*):`)
	for _, m := range open.FindAllStringSubmatchIndex(body, -1) {
		pkg := body[m[2]:m[3]]
		depth, i := 1, m[1]
		for depth > 0 && i < len(body) {
			switch body[i] {
			case '{':
				depth++
			case '}':
				depth--
			}
			i++
		}
		fs := map[string]bool{}
		for _, f := range field.FindAllStringSubmatch(body[m[1]:i-1], -1) {
			if f[1] != "Schema" {
				fs[f[1]] = true
			}
		}
		found[pkg] = append(found[pkg], inst{1 + strings.Count(body[:m[0]], "\n"), fs})
	}

	var checked int
	for pkg, insts := range found {
		if len(insts) < 2 || exempt[pkg] != "" {
			continue
		}
		checked++
		for i := 1; i < len(insts); i++ {
			for f := range insts[0].fields {
				if !insts[i].fields[f] {
					t.Errorf("%s.Options at main.go:%d omits %q, which the construction at "+
						"line %d sets. A stage configured differently on its second run "+
						"silently takes the zero value, and for a safety control that "+
						"means off.", pkg, insts[i].line, f, insts[0].line)
				}
			}
			for f := range insts[i].fields {
				if !insts[0].fields[f] {
					t.Errorf("%s.Options at main.go:%d omits %q, set at line %d",
						pkg, insts[0].line, f, insts[i].line)
				}
			}
		}
	}
	if checked < 2 {
		t.Fatalf("only %d repeated Options types were compared; the extractor stopped "+
			"matching and this test would pass by checking nothing", checked)
	}
	t.Logf("%d repeated Options types compared", checked)
}

// Findings are constructed in internal packages, never in cmd.
//
// The emit-site coverage check builds its profile from ./internal/... only. A
// finding constructed in cmd/unruly therefore has an emit site the check
// cannot see, and passes only when some OTHER package happens to construct the
// same id -- an accident, not a guarantee.
//
// That accident held for three constructors in main.go until a fourth was
// added whose id was unique, and two audit checks failed with "named by a
// test, but the emitting code never runs". The three were moved here and given
// tests; this keeps the next one from repeating it, with a message that
// explains the rule rather than leaving somebody to rediscover the coverage
// pipeline.
func TestFindingsAreNotConstructedInCmd(t *testing.T) {
	var offenders []string
	var scanned int
	err := filepath.WalkDir(filepath.Join("..", "..", "cmd"), func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return err
		}
		body, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		scanned++
		for i, line := range strings.Split(string(body), "\n") {
			// A composite literal of the finding type, i.e. a constructor.
			//
			// []finding.Finding{...} and map[...]finding.Finding{...} are NOT
			// constructors -- they are a slice and a map OF findings, which any
			// caller may legitimately build. The first version matched on the
			// substring alone and flagged a slice literal in cmd/unruly as an
			// offender, which is the false positive that sends somebody to
			// restructure correct code to satisfy a rule it never broke.
			if (strings.Contains(line, "finding.Finding{") &&
				!strings.Contains(line, "]finding.Finding{")) ||
				strings.Contains(line, "return Finding{") {
				offenders = append(offenders, fmt.Sprintf("%s:%d", filepath.Base(path), i+1))
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking cmd/: %v", err)
	}
	if scanned == 0 {
		t.Fatal("no Go files scanned under cmd/; the walk is not reaching them")
	}
	for _, o := range offenders {
		t.Errorf("%s constructs a finding. The coverage check profiles ./internal/... "+
			"only, so an emit site here is invisible to it and passes only if another "+
			"package builds the same id by coincidence. Put the constructor in "+
			"internal/finding (or the package that owns the surface) and unit-test it "+
			"there.", o)
	}
}

// Every make target the CI workflow invokes must exist.
//
// The workflow has never run. There is no remote, so "CI passes" has been a
// statement about a file nobody executed -- the never-executed-branch problem
// this project refuses everywhere else, sitting in the one file that decides
// whether a contributor's first pull request looks broken.
//
// A renamed or deleted target is the way this breaks, and it breaks for
// somebody else, on their change, in a way that says nothing about their
// change. Checked here because it costs nothing and the failure it prevents is
// paid by a stranger.
func TestCIWorkflowInvokesTargetsThatExist(t *testing.T) {
	wf, err := os.ReadFile(filepath.Join("..", "..", ".github", "workflows", "ci.yml"))
	if err != nil {
		t.Skipf("no workflow: %v", err)
	}
	mk, err := os.ReadFile(filepath.Join("..", "..", "Makefile"))
	if err != nil {
		t.Fatalf("read Makefile: %v", err)
	}

	defined := map[string]bool{}
	for _, m := range regexp.MustCompile(`(?m)^([a-zA-Z][a-zA-Z0-9_-]*):`).FindAllStringSubmatch(string(mk), -1) {
		defined[m[1]] = true
	}
	if len(defined) < 15 {
		t.Fatalf("parsed only %d Makefile targets; the extractor stopped matching", len(defined))
	}

	var checked int
	for _, m := range regexp.MustCompile(`make\s+([a-zA-Z][a-zA-Z0-9_-]*)`).FindAllStringSubmatch(string(wf), -1) {
		target := m[1]
		checked++
		if !defined[target] {
			t.Errorf("ci.yml runs `make %s`, which the Makefile does not define. The first "+
				"person to notice would be a contributor whose pull request fails for a "+
				"reason unrelated to their change.", target)
		}
	}
	if checked < 5 {
		t.Fatalf("found %d make invocations in the workflow; the extractor is not matching",
			checked)
	}
	// And the local mirror of the offline job must exist, or "check before
	// pushing" is advice nobody can follow.
	if !defined["ci-offline"] {
		t.Error("no ci-offline target: the offline job cannot be run locally, so its first " +
			"execution is on somebody's pull request")
	}
	t.Logf("%d make invocations in ci.yml, all defined", checked)
}

// Every mutation must still apply to the code it targets.
//
// A mutation is a patch: find this exact text, replace it, expect the suite to
// go red. Refactor the code it names and the text stops matching, so the
// mutation applies to nothing and is reported as caught -- the false assurance
// this project argues against, aimed at itself. Two broke in one commit
// (extracting classifyCode, widening deleteRow's return) and each cost a full
// audit cycle to find, because the mutation run stops at the first one.
//
// The check lives in mutate.py, which owns the mutation list; duplicating a
// Python string-literal parser in Go got 76 of 79 entries and would have passed
// while three went unchecked, which is the same bug one level up.
func TestEveryMutationStillApplies(t *testing.T) {
	if os.Getenv("UNRULY_MUTATION_ACTIVE") != "" {
		// This check grades mutate.py's bookkeeping AGAINST the tree, and a
		// mutation makes the tree deliberately wrong: the applied mutation has
		// replaced its own old_text, so --check reports that pattern missing
		// and this test fails for a reason unrelated to the behaviour on
		// trial. Left in, it answers for the whole suite and the mutation is
		// scored caught by bookkeeping. The audit runs this in its unmutated
		// `unit` stage, which is the only state where it means anything.
		t.Skip("a mutation is applied; this check only means something on a clean tree")
	}
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 not available; mutate.py owns this check")
	}
	// From the repo root: the mutation list names paths relative to it, and the
	// test runs in internal/eval.
	cmd := exec.Command("python3", filepath.Join("scripts", "mutate.py"), "--check")
	cmd.Dir = filepath.Join("..", "..")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Errorf("mutations no longer apply to the code they target:\n%s", out)
	}
	if !strings.Contains(string(out), "mutations checked") {
		t.Errorf("mutate.py --check did not report a count, so this test cannot tell "+
			"a clean result from a broken invocation:\n%s", out)
	}
	t.Logf("%s", strings.TrimSpace(string(out)))
}

// TestEveryMutationCompiles: a mutation that does not build is scored as
// CAUGHT and tests nothing.
//
// run_suite decides a mutation was caught when `go test` exits non-zero, and a
// build failure does exactly that. So a mutation with a syntax error, or one
// that leaves a variable unused, passes forever while never reaching a test.
//
// Five of eighty-six were in that state when this was written -- one had left
// an unmatched closing paren since the day it was added, and three more fell
// foul of Go's unused-variable rule. Each reported "caught" on every audit.
// The compiler is not the test suite, and a green mutation run that means
// "it did not build" is the false assurance this project argues against,
// pointed at itself.
func TestEveryMutationCompiles(t *testing.T) {
	if os.Getenv("UNRULY_MUTATION_ACTIVE") != "" {
		// This check grades mutate.py's bookkeeping AGAINST the tree, and a
		// mutation makes the tree deliberately wrong: the applied mutation has
		// replaced its own old_text, so --check reports that pattern missing
		// and this test fails for a reason unrelated to the behaviour on
		// trial. Left in, it answers for the whole suite and the mutation is
		// scored caught by bookkeeping. The audit runs this in its unmutated
		// `unit` stage, which is the only state where it means anything.
		t.Skip("a mutation is applied; this check only means something on a clean tree")
	}
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 not available; mutate.py owns this check")
	}
	root := filepath.Join("..", "..")
	cmd := exec.Command("python3", filepath.Join("scripts", "mutate.py"), "--buildcheck")
	cmd.Dir = root

	// Watch the working tree while the child runs.
	//
	// This check is spawned by a Go test, so it runs inside `go test ./...`
	// alongside every other package's compilation. If it applies mutations to
	// the tree the compiler is reading, another package can be built from a
	// mutated dependency and fail for a reason that has nothing to do with it
	// -- and the failure vanishes on the next run, which is the worst possible
	// shape for a defect in a project that grades itself.
	//
	// Observed: cmd/unruly's TestChooseKey failed with the exact three
	// symptoms of the mutation at scripts/mutate.py:1101. A `go test ./...`
	// that included this package had been killed at its timeout, and killing
	// the parent does not kill the child -- mutate.py went on cycling
	// mutations through the tree with nothing left to wait for it. The next
	// command compiled during one of those windows. mutate.py restores
	// correctly on SIGTERM; the hazard is not a failed cleanup, it is that the
	// file is mutated at all while other processes are reading it.
	//
	// Baseline-relative so a developer with local edits is not failed for
	// them. Sampling can only miss a window, never invent one: a false PASS is
	// possible here, a false FAIL is not.
	baseline := gitDirtySet(t, root)
	stop := make(chan struct{})
	var intruded testrec.Log
	var watching sync.WaitGroup
	watching.Add(1)
	go func() {
		defer watching.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			for path := range gitDirtySet(t, root) {
				if !baseline[path] {
					intruded.Add(path)
				}
			}
			time.Sleep(5 * time.Millisecond)
		}
	}()

	out, err := cmd.CombinedOutput()
	close(stop)
	watching.Wait()

	if intruded.Len() > 0 {
		seen := map[string]bool{}
		var names []string
		for _, p := range intruded.Entries() {
			if !seen[p] {
				seen[p] = true
				names = append(names, p)
			}
		}
		sort.Strings(names)
		t.Errorf("--buildcheck modified %d file(s) in the working tree while it ran: %v.\n"+
			"It is spawned from a test, so those writes are visible to every other package "+
			"being compiled by the same `go test` invocation, and to anything else running "+
			"against this checkout. Build the mutations somewhere else.", len(names), names)
	}

	if err != nil {
		t.Errorf("some mutations are killed by the compiler rather than by a test:\n%s", out)
	}
	if !strings.Contains(string(out), "build-checked") {
		t.Errorf("mutate.py --buildcheck did not report a count, so this test cannot "+
			"tell a clean result from a broken invocation:\n%s", out)
	}
	t.Logf("%s", strings.TrimSpace(string(out)))
}

// TestSkippedChecksNameFlagsThatExist: every skipped check tells the operator
// which flag would run it, and an Enable naming a flag that no longer exists
// sends them to a command that does nothing -- worse than saying nothing,
// because it looks actionable.
//
// Nothing checked these strings before. They are what turns the report's
// blindness into something a reader can act on, and they drift exactly the way
// the counts in TestReadmeCountsMatchReality drift.
func TestSkippedChecksNameFlagsThatExist(t *testing.T) {
	read := func(parts ...string) string {
		b, err := os.ReadFile(filepath.Join(append([]string{"..", ".."}, parts...)...))
		if err != nil {
			t.Fatalf("read %v: %v", parts, err)
		}
		return string(b)
	}
	// VarP as well as Var. The shorthand variants are declared with
	// fs.BoolVarP, and a pattern that misses them hides 13 of 49 flags: the
	// first version of this check reported that -write does not exist.
	flags := map[string]bool{}
	for _, m := range regexp.MustCompile(
		`fs\.\w+VarP?\(\s*&?[\w.]+,\s*"([\w-]+)"`).FindAllStringSubmatch(
		read("cmd", "unruly", "main.go"), -1) {
		flags[m[1]] = true
	}
	enables := regexp.MustCompile(`Enable:\s*"([^"]+)"`).FindAllStringSubmatch(
		read("cmd", "unruly", "skipped.go"), -1)

	// BOTH extractors must find something, and the reasons are asymmetric. If
	// the flag pattern breaks, every Enable reads as broken and the failure is
	// loud. If the Enable pattern breaks, there is nothing to check and this
	// test PASSES having graded nothing -- the silent direction, and the one
	// this repository keeps finding in its own checks.
	if len(flags) == 0 {
		t.Fatal("no flags parsed from main.go; the extractor stopped matching")
	}
	if len(enables) == 0 {
		t.Fatal("no Enable strings parsed from skipped.go; the extractor stopped matching")
	}
	for _, e := range enables {
		for _, named := range regexp.MustCompile(`-([a-z][\w-]*)`).FindAllStringSubmatch(e[1], -1) {
			if !flags[named[1]] {
				t.Errorf("a skipped check tells the operator to pass -%s, which this binary "+
					"does not define: %q", named[1], e[1])
			}
		}
	}
	t.Logf("%d Enable strings checked against %d declared flags", len(enables), len(flags))
}

// TestTheReadmeNamesEveryBackend: a backend the scanner recognises and the
// README never mentions is a capability nobody knows exists.
//
// The intro line has already gone stale once, in the UNDERSTATING direction:
// it said "PocketBase in progress" after PocketBase had a detector, two
// stages, fixtures that provision from the repo, four declared limits and a
// graded check inside the audit. Nothing noticed, because nothing connected
// the registry to the prose.
//
// Reads provider.Registered() -- the same list Detect consults -- so there is
// no separate extractor to stop matching. That is the failure this file keeps
// finding in its own checks, and the way to avoid it is to have nothing to
// parse.
func TestTheReadmeNamesEveryBackend(t *testing.T) {
	readme, err := os.ReadFile(filepath.Join("..", "..", "README.md"))
	if err != nil {
		t.Fatalf("read README: %v", err)
	}
	text := strings.ToLower(string(readme))

	names := provider.Registered()
	// A registry that stopped registering would make every assertion below
	// pass by having nothing to assert.
	if len(names) == 0 {
		t.Fatal("no providers registered; this check would pass by grading nothing")
	}
	for _, n := range names {
		if !strings.Contains(text, strings.ToLower(n)) {
			t.Errorf("the scanner recognises %q and the README never mentions it: a "+
				"backend nobody is told about is a capability nobody uses, and a reader "+
				"deciding whether to point this at their stack cannot tell", n)
		}
	}
	t.Logf("%d registered backends, all named in the README: %s",
		len(names), strings.Join(names, " "))
}

// The evals must never ship.
//
// They are build-time only, and today that is true by construction rather than
// by arrangement: nothing outside a test imports internal/eval, so the linker
// drops it and the binary contains none of it. Measured: `go tool nm` finds
// zero internal/eval symbols in the compiled scanner.
//
// That is worth pinning rather than restructuring. Splitting the package into
// a separate module would move ~8,700 lines to buy a property the module
// already has, and the failure mode it protects against -- a scanner shipping
// its own grading harness, answer keys and fixture credentials -- is caught
// exactly as well by refusing the first import.
func TestEvalCodeNeverReachesTheBinary(t *testing.T) {
	var offenders []string
	err := filepath.Walk(filepath.Join("..", ".."), func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		slash := filepath.ToSlash(path)
		if strings.Contains(slash, "/internal/eval/") {
			return nil // the package's own non-test helpers are fine
		}
		// cmd/benchmark is a build-time tool, like coveraudit and
		// exploitcheck. It is not built by `make release`, it is not in the
		// archive that ships, and the rule this guard enforces is about the
		// SHIPPED binary: the grading harness and the fixture credentials must
		// not reach an operator's machine. A scorer that may not import the
		// scoring package could not exist, and the corpus would go on having
		// verified answer keys that nothing was ever graded against.
		if strings.Contains(slash, "/cmd/benchmark/") {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if strings.Contains(string(b), `unruly/internal/eval"`) {
			offenders = append(offenders, path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	sort.Strings(offenders)
	for _, o := range offenders {
		t.Errorf("%s imports internal/eval from non-test code, which links the grading "+
			"harness, the answer keys and the fixture credentials into the shipped "+
			"binary. Evals are build-time only.", o)
	}
}

// -max-rpc-probes is a budget for the SCAN, not for each schema.
//
// It was passed unchanged to every surface.Routines call, so a project exposing
// five schemas spent five times the stated maximum while the flag help said
// "maximum RPC name probes". A bound that multiplies with the target's shape is
// not a bound, and this project's rule is that every budget is bounded and says
// so when it binds.
//
// Structural rather than behavioural: the number of exposed schemas is a
// property of the target, so reproducing the multiplication in a test would
// mean a fixture with several schemas and a budget small enough to bind in each
// -- which pins the arithmetic rather than the rule. What must hold is that no
// call site hands out the raw flag.
func TestRoutineBudgetIsSpentOnceAcrossSchemas(t *testing.T) {
	src, err := os.ReadFile(filepath.Join("..", "..", "cmd", "unruly", "main.go"))
	if err != nil {
		t.Fatalf("read main.go: %v", err)
	}
	body := string(src)

	raw := regexp.MustCompile(`MaxCandidates:\s+o\.maxRPC\b`)
	if got := raw.FindAllString(body, -1); len(got) > 0 {
		t.Errorf("%d routine sweep(s) receive the raw -max-rpc-probes value. Each one then "+
			"spends the full budget, so a project with N exposed schemas costs N times the "+
			"maximum the flag advertises.", len(got))
	}
	// And the remaining budget must actually be decremented, or sharing a
	// variable achieves nothing.
	//
	// The decrement moved when the schemas pass was ported: main used to write
	// "rpcLeft -= spent" inline, and the stage now charges a scan.Budget with
	// RPCRoutines.Take. Either satisfies the property this test exists for --
	// that the allowance one sweep consumes is not available to the next --
	// so it looks for the behaviour in both places rather than for the old
	// spelling in the old file.
	stageSrc, err := os.ReadFile(filepath.Join("..", "..", "backend", "supabase",
		"schemas_stage.go"))
	if err != nil {
		t.Fatalf("read schemas_stage.go: %v", err)
	}
	// Where the sharing lives has moved twice: inline arithmetic in main, then
	// a budget main read back between stages, and now a *scan.Budget that both
	// stages hold. The GUARANTEE is unchanged -- one sweep's spend must reduce
	// what the next sweep may spend -- so this checks that one takes from the
	// budget and the other reads what remains, wherever those two happen to
	// live. Requiring main to read it back outlived the design: main stopped
	// needing to, and the read-back became a dead assignment.
	surfaceSrc, err := os.ReadFile(filepath.Join("..", "..", "backend", "supabase",
		"surface_stage.go"))
	if err != nil {
		t.Fatalf("read surface_stage.go: %v", err)
	}
	decrementedInline := strings.Contains(body, "rpcLeft -= spent")
	decrementedByBudget := strings.Contains(string(stageSrc), "RPCRoutines.Take(") &&
		(strings.Contains(body, "rpcLeft = rpcRoutines.Left()") ||
			strings.Contains(string(surfaceSrc), "RPCRoutines.Left()"))
	if !decrementedInline && !decrementedByBudget {
		t.Error("the shared budget is never decremented, so every sweep sees the full " +
			"amount and the sharing is cosmetic")
	}
	// The default schema runs last and must not be starved by secondary ones.
	if !strings.Contains(body, "extraLeft := o.maxRPC / 2") {
		t.Error("secondary schemas are not capped, and they run BEFORE the default one: " +
			"public can be left with nothing to spend on the surface that matters most")
	}
}

// Every backend this tool scans must be named in the README.
//
// The README described a Supabase-only tool for the whole time Firebase
// support existed: nine checks shipping, and the front door said "A
// deterministic scanner for Supabase misconfigurations" with the word Firebase
// appearing zero times. Somebody deciding whether this would scan their
// Firebase app would have concluded, from the only document they read, that it
// would not.
//
// The Checks section carries a note saying it drifted four separate times,
// "including a period when two criticals were shipping and undocumented". It
// drifted again, in exactly the way it warned about, because a prose list is
// maintained by remembering. This is the check that replaces remembering.
func TestReadmeNamesEveryBackend(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "README.md"))
	if err != nil {
		t.Fatalf("README.md: %v", err)
	}
	readme := strings.ToLower(string(b))

	for _, name := range provider.Registered() {
		if !strings.Contains(readme, strings.ToLower(name)) {
			t.Errorf("this tool scans %s and the README never says so. A reader "+
				"deciding whether it covers their backend has only that file, and "+
				"the answer it gives them is wrong.", name)
		}
	}
}

// The gap list must not claim a limitation the tool no longer has.
//
// README's Known gaps said "UPDATE and DELETE are never tested... no finding
// speaks to either verb" while supabase-anon-update-allowed and
// supabase-anon-delete-allowed were shipping: measured on the lab fixture, a
// -write scan emits ten and three of them respectively.
//
// That direction of staleness is the harmful one. A gap list that misses a real
// limitation oversells; one that claims a limitation already closed makes a
// reader DISCOUNT findings they should act on -- and they will trust the prose,
// because it is the part written for them.
func TestKnownGapsDoNotDenyShippedChecks(t *testing.T) {
	readme, err := os.ReadFile(filepath.Join("..", "..", "README.md"))
	if err != nil {
		t.Fatalf("README.md: %v", err)
	}
	checks, err := os.ReadFile(filepath.Join("..", "..", "docs", "checks.md"))
	if err != nil {
		t.Fatalf("docs/checks.md: %v", err)
	}
	text, documented := string(readme), string(checks)

	// Each pair is a capability and the sentence that would deny it. Narrow on
	// purpose: a fuzzy match over prose would fire on the paragraphs that
	// explain WHY a naive probe was rejected, which are the ones worth keeping.
	for _, tc := range []struct{ id, denial string }{
		{"supabase-anon-update-allowed", "UPDATE and DELETE are never tested"},
		{"supabase-anon-delete-allowed", "no finding speaks to either verb"},
		{"firebase-storage-anon-read", "Cloud Storage is not checked"},
		{"firebase-function-public", "Cloud Functions are not checked"},
	} {
		if strings.Contains(documented, tc.id) && strings.Contains(text, tc.denial) {
			t.Errorf("docs/checks.md documents %s and the README still says %q; a "+
				"reader trusts the prose and would discount a finding they should act on",
				tc.id, tc.denial)
		}
	}
}

// The number of tools the README says were RUN must match the evidence kept.
//
// The README claimed eight scanners "were benchmarked" and that "five of eight
// return an empty result", while benchmark/ holds raw output for three. Eight
// were surveyed; three were measured. The gap is the difference between a claim
// somebody can check and one they have to take on trust -- in the section whose
// own closing line offers the measurements "so the comparison can be checked
// rather than taken on trust".
//
// It is a claim about other people's work, which is the kind this project is
// least entitled to get loose with.
func TestBenchmarkClaimMatchesTheEvidenceKept(t *testing.T) {
	entries, err := os.ReadDir(filepath.Join("..", "..", "benchmark"))
	if err != nil {
		t.Fatalf("benchmark: %v", err)
	}
	tools := map[string]bool{}
	for _, e := range entries {
		name := e.Name()
		if !strings.HasPrefix(name, "raw-") || !strings.HasSuffix(name, ".txt") {
			continue
		}
		// raw-<tool>.txt and raw-<tool>-lab.txt are the same tool.
		tool := strings.TrimSuffix(strings.TrimPrefix(name, "raw-"), ".txt")
		tool = strings.TrimSuffix(tool, "-lab")
		tools[tool] = true
	}

	readme, err := os.ReadFile(filepath.Join("..", "..", "README.md"))
	if err != nil {
		t.Fatalf("README.md: %v", err)
	}
	// The count is spelled out in the prose; keep the two in step.
	// Zero is a legitimate count in the public tree and is checked as one.
	//
	// The raw outputs this graded were transcripts of competing tools run
	// against the author's OWN live projects, and they named those projects.
	// They are not published. The check still runs: if raw output is added
	// back, the README has to count it, and if the README claims a comparison
	// with no evidence kept, that is caught below.
	if len(tools) == 0 {
		if strings.Contains(string(readme), "were run") {
			t.Errorf("the README describes a tool comparison but benchmark/ keeps no " +
				"raw output for it; publish the evidence or drop the claim")
		}
		return
	}
	words := map[int]string{2: "two were run", 3: "three were run", 4: "four were run",
		5: "five were run", 6: "six were run"}
	want, ok := words[len(tools)]
	if !ok {
		t.Fatalf("%d tools have raw output and this test has no phrase for that count; "+
			"add one rather than letting the claim drift", len(tools))
	}
	if !strings.Contains(string(readme), want) {
		t.Errorf("benchmark/ keeps raw output for %d tool(s) %v, and the README does not "+
			"say %q. A comparison offered as checkable must count the evidence it kept.",
			len(tools), keysOf(tools), want)
	}
}

func keysOf(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// A target list that ships populated is an authorization claim the repository
// cannot make on the reader's behalf.
//
// scan/targets-owned.csv shipped with 10,001 real third-party hosts in it -- a
// South African school, a Tunisian personal site -- under a filename asserting
// ownership, while its own header comment said "Add ONLY sites you own or hold
// written permission to test". scan/README.md documents the run as
// `scan-batch.py --targets scan/targets-owned.csv`, and --write turns that into
// INSERT probing. Anyone who cloned this repo and followed its own README
// scanned ten thousand strangers, and the flag telling them it was fine was the
// filename.
//
// The sibling file got this right: scan/test-targets.csv carries loopback only
// and says "Not research data". So the distinction was understood; it just was
// not enforced anywhere, and prose that forbids what the adjacent bytes do is
// not a control. This is that control. Research datasets live outside the repo.
func TestShippedTargetListsNameNoRealHosts(t *testing.T) {
	lists, err := filepath.Glob(filepath.Join("..", "..", "scan", "*.csv"))
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	if len(lists) == 0 {
		t.Fatal("no target lists found under scan/ -- this control now grades nothing")
	}

	// RFC 2606/6761 reserved names plus loopback: hosts that cannot belong to a
	// stranger. Anything else is someone's real machine.
	safe := func(host string) bool {
		host = strings.ToLower(strings.TrimSuffix(host, "."))
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		if ip := net.ParseIP(strings.Trim(host, "[]")); ip != nil {
			return ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified()
		}
		for _, s := range []string{"localhost", "example.com", "example.net", "example.org"} {
			if host == s {
				return true
			}
		}
		for _, s := range []string{".local", ".localhost", ".test", ".invalid", ".example"} {
			if strings.HasSuffix(host, s) {
				return true
			}
		}
		return false
	}

	for _, list := range lists {
		b, err := os.ReadFile(list)
		if err != nil {
			t.Fatalf("%s: %v", list, err)
		}
		name := filepath.Base(list)
		for i, line := range strings.Split(string(b), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "url,") {
				continue
			}
			raw, _, _ := strings.Cut(line, ",")
			u, err := url.Parse(strings.TrimSpace(raw))
			if err != nil || u.Host == "" {
				t.Errorf("%s:%d: unparseable target %q", name, i+1, raw)
				continue
			}
			if !safe(u.Host) {
				t.Errorf("%s:%d names the real host %q. A committed target list is "+
					"read as a list of things it is fine to scan, and this repo has "+
					"no permission to grant for that host. Keep research datasets "+
					"outside the repo and ship only loopback or reserved names.",
					name, i+1, u.Host)
				break // one per file is enough to fail it
			}
		}
	}
}

// A caller that builds a package's Options must set the controls that package
// declares.
//
// TestDeclaredControlsAreUsed is the other half of this and asks a different
// question: does a package READ its own declared field? internal/subdomain
// read Timeout and internal/realtime read Timeout, so that test was satisfied
// while neither control bound anything, because nothing asked whether the
// CALLER passed one -- and it walks internal/ only, so the stages in backend/
// were never looked at.
//
// Both instances were live when this test was written:
//
//	SubdomainStage restated three of subdomain.Options' four fields and
//	dropped Timeout, so every DNS lookup used the package's 5s default.
//	That one was a port regression -- the code it replaced passed it.
//
//	RealtimeStage never set realtime.Options.Timeout, so every subscription
//	used the package's 20s default. That one was never right: the code it
//	replaced did not pass it either.
//
// A zero Timeout is substituted with a package default rather than failing, so
// neither showed up as a bug. -timeout simply did not mean what it said, which
// is the shape this file exists to catch and had caught three times before.
func TestCallersForwardTheControlsTheyAreGiven(t *testing.T) {
	// package name -> control fields its Options declares
	declared := map[string][]string{}
	internalRoot := filepath.Join("..", "..", "internal")
	entries, err := os.ReadDir(internalRoot)
	if err != nil {
		t.Fatalf("read internal/: %v", err)
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		dir := filepath.Join(internalRoot, e.Name())
		fset := token.NewFileSet()
		pkgs, perr := parser.ParseDir(fset, dir, func(fi os.FileInfo) bool {
			return !strings.HasSuffix(fi.Name(), "_test.go")
		}, 0)
		if perr != nil {
			continue
		}
		for name, pkg := range pkgs {
			if fs := declaredControlFields(pkg); len(fs) > 0 {
				declared[name] = fs
			}
		}
	}
	if len(declared) == 0 {
		t.Fatal("no package declares a control field; the analyser stopped matching")
	}

	var literals int
	var offenders []string
	for _, root := range []string{filepath.Join("..", "..", "cmd"), filepath.Join("..", "..", "backend")} {
		err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") ||
				strings.HasSuffix(path, "_test.go") {
				return err
			}
			fset := token.NewFileSet()
			file, perr := parser.ParseFile(fset, path, nil, 0)
			if perr != nil {
				return nil
			}
			ast.Inspect(file, func(n ast.Node) bool {
				cl, ok := n.(*ast.CompositeLit)
				if !ok {
					return true
				}
				sel, ok := cl.Type.(*ast.SelectorExpr)
				if !ok || sel.Sel.Name != "Options" {
					return true
				}
				pkgIdent, ok := sel.X.(*ast.Ident)
				if !ok {
					return true
				}
				want, ok := declared[pkgIdent.Name]
				if !ok {
					return true
				}
				literals++
				set := map[string]bool{}
				for _, elt := range cl.Elts {
					if kv, ok := elt.(*ast.KeyValueExpr); ok {
						if k, ok := kv.Key.(*ast.Ident); ok {
							set[k.Name] = true
						}
					}
				}
				for _, c := range want {
					if !set[c] {
						offenders = append(offenders, fmt.Sprintf("%s:%d builds %s.Options "+
							"without %s", filepath.Base(path), fset.Position(cl.Pos()).Line,
							pkgIdent.Name, c))
					}
				}
				return true
			})
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", root, err)
		}
	}
	if literals == 0 {
		t.Fatal("no <pkg>.Options literal found in cmd/ or backend/; this test is " +
			"checking nothing")
	}
	for _, o := range offenders {
		t.Errorf("%s. The package substitutes its own default for a zero value, so "+
			"nothing fails and the operator's flag silently does not bind this stage. "+
			"Pass it, or forward the whole Options struct the way PreviewStage, "+
			"HistoryStage and RoutesStage do.", o)
	}
	t.Logf("%d Options literals checked across cmd/ and backend/", literals)
}

// Every path that writes the report must canonicalise it first.
//
// scanTarget has three exits. Only one sorted and deduplicated; the other two
// -- a scan that found another backend but no Supabase credential, and one that
// stopped because PostgREST answered PGRST125 and could not be located -- wrote
// findings in the order they were appended, duplicates intact. Both produce a
// stored report an operator keeps, and both are the quiet paths nobody reads
// twice.
//
// finding.Sort is the canonical order this project grades against:
// internal/parity measures agreement after it, eval-determinism grades byte
// identity between two scans of an unchanged target. A report written in a
// different order on a different code path is not comparable to any other
// report the tool produces, and the constraint the README states -- stable
// sorted output -- was true of one exit in three.
//
// So the write loop lives in exactly one place. This fails if a second appears.
func TestTheReportIsWrittenInOnlyOnePlace(t *testing.T) {
	dir := filepath.Join("..", "..", "cmd", "unruly")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read cmd/unruly: %v", err)
	}
	write := regexp.MustCompile(`\bw\.Write\(`)
	var sites []string
	var scanned int
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		scanned++
		for i, line := range strings.Split(string(b), "\n") {
			if write.MatchString(line) {
				sites = append(sites, fmt.Sprintf("%s:%d", name, i+1))
			}
		}
	}
	if scanned == 0 {
		t.Fatal("no Go files scanned under cmd/unruly; this check is vacuous")
	}
	if len(sites) == 0 {
		t.Fatal("no report write found at all; the extractor stopped matching and this " +
			"check would pass against any tree")
	}
	for _, s := range sites {
		if !strings.HasPrefix(s, "emit.go:") {
			t.Errorf("%s writes the report outside emitAll. Sorting and dedup are how "+
				"every report becomes comparable to every other one -- parity measures "+
				"after finding.Sort and eval-determinism grades byte identity -- and an "+
				"exit that writes its own loop skips both. Call emitAll.", s)
		}
	}
}

// The benchmark results must name the scanner that produced them.
//
// benchmark/RESULTS.md is the evidence behind the README's central claim, and
// it had no provenance line at all: no commit, no Go version. Nothing in the
// file distinguished a fresh run from one taken 62 scanner commits earlier,
// which is what it was when this test was written -- the last regeneration was
// eb1ad5e and `make benchmark` is not one of the audit's checks, so nothing
// re-runs it and nothing said it was old.
//
// docs/audit-report.md has carried that line since it existed. This is the
// same rule applied to the other report this project asks people to trust.
func TestBenchmarkResultsNameTheCommitTheyDescribe(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "benchmark", "RESULTS.md"))
	if err != nil {
		t.Fatalf("benchmark/RESULTS.md: %v", err)
	}
	body := string(b)
	if !regexp.MustCompile("(?m)^commit: `[0-9a-f]{7,40}`").MatchString(body) {
		t.Error("benchmark/RESULTS.md does not name the commit it was produced at. A " +
			"results table nobody can date is indistinguishable from a stale one, and " +
			"this one is the evidence for the README's accuracy claim. Regenerate it " +
			"with `make benchmark`.")
	}
	if !strings.Contains(body, "go: `") {
		t.Error("benchmark/RESULTS.md does not name the Go version it was produced with")
	}
}

// The README's benchmark numbers must be the ones in benchmark/RESULTS.md.
//
// The README names three recall figures and calls them "current numbers".
// They were the numbers from a run 62 scanner commits earlier, and regenerating
// the benchmark moved two of them -- relation discovery 87.6 -> 89.9, read
// exposure 83.3 -> 87.5. Nothing noticed, because a percentage in prose is
// exactly as checkable as a count in prose, and this repository has already
// been bitten by the same shape three times: the mutation count, the check
// count, and the sweep's "all N IDs".
//
// Understating accuracy is the harmless direction and this test does not care
// which way it drifts. What it prevents is the README claiming a number that
// the evidence file does not support -- in either direction, on the one claim
// this project is actually about.
func TestTheReadmeQuotesTheBenchmarkItCites(t *testing.T) {
	results, err := os.ReadFile(filepath.Join("..", "..", "benchmark", "RESULTS.md"))
	if err != nil {
		t.Fatalf("benchmark/RESULTS.md: %v", err)
	}
	readme, err := os.ReadFile(filepath.Join("..", "..", "README.md"))
	if err != nil {
		t.Fatalf("README.md: %v", err)
	}

	// dimension -> recall, from the summary table's "| name | NN.N% | ..." rows.
	row := regexp.MustCompile(`(?m)^\| ([a-z-]+) \| ([0-9.]+)% \|`)
	recall := map[string]string{}
	for _, m := range row.FindAllStringSubmatch(string(results), -1) {
		recall[m[1]] = m[2]
	}
	if len(recall) == 0 {
		t.Fatal("no summary rows parsed out of RESULTS.md; the extractor stopped " +
			"matching and this test would pass against any README")
	}

	// The three the README quotes, by the words it quotes them under.
	//
	// Matched across whitespace rather than by literal. This test used to
	// carry the README's exact line breaks -- `"read\n  exposure"` -- so
	// rewrapping a paragraph failed it while the claim was still true, and
	// the natural repair is to edit the pattern, which is one step from
	// editing it until it passes.
	for _, q := range []struct{ prose, dimension string }{
		{`relation\s+discovery`, "relation-discovery"},
		{`read\s+exposure`, "read-exposure"},
		{`write\s+exposure`, "write-exposure"},
	} {
		want, ok := recall[q.dimension]
		if !ok {
			t.Errorf("RESULTS.md has no %q row, but the README quotes it", q.dimension)
			continue
		}
		// Written as 89.9% or as 100%, both of which appear in the prose.
		trimmed := strings.TrimSuffix(want, ".0")
		quoted := regexp.MustCompile(q.prose + `\s+(` +
			regexp.QuoteMeta(want) + `|` + regexp.QuoteMeta(trimmed) + `)%`)
		if !quoted.MatchString(string(readme)) {
			t.Errorf("RESULTS.md reports %s recall of %s%%, and the README does not say "+
				"so next to %q. The README calls these the current numbers.",
				q.dimension, want, q.prose)
		}
	}
}

// Every finding the code can emit must be in docs/checks.md.
//
// This closes a hole that was live. seriousFindingIDs() -- the input to
// TestExploitabilityLedgerCoversEverySeriousFinding, the one check that records
// whether a high-severity claim has anything behind it -- reads docs/checks.md.
// So a finding missing from the documentation escaped the ledger as well: two
// safety nets, the same hole. PocketBase shipped pocketbase-anon-read-exposed
// and pocketbase-authenticated-escalation through both, and documenting them is
// what made the ledger notice they had no demonstration.
//
// The id list comes from internal/emitsites, which is the same extraction
// cmd/coveraudit uses for the coverage guarantee, rather than a second copy of
// the regexes here. A check that grades its own copy of a rule cannot fail for
// a reason the real rule would -- which is a defect this repository has now
// found three times.
func TestEveryEmittableFindingIsDocumented(t *testing.T) {
	roots := []string{
		filepath.Join("..", "..", "internal"),
		filepath.Join("..", "..", "backend"),
		filepath.Join("..", "..", "cmd"),
	}
	emitted, err := emitsites.IDs(roots...)
	if err != nil {
		t.Fatalf("emit sites: %v", err)
	}
	if len(emitted) == 0 {
		t.Fatal("no emit sites found at all; the extractor stopped matching and this " +
			"check would pass against any documentation")
	}

	b, err := os.ReadFile(filepath.Join("..", "..", "docs", "checks.md"))
	if err != nil {
		t.Fatalf("checks.md: %v", err)
	}
	documented := map[string]bool{}
	// Same prefix anchor as the counter above, and for the same reason:
	// checks.md documents the data-class vocabulary in a table too, and a
	// pattern that means "a backtick-quoted word at the start of a row" read
	// `credential` and `location` as finding ids that no code emits. A new
	// backend adds its prefix in both places.
	for _, m := range regexp.MustCompile("(?m)^\\| `((?:unruly|supabase|firebase|neon|pocketbase|app)-[a-z0-9-]+)`").
		FindAllStringSubmatch(string(b), -1) {
		documented[m[1]] = true
	}
	if len(documented) == 0 {
		t.Fatal("no ids parsed out of checks.md")
	}

	for _, id := range emitted {
		if !documented[id] {
			t.Errorf("%s can be emitted and is not in docs/checks.md. An operator who "+
				"receives it has nowhere to look up what it means -- and because the "+
				"exploitability ledger takes its list from that file, an undocumented "+
				"finding is also one nothing checks for a demonstration.", id)
		}
	}
	// The other direction: a documented finding the code cannot produce tells a
	// reader the tool checks something it does not.
	seen := map[string]bool{}
	for _, id := range emitted {
		seen[id] = true
	}
	for id := range documented {
		if !seen[id] {
			t.Errorf("docs/checks.md documents %s and no code emits it, so the "+
				"documentation claims a check that does not exist", id)
		}
	}
}

// gitDirtySet is the set of paths git currently reports as modified.
func gitDirtySet(t *testing.T, root string) map[string]bool {
	t.Helper()
	out, err := exec.Command("git", "-C", root, "status", "--porcelain").Output()
	if err != nil {
		return nil
	}
	dirty := map[string]bool{}
	for _, line := range strings.Split(string(out), "\n") {
		if len(line) > 3 {
			dirty[strings.TrimSpace(line[2:])] = true
		}
	}
	return dirty
}
