package eval_test

// A stage that can decline to run must say so in the report.
//
// `unruly-checks-skipped` is how this scanner says "I did not look at this,
// and here is the flag that would make me". Each declared entry has a test
// asserting it appears under the right condition and vanishes under the right
// flag. Nothing asserted the list was COMPLETE, and docs/auditing.md carried
// that as a known hole.
//
// It was not theoretical. The preview-deployment sweep needs a site or an
// explicit host list, returns early without one, and said nothing at all
// -- while historical-credentials, skipped for the identical
// reason, had always been disclosed. The only difference between them was
// which one somebody remembered to add.
//
// The recorded objection to closing this was that the guard "has to enumerate
// every stage and every input-conditional early return... that is a registry,
// and a registry is what already exists and already drifted". True of a
// hand-written list. Not true of one derived from the code: this finds the
// declining stages by reading them, so a new one cannot be absent from the
// enumeration -- only from the ACCOUNT below, which is a build failure.
//
// What counts as declining is deliberately narrow: a Run method whose opening
// statement is a guard returning nil, on a condition testing its own
// configuration for emptiness. That is a stage saying "nothing was supplied,
// so I did nothing" -- which is precisely the shape an operator would mistake
// for "looked, found nothing". Later returns are not matched: those follow
// work, and work that finds nothing is a real result.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// accountedFor maps a declining stage to how the report accounts for it.
//
// A name here must be either an entry in skippedChecks (checked below against
// cmd/unruly/skipped.go, so a renamed entry breaks this) or a written reason
// why the silence is not a blind spot. Adding a stage that declines and is
// neither is what this test is for.
var accountedFor = map[string]string{
	// Declared in skippedChecks and asserted there by name.
	"preview":    "preview-deployments",
	"history":    "historical-credentials",
	"escalation": "role-escalation",

	// Both added when this check first ran: each returned immediately on an
	// absent input and said nothing at all.
	"routes":     "application-routes",
	"subdomains": "subdomain-enumeration",
}

// notAnOperatorVisibleCheck records stages whose early return is not a
// declined check, with the reason. Kept next to the check rather than in a
// registry elsewhere, so the justification is read by whoever trips it.
var notAnOperatorVisibleCheck = map[string]string{}

func TestEveryStageThatCanDeclineIsAccountedFor(t *testing.T) {
	root := filepath.Join("..", "..")
	declining := map[string]string{} // stage name -> file:line

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && nestedModule(root, path) {
			return fs.SkipDir
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "node_modules", "audit-logs", "dist", "benchmark":
				return fs.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		fset := token.NewFileSet()
		f, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			return perr
		}
		rel, _ := filepath.Rel(root, path)
		names := stageNames(f)
		for _, fn := range f.Decls {
			fd, ok := fn.(*ast.FuncDecl)
			if !ok || fd.Name.Name != "Run" || fd.Recv == nil || fd.Body == nil {
				continue
			}
			recv := receiverType(fd)
			name, ok := names[recv]
			if !ok {
				continue // not a pipeline stage: no Name() method
			}
			if declinesUpFront(fd) {
				declining[name] = rel + ":" + strconv.Itoa(fset.Position(fd.Pos()).Line)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	if len(declining) == 0 {
		t.Fatal("found no declining stages at all; the check below would be vacuous")
	}

	skipped := readFile(t, filepath.Join(root, "cmd", "unruly", "skipped.go"))

	var unaccounted, stale []string
	for name, where := range declining {
		entry, known := accountedFor[name]
		if !known {
			if _, exempt := notAnOperatorVisibleCheck[name]; exempt {
				continue
			}
			unaccounted = append(unaccounted, name+" ("+where+")")
			continue
		}
		if !strings.Contains(skipped, `Name: "`+entry+`"`) {
			stale = append(stale, name+" -> "+entry)
		}
	}
	sort.Strings(unaccounted)
	sort.Strings(stale)

	for _, u := range unaccounted {
		t.Errorf("stage %s returns without doing anything when its input is absent, and "+
			"nothing in skippedChecks says so. To an operator that is indistinguishable "+
			"from a check that ran and found nothing. Add a finding.SkippedCheck naming "+
			"the flag that would run it, then record it in accountedFor -- or, if the "+
			"silence really is not a blind spot, say why in notAnOperatorVisibleCheck.", u)
	}
	for _, s := range stale {
		t.Errorf("accountedFor says %s, but skippedChecks has no entry by that name; "+
			"the entry was renamed or removed and the stage is now silent again", s)
	}

	// The account must not outlive the stages either: an entry naming a stage
	// that no longer declines is a claim nobody is checking.
	for name := range accountedFor {
		if _, ok := declining[name]; !ok {
			t.Errorf("accountedFor names stage %q, which no longer declines up front; "+
				"remove it so the list keeps describing the code", name)
		}
	}
}

// declinesUpFront reports whether the FIRST statement of a Run method is a
// guard that returns nil on its own configuration being empty.
func declinesUpFront(fd *ast.FuncDecl) bool {
	// Any top-level `if <emptiness> { ...; return nil }` that appears BEFORE
	// the stage does any work.
	//
	// This started as "the body's first statement is exactly that if". Two
	// real shapes broke it, and each break hid a stage rather than a bug:
	//
	//   - a stage that SAYS something and then declines (the escalation pass
	//     warning that public signup is open) -- the guard body stopped being
	//     one statement;
	//   - a stage that RESOLVES its input and then declines on it (the same
	//     pass, reading a credential the scan minted mid-run) -- the guard
	//     stopped being the first statement.
	//
	// Both still decline; a detector that only knows the tersest spelling
	// stops seeing them, and a stage it cannot see can lose its skippedChecks
	// entry with nothing failing. So: scan forward while the statements are
	// still bookkeeping -- assignments, declarations, ifs -- and stop at the
	// first one that could be work. Anything after that is not "up front".
	for _, stmt := range fd.Body.List {
		switch st := stmt.(type) {
		case *ast.AssignStmt, *ast.DeclStmt:
			continue
		case *ast.IfStmt:
			if declineShape(st) {
				return true
			}
			continue
		default:
			return false
		}
	}
	return false
}

// declineShape matches `if <emptiness test> { ...; return nil }` where the
// stage says NOTHING on the way out.
//
// A guard that records a finding before returning is not silent, and this test
// is about silence. Neon's enumerate stage is the case: with no token it adds
// its own unruly-surface-not-assessed finding explaining that an empty list
// would read exactly like a project with no tables, then declines. That is the
// behaviour the test wants, arrived at directly instead of through
// skippedChecks, and flagging it would push a correct stage onto an exemption
// list -- which is how exemption lists come to contain things that should not
// be exempt.
func declineShape(ifs *ast.IfStmt) bool {
	if ifs.Else != nil || len(ifs.Body.List) == 0 {
		return false
	}
	if reportsBeforeReturning(ifs.Body) {
		return false
	}
	ret, ok := ifs.Body.List[len(ifs.Body.List)-1].(*ast.ReturnStmt)
	if !ok || len(ret.Results) != 1 {
		return false
	}
	if id, ok := ret.Results[0].(*ast.Ident); !ok || id.Name != "nil" {
		return false
	}
	return testsForEmptiness(ifs.Cond)
}

// reportsBeforeReturning is true when a guard records a finding on its way out.
func reportsBeforeReturning(b *ast.BlockStmt) bool {
	found := false
	ast.Inspect(b, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "Add" {
			found = true
		}
		return true
	})
	return found
}

// testsForEmptiness matches `x == ""`, `x == nil`, `len(x) == 0` and any
// conjunction or disjunction of those.
func testsForEmptiness(e ast.Expr) bool {
	bin, ok := e.(*ast.BinaryExpr)
	if !ok {
		return false
	}
	switch bin.Op {
	case token.LAND, token.LOR:
		return testsForEmptiness(bin.X) && testsForEmptiness(bin.Y)
	case token.EQL:
		switch y := bin.Y.(type) {
		case *ast.BasicLit:
			return y.Kind == token.STRING && y.Value == `""` ||
				y.Kind == token.INT && y.Value == "0" && isLenCall(bin.X)
		case *ast.Ident:
			return y.Name == "nil"
		}
	}
	return false
}

func isLenCall(e ast.Expr) bool {
	call, ok := e.(*ast.CallExpr)
	if !ok {
		return false
	}
	id, ok := call.Fun.(*ast.Ident)
	return ok && id.Name == "len"
}

// stageNames maps a receiver type to the string its Name() method returns.
// Having a Name() is what makes a type a pipeline stage.
func stageNames(f *ast.File) map[string]string {
	out := map[string]string{}
	for _, decl := range f.Decls {
		fd, ok := decl.(*ast.FuncDecl)
		if !ok || fd.Name.Name != "Name" || fd.Recv == nil || fd.Body == nil {
			continue
		}
		if len(fd.Body.List) != 1 {
			continue
		}
		ret, ok := fd.Body.List[0].(*ast.ReturnStmt)
		if !ok || len(ret.Results) != 1 {
			continue
		}
		lit, ok := ret.Results[0].(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			continue
		}
		out[receiverType(fd)] = strings.Trim(lit.Value, `"`)
	}
	return out
}

func receiverType(fd *ast.FuncDecl) string {
	if fd.Recv == nil || len(fd.Recv.List) == 0 {
		return ""
	}
	t := fd.Recv.List[0].Type
	if star, ok := t.(*ast.StarExpr); ok {
		t = star.X
	}
	if id, ok := t.(*ast.Ident); ok {
		return id.Name
	}
	return ""
}

func readFile(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("read %s: %v", p, err)
	}
	return string(b)
}

// docs/auditing.md states how many checks can declare themselves skipped. That
// number was wrong within minutes of being written: two entries were added but
// only one was a new NAME -- application-routes already existed and gained a
// second condition -- and the prose said fifteen where the code says fourteen.
//
// Every other count in this repo that matters is guarded (mutations, checks,
// finding ids) precisely because prose counts rot silently. This one was not.
func TestTheSkippedCheckCountInTheDocsIsTrue(t *testing.T) {
	root := filepath.Join("..", "..")
	src := readFile(t, filepath.Join(root, "cmd", "unruly", "skipped.go"))

	names := map[string]bool{}
	for _, m := range regexp.MustCompile(`Name:\s*"([a-z-]+)"`).FindAllStringSubmatch(src, -1) {
		names[m[1]] = true
	}
	if len(names) == 0 {
		t.Fatal("parsed no skipped-check names; this comparison would be vacuous")
	}

	doc := readFile(t, filepath.Join(root, "docs", "auditing.md"))
	m := regexp.MustCompile(`([A-Za-z]+|\d+) checks declare themselves there`).FindStringSubmatch(doc)
	if m == nil {
		t.Fatal("docs/auditing.md no longer states how many checks can declare " +
			"themselves skipped. If the sentence moved, move this check with it -- " +
			"an unmatched pattern is a count nobody is verifying.")
	}
	claimed, ok := wordNumber(m[1])
	if !ok {
		t.Fatalf("cannot read the claimed count %q", m[1])
	}
	if claimed != len(names) {
		t.Errorf("docs/auditing.md says %d checks can declare themselves skipped; "+
			"cmd/unruly/skipped.go defines %d distinct names", claimed, len(names))
	}
}
