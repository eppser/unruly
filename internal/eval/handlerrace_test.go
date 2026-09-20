package eval_test

// A test HTTP handler must not mutate captured state without holding a lock.
//
// This exists because of a defect that shipped: the eval for Neon table
// enumeration recorded every probed path with
//
//	seen = append(seen, name)
//
// inside its httptest handler. net/http serves each connection on its own
// goroutine, the enumeration stage probes with bounded concurrency, and so
// two goroutines appended to the same slice header at once. `go test ./...`
// passed. `go test -race` failed, and only found it because the scheduler
// happened to overlap two appends in that run.
//
// That last clause is the reason for a static check rather than a reliance on
// -race. The race detector is dynamic: it reports the overlaps it observes,
// so a racy fixture that gets lucky reports nothing and the guard built on it
// looks sound. A recorded slice that silently drops an entry does not make a
// test fail loudly; it makes it assert about the wrong evidence. For a repo
// whose whole product is "the evidence is real", a fixture that quietly
// mis-records what was sent is the worst kind of defect, because every
// assertion downstream of it inherits the doubt.
//
// This is the second time the class has bitten. internal/enumerate's control
// test carries a comment recording the first: a bare `throttled++` in a
// fixture, "undetected for a long time", found by an audit run that happened
// to keep its logs. That one was fixed where it was found, and the class went
// on to reappear in a fixture written months later by someone who had read
// that very comment. A note in one file does not generalise; a check does.
//
// The rule is deliberately absolute — mutate captured state under a lock, or
// not at all — because "this handler is only ever called sequentially" is a
// property of the caller, invisible here, and true only until someone adds
// concurrency to the stage under test.
//
// The check is syntactic, and so has limits worth stating. It sees assignment
// and ++/--, not a mutating method call on a captured value, so a fixture that
// records through a helper of its own is invisible to it. It reads a name as
// locally declared if the handler declares it ANYWHERE, so a captured name
// shadowed later in the same body is missed. Both are gaps in the direction of
// false negatives: it will not fail for something safe, and everything it does
// flag is genuinely shared.

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// handlerLit reports whether fn has the signature of an http.Handler func.
func handlerLit(fn *ast.FuncLit) bool {
	ps := fn.Type.Params
	if ps == nil || len(ps.List) != 2 {
		return false
	}
	// Match on the types rather than the parameter names, so a handler that
	// names its parameters something other than (w, r) is still checked.
	sel, ok := ps.List[0].Type.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "ResponseWriter" {
		return false
	}
	star, ok := ps.List[1].Type.(*ast.StarExpr)
	if !ok {
		return false
	}
	sel2, ok := star.X.(*ast.SelectorExpr)
	return ok && sel2.Sel.Name == "Request"
}

// declaredWithin collects every name that the func literal itself introduces:
// parameters, results, short declarations, var specs, range variables and type
// switch bindings. Anything mutated that is NOT in this set is captured from an
// enclosing scope and therefore shared with whatever else calls the handler.
func declaredWithin(fn *ast.FuncLit) map[string]bool {
	in := map[string]bool{}
	addField := func(fl *ast.FieldList) {
		if fl == nil {
			return
		}
		for _, f := range fl.List {
			for _, n := range f.Names {
				in[n.Name] = true
			}
		}
	}
	addField(fn.Type.Params)
	addField(fn.Type.Results)
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		switch s := n.(type) {
		case *ast.AssignStmt:
			if s.Tok == token.DEFINE {
				for _, lhs := range s.Lhs {
					if id, ok := lhs.(*ast.Ident); ok {
						in[id.Name] = true
					}
				}
			}
		case *ast.ValueSpec:
			for _, id := range s.Names {
				in[id.Name] = true
			}
		case *ast.RangeStmt:
			for _, e := range []ast.Expr{s.Key, s.Value} {
				if id, ok := e.(*ast.Ident); ok {
					in[id.Name] = true
				}
			}
		case *ast.FuncLit:
			addField(s.Type.Params)
			addField(s.Type.Results)
		}
		return true
	})
	return in
}

// baseIdent walks down an lvalue to the identifier that owns the storage:
// x, x.f, x[i], x.f[i].g all resolve to x. That is the object a second
// goroutine would be racing on.
func baseIdent(e ast.Expr) string {
	for {
		switch v := e.(type) {
		case *ast.Ident:
			return v.Name
		case *ast.SelectorExpr:
			e = v.X
		case *ast.IndexExpr:
			e = v.X
		case *ast.StarExpr:
			e = v.X
		case *ast.ParenExpr:
			e = v.X
		default:
			return ""
		}
	}
}

// synchronised reports whether the body takes a lock or uses sync/atomic.
// A handler that does is making the sharing deliberate, which is the point.
func synchronised(fn *ast.FuncLit) bool {
	found := false
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		switch sel.Sel.Name {
		case "Lock", "RLock", "Unlock", "RUnlock":
			found = true
		}
		if id, ok := sel.X.(*ast.Ident); ok && id.Name == "atomic" {
			found = true
		}
		// A send to a captured channel is synchronised by construction.
		return true
	})
	if found {
		return true
	}
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		if _, ok := n.(*ast.SendStmt); ok {
			found = true
		}
		return true
	})
	return found
}

// handlerOffences reports every unsynchronised mutation of captured state in
// the handler literals of one parsed file, as "name:line mutates captured x".
func handlerOffences(fset *token.FileSet, f *ast.File, name string) []string {
	var offences []string
	ast.Inspect(f, func(n ast.Node) bool {
		fn, ok := n.(*ast.FuncLit)
		if !ok || !handlerLit(fn) || synchronised(fn) {
			return true
		}
		local := declaredWithin(fn)
		ast.Inspect(fn.Body, func(m ast.Node) bool {
			var targets []ast.Expr
			switch s := m.(type) {
			case *ast.AssignStmt:
				if s.Tok == token.DEFINE {
					return true
				}
				targets = s.Lhs
			case *ast.IncDecStmt:
				targets = []ast.Expr{s.X}
			default:
				return true
			}
			for _, tgt := range targets {
				base := baseIdent(tgt)
				if base == "" || base == "_" || local[base] {
					continue
				}
				offences = append(offences, fmt.Sprintf("%s:%d mutates captured %s",
					name, fset.Position(m.Pos()).Line, base))
			}
			return true
		})
		return true
	})
	return offences
}

func TestNoTestHandlerMutatesCapturedStateUnlocked(t *testing.T) {
	root := filepath.Join("..", "..")
	var offences []string

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && nestedModule(root, path) {
			return fs.SkipDir
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "node_modules", "audit-logs", "dist":
				return fs.SkipDir
			}
			// A directory with its own go.mod is a DIFFERENT MODULE -- a stale
			// checkout, a worktree, a vendored copy -- and its test files are
			// not this module's to police. The walk used to descend into them
			// and report nine offences from a copy last modified a month
			// earlier; `go test ./...` never compiles those packages, so the
			// failure was invisible until an unrelated edit invalidated the
			// test cache and this ran for real. A check that only fires when
			// the cache misses is a check that is not running.
			if path != root {
				if _, err := os.Stat(filepath.Join(path, "go.mod")); err == nil {
					return fs.SkipDir
				}
			}
			return nil
		}
		if !strings.HasSuffix(path, "_test.go") {
			return nil
		}
		fset := token.NewFileSet()
		f, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			return perr
		}
		rel, _ := filepath.Rel(root, path)
		offences = append(offences, handlerOffences(fset, f, rel)...)
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}

	sort.Strings(offences)
	if len(offences) > 0 {
		t.Errorf("test handlers mutate captured state without a lock (%d):", len(offences))
		for _, o := range offences {
			t.Errorf("  %s", o)
		}
		t.Errorf("guard a shared recorder with a mutex, or use internal/testrec.")
	}
}

// The check above passes when the tree is clean, which is also what it would do
// if its detection had been broken. These cases pin both directions on sources
// written for the purpose: the racy shapes it must catch, and the safe shapes
// it must not flag. Without them, deleting the body of handlerOffences leaves a
// green suite.
func TestHandlerOffencesDetectsWhatItClaimsTo(t *testing.T) {
	for _, tc := range []struct {
		name string
		src  string
		want int
	}{
		{name: "append to a captured slice", want: 1, src: `
			var seen []string
			_ = func(w http.ResponseWriter, r *http.Request) { seen = append(seen, r.URL.Path) }`},
		{name: "increment a captured counter", want: 1, src: `
			var n int
			_ = func(w http.ResponseWriter, r *http.Request) { n++ }`},
		{name: "assign a captured string", want: 1, src: `
			var last string
			_ = func(w http.ResponseWriter, r *http.Request) { last = r.URL.Path }`},
		{name: "write a captured map", want: 1, src: `
			var m map[string]string
			_ = func(w http.ResponseWriter, r *http.Request) { m[r.URL.Path] = "x" }`},
		{name: "write a field of a captured struct", want: 1, src: `
			var s struct{ got []string }
			_ = func(w http.ResponseWriter, r *http.Request) { s.got = append(s.got, r.URL.Path) }`},
		{name: "two offences in one handler", want: 2, src: `
			var n int
			var seen []string
			_ = func(w http.ResponseWriter, r *http.Request) {
				n++
				seen = append(seen, r.URL.Path)
			}`},

		// The other direction. A check that flags everything is no more useful
		// than one that flags nothing, and each of these is a shape the repo
		// actually contains.
		{name: "purely local state", want: 0, src: `
			_ = func(w http.ResponseWriter, r *http.Request) {
				n := 0
				for i := 0; i < 3; i++ {
					n++
				}
				body := map[string]any{}
				body["hint"] = n
			}`},
		{name: "captured but locked", want: 0, src: `
			var mu sync.Mutex
			var seen []string
			_ = func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				defer mu.Unlock()
				seen = append(seen, r.URL.Path)
			}`},
		{name: "captured but atomic", want: 0, src: `
			var n atomic.Int64
			_ = func(w http.ResponseWriter, r *http.Request) { n.Add(1) }`},
		{name: "recorded through testrec", want: 0, src: `
			var seen testrec.Log
			_ = func(w http.ResponseWriter, r *http.Request) { seen.Add(r.URL.Path) }`},
		{name: "writes only to the response", want: 0, src: `
			_ = func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(200)
			}`},
		{name: "not a handler at all", want: 0, src: `
			var seen []string
			_ = func(a int, b string) { seen = append(seen, b) }`},
		{name: "range variable is not captured", want: 0, src: `
			_ = func(w http.ResponseWriter, r *http.Request) {
				out := []string{}
				for _, h := range []string{"a", "b"} {
					out = append(out, h)
				}
				_ = out
			}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			src := "package p\nfunc f() {" + tc.src + "\n}\n"
			fset := token.NewFileSet()
			f, err := parser.ParseFile(fset, "x_test.go", src, 0)
			if err != nil {
				t.Fatalf("parse: %v\n%s", err, src)
			}
			got := handlerOffences(fset, f, "x_test.go")
			if len(got) != tc.want {
				t.Errorf("found %d offence(s), want %d: %v", len(got), tc.want, got)
			}
		})
	}
}
