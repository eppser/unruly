package eval_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// Every remediation block must be safe to pipe into psql, whichever backend
// produced it.
//
// The rule is not a style preference. `-fix` output is executed verbatim by
// this repository's own evals and by operators who pipe it into psql, so a line
// that is neither SQL nor a comment is a syntax error in somebody's terminal at
// best, and a statement they did not intend at worst.
//
// It was enforced only where it happened to be tested. The remediation evals
// all drive Supabase findings through a real database, so the Firebase provider
// -- whose remediations are Console instructions with no SQL in them at all --
// was never checked by anything. Today every one of its lines is correctly
// commented; nothing made that true tomorrow, and the next backend starts with
// no coverage whatsoever.
//
// So the rule is checked where the findings are BUILT, across every package,
// rather than inferred from whichever ones an integration test happens to
// execute.
func TestEveryRemediationIsCommentOrSQL(t *testing.T) {
	// Statement openers this project actually emits. A remediation line that
	// starts with none of these, and is not a comment, reaches psql as prose.
	openers := []string{
		"SELECT", "CREATE", "ALTER", "DROP", "GRANT", "REVOKE", "COMMENT",
		"INSERT", "UPDATE", "DELETE", "BEGIN", "COMMIT", "ROLLBACK", "DO",
		"WITH", "SET", "RESET", "ANALYZE", "VACUUM", "TRUNCATE", "NOTIFY",
	}
	isSQL := func(line string) bool {
		up := strings.ToUpper(strings.TrimSpace(line))
		for _, k := range openers {
			if strings.HasPrefix(up, k+" ") || up == k+";" {
				return true
			}
		}
		// A continuation of the statement above: indented, or closing it.
		return strings.HasPrefix(line, " ") || strings.HasPrefix(line, "\t") ||
			strings.HasPrefix(up, ")") || strings.HasPrefix(up, "FROM ") ||
			strings.HasPrefix(up, "WHERE ") || strings.HasPrefix(up, "ORDER BY ") ||
			strings.HasPrefix(up, "GROUP BY ") || strings.HasPrefix(up, "USING ") ||
			strings.HasPrefix(up, "AND ") || strings.HasPrefix(up, "OR ") ||
			strings.HasPrefix(up, "VALUES ") || strings.HasPrefix(up, "ON ")
	}

	// Blocks that are not SQL at all, and are not psql input.
	//
	// Two findings are about things above the database -- an application route
	// and an Edge Function -- and their remediation is a shell recipe and a
	// middleware snippet. Prefixing those with "--" would comment out the very
	// command the operator is meant to run, which is worse than the problem.
	// They are listed by their distinctive opening instead, so the rule stays
	// stated rather than quietly relaxed, and a THIRD such block has to be
	// added here deliberately.
	notSQLAtAll := []string{
		"Apply the same authorisation check",  // app-route inconsistency
		"# Require a JWT unless the function", // edge function without a JWT
	}
	skipBlock := func(text string) bool {
		for _, marker := range notSQLAtAll {
			if strings.HasPrefix(strings.TrimSpace(text), marker) {
				return true
			}
		}
		return false
	}

	type offence struct{ where, line string }
	var offences []offence
	var checked int

	roots := []string{filepath.Join("..", "..")}
	for _, root := range roots {
		err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() || !strings.HasSuffix(path, ".go") ||
				strings.HasSuffix(path, "_test.go") {
				return err
			}
			f, perr := parser.ParseFile(token.NewFileSet(), path, nil, 0)
			if perr != nil {
				return nil // not ours to compile
			}
			ast.Inspect(f, func(n ast.Node) bool {
				kv, ok := n.(*ast.KeyValueExpr)
				if !ok {
					return true
				}
				id, ok := kv.Key.(*ast.Ident)
				if !ok || id.Name != "Remediation" {
					return true
				}
				text, ok := staticString(kv.Value)
				if !ok {
					// Built at runtime from parts this walker cannot see.
					return true
				}
				checked++
				if skipBlock(text) {
					return true
				}
				for _, line := range strings.Split(text, "\n") {
					// "--" and "#" both, because executableSQL -- the thing that
					// actually runs these -- skips both. A "#" block is a shell
					// recipe (supabase functions deploy, and the like) rather
					// than SQL; prefixing its prose with "--" would not make it
					// psql-safe, because the whole block is not psql input.
					t := strings.TrimSpace(line)
					if t == "" || strings.HasPrefix(t, "--") || strings.HasPrefix(t, "#") {
						continue
					}
					if !isSQL(line) {
						offences = append(offences, offence{filepath.Base(path), line})
					}
				}
				return true
			})
			return nil
		})
		if err != nil {
			t.Fatalf("walk: %v", err)
		}
	}

	if checked == 0 {
		t.Fatal("no remediation blocks were read, so this test is measuring nothing")
	}
	sort.Slice(offences, func(i, j int) bool { return offences[i].line < offences[j].line })
	for _, o := range offences {
		t.Errorf("%s: this line is neither SQL nor a comment, and -fix output is piped "+
			"into psql verbatim:\n    %q", o.where, o.line)
	}
	t.Logf("%d remediation blocks checked", checked)
}

// staticString flattens a string literal, or a concatenation of them, and
// reports whether the whole expression was static.
func staticString(e ast.Expr) (string, bool) {
	switch v := e.(type) {
	case *ast.BasicLit:
		if v.Kind != token.STRING {
			return "", false
		}
		s, err := strconv.Unquote(v.Value)
		return s, err == nil
	case *ast.CallExpr:
		// fmt.Sprintf: the FORMAT string is a literal, and whether a line
		// starts with "--" does not depend on what the verbs interpolate.
		//
		// These were skipped as "built at runtime", which was true and hid five
		// bare prose lines -- including one in the GraphQL bypass finding, a
		// check whose positive path had never run anywhere. A documented blind
		// spot is still a blind spot.
		sel, ok := v.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "Sprintf" || len(v.Args) == 0 {
			return "", false
		}
		return staticString(v.Args[0])
	case *ast.BinaryExpr:
		if v.Op != token.ADD {
			return "", false
		}
		l, okl := staticString(v.X)
		r, okr := staticString(v.Y)
		if !okl || !okr {
			return "", false
		}
		return l + r, true
	}
	return "", false
}
