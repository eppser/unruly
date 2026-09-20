package eval_test

import (
	"os"
	"path/filepath"
)

// nestedModule reports a directory that belongs to a DIFFERENT Go module.
//
// Several checks in this package walk the repository and grade what they find:
// severities against docs/checks.md, flags against the README, handler races,
// declined stages. Every one of those walks descended into `unruly-bench/` and
// `worktrees/…/bronze-cape/` -- a stale checkout and a git worktree of another
// branch, each with its own go.mod, neither compiled by `go test ./...`.
//
// The consequence was not theoretical. TestDocumentedSeverityMatchesTheCode
// read `app-docs-exposed` at `low` and `app-openapi-schema-exposed` at
// `medium` out of the OTHER BRANCH and reported them as contradicting this
// branch's documentation, which had deliberately moved both to `info`. The
// code and the docs agreed; the test was reading a third thing.
//
// It stayed hidden because `go test` caches: the walks read files outside the
// module, the cache did not know they had changed, and the checks reported a
// stale pass until an unrelated edit finally invalidated it. A check that only
// runs on a cache miss is a check that is not running.
//
// A directory with its own go.mod is another module's source. This package
// grades THIS module.
// walkRoot is the repository root, the boundary every walk in this package
// starts at or below.
var walkRoot = filepath.Join("..", "..")

func nestedModule(root, path string) bool {
	if path == root {
		return false
	}
	// `private/` is ignored by git and holds material that is not published --
	// live labs, research outputs, experiment harnesses, an archive of this
	// project's pre-publication history. None of it is this repository's code
	// and none of it may be graded as if it were. Without this, a Go file
	// dropped in an ignored directory would make these checks report on source
	// no contributor can see.
	if filepath.Base(path) == "private" {
		return true
	}
	_, err := os.Stat(filepath.Join(path, "go.mod"))
	return err == nil
}
