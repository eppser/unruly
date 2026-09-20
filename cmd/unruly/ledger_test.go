package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The ledger exists to make a total actionable. These pin the two properties
// that give it that: the biggest spender is named first, and the ordering does
// not depend on map iteration.
func TestLedgerNamesTheBiggestSpenderFirst(t *testing.T) {
	l := newLedger()
	l.add("relations", 866)
	l.add("relations-retry", 13935)
	l.add("storage", 1704)
	l.add("probe", 12)

	if l.total() != 866+13935+1704+12 {
		t.Errorf("total is %d", l.total())
	}
	got := l.summary(3)
	if !strings.HasPrefix(got, "relations-retry 13935") {
		t.Errorf("the stage spending 76%% of the budget is not named first: %q", got)
	}
	if strings.Contains(got, "probe 12") {
		t.Errorf("summary(3) returned more than three stages: %q", got)
	}
}

// Reports get diffed between runs, and a Go map iterates in a different order
// every time.
func TestLedgerIsDeterministic(t *testing.T) {
	build := func() *ledger {
		l := newLedger()
		for _, s := range []string{"a", "b", "c", "d", "e"} {
			l.add(s, 100) // all equal, so only the tiebreak decides
		}
		return l
	}
	first := build().summary(5)
	for i := 0; i < 30; i++ {
		if got := build().summary(5); got != first {
			t.Fatalf("unstable ordering:\n  %s\n  %s", first, got)
		}
	}
	if !strings.HasPrefix(first, "a 100") {
		t.Errorf("equal spenders are not broken by name: %q", first)
	}
}

// A stage that ran and spent nothing must not clutter the line, and an empty
// ledger must produce nothing rather than an empty label.
func TestLedgerOmitsStagesThatSpentNothing(t *testing.T) {
	l := newLedger()
	l.add("skipped", 0)
	l.add("realtime", 5)
	if got := l.summary(4); got != "realtime 5" {
		t.Errorf("summary is %q; a stage that spent nothing is noise", got)
	}
	if got := newLedger().summary(4); got != "" {
		t.Errorf("an empty ledger produced %q", got)
	}
}

// Every ledger label must name the stage it measures.
//
// The first version of this file labelled three of them by their position in a
// substitution list rather than by what the variable was: selfcheck.Run was
// reported as "surface", surface.Run as "storage", and routes.Run as
// "realtime". A whole investigation then reasoned from "storage is the biggest
// spender", which was not true and was not even a stage.
//
// A measurement that reports a plausible wrong answer is worse than one that
// reports nothing, and this project's entire argument is that other scanners
// fail exactly there. So the labels are checked against the constructor each
// one accumulates from.
func TestLedgerLabelsNameTheirStage(t *testing.T) {
	src, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatalf("read main.go: %v", err)
	}
	body := string(src)

	// variable -> the package AND function it holds the result of. Either may
	// name the stage: surface.Routines is honestly labelled "routines", which
	// says more than "surface" would.
	//
	// The package qualifier is optional and the second return value is allowed,
	// because a stage lifted out of scanTarget into this package is called as
	// `d, err := discovery(...)` -- no package, two results. The first version
	// of this regex required `pkg.Fn(` and a single LHS, so it lost sight of a
	// variable the moment its producer moved into cmd/unruly, and reported the
	// label as accumulating "from d, which is assigned nowhere this test can
	// see". A local stage's own name is its identity, so it stands in for the
	// package.
	assign := regexp.MustCompile(`(?m)^\s+(\w+)(?:,\s*\w+)?\s*:?=\s+(?:(\w+)\.)?(\w+)\(`)
	owner := map[string][2]string{}
	for _, m := range assign.FindAllStringSubmatch(body, -1) {
		pkg, fn := m[2], m[3]
		if pkg == "" {
			pkg = fn // a local stage: the function name is the source identity
		}
		if _, seen := owner[m[1]]; !seen {
			owner[m[1]] = [2]string{pkg, fn}
		}
	}

	// Each label must contain the package name it came from. Suffixes like
	// -retry and -extra-schema are fine; a different package is not.
	add := regexp.MustCompile(`spend\.add\("([a-z-]+)",\s*(?:int\()?(\w+)\.Requests`)
	ms := add.FindAllStringSubmatch(body, -1)

	// Ported stages accumulate through scan.State rather than from a package
	// result, so they read spend.add("realtime", rtState.Attributed()). The
	// extractor above cannot see those, and as stages moved the ledger count
	// fell from 8 to 6 and tripped this test's own anti-vacuous floor --
	// correctly, because it WAS checking almost nothing by then.
	//
	// Rather than lower the floor, follow the code: a label on an Attributed()
	// entry must name a stage that actually exists, and the stage names are
	// read from the backend packages instead of being listed here, so a
	// renamed stage cannot leave a stale label behind.
	stageNames := map[string]bool{}
	nameFn := regexp.MustCompile(`func \([A-Za-z]*\s*\w*Stage\) Name\(\) string \{ return "([a-z-]+)" \}`)
	for _, dir := range []string{"pocketbase", "supabase"} {
		entries, err := os.ReadDir(filepath.Join("..", "..", "backend", dir))
		if err != nil {
			continue
		}
		for _, e := range entries {
			if strings.HasSuffix(e.Name(), ".go") && !strings.HasSuffix(e.Name(), "_test.go") {
				b, err := os.ReadFile(filepath.Join("..", "..", "backend", dir, e.Name()))
				if err != nil {
					continue
				}
				for _, m := range nameFn.FindAllStringSubmatch(string(b), -1) {
					stageNames[m[1]] = true
				}
			}
		}
	}
	if len(stageNames) == 0 {
		t.Fatal("no stage names were recovered from the backend packages, so the " +
			"Attributed() half of this check verifies nothing")
	}
	staged := regexp.MustCompile(`spend\.add\("([a-z-]+)",\s*\w+\.Attributed\(\)`)
	stagedMs := staged.FindAllStringSubmatch(body, -1)
	for _, m := range stagedMs {
		if !stageNames[m[1]] {
			t.Errorf("ledger entry %q accumulates from a stage's Attributed(), but no "+
				"stage is named %q. A label that names no stage sends every later "+
				"measurement to the wrong place.", m[1], m[1])
		}
	}

	// Most labels are no longer written by hand at all. The engine folds each
	// state's StageSpend records, whose labels originate in Stage.Name().
	rs, err := os.ReadFile(filepath.Join("..", "..", "internal", "engine", "engine.go"))
	if err != nil {
		t.Fatalf("read engine.go: %v", err)
	}
	engineSrc := string(rs)
	if !strings.Contains(engineSrc, "totals[s.Stage]") {
		t.Error("engine no longer folds the state's own per-stage breakdown, so a " +
			"stage that attributes under several labels is collapsed into one opaque " +
			"entry -- which is the shape the surface pass was split out of")
	}
	if regexp.MustCompile(`totals\["`).MatchString(engineSrc) {
		t.Error("engine labels a stage spend entry from a string literal; the label " +
			"must come from StageSpend.Stage")
	}

	// The floor was 8, then 3, and is now 1: EnumerateStage converted the last
	// two entries this extractor could see (it requires a ".Requests" operand,
	// so "providers" and "prefix" never matched it). Only "discovery" remains
	// hand-written in that shape.
	//
	// The floor keeps falling because the mechanism above is the real
	// guarantee -- runStage labels from the stage, so no spelling exists to get
	// wrong. What this half still buys is that a label written by HAND names
	// something real, and it must not silently become zero checks.
	if len(ms)+len(stagedMs) < 1 {
		t.Fatalf("only %d hand-written ledger entries found (%d package-sourced, %d "+
			"stage-sourced); the extractor stopped matching and the half of this test "+
			"that reads main.go would pass by checking nothing",
			len(ms)+len(stagedMs), len(ms), len(stagedMs))
	}
	// Packages whose label legitimately differs from the package name.
	alias := map[string]string{
		"enumerate": "relations", // what it enumerates, which reads better in a summary
		"discover":  "discovery",
	}
	for _, m := range ms {
		label, v := m[1], m[2]
		src, ok := owner[v]
		pkg, fn := src[0], src[1]
		if !ok {
			t.Errorf("ledger entry %q accumulates from %s, which is assigned nowhere "+
				"this test can see", label, v)
			continue
		}
		want := pkg
		if a, ok := alias[pkg]; ok {
			want = a
		}
		if !strings.Contains(label, want) && !strings.Contains(label, strings.ToLower(fn)) {
			t.Errorf("ledger label %q accumulates from %s.Requests (package %q). A label "+
				"that names neither the package nor the function sends every later "+
				"measurement to the wrong place.", label, v, pkg)
		}
	}
}
