// Command coveraudit checks that every finding the scanner can emit has an
// emit site a test actually EXECUTES.
//
// internal/eval/id_coverage_test.go already requires each finding id to be
// named by a test, on the stated grounds that a branch which has never
// executed is not known to work. An audit pointed out that the rule is
// textual: it greps string literals out of *_test.go, so it is satisfied by an
// id appearing anywhere in any test — including a hand-built struct in a
// sorting test that never calls the code that emits it. The rule was
// satisfiable by a comment.
//
// This closes it with the coverage profile. For each `ID: "supabase-..."`
// literal in non-test source, the line must fall inside a block the profile
// marks as executed at least once.
//
//	go test -coverprofile=cover.out -coverpkg=./internal/... ./internal/...
//	coveraudit -profile cover.out
//
// The textual rule stays: it is cheap, it runs offline, and it fails fast when
// somebody adds a finding with no test at all. This one is the expensive check
// that says whether the test does anything.
package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"

	"github.com/eppser/unruly/internal/emitsites"
	"sort"
	"strconv"
	"strings"
)

type block struct{ start, end int }

func main() {
	var profile, root string
	flag.StringVar(&profile, "profile", "cover.out", "coverage profile to read")
	flag.StringVar(&root, "root", ".", "source tree to scan for emit sites")
	flag.Parse()

	covered, err := readProfile(profile)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	sites, err := emitsites.Sites(root)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if len(sites) == 0 {
		fmt.Fprintln(os.Stderr, "no emit sites found; the extractor stopped matching")
		os.Exit(1)
	}

	var uncovered []string
	ids := make([]string, 0, len(sites))
	for id := range sites {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		var executed bool
		for _, s := range sites[id] {
			if isCovered(covered, s.File, s.Line) {
				executed = true
				break
			}
		}
		if !executed {
			uncovered = append(uncovered, fmt.Sprintf("%s (%s:%d)", id, sites[id][0].File, sites[id][0].Line))
		}
	}

	fmt.Printf("%d finding ids with an emit site\n", len(sites))
	fmt.Printf("%d have an emit site a test executes\n", len(sites)-len(uncovered))
	// The caveat belongs where the number is read, not only in a test file
	// somebody may never open. An audit pointed out that a reader of this
	// tool saw a clean count with no qualification at all.
	fmt.Println("note: this proves the code that BUILDS each finding runs under test. " +
		"It does not prove a scan can REACH it — a unit test calling the constructor " +
		"covers the emit site while the path to it stays unreachable. That gap is what " +
		"the exploitability cross-check is for.")
	if len(uncovered) == 0 {
		return
	}
	fmt.Printf("\n%d do NOT — named by a test, but the emitting code never runs:\n", len(uncovered))
	for _, u := range uncovered {
		fmt.Println("  " + u)
	}
	os.Exit(2)
}

// readProfile keeps only blocks executed at least once.

func readProfile(path string) (map[string][]block, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	covered := map[string][]block{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		if line == "" || strings.HasPrefix(line, "mode:") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 3 {
			continue
		}
		count, err := strconv.Atoi(fields[2])
		if err != nil || count == 0 {
			continue
		}
		i := strings.LastIndex(fields[0], ":")
		if i < 0 {
			continue
		}
		file, rng := fields[0][:i], fields[0][i+1:]
		parts := strings.Split(rng, ",")
		if len(parts) != 2 {
			continue
		}
		start, err1 := strconv.Atoi(strings.Split(parts[0], ".")[0])
		end, err2 := strconv.Atoi(strings.Split(parts[1], ".")[0])
		if err1 != nil || err2 != nil {
			continue
		}
		// Profiles name packages by import path; emit sites are repo-relative.
		if i := strings.Index(file, "unruly/"); i >= 0 {
			file = file[i+len("unruly/"):]
		}
		covered[file] = append(covered[file], block{start, end})
	}
	return covered, sc.Err()
}

func isCovered(covered map[string][]block, file string, line int) bool {
	for _, b := range covered[file] {
		if line >= b.start && line <= b.end {
			return true
		}
	}
	return false
}
