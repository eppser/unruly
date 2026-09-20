package main

import (
	"fmt"
	"sort"
	"strings"

	"github.com/eppser/unruly/internal/classify"
	"github.com/eppser/unruly/internal/finding"
)

// scanned is one target as unruly reported it.
type scanned struct {
	Target   string
	Ref      string
	Region   string
	Findings []finding.Finding
}

// dumped is one target as supabomb left it: whole tables, on disk.
type dumped struct {
	Target string
	Ref    string
	Region string
	// Tables holds every row the tool downloaded. This is the operator's own
	// copy of somebody's database, and the only reason to read it here is to
	// answer what kind of data it is. No value from it is ever rendered.
	Tables map[string][]map[string]any
	// Findings as graded by supabomb, when its test report is present.
	//
	// Deliberately NOT finding.Finding. A competitor's grade is not one of
	// this scanner's findings: reusing the struct would put another tool's
	// vocabulary into the type that carries ours, and it would construct a
	// finding inside cmd/, which the coverage audit profiles ./internal/...
	// only and therefore cannot see.
	Findings []graded
}

// graded is one result as another tool reported it: a severity and a subject,
// which is all any comparison can honestly use.
type graded struct {
	Severity finding.Severity
	Resource string
	Title    string
}

// ClassStat is one data class across the whole estate.
type ClassStat struct {
	Findings  int
	Relations int
	Targets   int
	Rows      int

	targets   map[string]bool
	relations map[string]bool
}

// RegionStat is one region across the whole estate.
type RegionStat struct {
	Projects  int
	Relations int
	Rows      int
	Findings  int
	Classes   []string

	projects map[string]bool
	classes  map[string]bool
}

// RelStat is one exposed relation, for the worst-first list.
type RelStat struct {
	Target   string
	Resource string
	Rows     int
	Classes  []string
}

// Estate is the whole scan, summarised.
type Estate struct {
	Tool          string
	Targets       int
	Projects      int
	Findings      int
	Relations     int
	CoverageGaps  int
	RowsReachable int
	RowsCaptured  int

	BySeverity map[string]int
	ByClass    map[string]*ClassStat
	ByRegion   map[string]*RegionStat
	Columns    map[string]int
	Top        []RelStat
}

// coverage ids describe the SCAN, not the target. They are counted apart from
// exposures for the same reason the comparison harness excludes them: adding
// them to a class table would put "did not look" beside "was readable".
var coverageID = map[string]bool{
	"unruly-scan-summary":           true,
	"unruly-stage-skipped":          true,
	"unruly-surface-not-assessed":   true,
	"unruly-checks-skipped":         true,
	"unruly-probe-budget-exhausted": true,
	"unruly-probes-unresolved":      true,
	"unruly-capability-degraded":    true,
	"unruly-relations-protected":    true,
}

func newEstate(tool string) Estate {
	return Estate{
		Tool:       tool,
		BySeverity: map[string]int{},
		ByClass:    map[string]*ClassStat{},
		ByRegion:   map[string]*RegionStat{},
		Columns:    map[string]int{},
	}
}

func (e *Estate) class(name string) *ClassStat {
	c := e.ByClass[name]
	if c == nil {
		c = &ClassStat{targets: map[string]bool{}, relations: map[string]bool{}}
		e.ByClass[name] = c
	}
	return c
}

// region resolves the bucket a project's data sits in.
//
// "unknown" is a value, not a gap to be filled in with something adjacent. An
// unresolved region is reported as unresolved: the alternative -- reading the
// Cloudflare colo that served the request -- was measured against a real
// project answering from FRA whose data is in eu-west-1, and would have put
// Irish data under German jurisdiction on the one table read for that purpose.
func (e *Estate) region(name string) *RegionStat {
	if strings.TrimSpace(name) == "" {
		name = "unknown"
	}
	r := e.ByRegion[name]
	if r == nil {
		r = &RegionStat{projects: map[string]bool{}, classes: map[string]bool{}}
		e.ByRegion[name] = r
	}
	return r
}

func projectKey(s scanned) string {
	if s.Ref != "" {
		return s.Ref
	}
	return s.Target
}

// summarizeUnruly rolls up what unruly reported, across every target.
func summarizeUnruly(in []scanned) Estate {
	e := newEstate("unruly")
	projects := map[string]bool{}

	for _, s := range in {
		e.Targets++
		key := projectKey(s)
		projects[key] = true
		reg := e.region(s.Region)
		reg.projects[key] = true

		for _, f := range s.Findings {
			if coverageID[f.ID] {
				e.CoverageGaps++
				continue
			}
			e.Findings++
			e.BySeverity[f.Severity.String()]++
			reg.Findings++

			if f.Resource != "" {
				e.Relations++
				reg.Relations++
			}
			// Rows the server said were there. REACHABLE, not captured: the
			// scan samples three rows as proof and leaves the rest where it
			// is, which is the difference this report refuses to blur.
			e.RowsReachable += f.Evidence.Rows
			reg.Rows += f.Evidence.Rows

			for _, c := range f.Evidence.Columns {
				e.Columns[c]++
			}
			for _, name := range f.Evidence.Classes {
				c := e.class(name)
				c.Findings++
				c.Rows += f.Evidence.Rows
				c.targets[key] = true
				c.relations[s.Target+"/"+f.Resource] = true
				reg.classes[name] = true
			}
			if f.Evidence.Rows > 0 {
				e.Top = append(e.Top, RelStat{Target: s.Target, Resource: f.Resource,
					Rows: f.Evidence.Rows, Classes: f.Evidence.Classes})
			}
		}
	}
	e.Projects = len(projects)
	finish(&e)
	return e
}

// summarizeSupabomb rolls up what supabomb took.
//
// The classes come from unruly's own classifier reading the rows supabomb
// wrote, because supabomb reports no classes of its own. Using the same
// classifier is what makes the two halves of this report comparable rather
// than two vocabularies printed side by side.
func summarizeSupabomb(in []dumped) Estate {
	e := newEstate("supabomb")
	projects := map[string]bool{}

	for _, d := range in {
		e.Targets++
		key := d.Ref
		if key == "" {
			key = d.Target
		}
		projects[key] = true
		reg := e.region(d.Region)
		reg.projects[key] = true

		for _, f := range d.Findings {
			e.Findings++
			e.BySeverity[f.Severity.String()]++
			reg.Findings++
		}

		names := make([]string, 0, len(d.Tables))
		for name := range d.Tables {
			names = append(names, name)
		}
		sort.Strings(names)

		for _, name := range names {
			rows := d.Tables[name]
			if len(rows) == 0 {
				continue
			}
			e.Relations++
			reg.Relations++
			// CAPTURED: these rows are on the operator's disk now.
			e.RowsCaptured += len(rows)
			reg.Rows += len(rows)

			cols := map[string]bool{}
			for _, r := range rows {
				for k := range r {
					cols[k] = true
				}
			}
			colNames := make([]string, 0, len(cols))
			for c := range cols {
				colNames = append(colNames, c)
				e.Columns[c]++
			}
			sort.Strings(colNames)

			// Both halves of the classifier: what the VALUES are, and what the
			// column names say they hold. Names() returns "column:class"
			// pairs, so the class is the half after the colon.
			kinds := map[string]bool{}
			for _, k := range classify.Kinds(rows) {
				kinds[k] = true
			}
			for _, pair := range classify.Names(colNames) {
				if i := strings.LastIndex(pair, ":"); i >= 0 {
					kinds[pair[i+1:]] = true
				}
			}
			classes := make([]string, 0, len(kinds))
			for k := range kinds {
				classes = append(classes, k)
			}
			sort.Strings(classes)

			for _, k := range classes {
				c := e.class(k)
				c.Findings++
				c.Rows += len(rows)
				c.targets[key] = true
				c.relations[d.Target+"/"+name] = true
				reg.classes[k] = true
			}
			e.Top = append(e.Top, RelStat{Target: d.Target, Resource: name,
				Rows: len(rows), Classes: classes})
		}
	}
	e.Projects = len(projects)
	finish(&e)
	return e
}

// finish resolves the set-counters and orders everything.
//
// Sorting is not cosmetic: this report exists to be diffed between runs of an
// estate, and map iteration order would make every run differ from the last
// for no reason anybody could act on.
func finish(e *Estate) {
	for _, c := range e.ByClass {
		c.Targets = len(c.targets)
		c.Relations = len(c.relations)
	}
	for _, r := range e.ByRegion {
		r.Projects = len(r.projects)
		names := make([]string, 0, len(r.classes))
		for k := range r.classes {
			names = append(names, k)
		}
		sort.Strings(names)
		r.Classes = names
	}
	sort.SliceStable(e.Top, func(i, j int) bool {
		if e.Top[i].Rows != e.Top[j].Rows {
			return e.Top[i].Rows > e.Top[j].Rows
		}
		if e.Top[i].Target != e.Top[j].Target {
			return e.Top[i].Target < e.Top[j].Target
		}
		return e.Top[i].Resource < e.Top[j].Resource
	})
}

func sortedKeys[T any](m map[string]T) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func comma(n int) string {
	s := fmt.Sprintf("%d", n)
	if len(s) <= 3 {
		return s
	}
	var b strings.Builder
	pre := len(s) % 3
	if pre > 0 {
		b.WriteString(s[:pre])
	}
	for i := pre; i < len(s); i += 3 {
		if b.Len() > 0 {
			b.WriteByte(',')
		}
		b.WriteString(s[i : i+3])
	}
	return b.String()
}

// render writes the estate report.
//
// Class names, column names, counts and regions. Never a value: this report
// reads sampled rows and, on the supabomb side, entire downloaded tables, and
// a report an operator forwards must not become a second copy of the leak.
func render(e Estate) string {
	var b strings.Builder
	w := func(format string, a ...any) { fmt.Fprintf(&b, format+"\n", a...) }

	w("# Estate summary — %s", e.Tool)
	w("")
	w("| | |")
	w("|---|---:|")
	w("| targets scanned | %s |", comma(e.Targets))
	w("| distinct projects | %s |", comma(e.Projects))
	w("| findings | %s |", comma(e.Findings))
	w("| relations affected | %s |", comma(e.Relations))
	if e.Tool == "unruly" {
		w("| rows **reachable** | %s |", comma(e.RowsReachable))
		w("| rows downloaded | %s |", comma(e.RowsCaptured))
		w("| coverage gaps | %s |", comma(e.CoverageGaps))
	} else {
		w("| rows **captured to disk** | %s |", comma(e.RowsCaptured))
	}
	w("")
	if e.Tool == "unruly" {
		w("Rows reachable is what the server reported, proven by a three-row sample.")
		w("Nothing was downloaded: exposure was established without taking a copy.")
	} else {
		w("Rows captured are on this machine. supabomb's `all` dumps every accessible")
		w("table with no row limit, so this number is a second copy of somebody's")
		w("database, and it is counted here so that it can be deleted deliberately.")
	}
	w("")

	if len(e.BySeverity) > 0 {
		w("## By severity")
		w("")
		w("| severity | findings |")
		w("|---|---:|")
		for _, s := range []string{"critical", "high", "medium", "low", "info"} {
			if n := e.BySeverity[s]; n > 0 {
				w("| %s | %s |", s, comma(n))
			}
		}
		w("")
	}

	w("## By data class")
	w("")
	if len(e.ByClass) == 0 {
		w("No classified data was reached.")
		w("")
	} else {
		verb := "rows reachable"
		if e.Tool == "supabomb" {
			verb = "rows captured"
		}
		w("| class | findings | relations | projects | %s |", verb)
		w("|---|---:|---:|---:|---:|")
		for _, name := range sortedKeys(e.ByClass) {
			c := e.ByClass[name]
			w("| %s | %s | %s | %s | %s |", name, comma(c.Findings),
				comma(c.Relations), comma(c.Targets), comma(c.Rows))
		}
		w("")
	}

	w("## By region")
	w("")
	w("Regions come from the owner's own account through the Supabase management")
	w("API. They are never inferred from the edge that served the request: a")
	w("project measured for this tool answered from `cf-ray: …-FRA` while its data")
	w("sits in `eu-west-1`, and reading the colo would have placed Irish data under")
	w("German jurisdiction on the one table read for exactly that question.")
	w("")
	w("| region | projects | relations | rows | classes held |")
	w("|---|---:|---:|---:|---|")
	for _, name := range sortedKeys(e.ByRegion) {
		r := e.ByRegion[name]
		classes := strings.Join(r.Classes, ", ")
		if classes == "" {
			classes = "—"
		}
		w("| %s | %s | %s | %s | %s |", name, comma(r.Projects),
			comma(r.Relations), comma(r.Rows), classes)
	}
	w("")

	if len(e.Columns) > 0 {
		w("## Most frequently exposed column names")
		w("")
		type kv struct {
			name string
			n    int
		}
		var cols []kv
		for _, k := range sortedKeys(e.Columns) {
			cols = append(cols, kv{k, e.Columns[k]})
		}
		sort.SliceStable(cols, func(i, j int) bool { return cols[i].n > cols[j].n })
		if len(cols) > 20 {
			cols = cols[:20]
		}
		var parts []string
		for _, c := range cols {
			parts = append(parts, fmt.Sprintf("`%s` (%d)", c.name, c.n))
		}
		w("%s", strings.Join(parts, ", "))
		w("")
	}

	if len(e.Top) > 0 {
		w("## Largest exposures")
		w("")
		w("| target | relation | rows | classes |")
		w("|---|---|---:|---|")
		top := e.Top
		if len(top) > 25 {
			top = top[:25]
		}
		for _, r := range top {
			classes := strings.Join(r.Classes, ", ")
			if classes == "" {
				classes = "—"
			}
			w("| `%s` | `%s` | %s | %s |", r.Target, r.Resource, comma(r.Rows), classes)
		}
		if len(e.Top) > 25 {
			w("")
			w("_%d further relations not listed._", len(e.Top)-25)
		}
		w("")
	}

	return b.String()
}
