package finding

import (
	"fmt"
	"sort"
	"strings"
)

// FixPlan turns a report into one script an operator can read top to bottom.
//
// Every finding already carries remediation that works, and the remediation
// eval executes all of it against a live database on each audit. The problem is
// shape, not correctness: a relation that is readable AND insertable AND
// updatable AND deletable produces four blocks, each repeating ALTER TABLE ...
// ENABLE ROW LEVEL SECURITY, each ending in the same REVOKE. Pasted together
// for a project with ten exposed relations, that is a wall of near-duplicate
// statements, and a fix nobody reads is a fix nobody applies.
//
// This groups by relation and states, once, what is open and what closes it.
// Ordering is worst-first so a reader who stops early has fixed the worst
// thing, and every non-SQL line is a comment because this output is piped into
// psql -- by the eval on every audit, and by operators for real.

// verbOfID maps the finding ids that describe reachable data onto the verb an
// attacker holds. Ids absent from this map contribute nothing to a plan: a
// coverage note has no SQL, and inventing some would be worse than silence.
var verbOfID = map[string]string{
	"supabase-anon-read-exposed":        "SELECT",
	"supabase-anon-insert-allowed":      "INSERT",
	"supabase-anon-update-allowed":      "UPDATE",
	"supabase-anon-delete-allowed":      "DELETE",
	"supabase-authenticated-escalation": "SELECT (to any signed-up user)",
}

type planEntry struct {
	relation string
	worst    Severity
	verbs    []string
	why      []string
}

// FixPlan returns SQL, or "" when nothing in the report has a relational fix.
func FixPlan(fs []Finding) string {
	byRel := map[string]*planEntry{}
	for _, f := range fs {
		verb, ok := verbOfID[f.ID]
		if !ok || f.Resource == "" {
			continue
		}
		e := byRel[f.Resource]
		if e == nil {
			e = &planEntry{relation: f.Resource, worst: f.Severity}
			byRel[f.Resource] = e
		}
		if f.Severity > e.worst {
			e.worst = f.Severity
		}
		e.verbs = append(e.verbs, verb)
		if r := strings.TrimSpace(f.Evidence.Reason); r != "" {
			e.why = append(e.why, r)
		}
	}
	// Findings whose remediation is real but is not SQL.
	//
	// The verb map above is Supabase's, so a Firebase-only report produced a
	// plan of exactly zero characters -- measured -- while one Supabase
	// finding produced 814. The scan was right on both backends and -fix
	// printed each finding's own remediation; what was empty was the grouped
	// plan, which is what the HTML report offers as the thing to copy. An
	// operator with two critical Firebase findings was handed a blank box,
	// which reads as "nothing to do".
	//
	// Info findings are excluded deliberately: their remediation says there is
	// nothing to fix on the target, and a plan repeating that for every
	// coverage note would bury the part that matters.
	other := otherSteps(fs)

	if len(byRel) == 0 && len(other) == 0 {
		return ""
	}

	entries := make([]*planEntry, 0, len(byRel))
	for _, e := range byRel {
		sort.Strings(e.verbs)
		e.verbs = dedupe(e.verbs)
		sort.Strings(e.why)
		e.why = dedupe(e.why)
		entries = append(entries, e)
	}
	// Worst first, then by name so two runs of an unchanged project match.
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].worst != entries[j].worst {
			return entries[i].worst > entries[j].worst
		}
		return entries[i].relation < entries[j].relation
	})

	var b strings.Builder
	b.WriteString("-- unruly fix plan\n")
	if len(entries) > 0 {
		b.WriteString("-- One block per relation, worst first. Read before running: every\n")
		b.WriteString("-- statement here removes access, and only you know which of it was\n")
		b.WriteString("-- intended.\n")
	}
	for _, e := range entries {
		fmt.Fprintf(&b, "\n-- ---------- %s  [%s] ----------\n", e.relation, e.worst)
		fmt.Fprintf(&b, "-- anonymous callers can: %s\n", strings.Join(e.verbs, ", "))
		for _, w := range e.why {
			fmt.Fprintf(&b, "-- %s\n", truncateComment(w))
		}
		// A relation here may be a VIEW, and a scan cannot tell from outside:
		// PostgREST exposes both as relations and answers identically. The
		// difference matters because ALTER TABLE ... ENABLE ROW LEVEL SECURITY
		// is not a no-op on a view, it is an error --
		//
		//   ERROR: ALTER action ENABLE ROW SECURITY cannot be performed on
		//          relation "view_leak"
		//   DETAIL: This operation is not supported for views.
		//
		// -- measured on PostgreSQL 16.14, and it stopped a real plan of 11,888
		// characters part-way through when piped into psql with ON_ERROR_STOP.
		//
		// So the statement is chosen at run time from pg_class. For a view the
		// right fix is security_invoker, which makes the view evaluate the base
		// table's policies as the CALLER instead of as its owner -- the default
		// of false is exactly why a protected table leaks through a view at all.
		//
		// REVOKE needs no such care: it works on both.
		// One line, not a formatted block. Every line of this output is either a
		// comment or a complete statement, and TestFixPlanIsExecutable enforces
		// that -- it is what makes the file safe to pipe anywhere. A pretty
		// multi-line DO block would have traded a real guarantee for
		// indentation.
		fmt.Fprintf(&b, "DO $$ BEGIN IF (SELECT relkind FROM pg_class WHERE oid = "+
			"to_regclass('%s')) = 'v' THEN EXECUTE 'ALTER VIEW %s SET "+
			"(security_invoker = true)'; ELSE EXECUTE 'ALTER TABLE %s ENABLE ROW "+
			"LEVEL SECURITY'; END IF; END $$;\n", e.relation, e.relation, e.relation)
		fmt.Fprintf(&b, "REVOKE ALL ON TABLE %s FROM anon;\n", e.relation)
		b.WriteString("-- Row-level security alone does not remove the GRANT, which is why\n")
		b.WriteString("-- both lines are here. If part of this access was intended, add it\n")
		b.WriteString("-- back explicitly rather than leaving the table open:\n")
		fmt.Fprintf(&b, "--   GRANT SELECT ON TABLE %s TO anon;\n", e.relation)
		fmt.Fprintf(&b, "--   CREATE POLICY %q ON %s FOR SELECT TO anon USING (true);\n",
			policyName(e.relation), e.relation)
	}
	if len(entries) > 0 {
		b.WriteString("\n-- What is open right now, per relation and per verb:\n")
		b.WriteString("-- SELECT c.relname, p.polname, p.polcmd FROM pg_policy p\n")
		b.WriteString("--   JOIN pg_class c ON c.oid = p.polrelid ORDER BY 1, 2;\n")
	}

	if len(other) > 0 {
		b.WriteString("\n-- ---------- not SQL ----------\n")
		b.WriteString("-- These are fixed somewhere other than the database: a rules file,\n")
		b.WriteString("-- a console setting, a redeploy. They are comments here because this\n")
		b.WriteString("-- file is piped into psql, and they are INCLUDED because a plan that\n")
		b.WriteString("-- silently drops them tells you there is nothing to do.\n")
		for _, o := range other {
			// Where, not just what. A rules file and a console setting are
			// different journeys, and a reader deciding what to do next needs
			// the destination before the instructions.
			fmt.Fprintf(&b, "--\n-- [%s] %s (%s)", o.sev, o.name, o.where)
			if o.resource != "" {
				fmt.Fprintf(&b, " -- %s", o.resource)
			}
			b.WriteString("\n")
			for _, ln := range strings.Split(strings.TrimRight(o.steps, "\n"), "\n") {
				t := strings.TrimSpace(ln)
				if t == "" {
					continue
				}
				// Remediation is already comment-or-SQL by the audit's rule.
				// Anything that is not a comment becomes one here, because in
				// THIS section it is prose about another system rather than a
				// statement for this one.
				if !strings.HasPrefix(t, "--") {
					fmt.Fprintf(&b, "-- %s\n", truncateComment(t))
					continue
				}
				fmt.Fprintf(&b, "%s\n", truncateComment(t))
			}
		}
	}
	return b.String()
}

// otherStep is a finding whose fix lives outside the database.
type otherStep struct {
	sev      Severity
	name     string
	resource string
	steps    string
	where    string
}

// otherSteps collects actionable findings the SQL section cannot express,
// ordered worst-first and then by name so two runs of an unchanged project
// produce identical bytes.
func otherSteps(fs []Finding) []otherStep {
	var out []otherStep
	for _, f := range fs {
		if _, isSQL := verbOfID[f.ID]; isSQL {
			continue
		}
		if f.Severity < Medium || strings.TrimSpace(f.Remediation) == "" {
			continue
		}
		out = append(out, otherStep{
			sev: f.Severity, name: f.Name, resource: f.Resource, steps: f.Remediation,
			where: f.Where(),
		})
	}
	// Grouped by destination, then worst-first within each. An operator fixing
	// a project does not interleave "edit the rules file" with "open the
	// console"; they finish one place before moving to the next.
	sort.Slice(out, func(i, j int) bool {
		if out[i].where != out[j].where {
			return out[i].where < out[j].where
		}
		if out[i].sev != out[j].sev {
			return out[i].sev > out[j].sev
		}
		if out[i].name != out[j].name {
			return out[i].name < out[j].name
		}
		return out[i].resource < out[j].resource
	})
	return out
}

// policyName keeps the suggested name stable and obviously ours.
func policyName(rel string) string {
	bare := rel
	if i := strings.LastIndex(bare, "."); i >= 0 {
		bare = bare[i+1:]
	}
	return bare + "_public_read"
}

// truncateComment keeps a reason on one line. A newline inside a -- comment
// turns the rest of the sentence into SQL.
func truncateComment(s string) string {
	s = strings.ReplaceAll(strings.ReplaceAll(s, "\r", " "), "\n", " ")
	if len(s) > 160 {
		s = s[:160] + "..."
	}
	return s
}

func dedupe(in []string) []string {
	out := in[:0]
	var last string
	for i, s := range in {
		if i == 0 || s != last {
			out = append(out, s)
		}
		last = s
	}
	return out
}
