package finding

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// Table renders the report as one row per relation, for a terminal.
//
// The per-finding stream is the right default while a scan runs: it is
// grep-friendly, it interleaves with progress, and it is what a pipeline
// consumes. It is the wrong thing to read at the end. A relation that is
// readable and insertable and updatable and deletable appears as four lines
// scattered through the output, so the one question an operator actually has --
// which tables are worst, and what can be done to them -- has to be
// reconstructed by hand from a screen of text.
//
// This answers it directly: severity, relation, the four verbs, and what kind
// of data is in it. Worst first, because that is the order attention runs out.

// tableVerb maps a finding id onto its column. Ids absent from this map are not
// about reachable data and do not appear: a coverage note has no verb, and
// giving it one would be a lie in a table that reads as fact.
var tableVerb = map[string]int{
	"supabase-anon-read-exposed":            0,
	"firebase-firestore-anon-read":          0,
	"firebase-rtdb-anon-read":               0,
	"supabase-rpc-returns-data":             0,
	"supabase-anon-insert-allowed":          1,
	"supabase-anon-update-allowed":          2,
	"supabase-anon-delete-allowed":          3,
	"firebase-firestore-authenticated-read": 4,
	"supabase-authenticated-escalation":     4,
}

type tableRow struct {
	relation string
	worst    Severity
	verbs    [5]bool
	kinds    []string
	// rows is the count the SERVER reported, and known says whether it
	// reported one at all. Evidence.Rows is 0 both for "zero rows" and for
	// "no count came back", and printing 0 for the second claims a
	// measurement nobody made.
	rows  int
	known bool
}

// Table returns the rendering, or "" when nothing reachable was found.
func Table(fs []Finding, noColor bool) string {
	rows := map[string]*tableRow{}
	for _, f := range fs {
		col, ok := tableVerb[f.ID]
		if !ok || f.Resource == "" {
			continue
		}
		r := rows[f.Resource]
		if r == nil {
			r = &tableRow{relation: f.Resource, worst: f.Severity}
			rows[f.Resource] = r
		}
		if f.Severity > r.worst {
			r.worst = f.Severity
		}
		r.verbs[col] = true
		r.kinds = append(r.kinds, kindsOf(f)...)
		// Largest wins. One relation can carry several findings and only the
		// read finding asks for a count, so taking the last would overwrite a
		// real total with the zero an insert finding carries.
		if f.Evidence.Rows > r.rows {
			r.rows, r.known = f.Evidence.Rows, true
		}
	}
	if len(rows) == 0 {
		return ""
	}

	out := make([]*tableRow, 0, len(rows))
	for _, r := range rows {
		sort.Strings(r.kinds)
		r.kinds = dedupe(r.kinds)
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].worst != out[j].worst {
			return out[i].worst > out[j].worst
		}
		return out[i].relation < out[j].relation
	})

	// Width from content, so the table does not wrap on a name nobody expected.
	relW := len("RELATION")
	for _, r := range out {
		if len(r.relation) > relW {
			relW = len(r.relation)
		}
	}
	if relW > 44 {
		relW = 44
	}

	// Width from content here too, so a nine-figure count does not shove the
	// verb columns out of line.
	rowW := len("ROWS")
	for _, r := range out {
		if n := len(rowCell(r)); n > rowW {
			rowW = n
		}
	}

	const sevW = 9
	var b strings.Builder
	fmt.Fprintf(&b, "\n%-*s  %-*s  %*s  %-4s %-6s %-6s %-6s %-6s  %s\n",
		sevW, "SEVERITY", relW, "RELATION", rowW, "ROWS",
		"READ", "INSERT", "UPDATE", "DELETE", "SIGNUP", "HOLDS")
	b.WriteString(strings.Repeat("-", sevW+2+relW+2+rowW+2+4+1+6+1+6+1+6+1+6+2+5) + "\n")
	for _, r := range out {
		name := r.relation
		if len(name) > relW {
			name = name[:relW-1] + "…"
		}
		// Padded on the UNPAINTED width. %-9s applied to a coloured string
		// pads to nine BYTES, and the escape sequences alone are nine, so no
		// padding was ever added and every severity of a different length
		// started the next column somewhere else.
		sev := r.worst.String()
		pad := sevW - len(sev)
		if pad < 0 {
			pad = 0
		}
		fmt.Fprintf(&b, "%s%s  %-*s  %*s  %-4s %-6s %-6s %-6s %-6s  %s\n",
			paint(sev, r.worst, noColor), strings.Repeat(" ", pad), relW, name,
			rowW, rowCell(r),
			mark(r.verbs[0]), mark(r.verbs[1]), mark(r.verbs[2]), mark(r.verbs[3]),
			mark(r.verbs[4]), strings.Join(r.kinds, ", "))
	}
	return b.String()
}

// rowCell renders how many rows are retrievable.
//
// "?" when the server reported no count. That is not the same as none, and a
// table that prints 0 for it states a measurement that was never taken -- the
// distinction this whole project is built on, applied to a column.
func rowCell(r *tableRow) string {
	if !r.known {
		return "?"
	}
	return strconv.Itoa(r.rows)
}

// mark keeps the columns readable at a glance: something to see where access
// exists, nothing where it does not.
func mark(yes bool) string {
	if yes {
		return "yes"
	}
	return "-"
}

func paint(s string, sev Severity, noColor bool) string {
	if noColor {
		return s
	}
	var c string
	switch sev {
	case Critical:
		c = red
	case High:
		c = red
	case Medium:
		c = yellow
	case Low:
		c = blue
	default:
		c = cyan
	}
	return c + s + reset
}
