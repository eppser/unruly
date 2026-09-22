package browserscan

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/eppser/unruly/internal/classify"
)

// halfFrom is the length above which a value is masked by HALVES rather than
// reduced to a token.
//
// The first version kept at most four characters of anything. Safe, and too
// little: a reader looking at their own table could not tell a name from a
// product code. The operator asked for half, and this runs in their browser
// against their own project, so the trade is theirs to make.
//
// Below this length halving reveals almost nothing useful anyway, so short
// values stay heavily masked.
const halfFrom = 8

var (
	reUUID      = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	reTimestamp = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}([T ]\d{2}:\d{2}(:\d{2})?(\.\d+)?(Z|[+-]\d{2}:?\d{2})?)?$`)
)

// MaskTight keeps at most a few characters, for values that are secret.
//
// Half of a bcrypt hash is half of a bcrypt hash, and half of a card number is
// half of a PAN. The halving rule below is right for ordinary data and wrong
// for these, so anything the classifier calls a credential or a payment
// instrument comes through here instead.
func MaskTight(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	if len(s) <= 4 {
		return strings.Repeat("•", len(s))
	}
	if at := strings.IndexByte(s, '@'); at > 0 && strings.Contains(s[at:], ".") {
		local, domain := s[:at], s[at+1:]
		dot := strings.LastIndexByte(domain, '.')
		return string(local[0]) + "•••@" + string(domain[0]) + "•••" + domain[dot:]
	}
	digits := 0
	for _, r := range s {
		if r >= '0' && r <= '9' {
			digits++
		}
	}
	if digits >= 8 && digits*2 >= len(s) {
		return "•••• " + s[len(s)-4:]
	}
	n := len(s) - 1
	if n > 12 {
		n = 12
	}
	return string(s[0]) + strings.Repeat("•", n)
}

// secret reports whether a value is the kind where showing half is a leak.
func secret(column, value string) bool {
	for _, k := range classify.Kinds([]map[string]any{{column: value}}) {
		if k == "credential" || k == "financial" {
			return true
		}
	}
	return false
}

// Mask renders a value recognisable without making the report a second copy of
// the leak.
//
// Shape-aware, because the shape is the part that communicates. An email keeps
// its @ and its dot, a card number keeps its last four the way a receipt does,
// and everything else keeps a first character and its length. A value too
// short to mask safely is replaced outright rather than previewed.
func Mask(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	if s == "true" || s == "false" || s == "null" {
		return s
	}
	if len(s) <= 4 {
		return strings.Repeat("•", len(s))
	}
	// Structural noise is DESCRIBED, not masked.
	//
	// A masked timestamp reads "•••• 0:00" and a masked UUID "•••• 768d".
	// Both are safe and neither says anything, and on a wide table most
	// columns look like that, so the preview fills up with nothing. Naming the
	// shape is more useful to the reader and reveals strictly less.
	if reUUID.MatchString(s) {
		return "an ID"
	}
	if reTimestamp.MatchString(s) {
		return "a date"
	}
	// Longer than halfFrom: keep the first half, mask the rest. Enough to read
	// your own data, and the back half is still gone.
	r := []rune(s)
	if len(r) > halfFrom {
		keep := len(r) / 2
		return string(r[:keep]) + strings.Repeat("•", len(r)-keep)
	}
	// Between 5 and halfFrom characters: one character and a length hint.
	// Halving these would leave two or three characters, which reads as noise
	// without being meaningfully safer.
	return string(r[0]) + strings.Repeat("•", len(r)-1)
}

// Examples returns up to max MASKED examples per data kind, taken from rows
// the scan already retrieved.
//
// Each value is classified on its own through the public classifier, so the
// page and the CLI agree about what a value is. Nothing here sends a request,
// and nothing unmasked leaves this function.
func Examples(rows []map[string]any, max int) map[string][]string {
	out := map[string][]string{}
	if max <= 0 {
		return out
	}
	seen := map[string]bool{}
	// Columns in a stable order, so two runs against an unchanged table produce
	// the same examples.
	for _, row := range rows {
		cols := make([]string, 0, len(row))
		for c := range row {
			cols = append(cols, c)
		}
		sort.Strings(cols)
		for _, c := range cols {
			v, ok := row[c].(string)
			if !ok || v == "" {
				continue
			}
			for _, kind := range classify.Kinds([]map[string]any{{c: v}}) {
				if kind == "none" || len(out[kind]) >= max {
					continue
				}
				m := MaskTight(v)
				if m == "" || seen[kind+"\x00"+m] {
					continue
				}
				seen[kind+"\x00"+m] = true
				out[kind] = append(out[kind], m)
			}
		}
	}
	return out
}

// Field is one column and a masked sample of what it held.
type Field struct {
	Column string `json:"column"`
	Value  string `json:"value"`
}

// Preview returns one masked value per column, for EVERY readable table.
//
// Examples covers the columns a rule recognised. Most tables hold nothing a
// structural rule can name, so a page keyed only off that would tell the
// majority of people "readable" and nothing else, which reads as harmless.
// One masked value per column is what turns an abstract finding into "that is
// my customer list".
//
// Masked by the same function, so the ceiling on what escapes is the same
// whether a rule recognised the column or not.
func Preview(rows []map[string]any, maxCols int) []Field {
	if maxCols <= 0 || len(rows) == 0 {
		return nil
	}
	first := map[string]string{}
	for _, r := range rows {
		for c, v := range r {
			if _, ok := first[c]; ok {
				continue
			}
			if s := stringOf(v); s != "" {
				first[c] = s
			}
		}
	}
	cols := make([]string, 0, len(first))
	for c := range first {
		cols = append(cols, c)
	}
	// Stable order, so two runs against an unchanged table preview the same
	// columns rather than whichever the map happened to yield.
	sort.Strings(cols)
	if len(cols) > maxCols {
		cols = cols[:maxCols]
	}
	out := make([]Field, 0, len(cols))
	for _, c := range cols {
		v := first[c]
		if secret(c, v) {
			out = append(out, Field{Column: c, Value: MaskTight(v)})
			continue
		}
		out = append(out, Field{Column: c, Value: Mask(v)})
	}
	return out
}

// stringOf renders a JSON value for preview. Numbers and booleans are shown as
// written; objects and arrays are described rather than dumped, because a
// nested blob pasted into a page is the leak it is reporting.
func stringOf(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case float64:
		return strings.TrimSuffix(strings.TrimRight(fmt.Sprintf("%.4f", t), "0"), ".")
	case bool:
		if t {
			return "true"
		}
		return "false"
	case nil:
		return ""
	case map[string]any:
		return fmt.Sprintf("{%d fields}", len(t))
	case []any:
		return fmt.Sprintf("[%d items]", len(t))
	}
	return ""
}

// RuleColumns maps each column the RULES classified to what they found.
//
// The precedence this serves is the whole safety argument for the model. A
// column the rules read is never sent: they measure 0.4% false positives and
// the model far more, so putting a proof up for a second opinion trades the
// number that is trustworthy for the one that is not. And a class the rules
// already established is not repeated as an opinion, because a report that
// states one fact twice, once as evidence and once as a guess, argues with
// itself.
//
// Columns the rules could not read are absent rather than empty, which is how
// the caller tells "nothing here" from "not looked at".
func RuleColumns(rows []map[string]any) map[string][]string {
	out := map[string][]string{}
	for _, row := range rows {
		for c, v := range row {
			s, ok := v.(string)
			if !ok || s == "" {
				continue
			}
			for _, k := range classify.Kinds([]map[string]any{{c: s}}) {
				if k == "none" {
					continue
				}
				if !contains(out[c], k) {
					out[c] = append(out[c], k)
				}
			}
		}
	}
	for c := range out {
		sort.Strings(out[c])
	}
	return out
}

func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}
