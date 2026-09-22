package browserscan

import (
	"sort"
	"strings"

	"github.com/eppser/unruly/internal/classify"
)

// maxKept is how many characters of an original value may survive masking.
//
// Four. Enough that someone recognises the shape of their own data -- "that is
// an email address, in my customers table" -- and not enough for the example
// to BE the data. internal/classify reports kinds and never values for exactly
// this reason; showing an example at all is a concession to the person reading
// the page, and this constant is the size of the concession.
const maxKept = 4

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
	if len(s) <= 4 {
		return strings.Repeat("•", len(s))
	}
	// Email: one character of the local part, one of the domain, the TLD.
	if at := strings.IndexByte(s, '@'); at > 0 && strings.Contains(s[at:], ".") {
		local, domain := s[:at], s[at+1:]
		dot := strings.LastIndexByte(domain, '.')
		return string(local[0]) + "•••@" + string(domain[0]) + "•••" + domain[dot:]
	}
	// Mostly digits: keep the last four, the way a receipt does.
	digits := 0
	for _, r := range s {
		if r >= '0' && r <= '9' {
			digits++
		}
	}
	if digits >= 8 && digits*2 >= len(s) {
		return "•••• " + s[len(s)-4:]
	}
	// Everything else: one character and a length hint.
	n := len(s) - 1
	if n > 12 {
		n = 12
	}
	return string(s[0]) + strings.Repeat("•", n)
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
				m := Mask(v)
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
