package routes

import (
	"fmt"
	"regexp"
	"strings"
)

// Templated paths, and where an identifier came from.
//
// /invoices/{id} is not probeable as written: {id} is not a resource, and
// inventing one means requesting a record belonging to somebody the operator
// never mentioned. So templates were discarded, and with them every endpoint
// that takes an identifier -- which on most APIs is where the data is.
//
// The operator knows an id: it is their application. Once they say so the path
// is as probeable as any other, and the request is for a record they named.

// Params are the values an operator supplied for path templates.
type Params map[string]string

// Source records where an identifier came from.
//
// THE DISTINCTION IS THE POINT. A finding on /invoices/42 means something
// different depending on whether 42 was supplied by the operator or guessed by
// the scanner. The first says "your own record is readable"; the second says
// "a record we picked is readable, and we do not know whose". Reporting them
// identically would let a guess be read as a demonstration.
type Source string

const (
	// SourceSupplied: the operator named this value.
	SourceSupplied Source = "supplied"
	// SourceGuessed: the scanner derived it. Never proof on its own.
	SourceGuessed Source = "guessed"
)

// reTemplate matches the placeholder syntaxes frameworks use.
var reTemplate = regexp.MustCompile(`\{([a-zA-Z0-9_]+)\}|:([a-zA-Z0-9_]+)|\[([a-zA-Z0-9_]+)\]`)

// ParseParams reads -route-param values as an operator types them.
//
// Malformed entries are DROPPED rather than turned into a request: a parameter
// somebody mistyped should not become a URL, and half a key=value pair names
// nothing.
func ParseParams(raw []string) Params {
	out := Params{}
	for _, r := range raw {
		k, v, ok := strings.Cut(r, "=")
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		if !ok || k == "" || v == "" {
			continue
		}
		out[k] = v
	}
	return out
}

// fillTemplate substitutes supplied values into a path template.
//
// ALL OR NOTHING. A template with any placeholder the operator did not supply
// is left alone: filling {customer_id} with the value given for {id} would
// send a request for a record nobody named, and calling the answer coverage.
func fillTemplate(path string, params Params) (string, bool) {
	if !reTemplate.MatchString(path) {
		return path, false
	}
	missing := false
	out := reTemplate.ReplaceAllStringFunc(path, func(m string) string {
		name := strings.Trim(m, "{}:[]")
		v, ok := params[name]
		if !ok {
			missing = true
			return m
		}
		return v
	})
	if missing {
		return "", false
	}
	return out, true
}

// paramEvidence describes how a concrete path was arrived at.
func paramEvidence(template, filled string, src Source) string {
	switch src {
	case SourceSupplied:
		return fmt.Sprintf("%s probed as %s, using an identifier the operator supplied "+
			"with -route-param: the record named is one they told this scan about",
			template, filled)
	default:
		return fmt.Sprintf("%s probed as %s, using an identifier this scan GUESSED from "+
			"a supplied one. Whose record that is, this scan does not know -- so what "+
			"came back is the evidence, and the guess alone proves nothing",
			template, filled)
	}
}
