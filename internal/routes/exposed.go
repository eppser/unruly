package routes

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/eppser/unruly/internal/classify"
	"github.com/eppser/unruly/internal/finding"
)

// standaloneExposure reports an endpoint that hands data to anyone, whether or
// not its siblings do.
//
// The route check emitted a finding only when a FAMILY was inconsistent --
// /orders/1 requiring a session while /orders/2 did not. Inconsistency is a
// proxy for a missing authorisation check and a good one, but it carries an
// assumption nobody stated: that an endpoint answering anonymously is fine if
// its siblings do too.
//
// So an API where EVERYTHING is open scores perfectly consistent, and the
// worst case became the blind spot. Measured on a real target: one endpoint
// returned a live, database-backed record containing an employee address to
// anyone who asked. Discovered, probed, 200, and silent, because it was alone
// in its family.
//
// THE CLASSIFIER IS THE DISCRIMINATOR. Plenty of endpoints answer 200 to
// anyone on purpose -- /health, /version, a public price list -- and reporting
// all of them would bury the one that matters. What separates them is not the
// status code or the path but what came back: if the body holds nothing worth
// protecting, there is nothing to report. That also means severity is not
// invented here; it follows what was found.
func standaloneExposure(r Route, redact bool) (finding.Finding, bool) {
	// Only a body that was actually served to an anonymous caller.
	if r.GET != 200 || strings.TrimSpace(r.Snippet) == "" {
		return finding.Finding{}, false
	}

	kinds := classifyBody(r.Snippet)
	if len(kinds) == 0 {
		return finding.Finding{}, false
	}

	sev := severityFor(kinds)
	url := r.Base + r.Path

	// The value is redacted and the CLASS is kept, always -- not only under
	// -redact. A report that copies the leaked address is a second copy of the
	// leak, and it gets stored, diffed and pasted into tickets.
	//
	// The class is what the finding is about, so removing it would leave a
	// sentence saying something was exposed without saying what.
	sample := []map[string]any{{
		"bytes":   len(r.Snippet),
		"holding": strings.Join(kinds, ", "),
	}}
	_ = redact

	return finding.Finding{
		ID:       "app-public-record-exposure",
		Name:     "An application endpoint serves data to anonymous callers",
		Severity: sev,
		Protocol: "http",
		Matched:  url,
		Resource: r.Path,
		Description: fmt.Sprintf("GET %s returns 200 to a caller with no credentials, "+
			"and the response holds %s. This is not an inconsistency between related "+
			"routes -- the endpoint simply serves the data to anyone. An API where "+
			"every route is open is perfectly consistent, which is why a check that "+
			"only looks for inconsistency cannot see this.",
			url, strings.Join(kinds, ", ")),
		Remediation: "-- Require authentication on this endpoint, or confirm the data " +
			"is intended to be public.\n-- If it is intended, record it: an endpoint " +
			"nobody meant to publish and one everybody agreed to publish look identical " +
			"from outside.",
		Evidence: finding.Evidence{
			Request: "curl -sS " + url,
			Status:  r.GET,
			Reason: fmt.Sprintf("200 with no credentials; response classified as %s",
				strings.Join(kinds, ", ")),
			Classes: kinds,
			Sample:  sample,
		},
	}, true
}

// classifyBody runs the existing data classifier over a JSON response.
//
// Reusing it rather than writing a second one: the vocabulary, the reserved
// domains and the lookalike exclusions are all decisions this project has
// already made and tested, and a second classifier would drift from the first.
func classifyBody(body string) []string {
	var rows []map[string]any

	var obj map[string]any
	if err := json.Unmarshal([]byte(body), &obj); err == nil {
		rows = append(rows, flatten(obj)...)
	} else {
		var arr []map[string]any
		if err := json.Unmarshal([]byte(body), &arr); err != nil {
			return nil
		}
		for _, o := range arr {
			rows = append(rows, flatten(o)...)
		}
	}
	if len(rows) == 0 {
		return nil
	}
	// Names as well as values: a field called `password_hash` matters even if
	// the value looks like nothing, and a field called `updated_by` holding an
	// address matters even though its name says nothing.
	kinds := classify.Kinds(rows)
	var names []string
	for _, row := range rows {
		for k := range row {
			names = append(names, k)
		}
	}
	// classify.Names returns "field:class" pairs; Kinds returns bare classes.
	// Reduced to bare classes here so severity and the finding's own wording
	// speak one vocabulary -- without this the severity switch matched
	// nothing and every exposure came out at the floor.
	return merge(kinds, bareClasses(classify.Names(names)))
}

// flatten turns nested JSON into flat rows, because the interesting field is
// routinely one level down inside a `data` envelope -- which is exactly the
// shape the real record had.
func flatten(o map[string]any) []map[string]any {
	flat := map[string]any{}
	var nested []map[string]any
	for k, v := range o {
		switch t := v.(type) {
		case map[string]any:
			nested = append(nested, flatten(t)...)
		case []any:
			for _, e := range t {
				if m, ok := e.(map[string]any); ok {
					nested = append(nested, flatten(m)...)
				}
			}
		default:
			flat[k] = v
		}
	}
	return append([]map[string]any{flat}, nested...)
}

func merge(a, b []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range append(append([]string{}, a...), b...) {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

// severityFor maps what was found to how much it matters.
//
// The same ordering the relation findings use, so one class does not mean two
// different things depending on which surface exposed it.
func severityFor(kinds []string) finding.Severity {
	worst := finding.Low
	for _, k := range kinds {
		switch k {
		case "credential":
			return finding.Critical
		case "financial", "government-id", "health":
			worst = finding.High
		case "pii":
			if worst < finding.Medium {
				worst = finding.Medium
			}
		case "contact", "location":
			if worst < finding.Low {
				worst = finding.Low
			}
		}
	}
	return worst
}

// bareClasses turns "field:class" pairs into classes.
//
// The two halves of the classifier answer in different shapes: Kinds says
// "contact", Names says "updated_by_email:contact". Both are useful -- the
// field name is what an operator needs to find the leak -- but severity is a
// function of the CLASS, and mixing the shapes made the severity switch match
// nothing while looking correct.
func bareClasses(pairs []string) []string {
	out := make([]string, 0, len(pairs))
	for _, p := range pairs {
		if i := strings.LastIndex(p, ":"); i >= 0 {
			p = p[i+1:]
		}
		out = append(out, p)
	}
	return out
}
