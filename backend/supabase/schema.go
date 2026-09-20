package supabase

import "github.com/eppser/unruly/internal/probe"

// SchemaScan is what one non-default exposed schema's pass produced.
//
// PostgREST exposes more than the default schema when configured to, and a
// subscriber or reader asks for one by name. Each extra schema therefore gets
// its own enumeration and its own probe, and several later stages -- realtime
// delivery, the escalation compare, the scan summary -- consume the result.
//
// This type used to be declared INSIDE scanTarget. That is not incidental to
// the size of that function: a type scoped to a function scopes every consumer
// of it to the same function, so realtime and escalation could not leave main
// while the thing they iterate over could not be named from outside. Moving it
// here is a prerequisite for porting them, and it is counted as part of that
// work rather than as separate tidying.
type SchemaScan struct {
	// Name is the schema, used to qualify findings so a fix names the right
	// relation: without it a remediation says CREATE POLICY ... ON invoices
	// for a table in another schema, which resolves against search_path and
	// either errors or targets something else entirely.
	Name string
	// Relations are the names enumerated in that schema.
	Relations []string
	// Result is what probing established there. Realtime steers on which
	// relations are writable and readable; escalation needs the whole thing.
	Result probe.Result
}
