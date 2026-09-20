// Package schemas discovers which PostgREST schemas a project exposes.
//
// Every scanner surveyed, including this one until now, probes the default
// schema and stops. That is a blind spot with the same shape as depending on
// the OpenAPI root: relations in another exposed schema are never asked about,
// nothing is reported, and nothing is exactly what a clean project looks like.
//
// PostgREST volunteers the answer. Ask for a schema that cannot exist and the
// refusal names every schema that does:
//
//	GET /rest/v1/anything
//	Accept-Profile: unruly_no_such_schema
//	-> 406 PGRST106
//	   "Only the following schemas are exposed: public, graphql_public, staging"
//
// One request, no wordlist, no guessing. Measured against both projects
// available: the exploit lab exposes the two defaults, and the reference target
// exposes a third that every scan of it had silently ignored.
//
// graphql_public is not interesting on its own -- it is pg_graphql's plumbing
// and is served to every project -- so the finding is about what a project
// ADDED, which is where an unreviewed surface lives.
package schemas

import (
	"context"
	"sort"
	"strings"

	"github.com/eppser/unruly/internal/client"
	"github.com/eppser/unruly/internal/finding"
)

// ProbeSchemaName is asked for so PostgREST refuses and lists the real ones.
// Nothing may define it.
const ProbeSchemaName = "unruly_control_schema_that_cannot_exist"

// hintPrefix is the text PostgREST puts before the list.
const hintPrefix = "Only the following schemas are exposed: "

// Default schemas every Supabase project serves. Anything else was added by
// the project and is worth naming.
var defaultSchemas = map[string]bool{
	"public":         true,
	"graphql_public": true,
}

// Result is what could be established about the schema surface.
type Result struct {
	// Exposed lists every schema PostgREST will serve, sorted. Empty when the
	// oracle did not answer, which is NOT the same as "only the default".
	Exposed []string
	// Extra is Exposed minus the schemas every project has.
	Extra []string
	// Answered is false when the probe produced no usable hint, so the schema
	// surface is unknown rather than known to be minimal.
	Answered bool
	Findings []finding.Finding
	Requests int
}

// Discover asks PostgREST which schemas it serves.
func Discover(ctx context.Context, c *client.Client) Result {
	var res Result

	resp := c.Get(ctx, c.RestURL("unruly_schema_probe")+"?limit=1",
		map[string]string{"Accept-Profile": ProbeSchemaName})
	res.Requests++
	if resp.Err != nil {
		return res
	}
	_, _, hint := resp.DecodeError()
	names, ok := parseExposed(hint)
	if !ok {
		// No hint: an older PostgREST, a gateway that rewrote the error, or a
		// host that is not PostgREST at all. Silence here means unknown, and
		// the caller decides whether that is worth reporting -- claiming "only
		// the default is exposed" would be inventing a measurement.
		return res
	}

	res.Answered = true
	res.Exposed = names
	for _, n := range names {
		if !defaultSchemas[n] {
			res.Extra = append(res.Extra, n)
		}
	}
	sort.Strings(res.Extra)
	if len(res.Extra) > 0 {
		res.Findings = append(res.Findings, extraSchemaFinding(c, res.Exposed, res.Extra, resp.Status))
	}
	return res
}

// parseExposed pulls the schema list out of the PGRST106 hint.
func parseExposed(hint string) ([]string, bool) {
	i := strings.Index(hint, hintPrefix)
	if i < 0 {
		return nil, false
	}
	rest := strings.TrimSpace(hint[i+len(hintPrefix):])
	rest = strings.TrimSuffix(rest, ".")
	var out []string
	for _, part := range strings.Split(rest, ",") {
		if name := strings.TrimSpace(part); name != "" {
			out = append(out, name)
		}
	}
	if len(out) == 0 {
		return nil, false
	}
	sort.Strings(out)
	return out, true
}

func extraSchemaFinding(c *client.Client, exposed, extra []string, status int) finding.Finding {
	return finding.Finding{
		ID:       "supabase-extra-schema-exposed",
		Name:     "PostgREST serves a schema beyond the defaults",
		Severity: finding.Info,
		Protocol: "postgrest",
		Matched:  c.RestBase(),
		Resource: strings.Join(extra, ","),
		Description: "PostgREST exposes " + strings.Join(exposed, ", ") + ". Beyond the " +
			"defaults every project serves, this one adds: " + strings.Join(extra, ", ") + ". " +
			"Relations there are reachable with an Accept-Profile header and are invisible to " +
			"any scanner that probes only the default schema. This scan probes them, and its " +
			"findings for them are named schema.relation.",
		Remediation: "If a schema is not meant to be part of the public API, stop exposing it:\n\n" +
			"-- Supabase: Settings > API > Exposed schemas, or\n" +
			"ALTER ROLE authenticator SET pgrst.db_schemas = 'public, graphql_public';\n" +
			"NOTIFY pgrst, 'reload config';\n\n" +
			"-- and confirm the roles cannot reach it regardless\n" +
			"REVOKE USAGE ON SCHEMA " + extra[0] + " FROM anon, authenticated;",
		Evidence: finding.Evidence{
			Reason: "PostgREST named its exposed schemas when asked for one that cannot exist",
			Request: "curl -sS '" + c.RestBase() + "/unruly_schema_probe?limit=1' " +
				"-H 'apikey: $SUPABASE_ANON_KEY' -H 'Accept-Profile: " + ProbeSchemaName + "'",
			// The refusal IS the disclosure: PGRST106 names every exposed
			// schema in its hint, so the status is the evidence rather than an
			// incidental detail.
			Status: status,
			Sample: []map[string]any{{"exposed": strings.Join(exposed, ", ")}},
		},
	}
}
