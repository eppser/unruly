package graphql

import (
	"fmt"
	"strings"

	"github.com/eppser/unruly/internal/finding"
)

// bypassFinding reports a relation readable over GraphQL that REST refused.
//
// High, because it is the case where the rest of the scan was wrong about the
// data. Both paths run the same policies, so agreement is the expectation and
// disagreement means a relation reported as protected is reachable anyway --
// by an endpoint most hardening checklists never mention.
func bypassFinding(endpoint, relation string, proof []string, limit int) finding.Finding {
	return finding.Finding{
		ID:       "supabase-graphql-rls-bypass",
		Name:     "Relation readable over GraphQL but not over REST",
		Severity: finding.High,
		Protocol: "graphql",
		Matched:  endpoint,
		Resource: relation,
		Description: fmt.Sprintf(
			"%q returned no rows to the anonymous role over the REST API and returned rows "+
				"over pg_graphql at %s. Both interfaces run the same row-level security "+
				"policies, so this is not two different verdicts about the same data -- it "+
				"is one path enforcing something the other does not, and the data is "+
				"reachable. A review that tested only the REST API would have recorded this "+
				"relation as protected.",
			relation, endpoint),
		Remediation: fmt.Sprintf(
			"-- Confirm the policy applies to every interface, then close the gap:\n\n"+
				"-- Check what is actually granted to the anonymous role\n"+
				"SELECT grantee, privilege_type FROM information_schema.role_table_grants\n"+
				"  WHERE table_name = '%s' AND grantee IN ('anon','authenticated');\n\n"+
				"-- RLS must be on, and FORCE makes it apply to the table owner too\n"+
				"ALTER TABLE public.%s ENABLE ROW LEVEL SECURITY;\n"+
				"ALTER TABLE public.%s FORCE ROW LEVEL SECURITY;\n\n"+
				"-- If GraphQL is not part of the application, take the endpoint away\n"+
				"DROP EXTENSION IF EXISTS pg_graphql;",
			relation, relation, relation),
		Evidence: finding.Evidence{
			Reason: fmt.Sprintf("GraphQL returned %d row(s); REST returned none", len(proof)),
			Request: fmt.Sprintf(
				"curl -sS -X POST '%s' -H 'apikey: $SUPABASE_ANON_KEY' "+
					"-H 'Content-Type: application/json' "+
					"-d '{\"query\":\"{ %sCollection(first: %d) { edges { node { nodeId } } } }\"}'",
				endpoint, relation, limit),
			Sample: proofRows(proof),
		},
	}
}

// exposedFinding records that the endpoint exists and answers anonymous
// queries at all.
//
// Info when it only mirrors REST, because it is then a second door to data
// already known to be public and raising it higher would put a medium on every
// project that has the extension enabled. It is still worth stating: an
// operator who has locked down PostgREST usually does not know this endpoint
// is serving the same tables.
func exposedFinding(endpoint string, readable, bypass []string, proof map[string][]string) finding.Finding {
	sev := finding.Info
	note := "Every relation it served is also readable over the REST API, so this is a " +
		"second route to data already exposed rather than new exposure."
	if len(bypass) > 0 {
		sev = finding.Medium
		note = fmt.Sprintf("%d of them returned rows the REST API refused, reported "+
			"separately as supabase-graphql-rls-bypass.", len(bypass))
	}

	var sample []map[string]any
	for _, rel := range readable {
		if ids := proof[rel]; len(ids) > 0 {
			sample = append(sample, map[string]any{"relation": rel, "node": ids[0]})
		}
		if len(sample) >= 3 {
			break
		}
	}

	return finding.Finding{
		ID:       "supabase-graphql-anon-read",
		Name:     "GraphQL endpoint answers anonymous queries",
		Severity: sev,
		Protocol: "graphql",
		Matched:  endpoint,
		Resource: strings.Join(readable, ","),
		Description: fmt.Sprintf(
			"pg_graphql is enabled and served rows to the anonymous role for %d relation(s): "+
				"%s. %s The node ids returned decode to the schema, table and primary key of "+
				"real rows, so this is the same data the REST API holds, reached over an "+
				"interface that most hardening checklists and every surveyed scanner ignore.",
			len(readable), strings.Join(readable, ", "), note),
		Remediation: "-- If the application does not use GraphQL, remove the endpoint entirely:\n\n" +
			"DROP EXTENSION IF EXISTS pg_graphql;\n\n" +
			"-- If it does, remember that every RLS policy review has to cover it: the same\n" +
			"-- tables are reachable through it, and testing only the REST API leaves half\n" +
			"-- the surface unmeasured.",
		Evidence: finding.Evidence{
			Reason: fmt.Sprintf("%d relation(s) returned rows over GraphQL", len(readable)),
			Request: fmt.Sprintf(
				"curl -sS -X POST '%s' -H 'apikey: $SUPABASE_ANON_KEY' "+
					"-H 'Content-Type: application/json' "+
					"-d '{\"query\":\"{ %sCollection(first: 3) { edges { node { nodeId } } } }\"}'",
				endpoint, readable[0]),
			Sample: sample,
		},
	}
}

// notAssessedFinding says the endpoint could not be judged, which is not the
// same as it being closed.
func notAssessedFinding(endpoint, detail string) finding.Finding {
	return finding.Finding{
		ID:       "unruly-surface-not-assessed",
		Name:     "GraphQL endpoint was not assessed",
		Severity: finding.Info,
		Protocol: "graphql",
		Matched:  endpoint,
		Resource: "graphql",
		Description: "The GraphQL surface could not be measured: " + detail + ". " +
			"This is not evidence that the endpoint is closed. pg_graphql serves the same " +
			"tables as the REST API, so an unmeasured endpoint is an unmeasured half of the " +
			"read surface.",
		Remediation: "Re-run when the endpoint is reachable, or confirm by hand:\n\n" +
			"curl -sS -X POST '" + endpoint + "' -H 'apikey: $SUPABASE_ANON_KEY' \\\n" +
			"  -H 'Content-Type: application/json' -d '{\"query\":\"{ __typename }\"}'",
		Evidence: finding.Evidence{Reason: detail},
	}
}

func proofRows(ids []string) []map[string]any {
	var out []map[string]any
	for _, id := range ids {
		out = append(out, map[string]any{"node": id})
	}
	return out
}
