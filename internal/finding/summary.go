package finding

import (
	"fmt"
	"strings"
)

// SeedOrigins counts what each source of candidate names contributed.
//
// It lives here rather than in a backend package because ScanSummary reports
// it and every backend has the same four kinds of source: a pinned list that
// ships with the binary, names harvested from the application, names the
// target advertises about itself, and names supplied from outside the process.
// A backend package could not own it without the reporting layer importing a
// backend, which is the wrong direction.
type SeedOrigins struct {
	// Pinned is the same on every scan and therefore says nothing about this
	// target.
	Pinned int
	// Harvested came from the application and is why a scan with a site beats
	// one without.
	Harvested int
	// Advertised is what the target named about itself.
	Advertised int
	// Supplied came from an operator or an agent. A report that cannot say how
	// many of its findings began as somebody else's suggestion cannot be
	// audited for it.
	Supplied int
}

// ScanSummary records the size of the examination, not its result.
//
// It is deliberately info severity and never blind: it is not a claim that
// anything is wrong, it is the denominator for everything else in the report.
// A reader diffing two scans of the same project sees the relation count move
// and knows whether a change in findings means the project changed or the
// scan reached less of it.
func ScanSummary(where string, relations, schemas, requests int, origins SeedOrigins) Finding {
	return Finding{
		ID:       "unruly-scan-summary",
		Name:     "What this scan examined",
		Severity: Info,
		Protocol: "unruly",
		Matched:  where,
		Resource: "scan",
		Description: fmt.Sprintf(
			"Discovered %d relation(s) across %d exposed schema(s) using %d requests. This "+
				"is the size of the examination, not its result: a report with no exposures "+
				"means something very different when %d relations were found than when none "+
				"were. Coverage limits are reported separately and apply to this number too.",
			relations, schemas, requests, relations) + seedProvenance(origins),
		Remediation: "-- Nothing to fix. If the relation count is lower than you expect, the " +
			"scan reached less of the project than you do: supply -site so vocabulary can " +
			"be harvested from the application, or raise -max-seeds.",
		Evidence: Evidence{
			Reason: fmt.Sprintf("%d relations, %d schemas, %d requests",
				relations, schemas, requests),
			Sample: []map[string]any{{
				"relations": relations, "schemas": schemas, "requests": requests,
				// Machine-readable, because a spreadsheet of scans is where a
				// drift in recall shows up first.
				"seeds_pinned": origins.Pinned, "seeds_harvested": origins.Harvested,
				"seeds_advertised": origins.Advertised, "seeds_supplied": origins.Supplied,
			}},
		},
	}
}

// WriteCoverage describes what the write probes actually established, derived
// from the findings themselves.
//
// It replaces a fixed sentence that said "write probing covered INSERT only:
// UPDATE and DELETE were NOT tested" — printed in the same run that emitted
// nine UPDATE findings and three DELETE findings. The tool contradicted its own
// report in a single screen of output, and a reader has no way to know which
// half to believe.
//
// The fix is structural rather than editorial. The sentence used to be a
// constant asserting a fact about the code, so it went stale the moment the
// code gained a capability. Counting the report means the summary cannot
// disagree with the findings it summarises: if a verb appears, it was tested,
// and if a verb was declined, the same not-assessed findings the reader can
// see are what says so.
func WriteCoverage(fs []Finding) string {
	proven := map[string]int{}
	declined := map[string]int{}
	for _, f := range fs {
		switch f.ID {
		case "supabase-anon-insert-allowed":
			proven["INSERT"]++
		case "supabase-anon-update-allowed":
			proven["UPDATE"]++
		case "supabase-anon-delete-allowed":
			proven["DELETE"]++
		case "unruly-surface-not-assessed":
			switch {
			case strings.HasPrefix(f.Resource, "write:"):
				declined["INSERT"]++
			case strings.HasPrefix(f.Resource, "update:"):
				declined["UPDATE"]++
			case strings.HasPrefix(f.Resource, "delete:"):
				declined["DELETE"]++
			}
		}
	}

	var parts []string
	for _, verb := range []string{"INSERT", "UPDATE", "DELETE"} { // fixed order: output is diffed
		switch {
		case proven[verb] > 0 && declined[verb] > 0:
			parts = append(parts, fmt.Sprintf("%s on %d (%d not assessed)",
				verb, proven[verb], declined[verb]))
		case proven[verb] > 0:
			parts = append(parts, fmt.Sprintf("%s on %d", verb, proven[verb]))
		case declined[verb] > 0:
			parts = append(parts, fmt.Sprintf("%s on none (%d not assessed)",
				verb, declined[verb]))
		default:
			parts = append(parts, verb+" on none")
		}
	}
	return "write probing: " + strings.Join(parts, ", ") +
		". DELETE is only decidable on a relation this scan could insert into, " +
		"because the only non-destructive DELETE probe is one aimed at a row of its own."
}

// ScanSummarySurfaces records the denominator for an application/provider
// scan that did not run the relational pipeline. Reporting "0 relations"
// would invent a database measurement; reporting nothing makes a stored
// artifact indistinguishable from a scan that never reached the target.
func ScanSummarySurfaces(where string, routes, origins, providerNames, requests int) Finding {
	return Finding{
		ID:       "unruly-scan-summary",
		Name:     "What this scan examined",
		Severity: Info,
		Protocol: "unruly",
		Matched:  where,
		Resource: "scan",
		Description: fmt.Sprintf(
			"Probed %d application route(s) across %d scoped origin(s) and asked about "+
				"%d provider candidate name(s), using %d requests. This is the size of the "+
				"examination, not its result. Provider and route coverage limits are reported "+
				"separately and apply to these counts too.",
			routes, origins, providerNames, requests),
		Remediation: "-- Nothing to fix. Review the separately reported coverage limits if " +
			"these counts are lower than expected.",
		Evidence: Evidence{
			Reason: fmt.Sprintf("%d application routes, %d origins, %d provider names, %d requests",
				routes, origins, providerNames, requests),
			Sample: []map[string]any{{
				"application_routes": routes, "application_origins": origins,
				"provider_names": providerNames, "requests": requests,
			}},
		},
	}
}

// seedProvenance names the sources that actually contributed.
//
// Sources that contributed nothing are omitted rather than reported as zero. A
// sentence that is always present and almost always says "0 supplied" is one
// readers learn to skip, and this has to survive being read on every scan.
func seedProvenance(o SeedOrigins) string {
	parts := []string{fmt.Sprintf("%d from the pinned list", o.Pinned)}
	if o.Harvested > 0 {
		parts = append(parts, fmt.Sprintf("%d harvested from the application", o.Harvested))
	}
	if o.Advertised > 0 {
		parts = append(parts, fmt.Sprintf("%d advertised by the OpenAPI document", o.Advertised))
	}
	if o.Supplied > 0 {
		parts = append(parts, fmt.Sprintf("%d supplied with -vocab", o.Supplied))
	}
	if len(parts) == 1 {
		return " Candidate names came from " + parts[0] + "."
	}
	return " Candidate names came from " + strings.Join(parts[:len(parts)-1], ", ") +
		" and " + parts[len(parts)-1] + "."
}
