package intent

import (
	"fmt"
	"sort"

	"github.com/eppser/unruly/internal/finding"
	"github.com/eppser/unruly/scan"
)

// Findings turns policy outcomes into the ordinary report contract.
// Violations are actionable; unverified expectations are coverage gaps and
// therefore use the scanner-wide not-assessed ID that already drives exit 3.
func Findings(target string, outcomes []Outcome) []finding.Finding {
	matched, violated, unverified := 0, 0, 0
	var out []finding.Finding
	for _, o := range outcomes {
		e := o.Expectation
		resource := fmt.Sprintf("intent:%s:%s:%s", e.Subject, e.Operation, e.Resource)
		switch o.State {
		case Matched:
			matched++
		case Unverified:
			unverified++
			f := finding.NotAssessedVerb(target, "unruly", "VERIFY INTENT",
				o.Detail+". This expectation is unverified, not satisfied")
			f.Resource = resource
			out = append(out, f)
		case Violated:
			violated++
			sev := finding.Medium
			name := "Deployed access is more restrictive than intended"
			if e.Result == Deny {
				sev = finding.High
				name = "Deployed access is more permissive than intended"
			}
			out = append(out, finding.Finding{
				ID: "unruly-intent-violation", Name: name, Severity: sev,
				Protocol: "unruly", Matched: target, Resource: resource,
				Description: o.Detail + ". This is a measured disagreement with the " +
					"operator-supplied intent manifest, not a guess about whether the " +
					"resource was meant to be public.",
				Remediation: "-- Reconcile the deployed policy and the intent manifest.\n" +
					"-- If the manifest is correct, tighten the target's access rule; if the\n" +
					"-- deployment is correct, review and update the manifest explicitly.",
				Evidence: finding.Evidence{Reason: o.Detail},
			})
		}
	}
	if len(outcomes) > 0 {
		out = append(out, finding.Finding{
			ID: "unruly-intent-summary", Name: "Intent verification summary",
			Severity: finding.Info, Protocol: "unruly", Matched: target,
			Resource: "intent:summary",
			Description: fmt.Sprintf("%d policy expectation(s): %d matched, %d violated, "+
				"%d unverified. Unverified expectations are not counted as passes.",
				len(outcomes), matched, violated, unverified),
			Evidence: finding.Evidence{Reason: fmt.Sprintf(
				"matched=%d violated=%d unverified=%d", matched, violated, unverified)},
		})
	}
	finding.Sort(out)
	return out
}

// Observations translates the provider-neutral pipeline artifact.
func Observations(access scan.Access) []Observation {
	out := make([]Observation, 0, len(access.Observed))
	for _, f := range access.Observed {
		out = append(out, Observation{Resource: f.Resource, Operation: Operation(f.Operation),
			Subject: Subject(f.Subject), Scope: Scope(f.Scope), Allowed: f.Allowed})
	}
	sort.Slice(out, func(i, j int) bool {
		return key(out[i].Resource, out[i].Operation, out[i].Subject) <
			key(out[j].Resource, out[j].Operation, out[j].Subject)
	})
	return out
}
