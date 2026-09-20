package routes

import (
	"fmt"

	"github.com/eppser/unruly/internal/finding"
)

func routeBudgetFinding(site, resource, flag string, probed, total int) finding.Finding {
	return finding.Finding{
		ID:       "unruly-probe-budget-exhausted",
		Name:     "Application route probing stopped at its budget",
		Severity: finding.Info,
		Protocol: "http",
		Matched:  site,
		Resource: resource,
		Description: fmt.Sprintf("%s limited this check to %d of %d eligible paths, so its "+
			"results are a lower bound. The bound limits requests sent to application "+
			"origins; increasing it trades more traffic for more recall.", flag, probed, total),
		Remediation: fmt.Sprintf("-- Re-run with a larger %s value if the additional application "+
			"traffic is acceptable.", flag),
		Evidence: finding.Evidence{Reason: fmt.Sprintf("%d of %d eligible paths probed", probed, total)},
	}
}
