package finding

import (
	"fmt"
	"sort"
	"strings"
)

// SkippedCheck is a check that did not run, and why.
type SkippedCheck struct {
	Name   string
	Reason string
	Enable string
}

// Coverage builds the finding that records what a scan did NOT examine.
//
// This belongs in the findings stream, not only in the log. The log is what a
// person watching a terminal sees; the findings stream is what gets stored,
// diffed in CI, pasted into a ticket and read by someone who was not there.
// With -silent -json a default scan emitted 13 findings and no trace at all
// that write exposure, routine callability, Edge Functions and route POST
// probing had never been checked — a machine-readable report that looks
// complete.
//
// A tool whose central claim is that absence of findings is not evidence of
// absence has to say which absences it created on purpose, in the same place
// it says everything else.
func Coverage(target string, skipped []SkippedCheck) (Finding, bool) {
	if len(skipped) == 0 {
		return Finding{}, false
	}
	sort.Slice(skipped, func(i, j int) bool { return skipped[i].Name < skipped[j].Name })

	var names []string
	var body strings.Builder
	body.WriteString("This scan did not examine the following, so it says nothing about them. " +
		"Absence of findings for a skipped check is not evidence that it is sound.\n")
	for _, s := range skipped {
		names = append(names, s.Name)
		fmt.Fprintf(&body, "\n  %s — %s (enable with %s)", s.Name, s.Reason, s.Enable)
	}

	return Finding{
		ID:          "unruly-checks-skipped",
		Name:        fmt.Sprintf("%d %s did not run", len(skipped), plural(len(skipped), "check", "checks")),
		Severity:    Info,
		Protocol:    "unruly",
		Matched:     target,
		Resource:    strings.Join(names, ","),
		Description: body.String(),
		Remediation: "-- Re-run with the flags listed above to cover them. Each is off by " +
			"default because performing it writes to the target: POSTing to an application " +
			"route, invoking a database routine or an Edge Function, or inserting a row.",
		Evidence: Evidence{
			Reason: fmt.Sprintf("%d of the scan's checks were not performed", len(skipped)),
		},
	}, true
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// blindIDs are findings that mean the scan COULD NOT look at something, as
// opposed to chose not to.
//
// unruly-checks-skipped is deliberately absent. It fires whenever -write
// is not passed, which is the default and a decision the operator made; if it
// counted here, almost every scan would report incomplete coverage and the
// signal would mean nothing.
var blindIDs = map[string]bool{
	"unruly-target-not-discriminating": true,
	"unruly-capability-degraded":       true,
	"unruly-surface-not-assessed":      true,
	"unruly-probes-unresolved":         true,
	// A scan truncated by its own probe budget did not finish looking, so it
	// must not exit 0. Added with the budget flag rather than after somebody
	// noticed a capped run reporting clean.
	"unruly-probe-budget-exhausted": true,
}

// notBlindResources are (id, resource) pairs excluded from the blindness set
// even though their id appears above.
//
// Routine discovery is capped at 1,200 candidates by DESIGN — the default
// binds on almost every real project (7,547 candidates on the reference
// target). Counting that as a surface the scan could not see would put nearly
// every scan at exit 3 and drain the code of meaning, which is the mistake
// made once already with Realtime delivery. The finding is still emitted,
// because "1200 of 7547 probed" is a fact the reader is owed; it is the exit
// code that must stay a signal.
//
// Relation discovery is different: its budget is 15,000 against an expansion
// of ~13,700, so truncation there is exceptional and means the fallback did
// not finish.
// The vocabulary cap is the same case as routine discovery: 2,000 seeds
// against 4,112 harvested on the reference project, so it binds on ordinary
// sites and counting it would move nearly every scan with a -site to exit 3.
// The finding is emitted regardless, because a lower bound the reader is not
// told about is the failure this scanner exists to avoid.
// The write blind spot on unreadable relations is the same case again, and it
// is the strongest instance of it. UPDATE and DELETE cannot be established on
// a relation that returns no rows -- there is no row to aim at and no way to
// create one -- so the statement fires on every project that has a single
// correctly protected table, which is every well-configured project there is.
// Counting it as blindness makes a hardened project exit 3 and become
// indistinguishable from an unreachable one, which is the exact inversion the
// exit code exists to prevent.
//
// Learned by doing it: the finding was added claiming it "does not move the
// exit code", and the hardened fixture went from 0 to 3 on the next audit.
// The claim was not checked, and the check already existed.
var notBlindResources = map[string]bool{
	"unruly-probe-budget-exhausted/routine-discovery":              true,
	"unruly-probe-budget-exhausted/vocabulary":                     true,
	"unruly-probe-budget-exhausted/application-bypasses":           true,
	"unruly-surface-not-assessed/write-verbs:unreadable-relations": true,
}

// CoverageIncomplete reports whether any part of the scan could not be
// measured, and names what.
//
// This exists because of the exit code. Measured before it did: a correctly
// hardened project, a host that is not Supabase at all, an origin returning
// 500, and a completely unreachable address ALL exited 0 — the same code as a
// clean scan. In CI that makes `unruly ... && echo secure` print secure
// for a typo in the URL, which is this project's entire thesis inverted and
// then handed to a machine.
func CoverageIncomplete(fs []Finding) (bool, []string) {
	seen := map[string]bool{}
	var what []string
	for _, f := range fs {
		if !blindIDs[f.ID] || notBlindResources[f.ID+"/"+f.Resource] {
			continue
		}
		key := f.ID + "/" + f.Resource
		if seen[key] {
			continue
		}
		seen[key] = true
		what = append(what, f.Resource)
	}
	sort.Strings(what)
	return len(what) > 0, what
}

// InterruptedResource marks the finding that reports a scan stopping early.
const InterruptedResource = "scan:interrupted"

// AttributeBlindnessToInterruption qualifies every could-not-measure verdict in
// an interrupted scan.
//
// Cancelling the context makes in-flight requests fail, and those failures are
// indistinguishable from a target that would not answer. The existing findings
// then describe them as properties of the TARGET, with remediation to match:
// after a Ctrl-C, a report says the control probe did not complete and advises
// "-- Point -u at the PostgREST endpoint itself, or pass -rest-prefix". That is an
// operator sent to debug a configuration problem they do not have.
//
// Saying the scan was interrupted, once, at the top of the report is not enough
// -- findings are read individually, sorted away from each other, and filtered
// by id. The attribution has to travel on each one.
//
// These are NOT deleted. On an interrupted scan the two causes genuinely cannot
// be told apart: the surface may really be unreachable, and dropping the
// findings would replace an ambiguous answer with a confidently wrong one.
func AttributeBlindnessToInterruption(fs []Finding) {
	for i := range fs {
		f := &fs[i]
		if !blindIDs[f.ID] || f.Resource == InterruptedResource {
			continue
		}
		f.Description = "THE SCAN WAS INTERRUPTED, so this surface may be unmeasured because " +
			"the scan stopped rather than because of anything the target did -- the two are " +
			"indistinguishable from here. " + f.Description
		f.Remediation = "First re-run the scan and let it finish; an interrupted scan produces " +
			"this finding on its own. If it persists on a complete run, then: " + f.Remediation
	}
}
