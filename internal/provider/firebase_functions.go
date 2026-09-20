package provider

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/eppser/unruly/internal/finding"
)

// Cloud Functions, probed only where probing is defensible.
//
// Existence is decidable here, as it is for Storage and unlike Firestore:
// measured against the lab, a name that does not exist answers 404 and the host
// resolves whether or not the project has functions at all.
//
//	GET https://us-central1-<project>.cloudfunctions.net/definitely-not-a-name  404
//	GET https://europe-west1-<project>.cloudfunctions.net/definitely-not-a-name 404
//
// What is NOT defensible is the obvious next step. The pinned function
// wordlist holds 398 names, and probing them across two regions would be some
// eight hundred requests that each RUN somebody's code. A function named
// send-invoices or purge-old-rows does what it says when called, and no
// wordlist can know which one it just triggered.
//
// So two limits, and they are the whole design:
//
//  1. gated behind -invoke, exactly as Supabase routines and Edge Functions
//     are, because calling is not reading;
//  2. candidates come ONLY from the application's own bundles, capped. A name
//     the app itself calls is a name the app already calls on every page load;
//     a guessed name is a stranger's code nobody asked to run.
//
// Measured on real infrastructure, which this comment used to deny.
//
// It said the positive path was "graded against a stub and has never been
// measured", because deploying needed a Blaze plan the lab did not have. That
// was true when written and is not now: billing was linked, firebase-tools
// deployed two functions to firebase-lab-000000, and all three shapes were
// measured in one run against the live project --
//
//	publicEcho      200, and it RAN: it returned its own output, which a
//	                reachable endpoint that refuses cannot produce
//	privateControl  403, identical except its invoker binding excludes
//	                allUsers, so "public" means invocable rather than resolvable
//	a name that cannot exist   404
//
// The 403 shape in particular is no longer reported-but-unseen. Left stale,
// this comment would have gone on understating what the scanner is known to
// do, in a file whose whole subject is not claiming more than was measured.

// functionHost lets a test point the probe at a stub, for the same reason
// identityToolkit and storageHost are variables: a unit test asserting that
// this scanner does NOT call things must not call Google to prove it.
var functionHostOverride string

func functionHost(real string) string {
	if functionHostOverride != "" {
		return functionHostOverride
	}
	return real
}

// functionRegions are where v1 HTTP functions live under a guessable hostname.
//
// v2 functions are Cloud Run services published at a host containing a
// generated hash, so they cannot be addressed by name at all. This check does
// not pretend otherwise: it covers v1, and says so.
var functionRegions = []string{"us-central1"}

// maxFunctionProbes caps how many of the application's own names are called.
const maxFunctionProbes = 25

// functionNameOK keeps the probe to things that can actually be function names.
var functionNameOK = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_-]{2,62}$`)

// functionFindings probes Cloud Functions named by the application.
func functionFindings(ctx context.Context, d Detection, o ScanOptions) []finding.Finding {
	base := "https://" + functionRegions[0] + "-" + d.Project + ".cloudfunctions.net"
	if !o.Invoke {
		return []finding.Finding{finding.NotAssessedVerb(base, "cloud-functions", "INVOKE",
			"establishing whether a Cloud Function is publicly callable means CALLING it, "+
				"and calling one runs it. That is gated: re-run with -invoke on a project "+
				"you own. Until then a function reachable by anyone is unmeasured, not absent")}
	}

	names, dropped := functionCandidates(o.Supplied, o.Harvested)
	if len(names) == 0 {
		return []finding.Finding{finding.NotAssessedVerb(base, "cloud-functions", "INVOKE",
			"the application names no Cloud Function this scan could recognise, and "+
				"function names are not guessed: probing a guessed name runs somebody's "+
				"code. Nothing was called and nothing is known about this project's "+
				"functions")}
	}

	var out []finding.Finding
	if dropped > 0 {
		out = append(out, finding.Finding{
			ID:       "unruly-probe-budget-exhausted",
			Name:     "Cloud Function probing stopped at the call budget",
			Severity: finding.Info,
			Protocol: "functions",
			Matched:  base,
			Resource: "cloud-functions",
			Description: fmt.Sprintf(
				"Calling a function RUNS it, so this check is bounded at %d names and %d "+
					"more were not called. Those were neither reached nor ruled out, and "+
					"that matters more here than elsewhere: a name nobody asked about "+
					"produces no finding, and so does a function that is not deployed, so "+
					"the functions reported are a LOWER BOUND rather than the whole set. "+
					"Names supplied with -vocab are called FIRST, so an operator who knows "+
					"what is deployed never loses one to this budget; the harvested "+
					"remainder is sampled across the whole list rather than its first "+
					"entries, so the loss is not concentrated in names beginning with any "+
					"particular letter.",
				maxFunctionProbes, dropped),
		})
	}
	regions := regionsFor(d)
	var reached int
	for _, region := range regions {
		host := "https://" + region + "-" + d.Project + ".cloudfunctions.net"
		for _, name := range names {
			r := o.Client.Do(ctx, "GET", functionHost(host)+"/"+name, nil, nil)
			switch {
			case r.Err != nil, r.Status == 404:
				// Absent, or unreachable. Neither is a finding: a name that is
				// not there says nothing about the ones that are.
			case r.Status == 403 || r.Status == 401:
				reached++
				out = append(out, functionPrivateFinding(d, host, name, r.Status))
			case r.Status >= 200 && r.Status < 300:
				reached++
				out = append(out, functionPublicFinding(d, host, name, r.Status))
			}
		}
	}

	// Silence has to say where it looked.
	//
	// Functions are addressed per REGION. This scan tries us-central1 plus one
	// region inferred from the Realtime Database URL, which helps only when the
	// project has an RTDB and it names a region the inference knows; Google
	// offers dozens. So a project whose functions live in asia-northeast1
	// answers 404 to every name and produces no finding -- output identical to
	// a project that has no functions at all.
	//
	// Probing every region is not the answer: each probe RUNS somebody's code,
	// and dozens of regions across the name budget is hundreds of executions of
	// software nobody asked this scanner to start. Saying where it looked costs
	// nothing and lets a reader tell an empty result from an unexamined one.
	//
	// Only when nothing answered. A note that fires on every scan is a note
	// people learn to skip past.
	if reached == 0 {
		out = append(out, finding.Finding{
			ID:       "unruly-surface-not-assessed",
			Name:     "Cloud Functions were looked for in some regions, not all",
			Severity: finding.Info,
			Protocol: "functions",
			Matched:  base,
			Resource: "cloud-functions",
			Description: fmt.Sprintf(
				"%d name(s) were called and none answered in the regions this scan tried: "+
					"%s. Functions are addressed per region and Google offers dozens, so "+
					"this is not evidence that the project has none -- one deployed "+
					"elsewhere answers 404 here exactly as an undeployed name does. The "+
					"region is guessed from the Realtime Database URL where there is one, "+
					"because that is the only region hint an anonymous caller gets. Every "+
					"region is not probed on purpose: calling a function runs it.",
				len(names), strings.Join(regions, ", ")),
		})
	}
	return out
}

// regionsFor returns the regions worth trying.
//
// The Realtime Database URL names the project's region when it is not the
// default, which is the only region hint an anonymous caller gets. Using it
// avoids probing us-central1 for a project that plainly lives in Europe, and
// avoids probing both for one that does not.
func regionsFor(d Detection) []string {
	regions := append([]string{}, functionRegions...)
	if d.RTDB == "" {
		return regions
	}
	for _, r := range []string{"europe-west1", "asia-southeast1", "us-east1", "us-east4"} {
		if strings.Contains(d.RTDB, r) {
			return append([]string{r}, regions...)
		}
	}
	return regions
}

// functionCandidates picks names to call, capped, and says how many it cut.
//
// Supplied names come first and the ordering is the whole point. Harvested
// vocabulary is whatever the page happened to contain -- config keys, fragments
// of the API key, "doctype" -- and there are always more of those than the
// budget allows. Sorting the merged set and truncating meant an operator could
// name a function, watch thirty tokens of noise sort ahead of it, and get
// silence back: measured against the lab, privateControl survived at position
// 25 and publicEcho was cut at 28.
//
// A supplied name is an assertion, not a guess. Nothing else here treats the
// two the same, and neither does this.
//
// The returned count is how many candidates the budget refused. It is not
// decoration: a dropped name produces no finding, and no finding is exactly
// what a function that is not deployed produces, so the only way a bounded
// search can be told apart from a complete one is by saying so.
func functionCandidates(supplied, harvested []string) ([]string, int) {
	seen := map[string]bool{}
	keep := func(src []string) []string {
		var out []string
		for _, h := range src {
			if !functionNameOK.MatchString(h) || seen[h] {
				continue
			}
			seen[h] = true
			out = append(out, h)
		}
		sort.Strings(out) // stable: the same application yields the same probe set
		return out
	}
	first, rest := keep(supplied), keep(harvested)
	if len(first) >= maxFunctionProbes {
		// Even the asserted names exceed the budget. Cut those rather than
		// silently preferring some of them over harvested guesses.
		return first[:maxFunctionProbes], len(first) - maxFunctionProbes + len(rest)
	}
	room := maxFunctionProbes - len(first)
	if len(rest) <= room {
		return append(first, rest...), 0
	}
	// Sample ACROSS the harvested names rather than taking their alphabetical
	// head. Taking the head concentrates every loss in the back half of the
	// alphabet, which is how publicEcho was cut while privateControl survived.
	// The stride is deterministic, so the same application yields the same
	// probe set on every run.
	step := float64(len(rest)) / float64(room)
	picked := make([]string, 0, room)
	for i := 0; i < room; i++ {
		picked = append(picked, rest[int(float64(i)*step)])
	}
	return append(first, picked...), len(rest) - room
}

// functionPublicFinding reports a function anyone can call.
func functionPublicFinding(d Detection, host, name string, status int) finding.Finding {
	return finding.Finding{
		ID:       "firebase-function-public",
		Name:     "Cloud Function runs for anyone who calls it",
		Severity: finding.High,
		Protocol: "functions",
		Matched:  host + "/" + name,
		Resource: name,
		Description: fmt.Sprintf(
			"The function %s answered HTTP %d to a request carrying no credentials, so its "+
				"invoker binding includes allUsers and anybody on the internet can run it. "+
				"What that costs depends entirely on what the function does -- functions "+
				"commonly hold the privileged access their callers are not trusted with, "+
				"which is the point of putting logic there. This scan called it once and "+
				"cannot tell you what it did.", name, status),
		FixKind: finding.FixConsole,
		Remediation: "-- Not a rules change: this is IAM on the function.\n" +
			"--   gcloud functions remove-invoker-policy-binding " + name + " \\\n" +
			"--     --region=<region> --member=allUsers\n" +
			"--\n" +
			"-- Then decide what SHOULD reach it. A function meant for the app's own\n" +
			"-- users verifies a Firebase ID token inside itself; a function meant for\n" +
			"-- another service uses a service account. 'Unauthenticated' is only\n" +
			"-- correct for something genuinely public, and then the function must\n" +
			"-- assume every caller is hostile.",
		Evidence: finding.Evidence{
			Request: "curl -sS '" + host + "/" + name + "'",
			Status:  status,
			Reason:  fmt.Sprintf("HTTP %d with no credentials", status),
		},
	}
}

// functionPrivateFinding records a function that exists and refused.
func functionPrivateFinding(d Detection, host, name string, status int) finding.Finding {
	return finding.Finding{
		ID:       "firebase-function-private",
		Name:     "Cloud Function exists and refused an unauthenticated call",
		Severity: finding.Info,
		Protocol: "functions",
		Matched:  host + "/" + name,
		Resource: name,
		Description: fmt.Sprintf(
			"The function %s answered HTTP %d, so it is deployed and its invoker binding "+
				"does not include allUsers. A positive result rather than an absence: a "+
				"name that is not deployed answers 404 here, so a refusal means something "+
				"is there and is closed.", name, status),
		FixKind: finding.FixConsole,
		Remediation: "-- Nothing to fix. Recorded so the report distinguishes a function\n" +
			"-- that was called and refused from one nobody asked about.",
		Evidence: finding.Evidence{
			Request: "curl -sS '" + host + "/" + name + "'",
			Status:  status,
			Reason:  fmt.Sprintf("HTTP %d: deployed, and not callable by anyone", status),
		},
	}
}
