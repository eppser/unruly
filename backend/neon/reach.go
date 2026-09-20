package neon

import (
	"context"
	"fmt"
	"net/http"
	"sort"
	"strconv"

	"github.com/eppser/unruly/internal/client"
	"github.com/eppser/unruly/internal/enumerate"
	"github.com/eppser/unruly/internal/finding"
	"github.com/eppser/unruly/scan"
)

// ReachStage decides whether the endpoint's answers carry any information.
//
// It asks for a name that cannot exist and compares that answer with the real
// candidates. If a table that is definitionally absent is answered the same
// way as one that is present, no response from this surface says anything
// about any table, and every conclusion drawn from them would be invented.
//
// On Neon this is not a hypothetical. Measured against a live Data API: with
// no Authorization header every name answers 400 "missing authentication
// credentials", the control name included. Present a JWT and the same control
// answers 404 PGRST205 while real tables answer distinctly. So the anonymous
// surface is blind and the authenticated one is not -- which is exactly
// backwards from the vendor documentation, and the reason this stage exists
// rather than an assumption in a comment.
//
// The trap it guards against is that 400 reads like a refusal, a refusal reads
// like protection, and a scan that follows that chain reports a clean project
// having measured nothing.
type ReachStage struct {
	// Base is the Data API root.
	Base string
	// Tables are the candidates the rest of the scan would probe.
	Tables []string
	// Token, when present, is what the surface is assessed under. The answer
	// differs by principal, so "is this target discriminating" is a question
	// about a principal and not about a host.
	Token string
	// Client carries the shared limiter.
	Client *client.Client

	// compared records how many candidates were held against the control,
	// so the finding can state the strength of the observation it made.
	compared int
}

// reachSampleSize bounds the comparison. Deciding whether a surface
// discriminates needs the control plus enough candidates to disagree with it,
// and a handful settles that; sweeping hundreds re-answers a question the
// first few already did.
//
// Eight rather than one: a single candidate that happened to be absent would
// answer like the control and the surface would be called blind on one
// coincidence.
const reachSampleSize = 8

func (ReachStage) Name() string { return "neon-reach" }

func (ReachStage) Describe() scan.StageDescriptor {
	return scan.StageDescriptor{ID: (ReachStage{}).Name(),
		Optional: []scan.ArtifactType{scan.ArtifactOf[Relations]()}}
}

// Run probes the control name and enough candidates to compare it against.
func (s ReachStage) Run(ctx context.Context, st *scan.State) error {
	if s.Client == nil {
		// Deliberately an error rather than a default. Building a client here
		// would silently substitute the package defaults for -rate-limit,
		// -timeout and the user agent, so the operator's flags would not bind
		// this stage and nothing would say so.
		return errNoClient
	}
	// The same control name the PostgREST enumerator uses. Sharing it is not
	// tidiness: a second name would be a second thing to keep absent.
	control := s.probe(ctx, enumerate.ControlRelationName)

	names := relationNames(st, s.Tables)
	sort.Strings(names)
	sampled := names
	if len(sampled) > reachSampleSize {
		sampled = sampled[:reachSampleSize]
	}
	statuses := map[int]bool{}
	for _, n := range sampled {
		statuses[s.probe(ctx, n).status] = true
	}
	st.Attribute(s.Name(), len(sampled)+1)

	if discriminating(control.status, statuses) {
		return nil
	}
	s.compared = len(sampled)
	st.Add(s.blindFinding(control, statuses))
	return nil
}

// discriminating reports whether an absent name is distinguishable from the
// present ones.
//
// A 404 for the control is the positive answer: the endpoint looked, and said
// it is not there. Anything else that every real candidate ALSO returns means
// the answers are uniform and carry nothing.
func discriminating(controlStatus int, candidateStatuses map[int]bool) bool {
	if controlStatus == http.StatusNotFound {
		return true
	}
	// If some candidate answered differently from the control, the surface is
	// still telling us something, even if not a clean 404.
	for st := range candidateStatuses {
		if st != controlStatus {
			return true
		}
	}
	return false
}

func (s ReachStage) probe(ctx context.Context, table string) observation {
	c := s.Client
	if s.Token != "" {
		c = c.WithBearer(s.Token)
	}
	o := observation{table: table, path: "/" + table + "?select=*"}
	resp := c.Get(ctx, s.Base+o.path, nil)
	if resp.Err != nil {
		o.err = resp.Err
		return o
	}
	o.status = resp.Status
	return o
}

// blindFinding says the surface was not assessed. Info severity: nothing about
// the target is known to be wrong, and that is the whole point -- nothing
// about it is known at all. Ranking it higher would bury real findings from
// other stages under a scanner-configuration problem.
func (s ReachStage) blindFinding(control observation, statuses map[int]bool) finding.Finding {
	seen := make([]string, 0, len(statuses))
	for st := range statuses {
		seen = append(seen, strconv.Itoa(st))
	}
	sort.Strings(seen)

	principal := "an unauthenticated caller"
	if s.Token != "" {
		principal = "the supplied credential"
	}

	detail := fmt.Sprintf("%q answered %d, and every one of the %d candidates compared "+
		"against it answered the same", enumerate.ControlRelationName, control.status,
		s.compared)

	return finding.Finding{
		ID:       "unruly-target-not-discriminating",
		Name:     "Target does not distinguish absent relations from present ones",
		Severity: finding.Info,
		Protocol: "neon",
		Matched:  s.Base,
		Resource: "relation-discovery",
		Description: "A control probe for a table that cannot exist was answered exactly " +
			"as the real candidates were: " + detail + ". Every candidate name would " +
			"therefore appear equally real, so read exposure and relation discovery were " +
			"skipped for " + principal + ". This scan says nothing about them -- it is NOT " +
			"a clean result. On a Neon Data API this is the ordinary answer to a request " +
			"with no Authorization header: the endpoint refuses before it looks at the " +
			"table, so the refusal describes the request and not the data.",
		Remediation: "-- Nothing to fix on the target: this is a limit of the scan, not a\n" +
			"-- weakness in the project.\n" +
			"--\n" +
			"-- Neon's Data API answers a request with no Authorization header the same\n" +
			"-- way whatever table is asked for, so an unauthenticated scan of one\n" +
			"-- cannot say anything about it. Assessing it needs a token issued by the\n" +
			"-- project's own auth provider.\n" +
			"--\n" +
			"--\n" +
			"--   unruly -u <data-api-url> -user-jwt \"$NEON_TOKEN\"\n" +
			"--\n" +
			"-- Obtain the token from the project's Neon Auth service: sign in, then\n" +
			"-- GET {auth-url}/token carrying the SESSION COOKIE -- a bearer is refused\n" +
			"-- there with 401.\n" +
			"--\n" +
			"-- Scan only a project you own or are authorised to test.",
		Evidence: finding.Evidence{
			Request: requestLine(s.Base, enumerate.ControlRelationName),
			Status:  control.status,
			Reason: detail + "; candidate statuses observed: " +
				fmt.Sprint(seen),
		},
	}
}
