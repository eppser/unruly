package enumerate

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/eppser/unruly/internal/client"
	"github.com/eppser/unruly/internal/finding"
	"github.com/eppser/unruly/internal/postgrest"
)

// Relation is a discovered relation and how it was found.
type Relation struct {
	Name string
	// Source records the discovery channel, so results are auditable.
	// One of: "hint", "direct", "wordlist".
	Source string
	// State is the read classification observed during confirmation.
	State postgrest.ReadState
	// Rows is the anon-visible row count, -1 when unknown.
	Rows int
}

// Result is the outcome of enumeration.
type Result struct {
	Relations []Relation
	// Requests counts HTTP calls issued, for the stats line.
	Requests int
	// SeedCount is how many candidates were probed.
	SeedCount int
	// Denied counts probes rejected before the schema was consulted (401/403).
	// A handful means little; a majority means the credential is wrong, and
	// nothing else in the scan can tell the difference.
	Denied int
	// HintsObserved counts how many times the server volunteered a relation
	// name. This is direct evidence the oracle works against THIS target,
	// which a synthetic probe cannot establish: a probe that draws no hint may
	// simply have been unlike anything in the schema.
	// Discriminating is false when a relation that cannot exist answers the
	// same way a real one does. Every conclusion here rests on the target
	// telling absent relations apart from present ones; where it does not, the
	// enumerated set is the wordlist reflected back and must not be used.
	Discriminating bool
	// UnresolvedByCause splits Unresolved by WHY, because the answer decides
	// what the operator should do next and the two actions are opposites.
	//
	// A throttling host wants a slower scan. A host that is still starting
	// wants the same scan a minute later -- PostgREST answers 503 with
	// PGRST002 for a window after a deploy while it builds its schema cache,
	// and lowering the rate limit does nothing about that. Advising one when
	// the cause is the other sends somebody to tune a knob that was never the
	// problem, and they conclude the tool is wrong rather than the advice.
	//
	// Measured in the benchmark corpus: a key verified warm passed; the same
	// key cold failed 23 of 35 claims. Same target, same credential, seconds
	// of uptime between them.
	UnresolvedByCause map[string]int

	// Unresolved counts candidates whose probe never produced a readable
	// answer. Those relations may or may not exist; the scan does not know.
	Unresolved int
	// ControlDetail carries what the control probe observed, so a report can
	// say why enumeration returned nothing.
	ControlDetail string
	HintsObserved int
}

// Names returns discovered relation names, sorted.
func (r Result) Names() []string {
	out := make([]string, 0, len(r.Relations))
	for _, rel := range r.Relations {
		out = append(out, rel.Name)
	}
	sort.Strings(out)
	return out
}

// Options configures enumeration.
type Options struct {
	// Seeds are candidate names, typically from Harvest plus a pinned wordlist.
	Seeds []string
	// Concurrency bounds in-flight probes.
	Concurrency int
	// MaxRounds bounds the truncation BFS.
	MaxRounds int
}

// probe result for one candidate name.
type probeOut struct {
	name  string
	state postgrest.ReadState
	rows  int
	hints []string
	reqs  int
	// cause explains an unresolved probe: throttled, still starting, a server
	// error, or no answer at all. Empty for probes that resolved.
	cause string
	// privilegeDenied is true when Postgres itself refused the read with
	// SQLSTATE 42501. That is a statement about the SCHEMA, unlike a gateway
	// rejection, so it proves the relation exists.
	privilegeDenied bool
}

// Run enumerates relations using the hint oracle.
//
// Determinism: probes are dispatched in sorted order and results are collected
// by input index, so the discovered set never depends on completion order.
// ControlRelationName is the relation the control probe asks for. It cannot
// exist in any real schema, and is fixed rather than random so that runs stay
// comparable and the emitted evidence command is reproducible.
const ControlRelationName = "unruly_control_relation_that_cannot_exist"

func Run(ctx context.Context, c *client.Client, o Options) Result {
	if o.Concurrency <= 0 {
		o.Concurrency = client.DefaultConcurrency
	}
	if o.MaxRounds <= 0 {
		o.MaxRounds = 3
	}

	found := map[string]*Relation{}
	probed := map[string]bool{}
	res := Result{Discriminating: true}

	probe := func(ctx context.Context, name string) probeOut {
		out := probeOut{name: name, reqs: 1}
		resp := c.Get(ctx, c.RestURL(name)+"?select=*&limit=1",
			map[string]string{"Prefer": "count=exact"})
		if resp.Err != nil {
			out.state = postgrest.ReadUnknown
			// Why, not just that. The remediation depends on it.
			out.cause = causeOf(0, "", true)
			return out
		}
		state, rows := postgrest.ClassifyRead(resp.Status, resp.ContentRange(), len(resp.Body))
		out.state, out.rows = state, rows
		if state == postgrest.ReadUnknown {
			code, _, _ := resp.DecodeError()
			out.cause = causeOf(resp.Status, code, false)
		}
		if state == postgrest.ReadDenied {
			if code, _, _ := resp.DecodeError(); code == "42501" {
				out.privilegeDenied = true
			}
		}
		if state == postgrest.ReadNotFound {
			if _, _, hint := resp.DecodeError(); hint != "" {
				if rel, ok := postgrest.HintedRelation(hint); ok {
					out.hints = append(out.hints, rel)
				}
			}
		}
		return out
	}

	// ---- control probe --------------------------------------------------
	//
	// Before believing anything this stage reports, check that the target can
	// tell an absent relation from a present one. A host that answers 200 to
	// every path -- a catch-all router, a CDN error page, a single-page app
	// serving index.html for unknown routes, or simply not PostgREST -- makes
	// every candidate look real, and the enumerated set becomes the wordlist
	// reflected back.
	//
	// Measured, not hypothetical: pointed at an edge-runtime host that answers
	// 200 to any name, this stage reported 706 relations and the scan emitted
	// 1,412 findings, 706 of them critical. The self-check noticed the target
	// was not behaving like PostgREST and said so in a medium finding, while
	// those criticals were printed alongside it. Detecting your own blindness
	// and then ignoring the diagnosis is worse than not detecting it, because
	// the report now carries a note that makes it look considered.
	//
	// The name is fixed rather than random so that runs stay comparable, and
	// long enough that no real schema will collide with it.
	ctrl := probe(ctx, ControlRelationName)
	res.Requests += ctrl.reqs
	switch ctrl.state {
	case postgrest.ReadExposed, postgrest.ReadEmpty:
		res.Discriminating = false
		res.ControlDetail = "a relation that cannot exist answered as though it does " +
			"(" + ctrl.state.String() + "), so every candidate would look real"
	case postgrest.ReadUnknown:
		res.Discriminating = false
		res.ControlDetail = "the control probe did not complete, so absent and present " +
			"relations could not be shown to differ"
	}
	if !res.Discriminating {
		return res
	}

	// record folds a probe result into the discovered set.
	record := func(p probeOut, source string) []string {
		res.Requests += p.reqs
		res.HintsObserved += len(p.hints)
		if p.state == postgrest.ReadDenied {
			res.Denied++
		}
		if p.state == postgrest.ReadUnknown {
			if res.UnresolvedByCause == nil {
				res.UnresolvedByCause = map[string]int{}
			}
			res.UnresolvedByCause[p.cause]++
			// The probe never got an answer it could read: a 429 that survived
			// the client's retries, a 5xx, or a transport failure. This says
			// nothing about the relation, and dropping it silently is the
			// failure mode this counter exists to prevent -- a candidate that
			// could not be measured is indistinguishable in the report from
			// one that was measured and found absent.
			res.Unresolved++
		}
		// A relation Postgres refused with 42501 EXISTS. The refusal comes from
		// the database, after the schema was consulted, and the message names
		// the table:
		//
		//	{"code":"42501","message":"permission denied for table survival_series"}
		//
		// This is not the 401 the comment below warns about. A wrong or expired
		// key is refused by the gateway with {"message":"Invalid API key"} and
		// no SQLSTATE at all, so the bad-key case that once reported 2684
		// relations against a database with 21 cannot come back through here.
		//
		// It matters because REVOKE is a legitimate way to protect a table, and
		// until now every relation protected that way was invisible: the scan
		// said "0 relations" for a schema that has them. Measured on the
		// reference target's staging schema -- 5 hints observed, 3 probes
		// denied, 0 relations reported.
		if p.privilegeDenied {
			if _, ok := found[p.name]; !ok {
				found[p.name] = &Relation{
					Name: p.name, Source: source, State: postgrest.ReadDenied,
				}
			}
		}
		switch p.state {
		case postgrest.ReadExposed, postgrest.ReadEmpty:
			// A 200 or 206 proves the relation exists: PostgREST consulted the
			// schema to answer.
			//
			// A 401/403 does NOT, and used to be counted here. That check runs
			// before the schema is consulted, so it says nothing about the
			// relation — and with a wrong or expired key EVERY probe returns
			// 401, so every seed was recorded as an existing relation. A bad
			// key produced "2684 relations discovered" against a database with
			// 21. Authentication failure is not a fact about the schema.
			if _, ok := found[p.name]; !ok {
				found[p.name] = &Relation{
					Name: p.name, Source: source, State: p.state, Rows: p.rows,
				}
			}
		}
		var fresh []string
		for _, h := range p.hints {
			if _, ok := found[h]; ok {
				continue
			}
			if probed[h] {
				continue
			}
			fresh = append(fresh, h)
		}
		return fresh
	}

	// Round 1: probe the seed vocabulary.
	seeds := append([]string{}, o.Seeds...)
	sort.Strings(seeds)
	seeds = dedupSorted(seeds)
	res.SeedCount = len(seeds)
	for _, s := range seeds {
		probed[s] = true
	}
	frontier := map[string]bool{}
	for _, p := range client.Map(ctx, o.Concurrency, seeds, probe) {
		for _, h := range record(p, "direct") {
			frontier[h] = true
		}
	}

	// Subsequent rounds: confirm hinted names, and probe truncations of every
	// discovered name. A substring of one real name frequently points the
	// oracle at a different real name.
	for round := 0; round < o.MaxRounds && len(frontier) > 0; round++ {
		next := make([]string, 0, len(frontier))
		for n := range frontier {
			if !probed[n] {
				next = append(next, n)
				probed[n] = true
			}
		}
		sort.Strings(next)
		frontier = map[string]bool{}
		if len(next) == 0 {
			break
		}
		for _, p := range client.Map(ctx, o.Concurrency, next, probe) {
			for _, h := range record(p, "hint") {
				frontier[h] = true
			}
		}

		// Expand: truncations of confirmed names seed the next round.
		var truncs []string
		for name := range found {
			for cut := 3; cut < len(name) && cut < 14; cut++ {
				t := name[:cut]
				if !probed[t] {
					truncs = append(truncs, t)
				}
			}
		}
		sort.Strings(truncs)
		truncs = dedupSorted(truncs)
		for _, t := range truncs {
			probed[t] = true
		}
		for _, p := range client.Map(ctx, o.Concurrency, truncs, probe) {
			for _, h := range record(p, "hint") {
				frontier[h] = true
			}
		}
	}

	names := make([]string, 0, len(found))
	for n := range found {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		res.Relations = append(res.Relations, *found[n])
	}
	return res
}

// ControlFinding reports that the target could not be shown to distinguish an
// absent relation from a present one.
//
// It is deliberately Info severity. Nothing about the target is known to be
// wrong -- the point is the opposite, that nothing about it is known at all.
// Ranking it higher would put a scanner-configuration problem above real
// findings from other stages; omitting it would leave an empty relation list
// reading as a clean project, which is the failure this whole package guards
// against.
func (r Result) ControlFinding(restBase string) (finding.Finding, bool) {
	if r.Discriminating {
		return finding.Finding{}, false
	}
	return finding.Finding{
		ID:       "unruly-target-not-discriminating",
		Name:     "Target does not distinguish absent relations from present ones",
		Severity: finding.Info,
		Protocol: "postgrest",
		Matched:  restBase,
		Resource: "relation-discovery",
		Description: "A control probe for a relation that cannot exist was answered as " +
			"though the relation does exist: " + r.ControlDetail + ". This happens when a " +
			"catch-all router, a CDN error page or a single-page application sits in front " +
			"of the API, or when the endpoint is not PostgREST at all. Every candidate name " +
			"would appear to be a real relation, so relation discovery, read exposure and " +
			"write exposure were ALL skipped. This scan says nothing about them -- it is " +
			"not a clean result.",
		Remediation: "-- Point -u at the PostgREST endpoint itself, or pass -rest-prefix so " +
			"requests reach it. For a managed project that is https://<ref>.supabase.co " +
			"with the default /rest/v1 prefix. Then re-run.",
		Evidence: finding.Evidence{
			Request: "curl -sS '" + restBase + "/" + ControlRelationName +
				"?select=*&limit=1' -H \"apikey: $SUPABASE_ANON_KEY\"",
			Reason: r.ControlDetail,
		},
	}, true
}

// UnresolvedFinding reports candidates the scan could not measure.
//
// Measured against a host that throttles half its paths: 360 of 702 probes
// answered 429 after retries, and the scan reported "342 relations discovered"
// with no mention that half the target was never looked at. A rate-limited
// project would produce a report missing half its tables and reading as
// complete -- silent loss arriving through the network rather than through the
// classifier, which is the same ambiguity in a place the classifier cannot
// see.
//
// Info, because nothing is known to be wrong with the target. What is being
// reported is the boundary of what this scan can claim.
// Causes an unresolved probe can have. Named for what the reader must do
// about them rather than for the status code that produced them.
const (
	causeThrottled = "throttled"
	causeStarting  = "still starting"
	causeServerErr = "server error"
	causeTransport = "no answer at all"
)

// causeOf maps a probe's outcome to the reason it could not be read.
func causeOf(status int, code string, transportErr bool) string {
	switch {
	case transportErr:
		return causeTransport
	case status == 429:
		return causeThrottled
	// PGRST002 is decisive: PostgREST is up and answering, and says outright
	// that it could not load the schema cache. Any other 503 is a server
	// error, because guessing "starting" from the status alone would advise
	// waiting for an outage that waiting will not fix.
	case code == "PGRST002":
		return causeStarting
	case status >= 500:
		return causeServerErr
	}
	return causeServerErr
}

// adviceFor returns the remediation matching the dominant cause.
func adviceFor(cause string) string {
	switch cause {
	case causeStarting:
		return "-- Nothing to change in the scan. PostgREST answered PGRST002: it is " +
			"running but had not finished loading its schema cache, which happens for a\n" +
			"-- window after a deploy or a restart. Wait a minute and run again; a warm\n" +
			"-- server resolves these candidates. Lowering -rate-limit will not help,\n" +
			"-- because the requests were answered, just not usefully."
	case causeTransport:
		return "-- The target did not answer at all for these candidates -- a connection " +
			"refused, reset, or timed out. Check that the host is reachable from where\n" +
			"-- the scan runs, and raise -timeout if the network is slow, before reading\n" +
			"-- the relation count as complete."
	case causeServerErr:
		return "-- The target returned server errors for these candidates. They are not " +
			"evidence about the relations; re-run when the backend is healthy, and treat\n" +
			"-- the relation count below as a lower bound until it is."
	}
	return "-- Re-run with -rate-limit set lower and -c reduced so the target is not " +
		"throttled, then compare the relation count. A run that resolves every candidate " +
		"produces no finding of this kind."
}

// dominantCause returns the cause with the most probes, and a stable rendering
// of every cause seen. Sorted, because two scans of an unchanged project must
// produce identical bytes and Go randomises map iteration.
func (r Result) dominantCause() (string, string) {
	if len(r.UnresolvedByCause) == 0 {
		return causeThrottled, ""
	}
	names := make([]string, 0, len(r.UnresolvedByCause))
	for c := range r.UnresolvedByCause {
		names = append(names, c)
	}
	sort.Strings(names)
	top, best := names[0], -1
	var parts []string
	for _, c := range names {
		n := r.UnresolvedByCause[c]
		parts = append(parts, fmt.Sprintf("%d %s", n, c))
		if n > best {
			top, best = c, n
		}
	}
	return top, strings.Join(parts, ", ")
}

func (r Result) UnresolvedFinding(restBase string, candidates int) (finding.Finding, bool) {
	if r.Unresolved == 0 {
		return finding.Finding{}, false
	}
	dominant, breakdown := r.dominantCause()
	return finding.Finding{
		ID:       "unruly-probes-unresolved",
		Name:     "Some relation probes never got a readable answer",
		Severity: finding.Info,
		Protocol: "postgrest",
		Matched:  restBase,
		Resource: "relation-discovery",
		Description: fmt.Sprintf(
			"%d of %d relation candidates returned no answer this scan could read (%s). "+
				"Those candidates were neither confirmed nor ruled out, so the relations "+
				"reported below are a LOWER BOUND and this scan cannot say the rest are "+
				"absent.",
			r.Unresolved, candidates, describe(breakdown, dominant)),
		Remediation: adviceFor(dominant),
		Evidence: finding.Evidence{
			Reason: fmt.Sprintf("%d of %d probes unresolved: %s",
				r.Unresolved, candidates, breakdown),
		},
	}, true
}

// BudgetFinding reports that relation discovery stopped at its probe budget
// rather than at the end of the candidate list.
//
// A scan that stops early and stays quiet about it is the failure this whole
// tool exists to correct, so adding -max-relation-probes without this note
// would have introduced one. Measured: capping the expansion at 3,000
// candidates finds 3 of 7 relations on a project where the full 13,740 find
// all seven.
//
// Info, and in the blindIDs set that drives exit 3: nothing is known to be
// wrong with the target, and what is being reported is the boundary of what
// this scan can claim.
//
// It lives here rather than inline at the call site because the severity
// analyser in internal/eval reads the enclosing FUNCTION, and a finding built
// inside a large one is credited with every severity that function mentions.
// Every other finding has a constructor; this one now does too.
func BudgetFinding(restBase string, probed, total int) finding.Finding {
	return finding.Finding{
		ID:       "unruly-probe-budget-exhausted",
		Name:     "Relation discovery stopped at the probe budget",
		Severity: finding.Info,
		Protocol: "postgrest",
		Matched:  restBase,
		Resource: "relation-discovery",
		Description: fmt.Sprintf(
			"The fallback expansion was truncated to %d of %d candidate names by "+
				"-max-relation-probes, so the relations reported are a LOWER BOUND and this "+
				"scan cannot say the rest are absent. Recall falls roughly linearly with the "+
				"budget: on a reference project 3,435 probes found 4 of 7 relations where "+
				"13,740 found all 7.", probed, total),
		Remediation: fmt.Sprintf("-- Re-run with -max-relation-probes %d, or supply -site so "+
			"vocabulary can be harvested from the application, which reaches the same "+
			"relations in a fraction of the requests.", total),
		Evidence: finding.Evidence{
			Reason: fmt.Sprintf("%d of %d candidates probed", probed, total),
		},
	}
}

// Merge folds a second pass into the first.
//
// The fallback expansion used to REPLACE the first result: `if
// len(retry.Relations) > 0 { en = retry }`. That looks safe and is not.
// RelationCandidates emits n-1 stems and modifier_singular compounds, so it is
// NOT a superset of the seeds — measured, 92 of 702 original seeds survive
// into the expansion. If the first pass found twenty relations and the retry
// found three different ones, the scan reported three, and every stage
// downstream — probing, escalation, realtime, the emitted fixes — worked from
// the smaller set.
//
// It also discarded the first pass's HintsObserved, Denied, SeedCount and
// Unresolved, which feed the self-check and the unresolved-probe finding: the
// evidence that the oracle works on this target, thrown away by the pass that
// ran because it seemed not to.
//
// An audit found this. There was no test.
func (r Result) Merge(other Result) Result {
	seen := make(map[string]bool, len(r.Relations))
	for _, rel := range r.Relations {
		seen[rel.Name] = true
	}
	for _, rel := range other.Relations {
		if !seen[rel.Name] {
			seen[rel.Name] = true
			r.Relations = append(r.Relations, rel)
		}
	}
	sort.Slice(r.Relations, func(i, j int) bool {
		return r.Relations[i].Name < r.Relations[j].Name
	})
	r.Requests += other.Requests
	r.SeedCount += other.SeedCount
	r.Denied += other.Denied
	r.HintsObserved += other.HintsObserved
	r.Unresolved += other.Unresolved
	// And the reasons, or a scan across two schemas keeps the count and loses
	// the advice -- which is the half that tells an operator what to do.
	for c, n := range other.UnresolvedByCause {
		if r.UnresolvedByCause == nil {
			r.UnresolvedByCause = map[string]int{}
		}
		r.UnresolvedByCause[c] += n
	}
	// Discriminating is an AND: if either pass could not tell an absent
	// relation from a present one, nothing either pass reports can be trusted.
	r.Discriminating = r.Discriminating && other.Discriminating
	if r.ControlDetail == "" {
		r.ControlDetail = other.ControlDetail
	}
	return r
}

// describe renders the cause breakdown for a reader, falling back to the
// generic phrasing when a caller has not recorded causes.
func describe(breakdown, dominant string) string {
	if breakdown == "" {
		return "a 429 that survived retries, a 5xx, or a transport failure"
	}
	return breakdown + "; mostly " + dominant
}
