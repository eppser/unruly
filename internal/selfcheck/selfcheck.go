// Package selfcheck verifies that unruly's own oracles work against the
// target before their results are trusted.
//
// Every scanner surveyed fails the same way: an oracle stops working, the tool
// finds nothing, and "nothing found" is printed as though it meant "nothing is
// wrong". supascan's enumerator returns an empty slice when the OpenAPI spec
// answers 401 — no warning, no error, a clean report on a world-writable
// database. That is not an unlucky bug; it is what happens whenever a tool
// cannot tell "I looked and it is fine" apart from "I could not look".
//
// unruly is not immune by construction. Its enumeration depends on
// PostgREST volunteering relation names in a 404 hint. That behaviour is a
// convenience of a particular server version, not a guarantee: an older
// PostgREST, a proxy that rewrites error bodies, or a future release that
// stops being helpful would each silently reduce recall to whatever the
// wordlist happens to cover. The scan would still print findings, so nothing
// would look wrong.
//
// So the oracles are tested, not assumed, and a capability that fails is
// reported as a finding in its own right — a scan run half-blind is a fact the
// operator needs, and it outranks any individual finding in that scan.
//
// Where possible the test uses EVIDENCE FROM THE SCAN rather than a synthetic
// probe. That distinction was learned the hard way: the first version of this
// package asked for a made-up relation name, drew no hint because nothing in
// the schema resembled it, and declared the oracle broken on two of three
// targets while enumeration was recovering 21 of 21 relations. A probe that
// draws no signal has not shown the oracle is broken; it has shown the probe
// was unlike anything present. Watching whether the server volunteered hints
// during the real scan settles the question without that ambiguity.
package selfcheck

import (
	"context"
	"fmt"
	"sort"

	"github.com/eppser/unruly/internal/client"
	"github.com/eppser/unruly/internal/finding"
	"github.com/eppser/unruly/internal/postgrest"
)

// Capability names an oracle the scan depends on.
type Capability struct {
	Name string
	// Working is true when the oracle answered as expected.
	Working bool
	// Detail explains what was observed.
	Detail string
	// Impact states what the scan loses when this oracle is down.
	Impact string
}

// Result is the outcome of the self-check.
type Result struct {
	Capabilities []Capability
	Findings     []finding.Finding
	Requests     int
}

// Degraded lists capabilities that failed, sorted.
func (r Result) Degraded() []string {
	var out []string
	for _, c := range r.Capabilities {
		if !c.Working {
			out = append(out, c.Name)
		}
	}
	sort.Strings(out)
	return out
}

// Evidence is what the scan itself observed. Preferring it to synthetic probes
// is the correction to a bug in this package's first version: it probed with a
// made-up name, drew no hint because nothing in the schema resembled it, and
// declared the oracle broken on two of three targets while enumeration was
// recovering 21 of 21 relations. Absence of a hint for one arbitrary name is
// not evidence of a broken oracle — a fact this package exists to insist on,
// and promptly got wrong itself.
type Evidence struct {
	// ProbesDenied and ProbesTotal describe credential acceptance. When most
	// probes are rejected before the schema is consulted, the credential is
	// wrong — and every downstream stage would otherwise report an empty,
	// confident, wrong result.
	ProbesDenied int
	ProbesTotal  int
	// RequestsSent and RequestsFailed describe the transport. A scan that lost
	// requests may have lost findings: a relation whose probe never got an
	// answer looks exactly like one that does not exist.
	RequestsSent   int64
	RequestsFailed int64

	// HintsObserved is how many relation names the server volunteered during
	// enumeration. Any number above zero proves the oracle works here.
	HintsObserved int
	// RelationsFound is how many relations enumeration recovered.
	RelationsFound int
}

// Run verifies each oracle, preferring evidence from the scan over synthetic
// probes wherever the scan can supply it.
func Run(ctx context.Context, c *client.Client, ev Evidence) Result {
	res := Result{}
	res.Capabilities = append(res.Capabilities,
		checkCredential(ev),
		checkTransport(ev),
		checkRelationHintOracle(ev),
		checkRoutineHintOracle(ctx, c, &res),
		checkWriteDiscriminator(ctx, c, &res),
	)
	for _, cap := range res.Capabilities {
		if !cap.Working {
			res.Findings = append(res.Findings, degradedFinding(c, cap))
		}
	}
	finding.Sort(res.Findings)
	return res
}

// probeRelation is a name no schema would contain. Used only where a synthetic
// probe is sound: checking that structured error codes still arrive.
const probeRelation = "unruly_probe_relation_absent"

// checkRelationHintOracle judges the oracle by what the scan actually saw.
//
// A hint observed during enumeration proves the oracle works. Zero hints is
// only meaningful when the scan ALSO found nothing: that combination is the
// dangerous one, because it is indistinguishable from a healthy scan of a
// healthy project unless the tool says so. Finding relations without hints is
// normal — the pinned wordlist covers conventional names on its own.
func checkRelationHintOracle(ev Evidence) Capability {
	cap := Capability{
		Name: "postgrest-relation-hints",
		Impact: "Relation discovery falls back to the pinned wordlist alone, which cannot " +
			"reach domain-specific names. Recall drops sharply and the scan may report a " +
			"vulnerable database as clean.",
	}
	switch {
	case ev.HintsObserved > 0:
		cap.Working = true
		cap.Detail = fmt.Sprintf("server volunteered %d relation names during enumeration",
			ev.HintsObserved)
	case ev.RelationsFound > 0:
		cap.Working = true
		cap.Detail = fmt.Sprintf("no hints seen, but %d relations were recovered from the "+
			"pinned wordlist; discovery is functioning", ev.RelationsFound)
	default:
		cap.Detail = "no relations found and the server volunteered no hints; " +
			"enumeration cannot be distinguished from a target with nothing to find"
	}
	return cap
}

// checkCredential reports a key the target will not accept.
//
// This is the likeliest user error and it used to fail silently in the worst
// possible direction: a wrong key made every probe return 401, and 401 was
// being counted as proof a relation exists, so a bad key produced thousands of
// imaginary relations and a report full of nothing.
func checkCredential(ev Evidence) Capability {
	cap := Capability{
		Name: "credential",
		Impact: "The target rejected the key before consulting its schema. Nothing in this " +
			"report describes the database; every stage saw the same refusal.",
	}
	switch {
	case ev.ProbesTotal == 0:
		cap.Working = true
		cap.Detail = "no probes issued"
	case ev.ProbesDenied*2 > ev.ProbesTotal:
		cap.Detail = fmt.Sprintf("%d of %d probes rejected with 401/403; the key is wrong, "+
			"expired, or for a different project", ev.ProbesDenied, ev.ProbesTotal)
	default:
		cap.Working = true
		cap.Detail = fmt.Sprintf("accepted (%d of %d probes rejected)",
			ev.ProbesDenied, ev.ProbesTotal)
	}
	return cap
}

// checkTransport reports when requests were lost.
//
// A total outage is obvious: every oracle fails and the scan is loud. A PARTIAL
// one is not. If a handful of probes out of thousands never get an answer, the
// oracles still work, the self-check still passes, and the relations behind
// those probes are simply absent from the report — indistinguishable from
// relations that do not exist. Nothing else in this tool would notice.
func checkTransport(ev Evidence) Capability {
	cap := Capability{
		Name: "transport",
		Impact: "Requests that never received an answer leave gaps that look identical to " +
			"absence. Any relation, routine or route behind a lost request is missing from " +
			"this report without being reported as missing.",
	}
	switch {
	case ev.RequestsSent == 0:
		cap.Working = true
		cap.Detail = "no requests issued"
	case ev.RequestsFailed == 0:
		cap.Working = true
		cap.Detail = fmt.Sprintf("%d requests, none lost", ev.RequestsSent)
	default:
		cap.Detail = fmt.Sprintf("%d of %d requests never received an answer",
			ev.RequestsFailed, ev.RequestsSent)
	}
	return cap
}

// checkRoutineHintOracle does the same for the RPC arm.
func checkRoutineHintOracle(ctx context.Context, c *client.Client, res *Result) Capability {
	cap := Capability{
		Name: "postgrest-routine-hints",
		Impact: "RPC discovery falls back to the pinned wordlist alone. SECURITY DEFINER " +
			"routines with project-specific names will not be found.",
	}
	resp := c.Do(ctx, "POST", c.RPCURL("rpcz"), []byte(`{}`), nil)
	res.Requests++
	if resp.Err != nil {
		cap.Detail = "probe failed: " + resp.Err.Error()
		return cap
	}
	code, _, hint := resp.DecodeError()
	if _, ok := postgrest.HintedFunction(hint); ok {
		cap.Working = true
		cap.Detail = "server volunteers routine names on a near miss"
		return cap
	}
	// No hint is not conclusive on its own: a project with no routines at all
	// has nothing to suggest. PGRST202 confirms we reached the RPC layer and
	// were answered properly, which is the most that can be established here.
	if code == "PGRST202" {
		cap.Working = true
		cap.Detail = "RPC layer answers correctly; no routine near this probe to suggest"
		return cap
	}
	cap.Detail = fmt.Sprintf("unexpected RPC response: HTTP %d code=%q", resp.Status, code)
	return cap
}

// checkWriteDiscriminator verifies the platform still distinguishes an RLS
// refusal from a schema rejection. The whole write finding rests on that
// difference, and it is a property of the server, not of this tool.
func checkWriteDiscriminator(ctx context.Context, c *client.Client, res *Result) Capability {
	cap := Capability{
		Name: "postgrest-error-codes",
		Impact: "Write exposure cannot be classified soundly. Findings that depend on " +
			"telling 42501 apart from a schema error are suppressed rather than guessed.",
	}
	// Writing to a relation that cannot exist must produce a PostgREST-level
	// error carrying a code. If codes have stopped arriving, classification is
	// impossible and every write verdict would be a guess.
	resp := c.Do(ctx, "POST", c.RestURL(probeRelation), []byte(`{}`), nil)
	res.Requests++
	if resp.Err != nil {
		cap.Detail = "probe failed: " + resp.Err.Error()
		return cap
	}
	code, _, _ := resp.DecodeError()
	if code == "" {
		cap.Detail = fmt.Sprintf("response HTTP %d carried no error code", resp.Status)
		return cap
	}
	cap.Working = true
	cap.Detail = "server returns structured error codes (" + code + ")"
	return cap
}

func degradedFinding(c *client.Client, cap Capability) finding.Finding {
	return finding.Finding{
		ID:   "unruly-capability-degraded",
		Name: "Scanner capability unavailable — results are incomplete",
		// Info, not Medium. Severity ranks how bad something is ON THE TARGET,
		// and this finding says nothing about the target: it says the scan
		// could not see. The other two coverage findings --
		// unruly-checks-skipped and unruly-surface-not-assessed --
		// are already Info, and a reader filtering severity >= medium for
		// "things to fix" should not be handed a scanner diagnostic.
		//
		// Measured: scanning four hosts that are not Supabase at all -- a
		// single-page app, an API gateway, a 401 wall, a 500 origin --
		// produced no vulnerability findings and three to four Mediums each,
		// every one of them this finding. A consumer counting Mediums would
		// read "3 issues" from a static web server.
		//
		// The human signal is not lost: the scan still logs a Warning naming
		// each degraded capability, which is what someone watching a terminal
		// acts on.
		Severity: finding.Info,
		Protocol: "unruly",
		Matched:  c.BaseURL(),
		Resource: cap.Name,
		Description: fmt.Sprintf(
			"The %s oracle did not behave as expected against this target (%s). %s "+
				"This finding exists so that an incomplete scan is never mistaken for a clean "+
				"one: absence of findings below is not evidence of absence of problems.",
			cap.Name, cap.Detail, cap.Impact),
		Remediation: "-- Re-run with -v to see the probe responses. If the target sits behind a " +
			"proxy or WAF that rewrites error bodies, scan the Supabase origin directly with " +
			"-base-url. If the platform itself has changed behaviour, treat this scan as " +
			"partial and audit the database from the inside (Supabase Security Advisor, or " +
			"pg_policies) until the scanner is updated.",
		Evidence: finding.Evidence{
			Reason: cap.Detail,
		},
	}
}
