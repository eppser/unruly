// Package graphql probes the pg_graphql endpoint Supabase serves at
// /graphql/v1.
//
// It is a second read path over the same tables, and no surveyed scanner looks
// at it. Hardening guidance concentrates on RLS and on the REST API; a project
// can be reviewed carefully, declared sound, and still answer the same queries
// over GraphQL because nobody checked that endpoint existed.
//
// What it is NOT is a better enumerator, which is what it looked like before
// measuring. Two things were assumed and both were wrong:
//
//   - pg_graphql is NOT enabled by default. Both projects available answered
//     "pg_graphql extension is not enabled." until it was switched on
//     deliberately, so the check must treat disabled as the common case and
//     say nothing when it is.
//   - Introspection is DISABLED. `{ __schema { types { name } } }` is refused
//     with `Unknown field "__schema" on type Query`, so there is no free schema
//     dump and no shortcut around the relation names the scan already has.
//
// What it does give is a clean three-way answer per relation, which is exactly
// what a sound probe needs:
//
//	rows returned          -> readable by this role
//	{"edges": []}          -> the relation exists and RLS filtered it
//	Unknown field ...      -> no such relation
//
// and it gives it without knowing a single column name. Every pg_graphql type
// carries nodeId, whose value is base64 of ["schema", "table", primary key] --
// evidence that names itself:
//
//	WyJwdWJsaWMiLCAiZmVlZGJhY2tfc3VibWlzc2lvbnMiLCAxMzFd
//	  -> ["public", "feedback_submissions", 131]
//
// The finding worth raising is disagreement. Both paths run the same policies,
// so they should agree; where GraphQL returns rows for a relation REST refused,
// the REST-only verdict was wrong and the data is reachable anyway.
package graphql

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/eppser/unruly/internal/client"
	"github.com/eppser/unruly/internal/finding"
)

// ControlRelationName is probed to prove the endpoint distinguishes a relation
// that exists from one that does not. Nothing may define it.
const ControlRelationName = "unruly_control_relation_that_cannot_exist"

// State is what could be established about the endpoint itself.
type State int

const (
	// Unreachable means the request failed at the transport.
	Unreachable State = iota
	// Disabled means the endpoint answered and pg_graphql is not installed.
	Disabled
	// Enabled means it answered a query.
	Enabled
)

// RelationState is what GraphQL says about one relation.
type RelationState int

const (
	// Absent means GraphQL has no field for it.
	Absent RelationState = iota
	// Filtered means the relation exists and returned no rows to this role.
	Filtered
	// Readable means rows came back.
	Readable
)

// Options configures the probe.
type Options struct {
	// Relations are names to test, normally those the scan already found.
	Relations []string
	// RESTReadable names the relations the REST pass could already read. A
	// relation in both is not new exposure; one readable here and not there is.
	RESTReadable map[string]bool
	// SampleRows bounds how many node ids are requested as evidence.
	SampleRows  int
	Concurrency int
	// Redact suppresses the decoded node ids, which contain primary keys.
	Redact bool
}

// Result is the outcome of the probe.
type Result struct {
	State State
	// Discriminating is false when a relation that cannot exist is answered as
	// though it does, which makes every other answer meaningless.
	Discriminating bool
	ControlDetail  string
	// Relations maps name to what GraphQL said.
	Relations map[string]RelationState
	// Proof maps a readable relation to its decoded node ids.
	Proof    map[string][]string
	Findings []finding.Finding
	Requests int
}

// Run probes the endpoint and every named relation.
//
// It issues only queries, never mutations, so it is safe by default and needs
// no consent flag: a GraphQL query is the same read the REST pass already made.
func Run(ctx context.Context, c *client.Client, o Options) Result {
	if o.SampleRows <= 0 {
		o.SampleRows = 3
	}
	if o.Concurrency <= 0 {
		o.Concurrency = client.DefaultConcurrency
	}
	res := Result{
		Relations: map[string]RelationState{},
		Proof:     map[string][]string{},
	}

	url := strings.TrimSuffix(c.BaseURL(), "/") + "/graphql/v1"

	// The control decides whether anything else can be believed, and it runs
	// first so a non-discriminating endpoint costs one request rather than one
	// per relation.
	ctrlState, ctrlErr := query(ctx, c, url, ControlRelationName, o.SampleRows)
	res.Requests++
	switch {
	case ctrlErr == errUnreachable:
		res.State = Unreachable
		res.Findings = append(res.Findings, notAssessedFinding(url,
			"no usable response from the GraphQL endpoint"))
		return res
	case ctrlErr == errDisabled:
		// The common case, and not a finding: an endpoint that answers "the
		// extension is not installed" is a closed door, not a silence.
		res.State = Disabled
		res.Discriminating = true
		return res
	case ctrlErr != nil:
		res.State = Unreachable
		res.Findings = append(res.Findings, notAssessedFinding(url, ctrlErr.Error()))
		return res
	}
	res.State = Enabled
	res.Discriminating = ctrlState.state == Absent
	if !res.Discriminating {
		res.ControlDetail = "a relation that cannot exist was answered as though it does, " +
			"so every candidate would look real"
		res.Findings = append(res.Findings, notAssessedFinding(url, res.ControlDetail))
		return res
	}

	names := append([]string{}, o.Relations...)
	sort.Strings(names)

	type outcome struct {
		name  string
		state RelationState
		ids   []string
	}
	got := client.Map(ctx, o.Concurrency, names, func(ctx context.Context, name string) outcome {
		st, err := query(ctx, c, url, name, o.SampleRows)
		if err != nil {
			return outcome{name: name, state: Absent}
		}
		return outcome{name: name, state: st.state, ids: st.ids}
	})
	res.Requests += len(names)

	for _, g := range got {
		if g.name == "" {
			continue
		}
		res.Relations[g.name] = g.state
		if g.state == Readable && !o.Redact {
			res.Proof[g.name] = g.ids
		}
	}

	// A relation readable here that REST refused is the finding: the REST-only
	// verdict said protected and the rows are reachable anyway.
	var readable, bypass []string
	for name, st := range res.Relations {
		if st != Readable {
			continue
		}
		readable = append(readable, name)
		if !o.RESTReadable[name] {
			bypass = append(bypass, name)
		}
	}
	sort.Strings(readable)
	sort.Strings(bypass)

	for _, name := range bypass {
		res.Findings = append(res.Findings, bypassFinding(url, name, res.Proof[name], o.SampleRows))
	}
	if len(readable) > 0 {
		res.Findings = append(res.Findings, exposedFinding(url, readable, bypass, res.Proof))
	}
	finding.Sort(res.Findings)
	return res
}

type queryResult struct {
	state RelationState
	ids   []string
}

var (
	errUnreachable = fmt.Errorf("graphql endpoint unreachable")
	errDisabled    = fmt.Errorf("pg_graphql is not enabled")
)

// query asks for one relation's node ids.
//
// nodeId is requested rather than real columns because the columns are not
// known for precisely the relations that matter: a relation REST could not read
// is a relation whose shape was never sampled. Every pg_graphql type has
// nodeId, so this works without a schema -- and it is better evidence than a
// count, because it decodes to the schema, table and primary key of a real row.
func query(ctx context.Context, c *client.Client, url, relation string, limit int) (queryResult, error) {
	q := fmt.Sprintf("{ %sCollection(first: %d) { edges { node { nodeId } } } }", relation, limit)
	body, err := json.Marshal(map[string]string{"query": q})
	if err != nil {
		return queryResult{}, err
	}
	resp := c.Do(ctx, "POST", url, body, map[string]string{"Content-Type": "application/json"})
	if resp.Err != nil {
		return queryResult{}, errUnreachable
	}

	var out struct {
		Data   map[string]json.RawMessage `json:"data"`
		Errors []struct {
			Message string `json:"message"`
		} `json:"errors"`
	}
	if json.Unmarshal(resp.Body, &out) != nil {
		return queryResult{}, errUnreachable
	}
	for _, e := range out.Errors {
		if strings.Contains(e.Message, "pg_graphql extension is not enabled") {
			return queryResult{}, errDisabled
		}
		// "Unknown field \"xCollection\" on type Query" -- no such relation.
		if strings.Contains(e.Message, "Unknown field") {
			return queryResult{state: Absent}, nil
		}
	}
	raw, ok := out.Data[relation+"Collection"]
	if !ok {
		return queryResult{state: Absent}, nil
	}
	var conn struct {
		Edges []struct {
			Node struct {
				NodeID string `json:"nodeId"`
			} `json:"node"`
		} `json:"edges"`
	}
	if json.Unmarshal(raw, &conn) != nil {
		return queryResult{state: Absent}, nil
	}
	if len(conn.Edges) == 0 {
		// The relation exists and this role saw none of it.
		return queryResult{state: Filtered}, nil
	}
	var ids []string
	for _, e := range conn.Edges {
		ids = append(ids, decodeNodeID(e.Node.NodeID))
	}
	return queryResult{state: Readable, ids: ids}, nil
}

// decodeNodeID turns pg_graphql's opaque cursor back into the tuple it encodes,
// so the evidence in a report names the row rather than quoting base64.
func decodeNodeID(id string) string {
	raw, err := base64.StdEncoding.DecodeString(id)
	if err != nil {
		return id
	}
	var parts []any
	if json.Unmarshal(raw, &parts) != nil {
		return id
	}
	var s []string
	for _, p := range parts {
		s = append(s, fmt.Sprint(p))
	}
	return strings.Join(s, ".")
}
