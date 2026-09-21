// Package probe classifies read and write exposure for a relation and builds
// proof-carrying findings.
//
// Write probing is the part everyone gets wrong, in both directions.
//
// Unsound: a zero-match DELETE or PATCH (?id=eq.-1). RLS does not raise on
// writes; it silently filters candidate rows to zero. A protected relation and
// a wide-open one both answer 204, so the probe cannot discriminate and flags
// every relation as writable. Measured against the reference target this
// produced 16 false positives out of 21.
//
// Sound: an INSERT. RLS evaluates WITH CHECK before the schema sees the row,
// so the two outcomes are distinguishable:
//
//	42501                     -> the security layer rejected it (protected)
//	23502/23505/23503/22P02   -> it passed RLS and the SCHEMA rejected it
//
// Reaching the schema is the proof: RLS would have stopped it earlier.
// PGRST204 is deliberately NOT in that list: PostgREST raises it from its own
// schema cache before any SQL runs, so it is returned identically for
// protected and open relations and proves nothing.
//
// Safety: an empty INSERT normally cannot land a row, because any NOT NULL
// column rejects it. On a relation where every column is nullable or defaulted
// it CAN succeed, so the probe requests the inserted representation and
// deletes what it created, reporting honestly when cleanup fails. Write
// probing is opt-in regardless.
package probe

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/eppser/unruly/internal/classify"
	"github.com/eppser/unruly/internal/client"
	"github.com/eppser/unruly/internal/finding"
	"github.com/eppser/unruly/internal/postgrest"
	"github.com/eppser/unruly/internal/semantic"
)

// Options configures probing.
type Options struct {
	// Write enables the INSERT discriminator. Off by default: it issues a
	// mutating request, and must be gated on target ownership.
	Write bool
	// SampleRows is how many real rows to quote as evidence.
	SampleRows int
	// Classifier is an optional local model asked about columns the
	// deterministic rules could not read. nil, and a disabled one, are both
	// no-ops: this feature is off unless an operator configures an endpoint.
	Classifier semantic.Asker
	// Concurrency bounds in-flight probes.
	Concurrency int
	// Redact suppresses sampled values in evidence. The rows are still
	// RETRIEVED; only the report is stripped. For consent reasons that is a
	// different thing from Measure.
	Redact bool
	// Measure establishes exposure without transferring any data.
	//
	// The read probe asks for limit=0 with an exact count, so PostgREST answers
	//
	//	206  Content-Range: */465   body: []
	//
	// "465 rows are readable by anyone", in two bytes, with not one row leaving
	// the database. Redact cannot do this: it fetches the rows and then hides
	// them, so the data has already crossed the network and sits in the
	// scanner's memory.
	//
	// The cost is honest and worth stating: with no rows there are no column
	// names, so the sensitivity heuristics that raise a finding to critical
	// when a column is called access_token or password cannot run. Measure
	// answers "is it readable, and how much", not "how bad is it".
	//
	// This exists for studying populations of third-party projects, where
	// retrieving strangers' personal data to prove a point is not defensible
	// however good the point is.
	Measure bool
	// MaxColumnProbes bounds the total sensitive-column probes a measurement
	// scan issues, across all relations. Zero means the default.
	//
	// Every other budget in this scanner is bounded and says so when it binds;
	// this one was added without either, and 33 candidates per exposed
	// relation is 16,500 requests against a project with 500 of them. A
	// bounded scan that discloses the bound is the pattern here, not an
	// unbounded one that is polite in practice.
	MaxColumnProbes int
	// Schema addresses a PostgREST schema other than the default, so findings
	// and their remediation name the relation the way SQL must refer to it.
	Schema string
	// NoResidue restricts write probing to INSERTs that should be rejected
	// before a row is created.
	//
	// It forbids phase B's bare INSERT, which on a relation that accepts
	// anonymous INSERT, refuses anonymous SELECT and has no NOT NULL column
	// succeeds with 201, no Location header and an empty body — leaving a row
	// whose key is unreadable and which no anon-key holder can delete.
	//
	// It also constrains phase A, which it did NOT do until an audit ran the
	// flag against the exploit lab and watched it leave exactly the rows it
	// promises not to: gating only phase B is no protection when phase A has
	// already committed one. Phase A now sends a row the read stage sampled, so
	// the primary key collides and nothing is created, and declines to probe at
	// all when no such row exists.
	//
	// The cost is write recall on relations this scan cannot read, which are
	// reported as inconclusive rather than as clean.
	NoResidue bool
}

// Relation is the fully classified state of one relation.
type Relation struct {
	Name string
	// ColumnsUnprobed marks a relation the column budget could not reach, so
	// its severity is a lower bound rather than a verdict.
	ColumnsUnprobed bool
	// measured records that this relation was probed WITHOUT retrieving rows,
	// so the evidence command can show the request that was actually sent.
	measured bool
	// Schema is the PostgREST schema this relation lives in. Empty means the
	// default one, and nothing is qualified.
	//
	// It exists because remediation SQL was being emitted UNQUALIFIED for
	// relations outside the default schema:
	//
	//	ALTER TABLE daily_revenue ENABLE ROW LEVEL SECURITY;
	//
	// pasted into a SQL editor that resolves against public via search_path.
	// That either errors or -- worse -- alters a different table of the same
	// name while the real exposure stays open and the operator believes it is
	// fixed. A fix that silently targets the wrong object is worse than no fix.
	Schema string
	Read   postgrest.ReadState
	// ReadStatus is the HTTP status the read actually returned.
	//
	// The classified ReadState is what the scanner reasons with; the status is
	// what the operator's own replay of the published command will show. A
	// finding that prints a command and not the answer it got cannot be checked
	// against anything -- replaying proves the command runs, and running is not
	// reproducing. measured: 51 findings published a command and one
	// stated a status, so a deliberately mangled URL replayed to 404 and the
	// replay check passed it.
	ReadStatus int
	// WriteStatus is what the insert probe was answered with.
	WriteStatus int
	// UpdateStatus is what the PATCH probe was answered with.
	UpdateStatus int
	Rows         int
	Columns      []string
	Sample       []map[string]any
	Write        postgrest.WriteState
	// Update and Delete are the other two write verbs, kept separate from Write
	// because they are separate permissions. A relation that accepts INSERT
	// frequently also accepts UPDATE and DELETE, but "frequently" is a guess and
	// this scanner reports what it measured.
	Update    postgrest.WriteState
	UpdateWhy string
	Delete    postgrest.WriteState
	DeleteWhy string
	WriteWhy  string
	Sensitive []string
	// SensitiveValues names the KINDS of data found in the sampled rows, as
	// opposed to in the column names.
	//
	// The two are different instruments pointed at the same question. Column
	// names are English, so a schema written in any other language -- or one
	// using notes, payload, data -- yields nothing from them however plainly
	// the rows contain card numbers. Values carry no language.
	//
	// Empty under -measure by construction: that mode retrieves no rows, so
	// there is nothing to look at, and the finding says so rather than
	// implying the rows were clean.
	SensitiveValues []string
	// ModelClasses names kinds a LOCAL MODEL suggested for columns neither the
	// name rules nor the value rules could read. Empty unless -classifier is
	// configured, and never merged into the two above: an operator has to be
	// able to tell a mod-97 check from an opinion about a street address.
	ModelClasses []string
	CleanupErr   string
	requests     int
}

// Qualified is the name to put in a report and in SQL: schema-qualified
// outside the default schema, bare inside it.
// classesOf is the union of what the two classifiers found, as kinds.
//
// Column names arrive as "column:kind" pairs and are reduced to the kind; the
// value classifier already returns bare kinds. Sorted and deduplicated because
// two scans of an unchanged target must produce identical bytes, and because a
// list naming "credential" twice reads as two findings.
//
// Kinds only, never values -- the point of reporting a kind is that the report
// does not become a second copy of the leak, and -redact must not be able to
// leave a card number behind in a field called Classes.
// classifyWithModel fills ModelClasses for one relation, where a classifier
// is configured and the rules left columns unread.
//
// Best effort by design. A model that is slow, down, or wrong costs this
// relation its model classes and nothing else: the scan's findings come from
// the rules, and losing a scan because an optional sidecar is unavailable is
// not a trade this tool makes. The error is dropped here rather than
// propagated for the same reason -- Augment already returns partial results
// alongside it, and the caller has no better decision to make than "continue".
//
// A relation with no sampled rows is skipped. There is nothing to classify,
// and the request would be spent on an empty relation.
func classifyWithModel(ctx context.Context, c semantic.Asker, rel *Relation) {
	if c == nil || !c.Enabled() || len(rel.Sample) == 0 {
		return
	}
	cols, vals, rules := semantic.FromSample(rel.Sample, rel.Sensitive)
	got, _ := semantic.Augment(ctx, c, cols, vals, rules)
	rel.ModelClasses = got
}

func classesOf(r Relation) []string {
	seen := map[string]bool{}
	for _, pair := range r.Sensitive {
		if i := strings.LastIndex(pair, ":"); i > 0 {
			seen[pair[i+1:]] = true
		}
	}
	for _, k := range r.SensitiveValues {
		seen[k] = true
	}
	if len(seen) == 0 {
		return nil
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func (r Relation) Qualified() string {
	if r.Schema == "" {
		return r.Name
	}
	return r.Schema + "." + r.Name
}

// profileHeader is the curl fragment that reaches this relation's schema.
//
// A URL cannot carry it: PostgREST addresses relations by BARE name and takes
// the schema from a header, so /reporting.daily_revenue is a 404. The evidence
// command has to include the header or it does not reproduce the finding, and
// evidence that does not reproduce is an assertion.
func (r Relation) profileHeader() string {
	if r.Schema == "" {
		return ""
	}
	return " -H 'Accept-Profile: " + r.Schema + "'"
}

// Result aggregates probing.
type Result struct {
	// Discriminating is false when the target answered a relation that cannot
	// exist exactly as it answered the ones that can. Nothing below it was
	// measured in that case, and reporting the empty list as a clean project
	// is the failure this guards.
	Discriminating bool
	// ControlDetail says why, in the words a report can print.
	ControlDetail string

	// ColumnsUnprobedCount is how many exposed relations the column budget
	// could not reach. The count, not just the fact: a budget that stopped one
	// relation short and one that stopped forty short are different reports.
	ColumnsUnprobedCount int
	// ColumnBudgetBound is true when at least one exposed relation went
	// unprobed for sensitive columns, so severity is understated.
	ColumnBudgetBound bool
	// ColumnProbesUsed counts the sensitive-column probes actually issued.
	ColumnProbesUsed int
	Relations        []Relation
	Requests         int
}

// ReadExposed returns relations that leak rows anonymously.
func (r Result) ReadExposed() []string {
	var out []string
	for _, rel := range r.Relations {
		if rel.Read == postgrest.ReadExposed {
			out = append(out, rel.Name)
		}
	}
	sort.Strings(out)
	return out
}

// InsertReachable returns relations that accept anonymous writes.
func (r Result) InsertReachable() []string {
	var out []string
	for _, rel := range r.Relations {
		if rel.Write == postgrest.WriteReached {
			out = append(out, rel.Name)
		}
	}
	sort.Strings(out)
	return out
}

// Rows maps relation name to anon-visible row count.
func (r Result) Rows() map[string]int {
	m := map[string]int{}
	for _, rel := range r.Relations {
		if rel.Read == postgrest.ReadExposed {
			m[rel.Name] = rel.Rows
		}
	}
	return m
}

// Run probes every relation. Results are returned in sorted name order.
// ControlRelationName is the name probed to decide whether this target's
// answers carry information. It cannot exist, and it is the same name the
// enumerator uses -- a second name would be a second thing to keep absent.
const ControlRelationName = "unruly_control_relation_that_cannot_exist"

// controlSampleSize is how many candidates are held against the control before
// the sweep is abandoned.
const controlSampleSize = 8

func Run(ctx context.Context, c *client.Client, names []string, o Options) Result {
	if o.SampleRows <= 0 {
		o.SampleRows = 3
	}
	if o.Concurrency <= 0 {
		o.Concurrency = client.DefaultConcurrency
	}
	if o.MaxColumnProbes <= 0 {
		o.MaxColumnProbes = DefaultMaxColumnProbes
	}
	sorted := append([]string{}, names...)
	sort.Strings(sorted)

	// Shared across relations because the bound is on the SCAN, not on any one
	// table: the cost that matters to the target is the total.
	budget := &probeBudget{left: o.MaxColumnProbes}

	// Does the answer depend on WHICH relation was asked for? A name that
	// cannot exist is probed alongside a sample of the candidates. When the
	// endpoint answers all of them the same way, no further probe can carry
	// information and the sweep is abandoned rather than spent.
	//
	// Measured against a live Neon Data API: an unauthenticated caller is
	// refused before the table is consulted, so every candidate answers 400 and
	// no reply distinguishes one relation from another.
	//
	// Do NOT read the 1707 requests that scan sends as this stage's waste. They
	// are attributed by the report itself to enumerate's fallback expansion,
	// truncated by -max-relation-probes; measured after this control landed,
	// the same scan sends 1708 -- one MORE, because probe.Run receives no
	// candidates on that target and the control is its only request. What this
	// saves is a sweep proportional to the candidate list on a target that
	// cannot answer, which is a real cost and a different one.
	sample := sorted
	if len(sample) > controlSampleSize {
		sample = sample[:controlSampleSize]
	}
	head := client.Map(ctx, o.Concurrency, append([]string{ControlRelationName}, sample...),
		func(ctx context.Context, name string) Relation {
			return probeOne(ctx, c, name, o, budget)
		})
	control, sampled := head[0], head[1:]

	res := Result{Discriminating: discriminates(control, sampled)}
	res.Requests += control.requests
	if !res.Discriminating {
		res.ControlDetail = fmt.Sprintf("%q answered the same way as every one of the "+
			"%d candidates compared against it, so no probe can distinguish a relation "+
			"that is there from one that is not", ControlRelationName, len(sampled))
		for _, r := range sampled {
			res.Requests += r.requests
		}
		return res
	}

	rels := sampled
	if len(sorted) > len(sample) {
		rels = append(rels, client.Map(ctx, o.Concurrency, sorted[len(sample):],
			func(ctx context.Context, name string) Relation {
				return probeOne(ctx, c, name, o, budget)
			})...)
	}

	res.Relations = rels
	for _, r := range rels {
		res.Requests += r.requests
		if r.ColumnsUnprobed {
			res.ColumnBudgetBound = true
			res.ColumnsUnprobedCount++
		}
	}
	res.ColumnProbesUsed = o.MaxColumnProbes - budget.remaining()
	return res
}

func probeOne(ctx context.Context, c *client.Client, name string, o Options, budget *probeBudget) Relation {
	rel := Relation{Name: name, Schema: o.Schema, measured: o.Measure}

	// ---- read -------------------------------------------------------------
	limit := o.SampleRows
	if o.Measure {
		limit = 0
	}
	url := fmt.Sprintf("%s?select=*&limit=%d", c.RestURL(name), limit)
	resp := c.Get(ctx, url, map[string]string{"Prefer": "count=exact"})
	rel.requests++
	if resp.Err == nil {
		rel.Read, rel.Rows = postgrest.ClassifyRead(resp.Status, resp.ContentRange(), len(resp.Body))
		rel.ReadStatus = resp.Status
		// The count comes from Content-Range, so classification is unaffected
		// by asking for no rows. Sampling is the only thing Measure gives up.
		if rel.Read == postgrest.ReadExposed && !o.Measure {
			rel.Sample = resp.DecodeRows()
			rel.Columns = columnsOf(rel.Sample)
			rel.Sensitive = SensitiveColumns(rel.Columns)
			// Over rows this scan already retrieved: no extra requests, and
			// nothing kept but the kind names.
			rel.SensitiveValues = classify.Kinds(rel.Sample)
			// And, only where those left a column unread, the optional model.
			classifyWithModel(ctx, o.Classifier, &rel)
		}
		if rel.Read == postgrest.ReadExposed && o.Measure {
			if budget.take(len(sensitiveCandidates)) {
				rel.Columns, rel.requests = probeSensitiveColumns(ctx, c, name, rel.requests)
				rel.Sensitive = SensitiveColumns(rel.Columns)
			} else {
				rel.ColumnsUnprobed = true
			}
		}
	}

	// ---- write (opt-in) ---------------------------------------------------
	if o.Write {
		policy := residueAllowed
		if o.NoResidue {
			policy = residueForbidden
		}
		var del deleteOutcome
		rel.Write, rel.WriteWhy, rel.CleanupErr, del, rel.requests, rel.WriteStatus =
			insertProbe(ctx, c, name, rel.Sample, rel.requests, policy)
		rel.Delete, rel.DeleteWhy = del.state, del.why
		if rel.Delete == postgrest.WriteUnknown && rel.DeleteWhy == "" {
			rel.DeleteWhy = "no row was created by this scan, and the only sound DELETE probe " +
				"is one aimed at a row of its own: a DELETE filtered to match nothing answers " +
				"204 either way, and one filtered to match a real row destroys it to find out"
			rel.Delete = postgrest.WriteInconclusive
		}

		// UPDATE is a separate permission and gets its own probe. It runs
		// whether or not INSERT succeeded: the two are independent policies,
		// and a relation that refuses INSERT while accepting UPDATE is exactly
		// the case a scanner that conflates them would miss.
		rel.Update, rel.UpdateWhy, rel.requests, rel.UpdateStatus =
			updateProbe(ctx, c, name, rel.Sample, rel.requests, policy)
	}
	return rel
}

// insertProbe runs the sound write discriminator in two phases.
//
// Phase A asks for the inserted representation. That makes the rare
// row-actually-landed case cleanable, because PostgREST hands back the row and
// its primary key.
//
// But RETURNING adds a SELECT, and the SELECT is subject to RLS too, so a
// relation that genuinely accepts anonymous writes can answer 42501 for the
// read-back rather than for the write. Measured on the reference target:
//
//	signatory_submissions {} bare              -> 23502 (writable, correct)
//	signatory_submissions {} +representation   -> 42501 (looks blocked, WRONG)
//
// Phase B therefore re-probes with a bare INSERT whenever phase A reports
// 42501, which is the only ambiguous outcome. Postgres rolls the statement
// back when RETURNING trips a policy, so phase A leaves nothing behind in that
// case and phase B is safe to run.
func insertProbe(ctx context.Context, c *client.Client, name string, sample []map[string]any, reqs int, policy residuePolicy) (postgrest.WriteState, string, string, deleteOutcome, int, int) {
	// status is what the server ANSWERED, carried out so the finding can print
	// it. A published command with no stated status cannot be checked against
	// anything: replaying proves it runs, and running is not reproducing.
	status := 0
	body := []byte(`{}`)
	if policy == residueForbidden {
		var ok bool
		if body, ok = collidingBody(sample); !ok {
			return postgrest.WriteInconclusive, noSampleToCollideWith, "", deleteOutcome{}, reqs, status
		}
	}

	// ---- phase A: representation, so a landed row can be removed ----------
	resp := c.Do(ctx, "POST", c.RestURL(name), body,
		map[string]string{"Prefer": "return=representation"})
	reqs++
	if resp.Err != nil {
		return postgrest.WriteUnknown, resp.Err.Error(), "", deleteOutcome{}, reqs, status
	}
	code, _, _ := resp.DecodeError()
	status = resp.Status
	state, why := postgrest.ClassifyWrite(resp.Status, postgrest.Body{Code: code})

	// The insert actually succeeded: every column is nullable or defaulted.
	// Remove what we created.
	if resp.Status == 200 || resp.Status == 201 {
		var cleanupErr string
		var del deleteOutcome
		if rows := resp.DecodeRows(); len(rows) > 0 {
			del.state, del.why, cleanupErr = deleteRow(ctx, c, name, rows[0])
			reqs += 2 // the DELETE and the verifying read
			why = "INSERT succeeded; probe row created and " +
				map[bool]string{true: "removed", false: "NOT removed"}[cleanupErr == ""]
		}
		return postgrest.WriteReached, why, cleanupErr, del, reqs, status
	}

	// ---- phase B: disambiguate 42501 --------------------------------------
	if state == postgrest.WriteBlockedRLS && code == "42501" && policy != residueAllowed {
		return postgrest.WriteInconclusive,
			"RLS refused the write, but phase A's RETURNING clause is also subject to RLS " +
				"so this may be a read-back artifact rather than a write refusal. " +
				"Disambiguating requires a bare INSERT, which on a write-only relation with " +
				"no NOT NULL column creates a row that cannot be deleted. Suppressed by " +
				"-no-residue; drop that flag to resolve it.",
			"", deleteOutcome{}, reqs, status
	}
	if state == postgrest.WriteBlockedRLS && code == "42501" {
		bare := c.Do(ctx, "POST", c.RestURL(name), []byte(`{}`), nil)
		reqs++
		if bare.Err != nil {
			return state, why + " (bare re-probe failed: " + bare.Err.Error() + ")", "", deleteOutcome{}, reqs, status
		}
		bcode, _, _ := bare.DecodeError()
		status = bare.Status
		bstate, bwhy := postgrest.ClassifyWrite(bare.Status, postgrest.Body{Code: bcode})
		switch {
		case bstate == postgrest.WriteReached && (bare.Status == 200 || bare.Status == 201 || bare.Status == 204):
			// A row landed and we have no representation to identify it.
			// Inherent, not a shortcoming: PostgREST answers 201 with no
			// Location header and an empty body, and reading the key back
			// requires the SELECT this relation refuses.
			return postgrest.WriteReached,
				"INSERT succeeded on bare re-probe",
				"probe row created and cannot be removed: the relation accepts anonymous " +
					"INSERT but refuses anonymous SELECT, so its primary key is unreadable. " +
					"Delete it with a service_role key, or use -no-residue to avoid this probe.",
				deleteOutcome{}, reqs, status
		case bstate == postgrest.WriteReached:
			return postgrest.WriteReached,
				bwhy + " (phase A 42501 was a RETURNING/SELECT artifact)", "", deleteOutcome{}, reqs, status
		default:
			return postgrest.WriteBlockedRLS, bwhy, "", deleteOutcome{}, reqs, status
		}
	}
	return state, why, "", deleteOutcome{}, reqs, status
}

// deleteOutcome carries what the cleanup DELETE proved. Removing a row this
// scan created is the only DELETE probe that is both sound and non-destructive:
// the row is ours, so its absence afterwards is evidence, and nothing of the
// target's is at risk. It used to be discarded into a cleanup message; it is a
// verdict.
type deleteOutcome struct {
	state postgrest.WriteState
	why   string
}

// updateProbe establishes whether the anonymous role may UPDATE a relation,
// without changing anything in it.
//
// The naive probe -- PATCH with a filter matching nothing -- is unsound for the
// same reason the zero-match DELETE is: RLS filters candidate rows to zero
// rather than raising, so protected and open relations both answer 204. The fix
// is not a different status code but a header. Prefer: count=exact makes
// PostgREST report how many rows the statement touched:
//
//	FOR ALL TO anon      PATCH -> 204  Content-Range: 0-0/1   admitted
//	SELECT, INSERT only  PATCH -> 204  Content-Range: */0     filtered
//
// Both measured on the exploit lab. The body sets one column to the value it
// already holds, so an admitted statement writes the row back unchanged.
//
// Two costs, stated rather than hidden. It is still a real UPDATE: an ON UPDATE
// trigger fires and an updated_at column moves, even though no value changes.
// And it needs a readable row to aim at, so a write-only relation cannot be
// probed this way.
//
// Under -no-residue the no-op is replaced by a collision: the sampled row's key
// is set to ANOTHER row's key, so the statement aborts on the unique constraint
// before touching anything. That answers 23505 when admitted and */0 when
// filtered, costing a second readable row.
func updateProbe(ctx context.Context, c *client.Client, name string, sample []map[string]any,
	reqs int, policy residuePolicy) (postgrest.WriteState, string, int, int) {
	// status is what the PATCH was answered with, carried out so the
	// finding can print the answer beside the command that produced it.
	status := 0

	if len(sample) == 0 {
		return postgrest.WriteInconclusive,
			"no readable row to aim an UPDATE at. A PATCH whose filter matches nothing " +
				"answers 204 whether or not the role may write, so probing without a target " +
				"row would be the false-positive design this scanner refuses",
			reqs, status
	}
	key, val, ok := rowKey(sample[0])
	if !ok {
		return postgrest.WriteInconclusive,
			"the sampled row has no column this scan recognises as a key (id, uuid, pk), " +
				"so there is no way to aim an UPDATE at exactly one row",
			reqs, status
	}

	// Collision first, whenever a second readable row makes one possible; the
	// no-op only if the collision cannot be built or cannot be answered.
	//
	// Both variants leave every value as they found it, but only the collision
	// leaves the ROW alone. The no-op is still a real UPDATE: PostgreSQL writes
	// a new tuple version even when the new value equals the old, so the row
	// moves to the end of the heap, ON UPDATE triggers fire and an updated_at
	// column advances. Measured on the lab fixture, where an unordered
	// select?limit=3 returned rows 1,2,3 before the probe and 3,4,1 after --
	// the data untouched, its physical order not. A scanner should not reorder
	// somebody's table to answer a question it can answer without doing so.
	//
	// The collision cannot reorder anything: the unique violation aborts the
	// statement before a tuple is written. It is not always available, though.
	// It needs a second readable row, and it cannot touch a GENERATED ALWAYS
	// key, which PostgreSQL refuses to update at all (428C9) before any policy
	// runs -- so on an identity-keyed relation the collision is inconclusive
	// while the relation may be wide open. That is why the no-op survives as a
	// fallback: preferring the collision without one silently reported
	// verb_identity_key, a table anyone can rewrite, as unassessed.
	//
	// Under -no-residue there is no fallback. Nothing may be written, and the
	// no-op writes a tuple.
	type attempt struct {
		how  string
		body []byte
	}
	var attempts []attempt
	if b, ok := collidingUpdateBody(sample, key); ok {
		attempts = append(attempts, attempt{"collision", b})
	}
	if policy != residueForbidden {
		if b, ok := noopUpdateBody(sample[0], key); ok {
			attempts = append(attempts, attempt{"no-op", b})
		}
	}
	if len(attempts) == 0 {
		if policy == residueForbidden {
			return postgrest.WriteInconclusive,
				"-no-residue requires an UPDATE the database is certain to abort, which needs " +
					"a second readable row whose key can be collided with; this relation " +
					"returned fewer than two",
				reqs, status
		}
		return postgrest.WriteInconclusive,
			"the sampled row has no non-null column that can be written back unchanged, " +
				"so there is no way to test UPDATE without altering a value",
			reqs, status
	}

	url := fmt.Sprintf("%s?%s=eq.%s", c.RestURL(name), key, val)
	var state postgrest.WriteState
	var why, how string
	for _, a := range attempts {
		how = a.how
		resp := c.Do(ctx, "PATCH", url, a.body, map[string]string{
			"Prefer":       "count=exact,return=minimal",
			"Content-Type": "application/json",
		})
		reqs++
		if resp.Err != nil {
			return postgrest.WriteUnknown, resp.Err.Error(), reqs, status
		}
		code, _, _ := resp.DecodeError()
		status = resp.Status
		state, why = postgrest.ClassifyAffected(resp.Status, resp.ContentRange(),
			postgrest.Body{Code: code})
		if state != postgrest.WriteInconclusive {
			break
		}
	}
	return state, how + " UPDATE probe: " + why, reqs, status
}

// rowKey finds the column an UPDATE or DELETE can be aimed at.
func rowKey(row map[string]any) (key, val string, ok bool) {
	for _, cand := range []string{"id", "uuid", "pk"} {
		if v, has := row[cand]; has && v != nil {
			return cand, fmt.Sprintf("%v", v), true
		}
	}
	return "", "", false
}

// noopUpdateBody writes one column back with the value it already holds.
//
// A non-key column is preferred: a key is often GENERATED ALWAYS, which
// PostgreSQL refuses to update at all (428C9) before any policy is consulted,
// which would report inconclusive for a relation that is in fact wide open.
func noopUpdateBody(row map[string]any, key string) ([]byte, bool) {
	pick := func(skipKey bool) (string, bool) {
		names := make([]string, 0, len(row))
		for k := range row {
			names = append(names, k)
		}
		sort.Strings(names) // determinism: map order is not a scan input
		for _, k := range names {
			if skipKey && k == key {
				continue
			}
			if row[k] != nil {
				return k, true
			}
		}
		return "", false
	}
	col, ok := pick(true)
	if !ok {
		if col, ok = pick(false); !ok {
			return nil, false
		}
	}
	b, err := json.Marshal(map[string]any{col: row[col]})
	return b, err == nil
}

// collidingUpdateBody sets the key to another row's key, so a unique constraint
// aborts the statement before anything is written.
func collidingUpdateBody(sample []map[string]any, key string) ([]byte, bool) {
	if len(sample) < 2 {
		return nil, false
	}
	first, ok := sample[0][key]
	if !ok || first == nil {
		return nil, false
	}
	for _, other := range sample[1:] {
		v, has := other[key]
		if !has || v == nil || fmt.Sprintf("%v", v) == fmt.Sprintf("%v", first) {
			continue
		}
		b, err := json.Marshal(map[string]any{key: v})
		return b, err == nil
	}
	return nil, false
}

// residuePolicy says what an INSERT probe is permitted to leave behind.
//
// This was a bool named noResidue, which two callers read as two different
// promises: -no-residue meant "create nothing", while Trigger passed the same
// true to mean "do not run phase B" while still WANTING a row to land, because
// a Realtime delivery probe has nothing to deliver otherwise. Splitting them is
// not tidying — the first version of the collision fix silently disarmed the
// Realtime trigger, since a colliding INSERT by design never changes a row.
type residuePolicy int

const (
	// residueAllowed runs both phases: a row may land, and phase B's bare
	// INSERT may leave one that cannot be removed.
	residueAllowed residuePolicy = iota
	// residueCleanable runs phase A only. A row may land, but representation
	// comes back with it, so it can be deleted.
	residueCleanable
	// residueForbidden issues only an INSERT a unique constraint should
	// reject, and declines to probe at all when it cannot build one.
	residueForbidden
)

const noSampleToCollideWith = "write exposure not assessed: -no-residue only permits an INSERT " +
	"that a unique constraint is expected to reject, which requires a row this scan could read. " +
	"This relation returned none, so any INSERT here might land a row that cannot be removed. " +
	"Drop -no-residue to probe it."

// collidingBody builds an INSERT body that an existing unique constraint should
// reject, so the probe never creates a row.
//
// The empty body `{}` is residue-free only when some column is NOT NULL without
// a default. Where every column is nullable or defaulted it SUCCEEDS, and if the
// relation also refuses anonymous DELETE the row cannot be taken back. That is
// not hypothetical: it is what the exploit lab's feedback_submissions does, and
// -no-residue used to leave rows there anyway, because it gated only the phase-B
// bare INSERT and phase A had already committed one.
//
// Re-sending a row the read stage already sampled collides with the primary key
// instead. Measured against the lab, with the row count unchanged either side:
//
//	feedback_submissions   {"id":106,...} -> 409 23505 duplicate key   (reached)
//	protected_rls_no_policy{"id":1}       -> 401 42501                 (blocked)
//
// RLS is evaluated BEFORE the unique constraint, so the collision still
// discriminates: a protected relation never gets far enough to raise 23505.
//
// Two alternatives were measured and rejected. PostgREST's `Prefer: tx=rollback`
// is not honoured by Supabase — the row committed regardless. A zero-match
// DELETE to test removability first returns 204 whether or not DELETE is
// granted, which is the unsound probe this package's doc comment already warns
// about; it was tried anyway and confirmed useless.
//
// Residual risk, stated rather than papered over: a readable relation with no
// unique constraint at all accepts the duplicate, and the row lands. Phase A's
// representation still lets it be deleted, and a failed delete is still
// reported. -no-residue narrows the window; it does not abolish it.
func collidingBody(sample []map[string]any) ([]byte, bool) {
	if len(sample) == 0 {
		return nil, false
	}
	b, err := json.Marshal(sample[0])
	if err != nil {
		return nil, false
	}
	return b, true
}

// deleteRow removes a probe-created row and VERIFIES the removal.
//
// The verification is not defensive padding. A DELETE denied by row-level
// security returns 204 having deleted nothing — the same ambiguity that makes
// zero-match DELETE unusable as a write probe — so a status check alone
// reports success while the row survives. These relations enable RLS with
// SELECT and INSERT policies and no DELETE policy, which is an ordinary
// configuration, and it silently accumulated probe rows across runs (6 -> 8)
// until the row-count eval caught it.
//
// So the row is read back. Still present means cleanup failed, whatever the
// status said.
func deleteRow(ctx context.Context, c *client.Client, name string, row map[string]any) (postgrest.WriteState, string, string) {
	key, val, ok := rowKey(row)
	if !ok {
		return postgrest.WriteInconclusive,
			"the probe row came back with no recognisable key, so the DELETE could not be " +
				"aimed at it",
			"no identifiable primary key in the returned row; manual cleanup required"
	}
	url := fmt.Sprintf("%s?%s=eq.%s", c.RestURL(name), key, val)
	resp := c.Do(ctx, "DELETE", url, nil, nil)
	if resp.Err != nil {
		return postgrest.WriteUnknown, resp.Err.Error(), resp.Err.Error()
	}
	if resp.Status >= 400 {
		code, _, _ := resp.DecodeError()
		state, why := postgrest.ClassifyWrite(resp.Status, postgrest.Body{Code: code})
		return state, "DELETE of the probe row: " + why,
			fmt.Sprintf("cleanup DELETE returned HTTP %d; manual cleanup required", resp.Status)
	}

	// Verify. A 204 proves nothing on its own -- which is the whole reason a
	// zero-match DELETE probe is unsound, and the reason this one is not: the
	// row is one this scan created, so its absence afterwards is the proof.
	check := c.Get(ctx, fmt.Sprintf("%s?%s=eq.%s&select=%s&limit=1",
		c.RestURL(name), key, val, key), nil)
	if check.Err != nil {
		return postgrest.WriteInconclusive,
			"the DELETE answered " + strconv.Itoa(resp.Status) + " but could not be verified: " +
				check.Err.Error(),
			"cleanup could not be verified: " + check.Err.Error()
	}
	if rows := check.DecodeRows(); len(rows) > 0 {
		return postgrest.WriteBlockedRLS,
			"the DELETE answered " + strconv.Itoa(resp.Status) + " and the row is still there, " +
				"so row-level security filtered it out rather than deleting it",
			fmt.Sprintf("cleanup DELETE returned HTTP %d but the row is still present "+
				"(%s=%s); row-level security most likely permits INSERT and SELECT but not "+
				"DELETE. Remove it with a service_role key.", resp.Status, key, val)
	}
	return postgrest.WriteReached,
		"a row this scan created was deleted anonymously and verified gone", ""
}

// restURL joins a PostgREST mount base with a relation name. The base already
// includes the mount path, which differs between the managed product (Kong at
// /rest/v1) and a bare self-hosted PostgREST (the root); hardcoding it here
// would emit evidence URLs that do not resolve.
func restURL(base, relation string) string {
	return strings.TrimRight(base, "/") + "/" + relation
}

// columnsOf lists the column names in a sample, INCLUDING paths inside json
// and jsonb values.
//
// Top-level keys alone under-grade the most common way personal data actually
// sits in a Supabase schema. A jsonb column called app_state, preferences or
// payload is not a sensitive NAME, so a relation holding
//
//	app_state = {"user": {"email": "...", "access_token": "..."}}
//
// was reported high rather than critical: the classifier saw one column called
// app_state and nothing else. Measured on a real target, which is where this
// came from. The column name is chosen by the developer and the sensitive part
// is chosen by the framework, so grading only the outer name grades the wrong
// half.
//
// Paths are dotted (app_state.user.email) and array elements collapse to one
// path rather than one per index, so the output does not grow with the data.
// Both bounds below are deliberate: a deeply nested or very wide document would
// otherwise turn one sampled row into thousands of names to match, and this
// runs per exposed relation.
func columnsOf(rows []map[string]any) []string {
	set := map[string]bool{}
	for _, r := range rows {
		keys := make([]string, 0, len(r))
		for k := range r {
			keys = append(keys, k)
		}
		sort.Strings(keys) // truncation must not depend on map order
		for _, k := range keys {
			set[k] = true
			walkJSON(k, r[k], 1, set)
		}
	}
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

const (
	// maxJSONDepth bounds recursion into a json value.
	maxJSONDepth = 6
	// maxJSONPaths bounds how many names one relation's sample can contribute.
	maxJSONPaths = 500
)

func walkJSON(prefix string, v any, depth int, set map[string]bool) {
	if depth > maxJSONDepth || len(set) >= maxJSONPaths {
		return
	}
	switch t := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			p := prefix + "." + k
			set[p] = true
			walkJSON(p, t[k], depth+1, set)
		}
	case []any:
		// One path for the whole array. Indexing would make the name set a
		// function of row count, and "payload[3].email" is not a different
		// disclosure from "payload[0].email".
		for _, e := range t {
			walkJSON(prefix+"[]", e, depth+1, set)
		}
	case string:
		// A text column holding JSON is the same disclosure as a jsonb one.
		// Unmarshal rejects anything that is not an object, so ordinary prose
		// beginning with a brace costs one failed parse and contributes
		// nothing.
		s := strings.TrimSpace(t)
		if len(s) < 2 || s[0] != '{' || len(s) > 64*1024 {
			return
		}
		var nested map[string]any
		if json.Unmarshal([]byte(s), &nested) == nil {
			walkJSON(prefix, nested, depth, set)
		}
	}
}

// ---------------------------------------------------------------- classifier

// sensitiveCandidates are the column names -measure asks about, pinned so the
// scan is reproducible.
//
// Measure mode retrieves no rows, so it has no column names, so it cannot say
// that an exposed table holds session tokens rather than blog posts -- and the
// difference between those is the difference between a finding and an
// incident.
//
// PostgREST answers the question without returning data:
//
//	?select=access_token&limit=0  ->  206 []          the column exists
//	?select=email&limit=0         ->  400 42703       it does not
//
// That is schema metadata, not anyone's data: it establishes that a publicly
// readable table HAS a column called access_token without reading a single
// token out of it. The list is short and high-signal on purpose, because every
// entry costs one request per exposed relation.
var sensitiveCandidates = []string{
	"access_token", "refresh_token", "api_key", "apikey", "auth_token",
	"session_token", "id_token", "secret", "client_secret", "private_key",
	"password", "password_hash", "encrypted_password", "salt",
	"email", "phone", "phone_number", "address", "date_of_birth", "dob",
	"ssn", "national_id", "passport_number", "drivers_license",
	"credit_card", "card_number", "iban", "bank_account", "routing_number",
	"otp", "totp_secret", "recovery_code", "stripe_customer_id",
}

// DefaultMaxColumnProbes bounds sensitive-column probing per scan.
//
// 2,000 is roughly 60 exposed relations at 33 candidates each, which covers
// every project seen in a 100-site sample -- the largest had 80 exposed
// relations, and the bound then truncates rather than silently issuing 2,640
// requests to one target.
const DefaultMaxColumnProbes = 2000

// probeBudget hands out column probes until the scan's allowance runs out.
type probeBudget struct {
	mu   sync.Mutex
	left int
}

// take reserves n probes, all or nothing: a half-probed relation would report
// "no sensitive columns" for the ones it never asked about, which is worse
// than reporting that it did not look.
func (b *probeBudget) take(n int) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.left < n {
		return false
	}
	b.left -= n
	return true
}

func (b *probeBudget) remaining() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.left
}

// probeSensitiveColumns asks which of the pinned names exist on a relation.
//
// One request per candidate, all with limit=0, so nothing is retrieved. The
// answer is the column list, which the ordinary severity rules then classify
// exactly as they classify names taken from a sampled row.
func probeSensitiveColumns(ctx context.Context, c *client.Client, name string, reqs int) ([]string, int) {
	var found []string
	for _, col := range sensitiveCandidates {
		resp := c.Get(ctx, fmt.Sprintf("%s?select=%s&limit=0", c.RestURL(name), col), nil)
		reqs++
		if resp.Err != nil {
			continue
		}
		// 200 and 206 both mean the column resolved. A 400 with 42703 means it
		// does not exist; any other status says nothing and is treated as no.
		if resp.Status == 200 || resp.Status == 206 {
			found = append(found, col)
		}
	}
	sort.Strings(found)
	return found, reqs
}

// sensitivePatterns are deterministic name-based rules. Name matching is used
// rather than value inspection so the classifier behaves identically whether
// or not a given row happens to contain data.
// SensitiveColumns is retained as the name this package's callers know, and
// forwards to internal/classify.
//
// The patterns moved because two providers were answering the same question
// differently. Supabase rated a relation critical for a column called
// password; Firebase rated every readable Firestore collection high whatever
// it was called, because the classifier lived in this Supabase-shaped package
// and the provider could not reach it without importing probing machinery it
// has no use for. "What kind of data is this" belongs to the shared core, next
// to the value classifier that answers the same question from the other side.
func SensitiveColumns(cols []string) []string { return classify.Names(cols) }

// ---------------------------------------------------------------- findings

// Findings converts probe results into deterministic, proof-carrying findings.
//
// It takes a base URL rather than a Client so finding generation is a pure
// function of observed state, independent of the network layer.
func (r Result) Findings(baseURL string, redact bool) []finding.Finding {
	var out []finding.Finding
	for _, rel := range r.Relations {
		if rel.Read == postgrest.ReadExposed {
			out = append(out, readFinding(baseURL, rel, redact))
		}
		if rel.Write == postgrest.WriteReached {
			out = append(out, writeFinding(baseURL, rel))
		}
		// An inconclusive write is a hole in the report, not a clean result.
		// See finding.NotAssessedWrite for what was silently dropped before.
		if rel.Write == postgrest.WriteInconclusive {
			out = append(out, finding.NotAssessedWrite(
				restURL(baseURL, rel.Name), rel.Qualified(), rel.WriteWhy))
		}
		if rel.Update == postgrest.WriteReached {
			out = append(out, verbFinding(baseURL, rel, "UPDATE", rel.UpdateWhy))
		}
		if rel.Delete == postgrest.WriteReached {
			out = append(out, verbFinding(baseURL, rel, "DELETE", rel.DeleteWhy))
		}
		// An unassessed verb is only worth reporting on a relation the anonymous
		// role can reach at all.
		//
		// Without this gate every correctly hardened table produces two info
		// findings and pushes the scan to exit 3, because a relation that
		// refuses SELECT offers no row to aim an UPDATE at and no way to create
		// one to DELETE -- so "not assessed" would be the answer for the entire
		// database, and exit 3 would stop meaning anything. Same reasoning as
		// notBlindResources in the coverage set.
		//
		// Readability is the gate, not writability. A relation that accepts an
		// intended public INSERT and refuses SELECT -- a contact form, the
		// commonest legitimate shape there is -- would otherwise collect two
		// coverage notes it can never shed, since neither verb can be probed
		// without a readable row. The hardened fixture caught exactly that: one
		// intended finding became three.
		//
		// The residual blind spot is stated rather than hidden: on a relation
		// this scan cannot read, UPDATE and DELETE are not established at all.
		// A policy written FOR ALL -- the common cause of an over-granted table
		// -- also grants SELECT, so the exposed cases are the ones that land in
		// the gate rather than outside it.
		if rel.Read == postgrest.ReadExposed {
			for _, v := range []struct {
				verb  string
				state postgrest.WriteState
				why   string
			}{{"UPDATE", rel.Update, rel.UpdateWhy}, {"DELETE", rel.Delete, rel.DeleteWhy}} {
				if v.state == postgrest.WriteInconclusive {
					out = append(out, finding.NotAssessedVerb(
						restURL(baseURL, rel.Name), rel.Qualified(), v.verb, v.why))
				}
			}
		}
		if rel.CleanupErr != "" {
			out = append(out, finding.Finding{
				ID: "unruly-probe-row-left-behind", Name: "Probe row could not be removed",
				Severity: finding.High, Protocol: "postgrest",
				Matched: restURL(baseURL, rel.Name), Resource: rel.Name,
				Description: "unruly inserted a probe row to test write access and could not delete it.",
				Evidence:    finding.Evidence{Reason: rel.CleanupErr},
			})
		}
	}
	if inv := inventoryFinding(baseURL, r.Relations); inv != nil {
		out = append(out, *inv)
	}
	if blind := writeBlindSpot(baseURL, r.Relations); blind != nil {
		out = append(out, *blind)
	}
	finding.Sort(out)
	return finding.Dedup(out)
}

// inventoryFinding records relations that exist and are correctly protected.
//
// Enumeration is the expensive half of this scanner: the hint oracle recovers
// real, domain-specific relation names that no wordlist contains, and it works
// whether or not the relation leaks. Findings were then emitted only for the
// ones that leak, so on one target 50 names were recovered and 7 survived into
// the report. The other 43 were discarded at the end of the run that paid for
// them.
//
// They are worth keeping for two different readers. For the operator they are
// the denominator: "7 exposed" means something different out of 50 than out of
// 7. For anyone analysing scans in bulk they are the schema itself, which is
// the recon product.
//
// One finding, not one per relation: at info severity, 43 rows per target
// swamps a batch artifact, and the names are only useful together. Info never
// moves the exit code, and this id is not in the blindness set -- a protected
// relation is a measurement, not a gap.
// writeBlindSpot states the limit the per-verb notes deliberately do not.
//
// Those notes are gated on readability, and the gate is right: a relation that
// refuses SELECT offers no row to aim an UPDATE at and no way to create one to
// DELETE, so without it every correctly hardened table collects two coverage
// findings and exit 3 stops meaning anything.
//
// What the gate leaves is a real blind spot that was only ever written in a
// comment. On a relation this scan cannot read, UPDATE and DELETE are not
// established AT ALL. The common over-grant is a policy written FOR ALL, which
// grants SELECT too and therefore lands inside the gate where the verbs ARE
// probed -- but INSERT and UPDATE without SELECT is a shape somebody can
// write, and it is invisible here.
//
// One statement for the scan, naming the relations, rather than two findings
// per relation. Info, because it describes the examination rather than the
// target, and it does not move the exit code: nothing here is a finding about
// the project, and a hardened project should still exit 0.
func writeBlindSpot(baseURL string, rels []Relation) *finding.Finding {
	var unreadable []string
	for _, rel := range rels {
		if rel.Read != postgrest.ReadExposed {
			unreadable = append(unreadable, rel.Qualified())
		}
	}
	if len(unreadable) == 0 {
		return nil
	}
	sort.Strings(unreadable)
	return &finding.Finding{
		ID:       "unruly-surface-not-assessed",
		Name:     "Write access was not established on the relations this scan cannot read",
		Severity: finding.Info,
		Protocol: "postgrest",
		Matched:  baseURL,
		Resource: "write-verbs:unreadable-relations",
		Description: fmt.Sprintf(
			"UPDATE and DELETE were not established on %d relation(s) that returned no "+
				"rows to this scan: %s. Establishing either needs a row to aim at, and a "+
				"relation that refuses SELECT offers none — so this is a limit of probing "+
				"from outside rather than a property of those relations. The usual "+
				"over-grant is a policy written FOR ALL, which grants SELECT as well and "+
				"is therefore covered above; a policy granting INSERT or UPDATE without "+
				"SELECT is not, and would not appear anywhere in this report.",
			len(unreadable), strings.Join(unreadable, ", ")),
		Evidence: finding.Evidence{
			Reason: fmt.Sprintf("%d relation(s) unreadable, so no row exists to probe "+
				"UPDATE or DELETE against", len(unreadable)),
		},
		FixKind: finding.FixNone,
		Remediation: "-- Nothing to fix. To establish these verbs, grant the scan a\n" +
			"-- readable row or check the policies directly:\n" +
			"SELECT c.relname, p.polname, p.polcmd FROM pg_policy p\n" +
			"  JOIN pg_class c ON c.oid = p.polrelid ORDER BY 1, 2;",
	}
}

// schemaLabel is the schema to name in SQL. The remediation is a statement an
// operator pastes into psql, and there the default schema does have a name --
// so this one guesses public where schemaOf correctly refuses to.
func schemaLabel(rels []Relation) string {
	if s := schemaOf(rels); s != "" {
		return s
	}
	return "public"
}

// schemaOf is the schema these relations were probed in, empty for the default
// one. Every relation in one Result carries the same value.
func schemaOf(rels []Relation) string {
	for _, r := range rels {
		if r.Schema != "" {
			return r.Schema
		}
	}
	return ""
}

func inventoryFinding(baseURL string, rels []Relation) *finding.Finding {
	var protected []string
	for _, rel := range rels {
		switch rel.Read {
		case postgrest.ReadEmpty, postgrest.ReadDenied:
			protected = append(protected, rel.Qualified())
		}
	}
	if len(protected) == 0 {
		return nil
	}
	sort.Strings(protected)
	// One resource per SCHEMA. A finding is deduplicated on id, protocol,
	// matched URL and resource, and every schema's inventory answered to the
	// same three of those -- so on a project exposing a second schema, that
	// schema's protected relations were built, appended, and then dropped as a
	// duplicate of the default schema's. Measured on the lab: reporting
	// recovered 3 relations and the report named the one that leaks, with the
	// other two invisible. Silent, and in the direction that makes a scan look
	// cleaner than the target is.
	//
	// The default schema keeps the unqualified name because it is whatever
	// PostgREST serves without an Accept-Profile header, which is not
	// necessarily public and must not be labelled as though it were.
	resource := "schema:inventory"
	if s := schemaOf(rels); s != "" {
		resource += ":" + s
	}
	return &finding.Finding{
		ID:       "unruly-relations-protected",
		Name:     "Relations that exist and returned nothing to the anonymous role",
		Severity: finding.Info,
		Protocol: "postgrest",
		Matched:  baseURL,
		Resource: resource,
		Description: fmt.Sprintf(
			"%d relations were recovered by enumeration and returned no rows to the "+
				"anonymous role, which is the correct behaviour and is recorded rather "+
				"than dropped: %s. Their existence is confirmed -- PostgREST answered for "+
				"each name -- so this is the schema an anonymous caller can prove is "+
				"there, and the denominator for the exposures reported above.",
			len(protected), strings.Join(protected, ", ")),
		FixKind: finding.FixSQL,
		Remediation: "-- Nothing to fix: these answered correctly. Names alone are still\n" +
			"-- disclosure, and they leak through PostgREST's near-miss hint regardless\n" +
			"-- of any policy. Confirm each is meant to be reachable at all:\n" +
			fmt.Sprintf("SELECT table_name FROM information_schema.tables "+
				"WHERE table_schema = '%s';", schemaLabel(rels)),
		Evidence: finding.Evidence{
			Reason: fmt.Sprintf("%d relations exist and are not readable anonymously",
				len(protected)),
		},
	}
}

// writableByAnyone reports whether any write verb was PROVEN, which outranks
// every judgement about what the relation holds.
func writableByAnyone(rel Relation) bool {
	return rel.Write == postgrest.WriteReached ||
		rel.Update == postgrest.WriteReached ||
		rel.Delete == postgrest.WriteReached
}

func readFinding(baseURL string, rel Relation, redact bool) finding.Finding {
	sev := finding.High
	name := "Relation is readable by the anonymous role"
	contentOnly := false
	switch {
	case len(rel.Sensitive) > 0:
		sev = finding.Critical
		name = "Relation exposes sensitive columns to the anonymous role"
	case len(rel.SensitiveValues) > 0:
		// The same severity as a sensitive column name, because it is the same
		// fact arrived at from the other side: a card number in a column called
		// notes is a card number. Rated second so a relation with both is
		// described by its columns, which is the more specific statement.
		sev = finding.Critical
		name = "Relation exposes sensitive data to the anonymous role"
	case writableByAnyone(rel):
		// Readable AND writable: what it holds stops mattering, because the
		// question is no longer what an attacker learns but what they can
		// change. Never demoted, whatever the columns are called.
		sev = finding.High
	case looksLikePublishedContent(rel):
		// The site's own copy, rendered into the page anyway. Reporting this
		// beside a table of password hashes is how a report stops being read.
		sev = finding.Medium
		name = "Relation is readable by the anonymous role, and looks like site content"
		contentOnly = true
	}
	sample := rel.Sample
	if redact {
		sample = nil
	}
	reason := ""
	if len(rel.Sensitive) > 0 {
		reason = strings.Join(rel.Sensitive, ", ")
	}
	if len(rel.Sensitive) > 0 && len(rel.SensitiveValues) > 0 {
		// BOTH, not either. These were combined with an "else if", so one
		// recognisable column name discarded every value finding: a table with
		// an `email` column and a service_role key in a `notes` column reported
		// pii and said nothing about the credential.
		reason += "; sampled rows also contain " +
			strings.Join(rel.SensitiveValues, ", ") + " data"
	} else if len(rel.SensitiveValues) > 0 {
		// Kinds, never the values. Naming what was found is the evidence;
		// quoting it would make the report a second copy of the leak.
		reason = "sampled rows contain " + strings.Join(rel.SensitiveValues, ", ") +
			" data, though no column NAME matched the sensitive list"
	}
	if contentOnly {
		// Say why it was rated lower, or the reader cannot tell a judgement
		// from a miss -- and cannot overrule it when the judgement is wrong.
		reason = "no column matched the sensitive list, and " +
			strings.Join(ContentColumns(rel.Columns), ", ") +
			" name presentation rather than people, so this reads as site content the " +
			"application publishes on purpose. Confirm that: if these rows are not meant " +
			"to be public, treat this as high."
	}
	return finding.Finding{
		ID:       "supabase-anon-read-exposed",
		Name:     name,
		Severity: sev,
		Protocol: "postgrest",
		Matched:  restURL(baseURL, rel.Name),
		Resource: rel.Qualified(),
		Description: fmt.Sprintf(
			"Anonymous SELECT returned %d rows from %q. Any holder of the public anon key can read this data.",
			rel.Rows, rel.Qualified()),
		FixKind:     finding.FixSQL,
		Remediation: readRemediation(rel.Qualified(), rel.Name),
		Reference: []string{
			"https://supabase.com/docs/guides/database/postgres/row-level-security",
		},
		Evidence: finding.Evidence{
			// The limit shown is the limit that was USED. Printing limit=3
			// after a -measure run would claim three rows had been retrieved
			// when none were, which is the one thing that mode exists to be
			// able to say -- and this repository has shipped evidence commands
			// that did not reproduce three times already.
			Request: fmt.Sprintf("curl -sS '%s?select=*&limit=%d' -H 'apikey: $SUPABASE_ANON_KEY'%s%s",
				restURL(baseURL, rel.Name), rel.evidenceLimit(), rel.profileHeader(),
				rel.countHeader()),
			Status:       rel.ReadStatus,
			Rows:         rel.Rows,
			Classes:      classesOf(rel),
			ModelClasses: rel.ModelClasses,
			Columns:      rel.Columns,
			Sample:       sample,
			Reason:       reason,
			Response:     jsonPreview(sample),
		},
	}
}

func writeFinding(baseURL string, rel Relation) finding.Finding {
	// Severity turns on whether the same role can also READ the relation.
	//
	// Writable AND readable is the compounding case: an attacker sees existing
	// rows, writes new ones, and reads back the effect. Writable but blind is a
	// genuine integrity problem and materially less dangerous, and it is also
	// the exact shape of a legitimate public submission form. Rating both
	// critical inflates the count on correctly built projects and teaches
	// operators to skim past criticals, which costs more than it gains.
	sev := finding.High
	blind := " Reads are closed, so this is a blind write: rows can be created " +
		"but not read back. That is also the shape of an intended public " +
		"submission form, so confirm whether it is deliberate."
	if rel.Read == postgrest.ReadExposed {
		sev = finding.Critical
		blind = " The same role can also read this relation, so an attacker can " +
			"see existing rows and read back whatever they write."
	}
	return finding.Finding{
		ID: "supabase-anon-insert-allowed",
		// Named for the verb actually tested. "accepts writes" reads as
		// INSERT, UPDATE and DELETE, and only INSERT was probed -- see the
		// description for why the other two are not, and are not guessed at.
		Name:     "Relation accepts INSERTs from the anonymous role",
		Severity: sev,
		Protocol: "postgrest",
		Matched:  restURL(baseURL, rel.Name),
		Resource: rel.Qualified(),
		Description: fmt.Sprintf(
			"An anonymous INSERT into %q passed row-level security and was rejected by the schema, "+
				"proving the security layer does not restrict INSERTs. Anyone with the public anon key "+
				"can create rows."+blind+" UPDATE and DELETE were NOT tested: a PATCH or DELETE "+
				"that matches no rows returns 204 whether or not the role is allowed to write, so "+
				"the obvious probe cannot tell the two apart and this scan does not run it. Check "+
				"those policies yourself -- a relation with no INSERT restriction frequently has no "+
				"UPDATE or DELETE restriction either.", rel.Qualified()),
		FixKind:     finding.FixSQL,
		Remediation: writeRemediation(rel.Qualified(), rel.Name),
		Reference: []string{
			"https://supabase.com/docs/guides/database/postgres/row-level-security",
		},
		Evidence: finding.Evidence{
			// Content-Type matters: without it curl sends
			// application/x-www-form-urlencoded and PostgREST reads the body
			// as a column list, answering PGRST204 "Could not find the '{}'
			// column". The command then fails to reproduce the finding it is
			// evidence for -- found by running every emitted evidence command
			// rather than reading them.
			Request: fmt.Sprintf("curl -sS -X POST '%s' -H 'apikey: $SUPABASE_ANON_KEY' "+
				"-H 'Content-Type: application/json'%s -d '{}'",
				restURL(baseURL, rel.Name), rel.profileHeader()),
			Status: rel.WriteStatus,
			Reason: rel.WriteWhy,
		},
	}
}

// readRemediation takes both names on purpose: %[1]s is the OBJECT, which must
// be schema-qualified or the statement hits whatever search_path resolves to,
// and %[2]s is the bare name used to build an identifier. A policy called
// "reporting.daily_revenue_owner_read" is legal but reads as a mistake.
func readRemediation(rel, bare string) string {
	return fmt.Sprintf(`-- Restrict %[1]s to the roles that need it.
-- 1. Enable row-level security (a table without it is fully readable):
ALTER TABLE %[1]s ENABLE ROW LEVEL SECURITY;

-- 2. If no anonymous access is intended, revoke the grant as well.
--    RLS alone still leaves the GRANT in place.
REVOKE ALL ON TABLE %[1]s FROM anon;

-- 3. Otherwise add an explicit, minimal policy, for example:
-- CREATE POLICY "%[2]s_owner_read" ON %[1]s
--   FOR SELECT TO authenticated USING (user_id = (select auth.uid()));`, rel, bare)
}

func writeRemediation(rel, bare string) string {
	return fmt.Sprintf(`-- %[1]s accepts anonymous INSERT. Close it:
ALTER TABLE %[1]s ENABLE ROW LEVEL SECURITY;
REVOKE INSERT, UPDATE, DELETE ON TABLE %[1]s FROM anon;

-- If public submission is intended, constrain it with WITH CHECK rather than
-- leaving the table open, e.g.:
-- CREATE POLICY "%[2]s_public_insert" ON %[1]s
--   FOR INSERT TO anon WITH CHECK (status = 'pending');`, rel, bare)
}

// verbFinding reports a proven UPDATE or DELETE by the anonymous role.
//
// DELETE outranks the other verbs at equal readability: a created row can be
// removed and a modified row can often be reconstructed, but a deleted row is
// gone, and an attacker who can empty a table needs no further access to do
// real damage.
func verbFinding(baseURL string, rel Relation, verb, why string) finding.Finding {
	sev := finding.High
	extra := " Reads are closed, so this is blind: rows can be " +
		map[string]string{"UPDATE": "altered", "DELETE": "destroyed"}[verb] +
		" without being read back first."
	if rel.Read == postgrest.ReadExposed {
		sev = finding.Critical
		extra = " The same role can also read this relation, so an attacker can pick " +
			"which rows to " + strings.ToLower(verb) + " and confirm the effect."
	}
	// Spelled out rather than assembled from the verb. The id coverage and
	// documentation checks read ids as string literals out of the source, so an
	// id built by concatenation is invisible to them: they saw only the common
	// prefix and reported an undocumented finding that no test names, while the
	// flag check read the trailing fragment as a command-line flag. An id that
	// the tooling cannot see is an id that can silently stop being emitted.
	//
	// The fragments are deliberately not quoted anywhere in this comment: those
	// same checks scan comments, and the first version of this note reproduced
	// the exact failure it describes.
	id := map[string]string{
		"UPDATE": "supabase-anon-update-allowed",
		"DELETE": "supabase-anon-delete-allowed",
	}[verb]
	return finding.Finding{
		ID:       id,
		Name:     "Relation accepts " + verb + "s from the anonymous role",
		Severity: sev,
		Protocol: "postgrest",
		Matched:  restURL(baseURL, rel.Name),
		Resource: rel.Qualified(),
		Description: fmt.Sprintf(
			"An anonymous %s against %q was admitted by row-level security. Anyone holding "+
				"the public anon key can %s rows in this table.%s Establishing this changed "+
				"nothing: %s",
			verb, rel.Qualified(), strings.ToLower(verb), extra, why),
		FixKind:     finding.FixSQL,
		Remediation: verbRemediation(rel.Qualified(), rel.Name, verb),
		Reference: []string{
			"https://supabase.com/docs/guides/database/postgres/row-level-security",
		},
		Evidence: finding.Evidence{
			Request: fmt.Sprintf("curl -sS -i -X %s '%s?<key>=eq.<value>' "+
				"-H 'apikey: $SUPABASE_ANON_KEY' -H 'Prefer: count=exact'%s",
				verb, restURL(baseURL, rel.Name), rel.profileHeader()),
			// No Status here, deliberately. This command is a TEMPLATE -- the
			// key and value are placeholders, because which row the probe
			// touched is its own business and printing the value would put a
			// row of somebody's data in the report. A template cannot
			// reproduce, so it must not claim a status it cannot produce:
			// stating 204 next to a command that answers 405 tells the reader
			// the tool is wrong about something it is right about.
			Reason: why,
		},
	}
}

func verbRemediation(rel, bare, verb string) string {
	return fmt.Sprintf(`-- %[1]s accepts anonymous %[3]s. Close it:
ALTER TABLE %[1]s ENABLE ROW LEVEL SECURITY;
REVOKE %[3]s ON TABLE %[1]s FROM anon;

-- A policy written FOR ALL grants all four verbs at once, which is the usual
-- cause. Grant only what the application needs:
-- DROP POLICY IF EXISTS "%[2]s_all" ON %[1]s;
-- CREATE POLICY "%[2]s_read" ON %[1]s FOR SELECT TO anon USING (true);

-- Check which verbs are currently open:
-- SELECT polname, polcmd FROM pg_policy WHERE polrelid = '%[1]s'::regclass;`, rel, bare, verb)
}

func jsonPreview(rows []map[string]any) string {
	if len(rows) == 0 {
		return ""
	}
	b, err := json.Marshal(rows[0])
	if err != nil {
		return ""
	}
	s := string(b)
	if len(s) > 400 {
		s = s[:400] + "…"
	}
	return s
}

// Trigger causes exactly one row-level change on a relation, for the Realtime
// delivery probe, and reports whether the write actually landed.
//
// It reuses the INSERT probe rather than issuing a bespoke write, which keeps
// one promise in one place: the probe cleans up any row it creates, and the
// two-phase logic that stops a RETURNING artifact from being read as an RLS
// denial applies here too. Callers must gate this on -write; nothing in this
// function checks consent, because consent is not a property of a relation.
func Trigger(ctx context.Context, c *client.Client, name string) bool {
	state, _, _, _, _, _ := insertProbe(ctx, c, name, nil, 0, residueCleanable)
	return state == postgrest.WriteReached
}

// evidenceLimit is the row limit the read probe used: 0 under -measure, where
// PostgREST returns the count in Content-Range and an empty body.
func (r Relation) evidenceLimit() int {
	if r.measured {
		return 0
	}
	return 3
}

// countHeader adds the Prefer header that makes limit=0 useful, so the command
// in the report reproduces the COUNT rather than returning a bare [].
// countHeader publishes the header the read actually carried.
//
// The probe sends Prefer: count=exact on EVERY read -- the count comes from
// Content-Range and is what tells an exposed relation from an empty one. This
// used to publish the header only under -measure, so an ordinary run printed a
// command missing it: PostgREST answers 206 to the request the scanner made and
// 200 to the one it printed. Found by replaying the published commands rather
// than by reading them, which is how the previous three drifts were found.
//
// -D - stays conditional: dumping headers is how a -measure run shows the
// Content-Range it counted from, and is noise otherwise.
func (r Relation) countHeader() string {
	if !r.measured {
		return " -H 'Prefer: count=exact'"
	}
	return " -H 'Prefer: count=exact' -D -"
}

// ColumnBudgetFinding reports that sensitive-column probing was truncated.
//
// Severity in a measurement scan depends on knowing column names, so a
// relation the budget could not reach is reported at the severity of a table
// whose contents are unknown -- which is lower than it may deserve. Every
// other budget here says so when it binds; this one does too.
func ColumnBudgetFinding(restBase string, used, limit, unprobed int) finding.Finding {
	return finding.Finding{
		ID:       "unruly-probe-budget-exhausted",
		Name:     "Sensitive-column probing stopped at the budget",
		Severity: finding.Info,
		Protocol: "postgrest",
		Matched:  restBase,
		Resource: "sensitive-columns",
		Description: fmt.Sprintf(
			"Sensitive-column probing used its allowance of %d requests (-max-column-probes) "+
				"before every exposed relation had been checked. Severity for the relations "+
				"it did not reach is a LOWER BOUND: a table holding access tokens is reported "+
				"the same as a table of blog posts when nobody asked which columns it has.",
			limit),
		FixKind: finding.FixSQL,
		Remediation: "-- Re-run with a larger -max-column-probes to classify the remaining " +
			"relations. Each relation costs one request per candidate column name.",
		Evidence: finding.Evidence{
			// The count of relations left unclassified, not just probes spent.
			//
			// "0 of 1 column probes used" is literally true when the budget was
			// too small to cover even one relation -- the probe is all-or-
			// nothing per relation -- and it reads like nothing was truncated,
			// which is the one direction a coverage notice must never read in.
			Reason: fmt.Sprintf("%d relation(s) left unclassified; %d of %d column "+
				"probes used", unprobed, used, limit),
		},
	}
}

// discriminates reports whether the target's answers depend on which relation
// was asked for.
func discriminates(control Relation, sampled []Relation) bool {
	// A clean "not there" for a name that cannot exist IS the endpoint
	// demonstrating it can report absence. Everything else it says can then be
	// taken at face value, including a schema where every candidate is also
	// absent -- an informative answer, not a blind one.
	if control.Read == postgrest.ReadNotFound {
		return true
	}
	// Otherwise a COMPARISON, never a test for a particular status. A proxy
	// that destroys PostgREST's error semantics still answers differently for
	// different relations, and corpus project 07 is probed to 75% recall
	// precisely because of that.
	for _, r := range sampled {
		if r.Read != control.Read {
			return true
		}
	}
	return len(sampled) == 0
}
