// Package escalate measures what a second role can read that the first cannot.
//
// Scanning only as `anon` understates exposure whenever public signup is open.
// Anyone can then mint an `authenticated` JWT, so a policy written
// `TO authenticated USING (true)` is effectively public — yet an anon-only scan
// reports the relation as protected, because anon genuinely cannot read it.
// That is a false negative with a clean bill of health attached, which is the
// failure mode this project exists to eliminate.
//
// The measurement is a diff, and the diff is what makes it sound. A relation is
// only reported when the second role reads rows the first cannot. A correctly
// scoped policy — one that restricts authenticated users to their own rows —
// yields nothing for either role and is not reported, so "scoped by owner" and
// "open to any logged-in user" are distinguished rather than lumped together.
//
// Obtaining the second credential is separate from using it. Supplying one is
// inert; minting one via signup creates an account, which is a mutation, so it
// is gated behind explicit authorisation and always reported for cleanup.
package escalate

import (
	"context"
	"fmt"
	"sort"

	"strings"

	"github.com/eppser/unruly/internal/classify"
	"github.com/eppser/unruly/internal/client"
	"github.com/eppser/unruly/internal/creds"
	"github.com/eppser/unruly/internal/finding"
	"github.com/eppser/unruly/internal/postgrest"
	"github.com/eppser/unruly/internal/probe"
)

// Gain is one relation the elevated role can read and the base role cannot.
type Gain struct {
	Relation string
	Rows     int
	Columns  []string
	Sample   []map[string]any
}

// Result is the outcome of an escalation comparison.
type Result struct {
	// Role is the role claimed by the elevated credential.
	Role string
	// Gains are relations newly readable, sorted by name.
	Gains []Gain
	// Account is set when unruly created one, so it can be removed.
	Account  string
	Findings []finding.Finding
	Requests int
}

// GainedRelations lists newly readable relation names, sorted.
func (r Result) GainedRelations() []string {
	out := make([]string, 0, len(r.Gains))
	for _, g := range r.Gains {
		out = append(out, g.Relation)
	}
	sort.Strings(out)
	return out
}

// Options configures the comparison.
type Options struct {
	// Relations to re-read as the elevated role.
	Relations []string
	// ElevatedKey is the second credential. Required.
	ElevatedKey string
	Concurrency int
	SampleRows  int
	Redact      bool
	// Measure establishes exposure without transferring any data, and must be
	// inherited here or the flag is a promise the tool breaks the moment a
	// -user-jwt is supplied: the compare re-reads every relation, so it is a
	// data-transferring path exactly like the base probe.
	Measure bool
	// Schema qualifies the relation in findings and in the SQL they carry.
	// Without it the fix says CREATE POLICY ... ON member_invoices for a table
	// in another schema, which resolves against search_path and either errors
	// or targets a different table entirely.
	Schema string
}

// Compare re-reads relations with an elevated credential and reports the delta
// against a base scan. It issues only reads, so it is non-destructive.
func Compare(ctx context.Context, base *client.Client, baseResult probe.Result, o Options) Result {
	res := Result{Role: JWTRole(o.ElevatedKey)}
	if o.ElevatedKey == "" || len(o.Relations) == 0 {
		return res
	}
	if o.SampleRows <= 0 {
		o.SampleRows = 3
	}

	elevated := base.WithBearer(o.ElevatedKey)
	pr := probe.Run(ctx, elevated, o.Relations, probe.Options{
		SampleRows:  o.SampleRows,
		Concurrency: o.Concurrency,
		Measure:     o.Measure,
	})
	res.Requests = pr.Requests

	// What the base role could already read is not a gain.
	baseReadable := map[string]bool{}
	for _, rel := range baseResult.Relations {
		if rel.Read == postgrest.ReadExposed {
			baseReadable[rel.Name] = true
		}
	}

	for _, rel := range pr.Relations {
		if rel.Read != postgrest.ReadExposed || baseReadable[rel.Name] {
			continue
		}
		g := Gain{Relation: rel.Name, Rows: rel.Rows, Columns: rel.Columns}
		if !o.Redact {
			g.Sample = rel.Sample
		}
		res.Gains = append(res.Gains, g)
	}
	sort.Slice(res.Gains, func(i, j int) bool { return res.Gains[i].Relation < res.Gains[j].Relation })

	for _, g := range res.Gains {
		res.Findings = append(res.Findings, gainFinding(elevated, res.Role, g, o.Schema))
	}
	finding.Sort(res.Findings)
	res.Findings = finding.Dedup(res.Findings)
	return res
}

// profileHeader is the curl fragment reaching a non-default schema.
func profileHeader(schema string) string {
	if schema == "" {
		return ""
	}
	return " -H 'Accept-Profile: " + schema + "'"
}

func gainFinding(c *client.Client, role string, g Gain, schema string) finding.Finding {
	qualified, bare := g.Relation, g.Relation
	if schema != "" {
		qualified = schema + "." + g.Relation
	}
	sev := finding.High
	// Both questions, exactly as the anonymous path asks them: what are the
	// columns called, and what is in them. Only the first was asked here, so a
	// gain holding card numbers under columns named in any language but
	// English read as high -- the same blind spot fixed one layer down, still
	// open one layer up.
	//
	// A logged-in user is not a smaller audience than the public. Where signup
	// is open, and it is by default, the set of logged-in users is everyone
	// willing to spend one HTTP request.
	sensitive := classify.Names(g.Columns)
	kinds := classify.Kinds(g.Sample)
	if len(sensitive) > 0 || len(kinds) > 0 {
		sev = finding.Critical
	}
	reason := fmt.Sprintf("readable as %s, not as anon", role)
	if len(sensitive) > 0 {
		reason = fmt.Sprintf("%s; %v", reason, sensitive)
	} else if len(kinds) > 0 {
		// Kinds, never values.
		reason = fmt.Sprintf("%s; sampled rows contain %s data", reason,
			strings.Join(kinds, ", "))
	}
	return finding.Finding{
		ID:       "supabase-authenticated-escalation",
		Name:     "Relation readable by any logged-in user",
		Severity: sev,
		Protocol: "postgrest",
		Matched:  c.RestURL(g.Relation),
		Resource: qualified,
		Description: fmt.Sprintf(
			"%q returned %d rows to the %s role but none to anon. Where public signup is "+
				"enabled, anyone can obtain that role, so this data is effectively public "+
				"while an anonymous scan reports the relation as protected. The policy grants "+
				"access to the ROLE rather than to the owning user.",
			qualified, g.Rows, role),
		Remediation: fmt.Sprintf(`-- Scope the policy to the owning user rather than the role:
DROP POLICY IF EXISTS "<policy_name>" ON %[1]s;

CREATE POLICY "%[2]s_own_rows" ON %[1]s
  FOR SELECT TO authenticated
  USING (user_id = (select auth.uid()));

-- Find every policy that trusts any authenticated user:
-- SELECT tablename, policyname, cmd, qual FROM pg_policies
-- WHERE 'authenticated' = ANY (roles) AND qual = 'true';`, qualified, bare),
		Evidence: finding.Evidence{
			// The URL takes the BARE name; PostgREST reads the schema from a
			// header, so a qualified path is a 404.
			Request: fmt.Sprintf("curl -sS '%s?select=*&limit=3' -H 'apikey: $ANON_KEY' "+
				"-H 'Authorization: Bearer $USER_JWT'%s",
				c.RestURL(g.Relation), profileHeader(schema)),
			Rows:    g.Rows,
			Columns: g.Columns,
			Sample:  g.Sample,
			Reason:  reason,
		},
	}
}

// JWTProjectRef reads the `ref` claim, which names the project a Supabase key
// was issued for. Comparing it against the target catches a key pasted from
// the wrong project before a single request is sent — a typo should not cost
// somebody else's project 2684 requests.
//
// Returns "" when there is no such claim, which is normal for self-hosted
// deployments and for the newer sb_publishable_ format.
// JWTProjectRef names the project a managed key belongs to, empty if absent.
func JWTProjectRef(tok string) string { return creds.JWTProjectRef(tok) }

// JWTRole reads the role claim without verifying the signature: we only need
// to know what the token claims to be.
// JWTRole reports the claimed role, or "unknown" when the token cannot be
// read. The distinction matters to callers: "unknown" is not "anon".
//
// The decoding itself lives in internal/creds; this keeps the sentinel its
// callers were written against.
func JWTRole(tok string) string {
	if r := creds.JWTRole(tok); r != "" {
		return r
	}
	return "unknown"
}
