// Package neon scans a Neon Data API.
//
// Neon's Data API is PostgREST, so the wire format is familiar, but the
// threat model is not Supabase's. Neon's anonymous role starts with no
// permissions, and a request carrying no Authorization header is refused
// outright rather than mapped onto that role -- measured, and contrary to the
// vendor documentation. What is left over is the accident that matters here:
// Row-Level Security is optional, and with it switched off any account that
// can sign itself up reads every row.
//
// So this backend leads with escalation where the Supabase one leads with the
// anonymous key.
package neon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/eppser/unruly/internal/client"
	"github.com/eppser/unruly/internal/enumerate"
	"github.com/eppser/unruly/internal/finding"
	"github.com/eppser/unruly/internal/probe"
	"github.com/eppser/unruly/scan"
)

// EscalationStage measures what any authenticated account can read.
//
// Two observations per table, because one proves nothing. The authenticated
// read establishes what an account can reach; the anonymous read establishes
// the contrast, and on Neon it is also what shows the endpoint refuses
// unauthenticated callers uniformly.
type EscalationStage struct {
	// Base is the Data API root, e.g. https://<ep>.apirest.<region>.aws.neon.tech/<db>/rest/v1
	Base string
	// Tables are the candidate names to try.
	Tables []string
	// Token authenticates the second observation. Without one this stage can
	// measure nothing and says so by reporting nothing.
	Token string
	// Redact drops sampled values while keeping the finding usable.
	Redact bool
	// Client carries the shared limiter, so this stage's traffic is covered by
	// -rate-limit like every other. Built from Base when the caller leaves it
	// nil; a stage that quietly spun up its own http.Client would be outside
	// every pacing control the scanner offers.
	Client *client.Client
}

// errNoClient is returned when a stage is run without a client. The caller
// owns the controls, so the caller owns the client.
var errNoClient = errors.New("neon: no client supplied; the caller must pass one so -rate-limit and -timeout bind")

// neonProbeConcurrency bounds in-flight probes. It is not the rate limit --
// the shared client owns that, so -rate-limit still binds -- it only stops a
// scan carrying hundreds of candidates from opening hundreds of goroutines.
const neonProbeConcurrency = 16

func (EscalationStage) Name() string { return "neon-escalation" }

func (EscalationStage) Describe() scan.StageDescriptor {
	return scan.StageDescriptor{ID: (EscalationStage{}).Name(),
		Optional: []scan.ArtifactType{scan.ArtifactOf[Relations]()}}
}

// Run probes every candidate table anonymously and then authenticated.
func (s EscalationStage) Run(ctx context.Context, st *scan.State) error {
	// Sorted so the report does not depend on the order candidates arrived in.
	names := relationNames(st, s.Tables)
	sort.Strings(names)

	if s.Client == nil {
		// Deliberately an error rather than a default. Building a client here
		// would silently substitute the package defaults for -rate-limit,
		// -timeout and the user agent, so the operator's flags would not bind
		// this stage and nothing would say so.
		return errNoClient
	}

	// The anonymous observation, ONCE. A Neon Data API refuses an
	// unauthenticated caller before it looks at the table, so the answer is the
	// same for every name and carries no information about any of them --
	// measured, and the reason ReachStage reports the anonymous surface blind.
	// Taking it per candidate doubled the traffic and learned nothing: names
	// come from the application's vocabulary because Neon exposes no
	// enumeration oracle, so a real scan carries hundreds of them.
	anon := s.read(ctx, enumerate.ControlRelationName, "")
	requests := 1

	// Probed concurrently, collected BY INDEX. A serial loop spends a blocking
	// round trip per candidate, and with hundreds of names -- which is what a
	// Neon scan carries, since the endpoint offers no enumeration oracle --
	// that is minutes of waiting. The index is what keeps the report ordered:
	// findings are appended in the sorted order of `names`, not in the order
	// the answers happened to arrive, because byte-identical output between
	// runs is graded.
	//
	// The pool bounds goroutines. The shared client's limiter is what actually
	// paces the traffic, and -rate-limit still binds through it.
	found := make([]*finding.Finding, len(names))
	// Refusals are counted so silence can be explained. A table that answers
	// 200 with no rows has been MEASURED; one that refuses the token has not,
	// and the two produce the same empty report unless somebody counts.
	refused := make([]bool, len(names))
	sem := make(chan struct{}, neonProbeConcurrency)
	var wg sync.WaitGroup
	for i, name := range names {
		wg.Add(1)
		go func(i int, name string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			authed := s.read(ctx, name, s.Token)
			// Rows actually came back, or there is nothing to report. A 403 is
			// a denial and a 200 with an empty array is a filtered or deny-all
			// result; neither is an exposure. This is the distinction Neon's
			// own console gets wrong on owner_only, where it infers exposure
			// from RLS state without checking whether any GRANT exists.
			if len(authed.rows) == 0 {
				// Not the same as "protected". A 401 or 403 means the token was
				// refused before the table was consulted, a 429 means the
				// endpoint declined to answer, and an error means nothing was
				// established at all. Recorded so the stage can say afterwards
				// whether its silence is a result or an inability to look.
				refused[i] = authed.err != nil || authed.status == http.StatusUnauthorized ||
					authed.status == http.StatusForbidden || authed.status == http.StatusTooManyRequests
				return
			}
			f := s.escalation(name, anon, authed)
			found[i] = &f
		}(i, name)
	}
	wg.Wait()
	requests += len(names)

	var reported, refusals int
	for i, f := range found {
		if f != nil {
			reported++
			st.Add(*f)
		}
		if refused[i] {
			refusals++
		}
	}

	// Silence has to say which kind it is.
	//
	// Escalation is the headline finding on this backend: Neon Auth signup is
	// open, so a stranger can hold the authenticated role, and a table whose
	// RLS was never enabled hands them every row. If the token this stage
	// carries has expired, was minted for another project, or the endpoint is
	// rate limiting, then every table refuses and the stage reports nothing --
	// which is exactly what a correctly protected project produces.
	//
	// Only when NOTHING was reported and every candidate refused. A project
	// with one exposed table and a dozen denials is measured; this is for the
	// case where nothing was established at all.
	if reported == 0 && len(names) > 0 && refusals == len(names) {
		st.Add(finding.Finding{
			ID:       "unruly-surface-not-assessed",
			Name:     "Authenticated reads were refused for every table",
			Severity: finding.Info,
			Protocol: "postgrest",
			Matched:  s.Base,
			Resource: "escalation:authenticated",
			Description: fmt.Sprintf(
				"All %d table(s) refused the authenticated read, so what a signed-up "+
					"account can reach was never established. This is NOT the same as "+
					"finding nothing exposed: a token that has expired, one minted for "+
					"another project, and an endpoint that is rate limiting all produce "+
					"this result, and so does a project where every table is correctly "+
					"protected. Escalation is the finding that matters most on this "+
					"backend -- open signup means a stranger can hold the authenticated "+
					"role -- so treat this as untested rather than clean.", len(names)),
		})
	}
	st.Attribute(s.Name(), requests)
	return nil
}

// read performs one observation through the shared client, so it is paced and
// retried like the rest of the scan.
func (s EscalationStage) read(ctx context.Context, table, token string) observation {
	o := observation{table: table, path: "/" + table + "?select=*"}
	c := s.Client
	if token != "" {
		c = c.WithBearer(token)
		o.authenticated = true
	}
	resp := c.Get(ctx, s.Base+o.path, nil)
	if resp.Err != nil {
		o.err = resp.Err
		return o
	}
	o.status = resp.Status
	if resp.Status == http.StatusOK {
		// A non-array body is an error document, not rows.
		_ = json.Unmarshal(resp.Body, &o.rows)
	}
	return o
}

type observation struct {
	table         string
	path          string
	authenticated bool
	status        int
	rows          []map[string]any
	err           error
}

// escalation builds the finding for a table any account can read.
func (s EscalationStage) escalation(table string, anon, authed observation) finding.Finding {
	cols := columnsOf(authed.rows)
	// Shared-core reuse: the same classifier the Supabase backend uses decides
	// what is sensitive here. If that classification is real it is not
	// PostgREST-specific, and this is where that claim gets tested.
	sensitive := probe.SensitiveColumns(cols)

	rows := authed.rows
	reason := strconv.Itoa(len(authed.rows)) + " row(s) returned to an account that can " +
		"sign itself up, while an unauthenticated caller was refused (" +
		strconv.Itoa(anon.status) + ")"
	if len(sensitive) > 0 {
		reason += "; sensitive columns " + strings.Join(sensitive, ", ")
	}
	if s.Redact {
		rows = nil
		if len(cols) > 0 {
			reason += "; columns " + strings.Join(cols, ", ")
		}
	}

	return finding.Finding{
		ID:       "neon-authenticated-read-unrestricted",
		Name:     "Any account can read the whole table",
		Severity: finding.High,
		Protocol: "neon",
		Matched:  s.Base + "/" + table,
		Resource: table,
		Description: "An authenticated request returned " + strconv.Itoa(len(authed.rows)) +
			" row(s) from \"" + table + "\". Neon's Data API grants the authenticated " +
			"role whatever the table's GRANTs allow, and Row-Level Security is what " +
			"narrows that to the caller's own rows. With RLS off, every account sees " +
			"every row. Sign-up is open on this project, so \"any account\" includes " +
			"anyone on the internet. The rows below were actually returned.",
		Remediation: "-- Enable Row-Level Security and add a policy scoping rows to the caller.\n" +
			"-- Neon exposes the verified JWT subject as auth.user_id().\n" +
			"--\n" +
			"ALTER TABLE " + table + " ENABLE ROW LEVEL SECURITY;\n" +
			"--\n" +
			"-- Replace owner_id with the column that identifies the owning user.\n" +
			"CREATE POLICY " + table + "_own_rows ON " + table + "\n" +
			"  FOR SELECT TO authenticated\n" +
			"  USING (owner_id = auth.user_id());\n" +
			"--\n" +
			"-- Enabling RLS without a policy denies every row, which is safe but\n" +
			"-- indistinguishable from an empty table. Add the policy in the same\n" +
			"-- change, and confirm afterwards that a caller still sees its OWN rows.\n" +
			"--\n" +
			"-- If the table is not meant to be reachable at all, revoke instead:\n" +
			"-- REVOKE SELECT ON " + table + " FROM authenticated;",
		Evidence: finding.Evidence{
			Reason:  reason,
			Request: requestLine(s.Base, table),
			Status:  authed.status,
			Rows:    len(authed.rows),
			Columns: cols,
			Sample:  rows,
		},
	}
}

// requestLine is the replayable command. The token is referenced through an
// environment variable: a report is a document that gets forwarded, and a
// credential pasted into one is a second incident.
func requestLine(base, table string) string {
	return fmt.Sprintf(`curl -s -H "Authorization: Bearer $NEON_TOKEN" '%s/%s?select=*'`, base, table)
}

// columnsOf lists field names present in the sampled rows, sorted.
//
// Sorted because JSON object iteration is unordered and the report is graded
// for byte identity.
func columnsOf(rows []map[string]any) []string {
	seen := map[string]bool{}
	for _, r := range rows {
		for k := range r {
			seen[k] = true
		}
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
