package neon

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"sync"

	"github.com/eppser/unruly/internal/client"
	"github.com/eppser/unruly/internal/finding"
	"github.com/eppser/unruly/scan"
)

// WriteStage measures which tables accept an INSERT.
//
// Opt-in, and the opt-in is enforced before anything is built rather than
// before anything is reported: a probe whose result is discarded has still
// written a row into somebody's database. With no consent this stage sends
// nothing at all and says so.
//
// What it sends is one row per candidate, with a marker value, and it does not
// remove it. Deleting would need DELETE to be permitted, which is a different
// permission and often is not -- a stage that assumed otherwise would leave
// rows behind while reporting that it had cleaned up. The finding names the
// marker so an operator can find what this scan created.
type WriteStage struct {
	// Base is the Data API root.
	Base string
	// Tables are the candidates to try.
	Tables []string
	// Token authenticates the attempt. Neon refuses an unauthenticated caller
	// before looking at the table, so there is no anonymous tier to measure.
	Token string
	// Consent is the operator's -write -yes-i-own-this.
	Consent bool
	// Client carries the shared limiter.
	Client *client.Client
}

func (WriteStage) Name() string { return "neon-write" }

func (s WriteStage) Describe() scan.StageDescriptor {
	return scan.StageDescriptor{ID: s.Name(), MutatesTarget: s.Consent,
		Optional: []scan.ArtifactType{scan.ArtifactOf[Relations]()}}
}

// WriteProbeMarker is the value written, constant so a report names something
// an operator can search for and so repeated scans stay byte-identical.
const WriteProbeMarker = "unruly_write_probe"

func (s WriteStage) Run(ctx context.Context, st *scan.State) error {
	if s.Client == nil {
		return errNoClient
	}
	if !s.Consent {
		st.Add(finding.NotAssessedStage(s.Base, "write",
			"measuring which tables accept a write requires PERFORMING one, which adds a "+
				"row to the target; re-run with -write -yes-i-own-this. Nothing was sent. "+
				"A table that refuses reads can still accept writes, so this tier is not "+
				"implied by the read result above"))
		return nil
	}

	names := relationNames(st, s.Tables)
	sort.Strings(names)

	// Concurrent and collected BY INDEX, for the reasons the read path is:
	// a serial loop over hundreds of candidates is minutes of waiting, and the
	// order answers arrive in is not an order a report may depend on.
	//
	// It matters more here rather than less. This stage only runs when an
	// operator consented, which means they are waiting for it.
	found := make([]*finding.Finding, len(names))
	// Counted so silence can be explained: a token nobody accepted produces
	// the same empty report as a project where every table refuses the write.
	refused := make([]bool, len(names))
	sem := make(chan struct{}, neonProbeConcurrency)
	var wg sync.WaitGroup
	for i, name := range names {
		wg.Add(1)
		go func(i int, name string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			c := s.Client
			if s.Token != "" {
				c = c.WithBearer(s.Token)
			}
			// An EMPTY object, because this scanner cannot know a column name
			// and must not invent one. The previous payload named `body`,
			// which exists in the reference lab's open_guestbook and in
			// nothing else: every other table answered 400 PGRST204 `column
			// "body" does not exist`, which is not 201, so the stage reported
			// nothing and the write tier went unmeasured on five of six tables
			// while reading like a clean result.
			//
			// {} needs no schema knowledge. PostgREST hands it to Postgres and
			// the privilege check runs before any column is considered, so the
			// answer is about permission rather than about the guess.
			resp := c.Do(ctx, http.MethodPost, s.Base+"/"+name, []byte(writeProbePayload),
				map[string]string{
					"Content-Type": "application/json",
					// Ask for the stored row. Without it PostgREST answers 201
					// with an empty body, and a finding that cannot name the
					// row it created cannot offer a statement that removes it.
					"Prefer": "return=representation",
				})
			if resp.Err != nil {
				refused[i] = true
				return
			}
			switch {
			case resp.Status == http.StatusCreated:
				// Accepted, and a row now exists. Reported as such, naming it.
				f := s.accepted(name, resp.Status, rowIdentity(resp.Body))
				found[i] = &f
			case isConstraintViolation(resp.Body):
				// The strongest result this probe can get. 23502 and 23505 are
				// raised by the TABLE after the security layer admitted the
				// insert, so the write is permitted and nothing was stored --
				// proof without residue. The same discriminator the Supabase
				// side already uses, and the reason it is sound is that 42501
				// is decided before any constraint is reached.
				f := s.acceptedByConstraint(name, resp.Status, constraintCode(resp.Body))
				found[i] = &f
			case resp.Status == http.StatusUnauthorized,
				resp.Status == http.StatusTooManyRequests:
				// The token was refused, or the endpoint declined to answer.
				// Neither says anything about whether the write is allowed.
				refused[i] = true
			}
		}(i, name)
	}
	wg.Wait()

	for _, f := range found {
		if f != nil {
			st.Add(*f)
		}
	}
	st.Attribute(s.Name(), len(names))
	return nil
}

func (s WriteStage) accepted(table string, status int, row rowRef) finding.Finding {
	return finding.Finding{
		ID:       "neon-authenticated-write-allowed",
		Name:     "Any account can add rows to the table",
		Severity: finding.High,
		Protocol: "neon",
		Matched:  s.Base + "/" + table,
		Resource: table,
		Description: "An authenticated request added a row to \"" + table + "\" and the " +
			"API accepted it (HTTP " + strconv.Itoa(status) + "). Neon grants the " +
			"authenticated role whatever the table's GRANTs allow, and Row-Level Security " +
			"is what narrows an INSERT to rows the caller may create. Sign-up is open on " +
			"projects configured this way, so \"any account\" includes anyone on the " +
			"internet. " + row.sentence,
		Remediation: "-- Enable Row-Level Security and add a policy that constrains what a\n" +
			"-- caller may create. Neon exposes the verified JWT subject as auth.user_id().\n" +
			"--\n" +
			"ALTER TABLE " + table + " ENABLE ROW LEVEL SECURITY;\n" +
			"--\n" +
			"-- Replace owner_id with the column that identifies the owning user.\n" +
			"CREATE POLICY " + table + "_own_inserts ON " + table + "\n" +
			"  FOR INSERT TO authenticated\n" +
			"  WITH CHECK (owner_id = auth.user_id());\n" +
			"--\n" +
			"-- WITH CHECK constrains rows going IN; USING constrains rows coming out.\n" +
			"-- A policy with only USING leaves INSERT unconstrained, which is this\n" +
			"-- finding arriving by a different route.\n" +
			"--\n" +
			"-- If the table should not be writable at all:\n" +
			"-- REVOKE INSERT ON " + table + " FROM authenticated;\n" +
			"--\n" +
			row.cleanup(table),
		Evidence: finding.Evidence{
			Reason: "HTTP " + strconv.Itoa(status) + ": the row was accepted, so the " +
				"permission is real rather than inferred",
			// The request as SENT, including the Prefer header. A replayable
			// request that replays something else is not evidence, and this
			// one quietly stopped matching when the payload changed.
			Request: `curl -s -X POST -H "Authorization: Bearer $NEON_TOKEN" ` +
				`-H 'Content-Type: application/json' ` +
				`-H 'Prefer: return=representation' ` +
				`-d '` + writeProbePayload + `' '` + s.Base + "/" + table + `'`,
			Status: status,
		},
	}
}

// writeProbePayload is what the probe sends: an empty object, naming no column.
//
// Named rather than inlined so the committed transcript can be checked against
// it. A recording that answers a payload the scanner no longer sends is a
// hand-written stub wearing a recording's provenance, which is the one thing
// internal/transcript exists to prevent.
const writeProbePayload = `{}`

// isConstraintViolation reports whether the body carries a Postgres error
// raised by the table rather than by the privilege system.
//
// 23502 is a NOT NULL violation and 23505 a unique violation. Both mean the
// statement got past the security layer -- 42501 is decided first, and never
// reaches a constraint -- so they establish that the write is permitted while
// leaving nothing behind.
func isConstraintViolation(body []byte) bool {
	switch constraintCode(body) {
	case "23502", "23505":
		return true
	}
	return false
}

// constraintCode extracts PostgREST's SQLSTATE, or "".
func constraintCode(body []byte) string {
	var e struct {
		Code string `json:"code"`
	}
	if json.Unmarshal(body, &e) != nil {
		return ""
	}
	return e.Code
}

// acceptedByConstraint reports a write the table admitted and a column refused.
func (s WriteStage) acceptedByConstraint(table string, status int, code string) finding.Finding {
	f := s.accepted(table, status, rowRef{
		sentence: "NO row was created: the statement was admitted and then rejected by a " +
			"column constraint, so there is nothing to clean up.",
	})
	f.Description = "An authenticated INSERT into " + table + " was ADMITTED by the security " +
		"layer and stopped by a column constraint (SQLSTATE " + code + ", HTTP " +
		itoa(status) + "). That distinction is the evidence: 42501 is decided before any " +
		"constraint is reached, so a constraint error can only be raised on a statement " +
		"that was already allowed to run. The write is permitted and NO row was created, " +
		"which is why this probe sends an empty object rather than inventing a column: " +
		"the strongest result it can get is also the one that leaves nothing behind."
	return f
}

func itoa(n int) string { return strconv.Itoa(n) }

// A rowRef is what the server said it stored, if anything.
//
// The probe sends an empty object, so a created row carries defaults and no
// marker. Its identity therefore has to come from the server, which is why the
// insert asks for the representation back: without it the finding can say a row
// exists and cannot say which, and remediation that cannot name a row cannot
// remove one.
type rowRef struct {
	sentence string
	pk       string // "id = 42", or empty when unknown
}

func (r rowRef) cleanup(table string) string {
	if r.pk == "" {
		return "--\n-- This scan created no row to remove."
	}
	return "--\n" +
		"-- Then remove the row this scan created. The probe sends an empty object,\n" +
		"-- so the row carries defaults and is identified by the key the server\n" +
		"-- returned rather than by any value the scan chose:\n" +
		"-- DELETE FROM " + table + " WHERE " + r.pk + ";"
}

// rowIdentity reads the created row out of a return=representation body.
func rowIdentity(body []byte) rowRef {
	var rows []map[string]any
	if json.Unmarshal(body, &rows) != nil || len(rows) == 0 {
		return rowRef{sentence: "A row was created and the server returned nothing to " +
			"identify it, so this scan cannot tell you which row to remove. It is the " +
			"most recent in the table."}
	}
	for _, k := range []string{"id", "uuid", "pk"} {
		if v, ok := rows[0][k]; ok {
			pk := fmt.Sprintf("%s = %v", k, v)
			if _, isString := v.(string); isString {
				pk = fmt.Sprintf("%s = '%v'", k, v)
			}
			return rowRef{
				pk: pk,
				sentence: fmt.Sprintf("The row is still there -- the server returned it, "+
					"and it is the one where %s. This scan did not remove it, because "+
					"deleting needs a permission the write does not imply.", pk),
			}
		}
	}
	return rowRef{sentence: "A row was created; the server returned it but it carries no " +
		"column this scan recognises as a key, so the row cannot be named here."}
}
