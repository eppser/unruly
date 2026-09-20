package eval_test

// The commented-out half of every remediation.
//
// Each fix this tool emits has two parts. The uncommented statements are the
// blunt close -- enable RLS, revoke the grant -- and TestRemediationCloses-
// TheFindings already runs those and rescans. The commented lines are the
// worked example an operator uncomments when they want to keep some access:
//
//   -- CREATE POLICY "x_owner_read" ON x
//   --   FOR SELECT TO authenticated USING (user_id = (select auth.uid()));
//
// Nothing had ever executed those. They are the lines most likely to be run by
// hand against production, by someone who trusts the tool that printed them,
// and a syntax error or a wrong function signature would surface there.
//
// The templates are extracted from the tool's own output rather than copied
// into this file. A test built from a copy validates the copy.
//
//   make fixtures-reset && UNRULY_LIVE=1 go test ./internal/eval -run RemediationTemplates -v

import (
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/eppser/unruly/internal/postgrest"
	"github.com/eppser/unruly/internal/probe"
	"github.com/eppser/unruly/internal/realtime"
)

// scratchRelation is a table created inside the test transaction carrying the
// columns the worked examples refer to. The examples name user_id and status
// illustratively; giving the scratch table those columns tests what can
// actually be wrong -- syntax, function signatures, clause order -- without
// pretending the column names are prescriptive.
const scratchRelation = "remediation_scratch"

// platformShim creates the objects a managed Supabase project provides and a
// bare PostgREST fixture does not. Inside the transaction, so the lab
// fixture's answer key is untouched: a new table here would be discovered by
// the next scan and fail every recall eval.
const platformShim = `
-- IF NOT EXISTS, because the lab now runs a real GoTrue and the auth schema
-- belongs to it. This shim supplies auth.uid(), which is a Supabase PLATFORM
-- function rather than anything GoTrue creates, so it is still needed -- but
-- the schema is no longer this test's to make. CREATE SCHEMA auth failed with
-- "already exists" the moment the auth fixture landed.
CREATE SCHEMA IF NOT EXISTS auth;
CREATE OR REPLACE FUNCTION auth.uid() RETURNS uuid LANGUAGE sql STABLE AS $fn$ SELECT NULL::uuid $fn$;
CREATE TABLE ` + scratchRelation + ` (
  id bigserial PRIMARY KEY, user_id uuid, status text
);
ALTER TABLE ` + scratchRelation + ` ENABLE ROW LEVEL SECURITY;
`

var reSQLStart = regexp.MustCompile(`^(CREATE|ALTER|DROP|REVOKE|GRANT|SELECT)\b`)

// uncomment returns the SQL an operator would get by removing the leading
// comment markers, exactly as they would with a text editor. A commented line
// is treated as SQL when it starts with a statement keyword, or when it
// continues one that has not yet been terminated.
func uncomment(block string) string {
	var out []string
	var inStatement bool
	for _, line := range strings.Split(block, "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "--") {
			inStatement = false
			continue
		}
		body := strings.TrimSpace(strings.TrimPrefix(trimmed, "--"))
		switch {
		case reSQLStart.MatchString(body):
			inStatement = true
		case !inStatement:
			continue // prose
		}
		out = append(out, body)
		if strings.HasSuffix(body, ";") {
			inStatement = false
		}
	}
	return strings.Join(out, "\n")
}

// remediationBlocks collects the fixes for every SQL-emitting finding type,
// each built for the scratch relation.
func remediationBlocks() map[string]string {
	blocks := map[string]string{}

	pr := probe.Result{Relations: []probe.Relation{{
		Name: scratchRelation, Rows: 3,
		Read:  postgrest.ReadExposed,
		Write: postgrest.WriteReached, WriteWhy: "reached",
	}}}
	for _, f := range pr.Findings("http://x/rest/v1", true) {
		blocks[f.ID] = f.Remediation
	}

	blocks["supabase-realtime-anon-delivery"] = realtime.Remediation(scratchRelation)
	return blocks
}

func TestRemediationTemplatesAreValidSQL(t *testing.T) {
	// Gated like every other fixture-backed eval. Without this the test runs
	// in `make test`, which is documented as offline and deterministic, and
	// hard-fails on any machine without Docker running -- as it did the first
	// time this suite met a stopped daemon. An offline suite that needs a
	// container is not an offline suite.
	if os.Getenv("UNRULY_LIVE") != "1" {
		t.Skip("set UNRULY_LIVE=1 to run fixture-backed evals")
	}
	blocks := remediationBlocks()
	if len(blocks) == 0 {
		t.Fatal("no remediation blocks collected; nothing was asserted")
	}

	var checked int
	for id, block := range blocks {
		tmpl := uncomment(block)
		if strings.TrimSpace(tmpl) == "" {
			continue // this finding has no worked example
		}
		checked++
		t.Run(id, func(t *testing.T) {
			applySQL(t, "BEGIN;\n"+platformShim+"\n"+tmpl+"\nROLLBACK;\n")
			t.Logf("%s: %d template lines execute", id, len(strings.Split(tmpl, "\n")))
		})
	}
	if checked == 0 {
		t.Fatal("no finding carried a commented worked example; either the fixes lost " +
			"them or the extractor stopped matching")
	}
}
