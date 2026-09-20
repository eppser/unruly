package eval_test

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/eppser/unruly/internal/client"
)

// supabase-graphql-rls-bypass reports a relation that returns rows over
// pg_graphql and none over REST. No scan has ever produced it, and this test
// says why: measured against both protection mechanisms Supabase offers,
// GraphQL is equal or MORE restrictive than REST.
//
//	protection            REST              GraphQL
//	REVOKE (no grant)     401 42501         Unknown field -- absent from the
//	                                        schema pg_graphql builds per role
//	RLS with no policy    200 []            edges: []
//
// So the finding guards a divergence that does not currently occur. That is
// worth keeping -- it costs one query per relation and would catch a
// regression in either engine -- but "never fires" should be a MEASURED
// statement rather than an untested assumption, which is what this makes it.
//
// If pg_graphql ever starts answering where REST refuses, this test fails and
// the bypass finding stops being theoretical.
func TestGraphQLIsNotMorePermissiveThanREST(t *testing.T) {
	key := os.Getenv("UNRULY_LAB_ANON_KEY")
	ref := os.Getenv("UNRULY_LAB_REF")
	if key == "" || ref == "" {
		t.Skip("set UNRULY_LAB_REF and UNRULY_LAB_ANON_KEY to run this")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	c := client.New(client.Options{ProjectRef: ref, AnonKey: key, Retries: 1})

	// The third case is a POSITIVE control and is the reason this test means
	// anything. The two protected relations return zero rows on both
	// interfaces, so `gqlRows > restRows` cannot fire for them -- the test
	// would pass just as well against a harness that never sees a row at all,
	// or a GraphQL endpoint answering nothing. A relation both interfaces CAN
	// read proves the comparison is looking at something.
	sawRows := false
	for _, tc := range []struct {
		relation string
		how      string
		open     bool
	}{
		{"gql_revoked_probe", "REVOKE: anon holds no privilege at all", false},
		{"gql_rls_probe", "RLS enabled with no policy, SELECT granted", false},
		{"feedback_submissions", "readable by anon: the positive control", true},
	} {
		// REST: rows, or a refusal.
		rest := c.Get(ctx, c.RestURL(tc.relation)+"?select=*", nil)
		restRows := 0
		if rest.Err == nil && (rest.Status == 200 || rest.Status == 206) {
			var rows []map[string]any
			_ = json.Unmarshal(rest.Body, &rows)
			restRows = len(rows)
		}

		// GraphQL: the same question over the other interface.
		q := `{"query":"{ ` + tc.relation + `Collection { edges { node { nodeId } } } }"}`
		gq := c.Do(ctx, "POST", strings.TrimSuffix(c.BaseURL(), "/")+"/graphql/v1",
			[]byte(q), map[string]string{"Content-Type": "application/json"})
		if gq.Err != nil {
			t.Fatalf("%s: graphql endpoint unreachable: %v", tc.relation, gq.Err)
		}
		var out struct {
			Data map[string]struct {
				Edges []struct{} `json:"edges"`
			} `json:"data"`
			Errors []struct {
				Message string `json:"message"`
			} `json:"errors"`
		}
		if err := json.Unmarshal(gq.Body, &out); err != nil {
			t.Fatalf("%s: graphql response is not JSON: %s", tc.relation, gq.Body)
		}
		gqlRows := len(out.Data[tc.relation+"Collection"].Edges)

		if gqlRows > restRows {
			t.Errorf("%s (%s): GraphQL returned %d row(s) where REST returned %d. Both "+
				"interfaces run the same policies, so this is one path enforcing what the "+
				"other does not -- supabase-graphql-rls-bypass has stopped being "+
				"theoretical and the check now has real work to do.",
				tc.relation, tc.how, gqlRows, restRows)
		}
		if tc.open {
			if restRows == 0 || gqlRows == 0 {
				t.Errorf("%s is readable by anon over both interfaces; REST %d, GraphQL %d. "+
					"With no relation returning rows the comparison above is vacuous.",
					tc.relation, restRows, gqlRows)
			} else {
				sawRows = true
			}
		}
		t.Logf("%-20s %-45s REST %d row(s), GraphQL %d row(s)", tc.relation, tc.how,
			restRows, gqlRows)
	}
	if !sawRows {
		t.Fatal("no relation returned rows over either interface, so this test compared " +
			"nothing against nothing")
	}
}
