package graphql

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/eppser/unruly/internal/client"
	"github.com/eppser/unruly/internal/finding"
)

// nodeID encodes a tuple the way pg_graphql does.
func nodeID(schema, table string, pk int) string {
	b, _ := json.Marshal([]any{schema, table, pk})
	return base64.StdEncoding.EncodeToString(b)
}

// fakeGraphQL answers like pg_graphql: rows for readable relations, an empty
// edge list for ones RLS filtered, and "Unknown field" for names that do not
// exist. Those three answers are the whole probe.
func fakeGraphQL(readable map[string]int, existing map[string]bool) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Query string `json:"query"`
		}
		json.NewDecoder(r.Body).Decode(&in)

		// "{ xCollection(first: 3) { ... } }" -> x
		rel := in.Query
		if i := strings.Index(rel, "{ "); i >= 0 {
			rel = rel[i+2:]
		}
		if i := strings.Index(rel, "Collection"); i >= 0 {
			rel = rel[:i]
		}

		w.Header().Set("Content-Type", "application/json")
		if n, ok := readable[rel]; ok {
			var edges []string
			for i := 1; i <= n; i++ {
				edges = append(edges, `{"node":{"nodeId":"`+nodeID("public", rel, i)+`"}}`)
			}
			w.Write([]byte(`{"data":{"` + rel + `Collection":{"edges":[` + strings.Join(edges, ",") + `]}}}`))
			return
		}
		if existing[rel] {
			w.Write([]byte(`{"data":{"` + rel + `Collection":{"edges":[]}}}`))
			return
		}
		w.Write([]byte(`{"data":null,"errors":[{"message":"Unknown field \"` + rel +
			`Collection\" on type Query"}]}`))
	}))
}

func run(t *testing.T, srv *httptest.Server, o Options) Result {
	t.Helper()
	c := client.New(client.Options{BaseURL: srv.URL, AnonKey: "k", RestPrefix: "/"})
	return Run(context.Background(), c, o)
}

// The case the check exists for: a relation REST said was protected, serving
// rows over GraphQL.
func TestGraphQLBypassIsReportedHigh(t *testing.T) {
	srv := fakeGraphQL(
		map[string]int{"public_posts": 2, "private_notes": 3},
		map[string]bool{"locked": true},
	)
	defer srv.Close()

	res := run(t, srv, Options{
		Relations:    []string{"public_posts", "private_notes", "locked", "absent"},
		RESTReadable: map[string]bool{"public_posts": true}, // REST could NOT read private_notes
		SampleRows:   3,
	})

	if res.State != Enabled {
		t.Fatalf("endpoint answered queries, want Enabled, got %v", res.State)
	}
	if !res.Discriminating {
		t.Fatal("the control name was answered as absent, so the endpoint discriminates")
	}
	if res.Relations["locked"] != Filtered {
		t.Errorf("an empty edge list means the relation EXISTS and RLS filtered it, got %v",
			res.Relations["locked"])
	}
	if res.Relations["absent"] != Absent {
		t.Errorf("\"Unknown field\" means no such relation, got %v", res.Relations["absent"])
	}

	var bypass *finding.Finding
	for i := range res.Findings {
		if res.Findings[i].ID == "supabase-graphql-rls-bypass" {
			bypass = &res.Findings[i]
		}
	}
	if bypass == nil {
		t.Fatal("private_notes returned rows over GraphQL and none over REST: that is one " +
			"interface enforcing what the other does not, and it must be reported")
	}
	if bypass.Resource != "private_notes" {
		t.Errorf("bypass named %q, want private_notes", bypass.Resource)
	}
	if bypass.Severity != finding.High {
		t.Errorf("severity %v: a relation the rest of the scan called protected, serving "+
			"rows, is a wrong verdict rather than a note", bypass.Severity)
	}
	// Proof-carrying: the node id decodes to a real row.
	if len(bypass.Evidence.Sample) == 0 {
		t.Fatal("the finding carries no proof")
	}
	if got := bypass.Evidence.Sample[0]["node"]; got != "public.private_notes.1" {
		t.Errorf("node id must decode to schema.table.key, got %v", got)
	}
	// public_posts was readable both ways, so it is NOT a bypass.
	for _, f := range res.Findings {
		if f.ID == "supabase-graphql-rls-bypass" && f.Resource == "public_posts" {
			t.Error("public_posts was already readable over REST; reporting it as a bypass " +
				"would put a high finding on every public relation")
		}
	}
}

// With no disagreement the endpoint is still worth stating, but only at info:
// a second door to data already known to be public.
func TestGraphQLMirroringRESTIsInfoOnly(t *testing.T) {
	srv := fakeGraphQL(map[string]int{"public_posts": 2}, nil)
	defer srv.Close()

	res := run(t, srv, Options{
		Relations:    []string{"public_posts"},
		RESTReadable: map[string]bool{"public_posts": true},
	})

	if len(res.Findings) != 1 {
		t.Fatalf("expected exactly one finding, got %d", len(res.Findings))
	}
	f := res.Findings[0]
	if f.ID != "supabase-graphql-anon-read" || f.Severity != finding.Info {
		t.Errorf("want supabase-graphql-anon-read at info, got %s at %v", f.ID, f.Severity)
	}
}

// The common case in the wild. Both real projects available answered this way
// until pg_graphql was deliberately enabled, so it must be silent -- an
// endpoint that says "not installed" is a closed door, not an unmeasured one.
func TestGraphQLDisabledIsSilent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"errors":[{"message":"pg_graphql extension is not enabled."}]}`))
	}))
	defer srv.Close()

	res := run(t, srv, Options{Relations: []string{"anything"}})

	if res.State != Disabled {
		t.Errorf("want Disabled, got %v", res.State)
	}
	if len(res.Findings) != 0 {
		t.Errorf("a project without the extension has nothing to report here, got %d "+
			"finding(s): %v", len(res.Findings), res.Findings[0].ID)
	}
	if res.Requests != 1 {
		t.Errorf("a disabled endpoint must cost ONE request, not one per relation; got %d",
			res.Requests)
	}
}

// An endpoint that answers every name is not evidence about any name.
func TestGraphQLNonDiscriminatingEndpointIsNotAssessed(t *testing.T) {
	// Claims every relation exists, including the control, and echoes the name
	// back the way a real endpoint does -- a fake that answered under a fixed
	// key would be classified absent and the test would pass for the wrong
	// reason.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Query string `json:"query"`
		}
		json.NewDecoder(r.Body).Decode(&in)
		rel := in.Query
		if i := strings.Index(rel, "{ "); i >= 0 {
			rel = rel[i+2:]
		}
		if i := strings.Index(rel, "Collection"); i >= 0 {
			rel = rel[:i]
		}
		w.Write([]byte(`{"data":{"` + rel + `Collection":{"edges":[]}}}`))
	}))
	defer srv.Close()

	res := run(t, srv, Options{Relations: []string{"a", "b"}})

	if res.Discriminating {
		t.Fatal("a relation that cannot exist was answered as though it does; the endpoint " +
			"does not discriminate and nothing it says can be believed")
	}
	if len(res.Findings) != 1 || res.Findings[0].ID != "unruly-surface-not-assessed" {
		t.Errorf("a blind surface must be reported as unassessed, not left silent; got %v",
			res.Findings)
	}
}

// Transport failure must not read as "closed".
func TestGraphQLUnreachableIsNotClean(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	srv.Close() // nothing is listening

	c := client.New(client.Options{BaseURL: srv.URL, AnonKey: "k", RestPrefix: "/", Retries: 0})
	res := Run(context.Background(), c, Options{Relations: []string{"a"}})

	if res.State != Unreachable {
		t.Errorf("want Unreachable, got %v", res.State)
	}
	if len(res.Findings) != 1 || res.Findings[0].ID != "unruly-surface-not-assessed" {
		t.Error("an endpoint that could not be reached is unmeasured, and unmeasured must " +
			"never render as nothing-to-find")
	}
}

// -redact removes the node ids, which carry primary keys.
func TestGraphQLRedactionDropsNodeIDs(t *testing.T) {
	srv := fakeGraphQL(map[string]int{"private_notes": 2}, nil)
	defer srv.Close()

	res := run(t, srv, Options{
		Relations: []string{"private_notes"}, RESTReadable: nil, Redact: true,
	})

	if len(res.Proof) != 0 {
		t.Errorf("-redact must drop the node ids: they decode to real primary keys; got %v",
			res.Proof)
	}
	// The finding itself must survive: redaction removes data, not verdicts.
	found := false
	for _, f := range res.Findings {
		if f.ID == "supabase-graphql-rls-bypass" {
			found = true
		}
	}
	if !found {
		t.Error("-redact removed the finding as well as the data")
	}
}

func TestDecodeNodeIDNamesTheRow(t *testing.T) {
	if got := decodeNodeID(nodeID("public", "feedback_submissions", 131)); got != "public.feedback_submissions.131" {
		t.Errorf("got %q, want public.feedback_submissions.131", got)
	}
	// Anything unexpected is returned as-is rather than mangled.
	if got := decodeNodeID("not-base64!"); got != "not-base64!" {
		t.Errorf("got %q, want the input back", got)
	}
}

// The package is exempt from the -no-residue control because a GraphQL query is
// a read that happens to travel by POST. An exemption is per-package and cannot
// notice if that stops being true, so the claim is held here instead: assert
// the wire format of every request.
//
// pg_graphql generates insertIntoXCollection, updateXCollection and
// deleteFromXCollection alongside the read fields. Any of them would be a write
// to somebody's database from a scan that promises reads only.
func TestGraphQLSendsOnlyQueries(t *testing.T) {
	var mu sync.Mutex
	var bodies []string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		bodies = append(bodies, string(b))
		mu.Unlock()
		if r.Method != http.MethodPost {
			t.Errorf("GraphQL speaks POST; got %s", r.Method)
		}
		w.Write([]byte(`{"data":null,"errors":[{"message":"Unknown field \"xCollection\" on type Query"}]}`))
	}))
	defer srv.Close()

	run(t, srv, Options{Relations: []string{"customers", "orders"}})

	mu.Lock()
	defer mu.Unlock()
	if len(bodies) == 0 {
		t.Fatal("no requests were sent, so this test asserts nothing")
	}
	for _, b := range bodies {
		for _, mutation := range []string{"insertInto", "updateBy", "update", "deleteFrom", "mutation"} {
			if strings.Contains(b, mutation) {
				t.Errorf("request contains %q, which is a WRITE: %s\n"+
					"This package is exempt from the -no-residue control on the grounds "+
					"that it only reads. If that is no longer true, the exemption in "+
					"internal/eval/controls_test.go must go.", mutation, b)
			}
		}
		if !strings.Contains(b, "Collection(first:") {
			t.Errorf("request is not the expected read query: %s", b)
		}
	}
}
