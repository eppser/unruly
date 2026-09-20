package supabase

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/eppser/unruly/internal/client"
	"github.com/eppser/unruly/internal/enumerate"
	"github.com/eppser/unruly/internal/finding"
	"github.com/eppser/unruly/internal/graphql"
	"github.com/eppser/unruly/internal/parity"
	"github.com/eppser/unruly/internal/postgrest"
	"github.com/eppser/unruly/internal/probe"
	"github.com/eppser/unruly/internal/testrec"
	"github.com/eppser/unruly/scan"
)

func noGraphQL(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"message":"not found"}`))
	}))
	t.Cleanup(srv.Close)
	return srv
}

// readableProbe is a probe result in which every named relation reads, which
// is what RESTReadable is derived from now.
func readableProbe(names ...string) probe.Result {
	var r probe.Result
	for _, n := range names {
		r.Relations = append(r.Relations, probe.Relation{Name: n, Read: postgrest.ReadExposed})
	}
	return r
}

// publishRelations publishes what the enumerate stage would have, so a graphql
// test can name the relations it means to examine.
func publishRelations(st *scan.State, names ...string) {
	rels := make([]enumerate.Relation, 0, len(names))
	for _, n := range names {
		rels = append(rels, enumerate.Relation{Name: n})
	}
	scan.Put(st, EnumerateOutcome{Result: enumerate.Result{Relations: rels}})
}

// The stage must report exactly what the code it replaced reported.
func TestTheGraphQLStageAgreesWithTheCodeItReplaced(t *testing.T) {
	srvOld := noGraphQL(t)
	cOld := client.New(client.Options{BaseURL: srvOld.URL, AnonKey: "k", RestPrefix: "/"})
	rels := []string{"notes"}
	readable := map[string]bool{"notes": true}

	// --- the original expression, transcribed ---------------------------
	var old []finding.Finding
	gq := graphql.Result{}
	gq = graphql.Run(context.Background(), cOld, graphql.Options{
		Relations:    rels,
		RESTReadable: readable,
		SampleRows:   3,
		Concurrency:  2,
	})
	oldRequests := gq.Requests
	old = append(old, gq.Findings...)

	// --- the same work through the pipeline ------------------------------
	srvNew := noGraphQL(t)
	cNew := client.New(client.Options{BaseURL: srvNew.URL, AnonKey: "k", RestPrefix: "/"})
	st := &scan.State{Target: cNew.RestBase()}
	publishRelations(st, "notes")
	// RESTReadable is derived from the published probe result now, so the test
	// publishes a probe result that reads "notes" -- the same map the
	// transcribed original was handed.
	scan.Put(st, readableProbe("notes"))
	stage := GraphQLStage{Client: cNew,
		SampleRows: 3, Concurrency: 2}
	if _, err := (scan.Pipeline{stage}).Run(context.Background(), st); err != nil {
		t.Fatal(err)
	}

	normalise(old, srvOld.URL, "http://target")
	got := st.Findings()
	normalise(got, srvNew.URL, "http://target")

	if d := parity.Diff(old, got); d != "" {
		t.Errorf("the ported stage disagrees with the code it replaced:\n%s", d)
	}
	if st.Attributed() != oldRequests {
		t.Errorf("attributed %d requests, the original counted %d",
			st.Attributed(), oldRequests)
	}
}

// -measure declines the GraphQL check rather than weakening it.
//
// GraphQL distinguishes a readable relation from an RLS-filtered one by asking
// for node ids, and a node id decodes to a real row's primary key -- data.
// There is no count-only form of that question, so under -measure the check is
// SKIPPED and said to be skipped. Silently running it would retrieve exactly
// what the mode promises not to.
func TestMeasureDeclinesTheGraphQLCheckEntirely(t *testing.T) {
	var asked testrec.Log
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		asked.Add(r.Method + " " + r.URL.RequestURI())
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	c := client.New(client.Options{BaseURL: srv.URL, AnonKey: "k", RestPrefix: "/"})
	st := &scan.State{Target: c.RestBase()}
	publishRelations(st, "notes")
	scan.Put(st, readableProbe("notes"))
	stage := GraphQLStage{Client: c, Measure: true,
		SampleRows: 3, Concurrency: 2}
	if _, err := (scan.Pipeline{stage}).Run(context.Background(), st); err != nil {
		t.Fatal(err)
	}
	if asked.Len() > 0 {
		t.Errorf("-measure was set and the GraphQL check still issued a request; node ids "+
			"decode to real primary keys, which is the data this mode promises not to take: %v",
			asked.Entries())
	}
	if st.Attributed() != 0 {
		t.Errorf("attributed %d requests under -measure", st.Attributed())
	}
}

func TestTheGraphQLStageHasAStableName(t *testing.T) {
	if got := (GraphQLStage{}).Name(); got != "graphql" {
		t.Errorf("stage name %q, want \"graphql\"", got)
	}
}
