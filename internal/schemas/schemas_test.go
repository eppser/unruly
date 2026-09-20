package schemas

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/eppser/unruly/internal/client"
)

func serve(body string, status int) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Accept-Profile"); got != ProbeSchemaName {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`[]`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		w.Write([]byte(body))
	}))
}

func TestExtraSchemaIsDiscoveredAndReported(t *testing.T) {
	srv := serve(`{"code":"PGRST106","hint":"Only the following schemas are exposed: public, graphql_public, staging"}`, 406)
	defer srv.Close()

	c := client.New(client.Options{BaseURL: srv.URL, AnonKey: "k", RestPrefix: "/"})
	res := Discover(context.Background(), c)

	if !res.Answered {
		t.Fatal("PostgREST named its schemas and the oracle did not read them")
	}
	if len(res.Exposed) != 3 {
		t.Errorf("want 3 exposed schemas, got %v", res.Exposed)
	}
	if len(res.Extra) != 1 || res.Extra[0] != "staging" {
		t.Errorf("public and graphql_public are served by every project; only what a "+
			"project ADDED is worth naming. got %v", res.Extra)
	}
	if len(res.Findings) != 1 || res.Findings[0].ID != "supabase-extra-schema-exposed" {
		t.Fatalf("want one supabase-extra-schema-exposed finding, got %v", res.Findings)
	}
	if s := res.Findings[0].Evidence.Sample; len(s) == 0 {
		t.Error("the finding must carry what PostgREST actually said as proof")
	}
}

// A project with only the defaults is not a finding.
func TestDefaultSchemasAreSilent(t *testing.T) {
	srv := serve(`{"code":"PGRST106","hint":"Only the following schemas are exposed: public, graphql_public"}`, 406)
	defer srv.Close()

	c := client.New(client.Options{BaseURL: srv.URL, AnonKey: "k", RestPrefix: "/"})
	res := Discover(context.Background(), c)

	if !res.Answered {
		t.Fatal("the oracle answered and was not read")
	}
	if len(res.Findings) != 0 {
		t.Errorf("every project serves these two; reporting them would put a finding on "+
			"every scan. got %v", res.Findings)
	}
}

// No hint means UNKNOWN, not "only the default is exposed".
func TestNoHintIsNotAnAnswer(t *testing.T) {
	srv := serve(`{"message":"Invalid API key"}`, 401)
	defer srv.Close()

	c := client.New(client.Options{BaseURL: srv.URL, AnonKey: "k", RestPrefix: "/"})
	res := Discover(context.Background(), c)

	if res.Answered {
		t.Error("nothing named a schema, so the schema surface is unknown; claiming " +
			"otherwise would be inventing a measurement")
	}
	if len(res.Exposed) != 0 {
		t.Errorf("no schemas were named, got %v", res.Exposed)
	}
}
