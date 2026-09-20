package probe

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/eppser/unruly/internal/client"
)

// The document a proxied PostgREST still serves.
//
// Measured on the benchmark corpus project that models an API gateway in front
// of Supabase: nginx rewrites every 401, 403 and 404 into one generic 403, so
// the hint oracle is destroyed and a REVOKE-protected relation is
// indistinguishable from a name that exists nowhere. The scan scored 0 of 4
// relations there and correctly exited 3 rather than claiming the project was
// clean -- honest, and still nothing found.
//
// The OpenAPI document is a 200, so the rewriting never touches it, and it
// names the three readable relations. This tool was already fetching that
// exact document to decide whether a candidate mount is PostgREST, and
// throwing the paths away.
func TestSchemaNamesReadsWhatTheDocumentAdvertises(t *testing.T) {
	const doc = `{"swagger":"2.0","basePath":"/api/db/v2/","paths":{
		"/":{},
		"/press_releases":{"get":{}},
		"/support_tickets":{"get":{}},
		"/session_tokens":{"get":{}},
		"/rpc/admin_purge":{"post":{}},
		"/顧客":{"get":{}}
	}}`
	got := schemaNamesFrom([]byte(doc))
	want := []string{"press_releases", "session_tokens", "support_tickets", "顧客"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("got %v, want %v", got, want)
	}
}

// The document is written by the target, so it is the same trust boundary as
// a hint: names go into URL paths.
func TestSchemaNamesRefusesWhatTheTargetShouldNotChoose(t *testing.T) {
	const doc = `{"paths":{
		"/orders?select=*&limit=999999":{},
		"/../../etc/passwd":{},
		"/my table":{},
		"/orders;drop":{},
		"/nested/path":{},
		"/rpc/anything":{},
		"/":{}
	}}`
	if got := schemaNamesFrom([]byte(doc)); len(got) != 0 {
		t.Errorf("accepted %v; every one of these is punctuation a scanned host "+
			"chose, and it would be pasted into a URL", got)
	}
	// A document that is not a document yields nothing rather than panicking.
	if got := schemaNamesFrom([]byte("<html>not json</html>")); got != nil {
		t.Errorf("got %v from an HTML body", got)
	}
}

// And the whole path: a served document contributes names, an absent one
// contributes nothing and is not an error.
func TestSchemaNamesIsSilentWhenTheRootIsClosed(t *testing.T) {
	var status int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(status)
		if status == 200 {
			_, _ = w.Write([]byte(`{"swagger":"2.0","paths":{"/invoices":{"get":{}}}}`))
			return
		}
		_, _ = w.Write([]byte(`{"message":"Invalid authentication credentials"}`))
	}))
	defer srv.Close()
	c := client.New(client.Options{BaseURL: srv.URL, Retries: 0})

	status = 200
	if got := SchemaNames(context.Background(), c); len(got) != 1 || got[0] != "invoices" {
		t.Errorf("a served document yielded %v", got)
	}
	// 401 is what the managed product answers, and is the reason this channel
	// can never be the only one.
	status = 401
	if got := SchemaNames(context.Background(), c); got != nil {
		t.Errorf("a closed root yielded %v; that is the managed product's normal "+
			"answer and must cost nothing", got)
	}
}
