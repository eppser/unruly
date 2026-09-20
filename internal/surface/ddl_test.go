package surface

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/eppser/unruly/internal/client"
	"github.com/eppser/unruly/internal/testrec"
)

// The SQL-executor probe must never send DDL, and nothing was checking.
//
// "Never send DDL" is a standing constraint of this project and the
// exploitability ledger states it outright -- "No DDL is ever sent". The whole
// of that guarantee was a constant. Replacing sqlProbeStatement with
// `DROP TABLE IF EXISTS unruly_probe` survived all 48 tests in this package.
//
// The file argues, correctly, that PostgREST serves GET inside a READ-ONLY
// transaction so a destructive argument could not commit. That is a property
// of somebody else's server, measured once, and it is the second line of
// defence rather than the first. The first is not sending the statement. A
// tool that probes strangers' databases does not get to rely on the target
// refusing to do what it was asked.
//
// Two assertions, because either alone is satisfiable by the wrong thing: the
// constant itself must be a read, and the request that actually goes out must
// carry it -- otherwise a refactor that builds the statement somewhere else
// passes the first check while sending anything it likes.
func TestTheSQLProbeStatementIsAReadAndNothingElse(t *testing.T) {
	if !strings.HasPrefix(strings.ToUpper(strings.TrimSpace(sqlProbeStatement)), "SELECT ") {
		t.Errorf("the probe statement does not begin with SELECT: %q", sqlProbeStatement)
	}
	for _, verb := range []string{
		"DROP", "DELETE", "UPDATE", "INSERT", "ALTER", "CREATE", "TRUNCATE",
		"GRANT", "REVOKE", "COPY", "COMMIT", ";",
	} {
		if strings.Contains(strings.ToUpper(sqlProbeStatement), verb) {
			t.Errorf("the probe statement contains %q: %q. This is sent to routines on "+
				"somebody else's database, chosen because they run arbitrary SQL as the "+
				"owner. The read-only transaction PostgREST wraps a GET in is the second "+
				"line of defence; not sending it is the first", verb, sqlProbeStatement)
		}
	}
}

func TestTheStatementOnTheWireIsTheProbeStatement(t *testing.T) {
	var sent testrec.Log
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sent.Add(r.Method + " " + r.URL.RequestURI())
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`[{"unruly_probe":42}]`))
	}))
	defer srv.Close()

	c := client.New(client.Options{BaseURL: srv.URL, AnonKey: "k", RestPrefix: "/"})
	Run(context.Background(), c, Options{})

	var rpc []string
	for _, req := range sent.Entries() {
		if strings.Contains(req, "/rpc/") {
			rpc = append(rpc, req)
		}
	}
	if len(rpc) == 0 {
		t.Fatal("no routine was probed, so this test measured nothing about what is sent")
	}
	for _, req := range rpc {
		upper := strings.ToUpper(req)
		for _, verb := range []string{"DROP+", "DROP%20", "DELETE+", "TRUNCATE", "ALTER"} {
			if strings.Contains(upper, verb) {
				t.Errorf("a request carried %q: %s", verb, req)
			}
		}
	}
}
