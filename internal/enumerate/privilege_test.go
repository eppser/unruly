package enumerate

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/eppser/unruly/internal/client"
)

// A relation Postgres refuses with 42501 EXISTS, and used to be discarded.
//
// Both answers are HTTP 401, which is why they were treated alike:
//
//	real table, no privilege  {"code":"42501","message":"permission denied for table x"}
//	wrong key                 {"message":"Invalid API key"}
//
// Only the first carries a SQLSTATE, because only the first came from the
// database. Measured against the reference target's staging schema, where
// REVOKE rather than RLS does the protecting: the scan reported 0 relations
// while the oracle was returning hints for them, and now reports 3.
//
// The distinction has to hold in both directions. Counting a bare 401 as proof
// of existence is not hypothetical either -- it once produced "2684 relations
// discovered" against a database with 21, because a wrong key makes EVERY
// probe answer 401.
func TestPrivilegeDeniedRelationIsDiscovered(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := strings.Trim(r.URL.Path, "/")
		w.Header().Set("Content-Type", "application/json")
		switch name {
		case ControlRelationName:
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte(`{"code":"PGRST205","message":"not found"}`))
		case "revoked_table":
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(`{"code":"42501","message":"permission denied for table revoked_table"}`))
		default:
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte(`{"code":"PGRST205","message":"not found"}`))
		}
	}))
	defer srv.Close()

	c := client.New(client.Options{BaseURL: srv.URL, AnonKey: "k", RestPrefix: "/"})
	res := Run(context.Background(), c, Options{Seeds: []string{"revoked_table"}, Concurrency: 2})

	var found bool
	for _, n := range res.Names() {
		if n == "revoked_table" {
			found = true
		}
	}
	if !found {
		t.Error("Postgres said \"permission denied for table revoked_table\" -- that answer " +
			"came from the database, after the schema was consulted, so the relation " +
			"exists. Dropping it means a schema protected with REVOKE reports as empty.")
	}
	// It exists, but nothing was read from it: it must not look exposed.
	for _, rel := range res.Relations {
		if rel.Name == "revoked_table" && rel.Rows != 0 {
			t.Errorf("no rows were returned, so the relation must not carry a row count; got %d",
				rel.Rows)
		}
	}
}

// The other direction, which is the one that has actually caused damage.
func TestWrongKeyInventsNoRelations(t *testing.T) {
	// atomic: this handler serves concurrent probes. Written as a bare int the
	// first time, one iteration after the identical race was fixed elsewhere in
	// this package -- which is why TestNoBareCounterInsideAnHTTPHandler exists.
	var probes atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		probes.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		// The gateway's rejection: no SQLSTATE, because no SQL ran.
		w.Write([]byte(`{"message":"Invalid API key","hint":"Double check your Supabase ` +
			"`anon`" + ` or ` + "`service_role`" + ` API key."}`))
	}))
	defer srv.Close()

	c := client.New(client.Options{BaseURL: srv.URL, AnonKey: "wrong", RestPrefix: "/"})
	res := Run(context.Background(), c, Options{
		Seeds: []string{"users", "orders", "payments", "sessions"}, Concurrency: 4,
	})

	if n := len(res.Names()); n > 0 {
		t.Errorf("a wrong key makes every probe answer 401, and %d relation(s) were "+
			"reported from those refusals: %v. Authentication failure is not a fact "+
			"about the schema.", n, res.Names())
	}
	if probes.Load() == 0 {
		t.Fatal("no probes were sent, so this test asserts nothing")
	}
	if res.Denied == 0 {
		t.Error("the refusals must still be COUNTED, or the scan cannot tell the operator " +
			"why it found nothing")
	}
}
