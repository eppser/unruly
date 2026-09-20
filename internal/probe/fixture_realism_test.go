package probe

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/eppser/unruly/internal/client"
	"github.com/eppser/unruly/internal/postgrest"
)

// onlyThese answers PostgREST's real 404 for a relation that is not there.
//
// Test servers in this package answered every path identically, which models
// no PostgREST that exists: a real one distinguishes a relation it serves from
// a name it has never heard of, and that distinction is the single most
// load-bearing signal the scanner reads. A fixture without it cannot tell a
// scan that asked for the right relation from one that asked for gibberish,
// and it silently defeats any check that depends on absence being reportable.
func onlyThese(present map[string]http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := strings.TrimPrefix(r.URL.Path, "/")
		h, ok := present[name]
		if !ok {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"code":"PGRST205","message":` +
				`"Could not find the table in the schema cache"}`))
			return
		}
		h(w, r)
	}
}

// The helper reports absence, and reports presence.
//
// Guarding the fixture itself, because a helper that 404s EVERYTHING would
// make every test using it pass by measuring nothing -- which is the failure
// this file exists to remove, arriving through the fix for it.
func TestTheFixtureDistinguishesPresentFromAbsent(t *testing.T) {
	srv := httptest.NewServer(onlyThese(map[string]http.HandlerFunc{
		"customers": func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Range", "0-0/7")
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusPartialContent)
			_, _ = w.Write([]byte(`[{"id":1,"email":"a@example.invalid"}]`))
		},
	}))
	defer srv.Close()

	c := client.New(client.Options{BaseURL: srv.URL, AnonKey: "k", RestPrefix: "/"})
	res := Run(context.Background(), c, []string{"customers", "not_a_table"}, Options{SampleRows: 3})

	byName := map[string]Relation{}
	for _, r := range res.Relations {
		byName[r.Name] = r
	}
	if got := byName["customers"].Read; got != postgrest.ReadExposed {
		t.Errorf("a relation the fixture serves classified as %v, want ReadExposed", got)
	}
	if got := byName["not_a_table"].Read; got != postgrest.ReadNotFound {
		t.Errorf("a relation the fixture does NOT serve classified as %v, want "+
			"ReadNotFound. A server that answers every path the same way cannot "+
			"tell a scan that asked for the right name from one that asked for "+
			"gibberish", got)
	}
}
