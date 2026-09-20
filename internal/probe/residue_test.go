package probe

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/eppser/unruly/internal/client"
	"github.com/eppser/unruly/internal/postgrest"
)

// -no-residue is a promise about the target's data, not about the report, so
// these tests assert what went over the wire.
//
// The flag shipped gating only phase B, and phase A committed rows anyway. It
// was caught by counting rows on the exploit lab before and after a scan --
// 1 -> 3 with the flag set, identical to without it. Nothing in the suite
// noticed, because every test asked what the scan CONCLUDED and none asked what
// it SENT.

// recordingTarget is a minimal PostgREST that records request bodies and can be
// told which relations are readable.
type recordingTarget struct {
	mu       sync.Mutex
	posts    map[string][]string // relation -> bodies received
	readable map[string][]map[string]any
}

// newRecordingTarget serves three kinds of relation, because a real PostgREST
// distinguishes all three and a fixture that cannot is a fixture that agrees
// with any scanner.
//
//	in readable  -> rows
//	in filtered  -> 200 with Content-Range */0: it EXISTS and RLS hid every row
//	anything else -> 404 PGRST205: it is not there
//
// The middle and the last used to be the same answer, which made this server
// unable to express the distinction the whole project turns on. A relation
// that exists and returns nothing is not the same fact as a name nobody has
// heard of, and a scan that cannot tell them apart is guessing.
func newRecordingTarget(readable map[string][]map[string]any,
	filtered ...string) (*recordingTarget, *httptest.Server) {

	hidden := make(map[string]bool, len(filtered))
	for _, f := range filtered {
		hidden[f] = true
	}
	rt := &recordingTarget{posts: map[string][]string{}, readable: readable}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rel := strings.Trim(r.URL.Path, "/")
		switch r.Method {
		case http.MethodGet:
			rows, ok := rt.readable[rel]
			if !ok {
				if !hidden[rel] {
					// Not there at all. PostgREST says so, and saying so is
					// what lets a scan tell absence from concealment.
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusNotFound)
					w.Write([]byte(`{"code":"PGRST205","message":` +
						`"Could not find the table in the schema cache"}`))
					return
				}
				// Present but RLS-filtered: 200 with an empty set is how
				// PostgREST answers a relation the caller may not read.
				w.Header().Set("Content-Range", "*/0")
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`[]`))
				return
			}
			b, _ := json.Marshal(rows)
			w.Header().Set("Content-Range", "0-0/1")
			w.WriteHeader(http.StatusPartialContent)
			w.Write(b)
		case http.MethodPost:
			body := make([]byte, r.ContentLength)
			r.Body.Read(body)
			rt.mu.Lock()
			rt.posts[rel] = append(rt.posts[rel], string(body))
			rt.mu.Unlock()
			// Answer as a relation with a unique constraint would: the
			// duplicate is rejected, and an empty body would have succeeded.
			if strings.Contains(string(body), `"id"`) {
				w.WriteHeader(http.StatusConflict)
				w.Write([]byte(`{"code":"23505","message":"duplicate key value violates unique constraint"}`))
				return
			}
			w.WriteHeader(http.StatusCreated)
			w.Write([]byte(`[{"id":1}]`))
		default:
			w.WriteHeader(http.StatusNoContent)
		}
	}))
	return rt, srv
}

func (rt *recordingTarget) bodies(rel string) []string {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	return append([]string{}, rt.posts[rel]...)
}

func runAgainst(t *testing.T, srv *httptest.Server, names []string, noResidue bool) Result {
	t.Helper()
	c := client.New(client.Options{BaseURL: srv.URL, AnonKey: "test", RestPrefix: "/"})
	return Run(context.Background(), c, names, Options{
		Write: true, NoResidue: noResidue, SampleRows: 1, Concurrency: 2,
	})
}

// A relation the scan can read is probed with a body that collides, so the
// target's unique constraint rejects it and no row is created.
func TestNoResidueSendsACollidingRowNotAnEmptyInsert(t *testing.T) {
	rt, srv := newRecordingTarget(map[string][]map[string]any{
		"readable": {{"id": float64(7), "note": "hello"}},
	})
	defer srv.Close()

	res := runAgainst(t, srv, []string{"readable"}, true)

	sent := rt.bodies("readable")
	if len(sent) != 1 {
		t.Fatalf("expected exactly one INSERT, got %d: %v", len(sent), sent)
	}
	if sent[0] == "{}" {
		t.Fatal("-no-residue sent an empty INSERT, which CREATES a row wherever every " +
			"column is nullable or defaulted -- the exact case the flag exists to prevent")
	}
	var got map[string]any
	if err := json.Unmarshal([]byte(sent[0]), &got); err != nil {
		t.Fatalf("body is not JSON: %q", sent[0])
	}
	if got["id"] != float64(7) {
		t.Fatalf("body must reuse the sampled key so it collides; got %v", got)
	}
	// The collision still has to be read as reachable, or the fix would trade
	// residue for a false negative.
	if res.Relations[0].Write != postgrest.WriteReached {
		t.Fatalf("23505 on the collision proves the write reached the table, got %v (%s)",
			res.Relations[0].Write, res.Relations[0].WriteWhy)
	}
}

// A relation the scan cannot read has no row to collide with, so any INSERT
// might land one. It is declined and reported as inconclusive -- never as
// clean, which is the failure mode this project exists to avoid.
func TestNoResidueDeclinesToProbeWhatItCannotRead(t *testing.T) {
	// "unreadable" EXISTS and RLS hides every row -- which is the case this
	// test is about. Declared, because the server now answers 404 for a name
	// it was not told about, and a 404 would make this a test about a relation
	// that is simply absent.
	rt, srv := newRecordingTarget(map[string][]map[string]any{}, "unreadable")
	defer srv.Close()

	res := runAgainst(t, srv, []string{"unreadable"}, true)

	if sent := rt.bodies("unreadable"); len(sent) != 0 {
		t.Fatalf("-no-residue issued %d INSERT(s) against a relation it could not read, "+
			"any of which may have created an unremovable row: %v", len(sent), sent)
	}
	rel := res.Relations[0]
	if rel.Write == postgrest.WriteBlockedRLS {
		t.Fatal("declining to probe was reported as the relation being protected; " +
			"not looking must never render as a clean result")
	}
	if rel.Write != postgrest.WriteInconclusive {
		t.Fatalf("want WriteInconclusive, got %v", rel.Write)
	}
	if !strings.Contains(rel.WriteWhy, "-no-residue") {
		t.Fatalf("the reason must name the flag that caused it, so an operator can "+
			"tell a declined check from a measured one; got %q", rel.WriteWhy)
	}
}

// The control is only meaningful if the unguarded path really does create rows;
// otherwise both tests above could pass against a scanner that never writes.
func TestWithoutNoResidueAnEmptyInsertIsStillSent(t *testing.T) {
	rt, srv := newRecordingTarget(map[string][]map[string]any{
		"readable": {{"id": float64(7)}},
	})
	defer srv.Close()

	runAgainst(t, srv, []string{"readable"}, false)

	sent := rt.bodies("readable")
	if len(sent) == 0 || sent[0] != "{}" {
		t.Fatalf("default write probing should send the empty INSERT; got %v", sent)
	}
}

// The probe promises to remove any row it creates. Nothing checked that it
// actually issues the DELETE.
//
// Found by mutation: replacing the cleanup call with `cleanupErr = ""` -- so
// the row is created, kept, and reported as removed -- left the whole probe
// package green. The reporting of a FAILED cleanup was tested; the cleanup
// itself was not, which is the half that touches the target's data.
func TestSuccessfulInsertIsDeletedAgain(t *testing.T) {
	var mu sync.Mutex
	var deletes []string

	// Named, so a GET for a relation this server was never told about is
	// answered as absent rather than as one that exists and hid its rows. The
	// two are different facts and this fixture used to give the same answer to
	// both.
	srv := httptest.NewServer(onlyThese(map[string]http.HandlerFunc{
		"landing": func(w http.ResponseWriter, r *http.Request) {
			switch r.Method {
			case http.MethodGet:
				w.Header().Set("Content-Range", "*/0")
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`[]`))
			case http.MethodPost:
				// Every column nullable or defaulted: the insert lands.
				w.WriteHeader(http.StatusCreated)
				w.Write([]byte(`[{"id":4242,"note":"probe"}]`))
			case http.MethodDelete:
				mu.Lock()
				deletes = append(deletes, r.URL.RawQuery)
				mu.Unlock()
				w.WriteHeader(http.StatusNoContent)
			}
		},
	}))
	defer srv.Close()

	c := client.New(client.Options{BaseURL: srv.URL, AnonKey: "test", RestPrefix: "/"})
	res := Run(context.Background(), c, []string{"landing"}, Options{
		Write: true, SampleRows: 1, Concurrency: 1,
	})

	mu.Lock()
	defer mu.Unlock()
	if len(deletes) == 0 {
		t.Fatal("the probe created a row and issued no DELETE: it changed the target " +
			"and the report would say the row was removed")
	}
	if !strings.Contains(deletes[0], "4242") {
		t.Errorf("the DELETE must target the row that was created, by the key the "+
			"server returned; got %q", deletes[0])
	}
	if rel := res.Relations[0]; rel.CleanupErr != "" {
		t.Errorf("cleanup succeeded, so no residue should be reported; got %q", rel.CleanupErr)
	}
}

// And when the DELETE is refused, the row is still there and the report must
// say so rather than claiming it was removed.
func TestFailedDeleteIsReportedAsResidue(t *testing.T) {
	srv := httptest.NewServer(onlyThese(map[string]http.HandlerFunc{
		"landing": func(w http.ResponseWriter, r *http.Request) {
			switch r.Method {
			case http.MethodGet:
				w.Header().Set("Content-Range", "*/0")
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`[]`))
			case http.MethodPost:
				w.WriteHeader(http.StatusCreated)
				w.Write([]byte(`[{"id":99,"note":"probe"}]`))
			case http.MethodDelete:
				// A bucket-style policy: INSERT granted, DELETE refused.
				w.WriteHeader(http.StatusUnauthorized)
				w.Write([]byte(`{"code":"42501","message":"permission denied"}`))
			}
		},
	}))
	defer srv.Close()

	c := client.New(client.Options{BaseURL: srv.URL, AnonKey: "test", RestPrefix: "/"})
	res := Run(context.Background(), c, []string{"landing"}, Options{
		Write: true, SampleRows: 1, Concurrency: 1,
	})

	if res.Relations[0].CleanupErr == "" {
		t.Fatal("the DELETE was refused, so a row is sitting in the target; reporting " +
			"nothing here is how a scan silently leaves data behind")
	}
}

// Absent and concealed are different facts, and the scan must classify them
// differently.
//
// This is the distinction the whole project turns on: a relation that returns
// nothing because RLS hid every row EXISTS, and one that returns nothing
// because it is not there does not. Reporting either as the other is how a
// scan invents a schema or misses one.
//
// It is asserted here because the fixture only just became able to express it.
// Before, this server answered 200 with an empty set for every name it had not
// been told about, so a scan could not have told the two apart and no test
// could have noticed.
func TestAbsentAndConcealedAreClassifiedDifferently(t *testing.T) {
	_, srv := newRecordingTarget(map[string][]map[string]any{
		"open": {{"id": float64(1)}},
	}, "concealed")
	defer srv.Close()

	res := runAgainst(t, srv, []string{"open", "concealed", "absent"}, true)

	got := map[string]postgrest.ReadState{}
	for _, r := range res.Relations {
		got[r.Name] = r.Read
	}
	for _, tc := range []struct {
		name string
		want postgrest.ReadState
		why  string
	}{
		{"open", postgrest.ReadExposed, "rows came back"},
		{"concealed", postgrest.ReadEmpty,
			"it exists and RLS filtered every row, which is not the same as being absent"},
		{"absent", postgrest.ReadNotFound,
			"it is not there, which is not the same as being hidden"},
	} {
		if got[tc.name] != tc.want {
			t.Errorf("%s classified as %v, want %v: %s",
				tc.name, got[tc.name], tc.want, tc.why)
		}
	}
}
