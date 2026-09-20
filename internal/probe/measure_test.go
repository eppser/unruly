package probe

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/eppser/unruly/internal/client"
)

// -measure must never ask for a row.
//
// This is not a reporting preference, it is the whole basis on which this
// scanner can be pointed at projects nobody involved owns. -redact hides rows
// that were already fetched: the data crossed the network and sat in memory,
// and "we deleted it afterwards" is not consent. -measure changes the REQUEST,
// so the data never leaves the database:
//
//	GET ?select=*&limit=0   Prefer: count=exact
//	206  Content-Range: */465  body: []
//
// Verified against a real project: 791 bytes of personal data at limit=3,
// 2 bytes at limit=0, same verdict and same count from both.
func TestMeasureNeverRequestsRows(t *testing.T) {
	var mu sync.Mutex
	var reads []string

	serve := func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			mu.Lock()
			reads = append(reads, r.URL.RawQuery)
			mu.Unlock()
		}
		w.Header().Set("Content-Range", "*/465")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusPartialContent)
		w.Write([]byte(`[]`))
	}
	// Named, so a scan that asked for the wrong relation would be told it is
	// not there rather than handed rows anyway.
	srv := httptest.NewServer(onlyThese(map[string]http.HandlerFunc{
		"customers": serve, "orders": serve,
	}))
	defer srv.Close()

	c := client.New(client.Options{BaseURL: srv.URL, AnonKey: "k", RestPrefix: "/"})
	res := Run(context.Background(), c, []string{"customers", "orders"}, Options{
		SampleRows: 3, // deliberately non-zero: -measure must override it
		Measure:    true,
	})

	mu.Lock()
	defer mu.Unlock()
	if len(reads) == 0 {
		t.Fatal("no reads were issued, so this test asserts nothing")
	}
	for _, q := range reads {
		if !strings.Contains(q, "limit=0") {
			t.Errorf("a measurement run asked for rows: %q. Every request must be limit=0, "+
				"or the promise that no data leaves the target is false", q)
		}
	}

	// The verdict must survive: a mode that is safe because it learns nothing
	// would pass the assertion above and be useless.
	var exposed int
	for _, rel := range res.Relations {
		if rel.Rows != 465 {
			t.Errorf("%s reported %d rows; the count comes from Content-Range and is "+
				"unaffected by asking for no rows", rel.Name, rel.Rows)
		}
		if len(rel.Sample) != 0 {
			t.Errorf("%s carries %d sampled rows in a measurement run", rel.Name, len(rel.Sample))
		}
		exposed++
	}
	if exposed == 0 {
		t.Error("no relation was classified, so the mode bought its safety by not looking")
	}
}

// And the default must be unchanged: proof-carrying is the point of this tool
// everywhere except a population study.
func TestDefaultStillSamplesRows(t *testing.T) {
	var mu sync.Mutex
	var reads []string
	srv := httptest.NewServer(onlyThese(map[string]http.HandlerFunc{
		"customers": func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodGet {
				mu.Lock()
				reads = append(reads, r.URL.RawQuery)
				mu.Unlock()
			}
			w.Header().Set("Content-Range", "0-0/1")
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusPartialContent)
			w.Write([]byte(`[{"id":1,"email":"a@example.invalid"}]`))
		},
	}))
	defer srv.Close()

	c := client.New(client.Options{BaseURL: srv.URL, AnonKey: "k", RestPrefix: "/"})
	res := Run(context.Background(), c, []string{"customers"}, Options{SampleRows: 3})

	mu.Lock()
	defer mu.Unlock()
	for _, q := range reads {
		if strings.Contains(q, "limit=0") {
			t.Errorf("a default scan asked for no rows (%q); findings would carry no proof", q)
		}
	}
	for _, rel := range res.Relations {
		if len(rel.Sample) == 0 {
			t.Error("a default scan produced no sampled rows, so its findings assert " +
				"exposure without showing any")
		}
	}
}

// Measure mode can still say WHICH exposure matters, without reading data.
//
// Without column names, every readable table looks alike: a table of blog
// posts and a table of session tokens both come back "high". The difference
// between those is the difference between a finding and an incident, and it is
// the whole reason severity exists.
//
// PostgREST answers the question without returning anything:
//
//	?select=access_token&limit=0  ->  206 []      the column exists
//	?select=email&limit=0         ->  400 42703   it does not
//
// That is schema metadata. It establishes that a publicly readable table HAS a
// column called access_token without reading one token out of it. Verified
// against a real project: sessions returns to critical, sample count zero.
func TestMeasureRecoversSensitivityWithoutData(t *testing.T) {
	var mu sync.Mutex
	var queries []string

	srv := httptest.NewServer(onlyThese(map[string]http.HandlerFunc{
		"sessions": func(w http.ResponseWriter, r *http.Request) {
			q := r.URL.RawQuery
			mu.Lock()
			queries = append(queries, q)
			mu.Unlock()

			w.Header().Set("Content-Type", "application/json")
			// The relation has access_token and nothing else from the list.
			if strings.Contains(q, "select=") && !strings.Contains(q, "select=*") {
				if !strings.Contains(q, "select=access_token") {
					w.WriteHeader(http.StatusBadRequest)
					w.Write([]byte(`{"code":"42703","message":"column x does not exist"}`))
					return
				}
			}
			w.Header().Set("Content-Range", "*/17")
			w.WriteHeader(http.StatusPartialContent)
			w.Write([]byte(`[]`))
		},
	}))
	defer srv.Close()

	c := client.New(client.Options{BaseURL: srv.URL, AnonKey: "k", RestPrefix: "/"})
	res := Run(context.Background(), c, []string{"sessions"}, Options{Measure: true, SampleRows: 3})

	mu.Lock()
	defer mu.Unlock()
	for _, q := range queries {
		if !strings.Contains(q, "limit=0") {
			t.Errorf("a column probe asked for rows (%q); the point of learning column "+
				"names this way is that no data moves", q)
		}
	}

	var rel Relation
	for _, r := range res.Relations {
		rel = r
	}
	if len(rel.Sample) != 0 {
		t.Fatalf("%d rows retrieved in a measurement run", len(rel.Sample))
	}
	if len(rel.Columns) != 1 || rel.Columns[0] != "access_token" {
		t.Errorf("columns = %v, want exactly [access_token]: the probe must report the "+
			"names that resolved and no others", rel.Columns)
	}
	if len(rel.Sensitive) == 0 {
		t.Error("access_token was found on a publicly readable table and the relation was " +
			"not marked sensitive, so it would be reported at the same severity as a table " +
			"of blog posts")
	}
}

// Every budget in this scanner is bounded and says so when it binds. This one
// was added without either.
//
// 33 candidate column names per exposed relation is 2,640 requests against a
// project with 80 of them -- which a 100-site sample actually contained -- and
// 16,500 against one with 500. Politeness in practice is not a bound.
//
// The budget is all-or-nothing per relation on purpose: a half-probed relation
// would report "no sensitive columns" for the names it never asked about,
// which is worse than reporting that it did not look.
func TestColumnProbingIsBoundedAndDisclosed(t *testing.T) {
	var probes atomic.Int64
	serve := func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.RawQuery
		if strings.Contains(q, "select=") && !strings.Contains(q, "select=*") {
			probes.Add(1)
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(`{"code":"42703","message":"no such column"}`))
			return
		}
		w.Header().Set("Content-Range", "*/10")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusPartialContent)
		w.Write([]byte(`[]`))
	}

	names := make([]string, 20)
	present := make(map[string]http.HandlerFunc, len(names))
	for i := range names {
		names[i] = "t" + string(rune('a'+i))
		present[names[i]] = serve
	}
	// The served set is built FROM the seeded list, so the fixture and the scan
	// cannot disagree about which relations exist -- and a scan that probed a
	// name outside it is told the truth rather than handed rows.
	srv := httptest.NewServer(onlyThese(present))
	defer srv.Close()

	c := client.New(client.Options{BaseURL: srv.URL, AnonKey: "k", RestPrefix: "/"})
	const limit = 100
	res := Run(context.Background(), c, names, Options{Measure: true, MaxColumnProbes: limit})

	if got := probes.Load(); got > limit {
		t.Errorf("%d column probes issued against a budget of %d; the bound is not a bound",
			got, limit)
	}
	if !res.ColumnBudgetBound {
		t.Fatal("20 relations at 33 candidates cannot fit in 100 probes, and the result " +
			"does not report the budget as bound -- so severity is understated in silence")
	}

	// All-or-nothing: no relation may be partially probed.
	var partial int
	for _, rel := range res.Relations {
		if rel.ColumnsUnprobed && len(rel.Columns) > 0 {
			partial++
		}
	}
	if partial > 0 {
		t.Errorf("%d relations were partially probed; the unasked names would read as "+
			"absent", partial)
	}

	f := ColumnBudgetFinding("http://x/rest/v1", res.ColumnProbesUsed, limit,
		res.ColumnsUnprobedCount)
	if !strings.Contains(f.Description, "LOWER BOUND") {
		t.Error("the finding does not say severity is a lower bound, which is the only " +
			"thing it exists to say")
	}
	// And the count of what went unclassified, which is the number a reader
	// acts on: the probe is all-or-nothing per relation, so "0 probes used"
	// alone reads as though nothing was truncated.
	if res.ColumnsUnprobedCount == 0 {
		t.Fatal("no relation went unprobed, so this case is not the one it describes")
	}
	if !strings.Contains(f.Evidence.Reason, "relation(s) left unclassified") {
		t.Errorf("evidence %q reports probes spent rather than relations missed",
			f.Evidence.Reason)
	}
}

// And with room to spare it must not fire, or the disclosure is noise.
func TestColumnBudgetSilentWhenItFits(t *testing.T) {
	srv := httptest.NewServer(onlyThese(map[string]http.HandlerFunc{
		"one": func(w http.ResponseWriter, r *http.Request) {
			if strings.Contains(r.URL.RawQuery, "select=") && !strings.Contains(r.URL.RawQuery, "select=*") {
				w.WriteHeader(http.StatusBadRequest)
				w.Write([]byte(`{"code":"42703","message":"no"}`))
				return
			}
			w.Header().Set("Content-Range", "*/10")
			w.WriteHeader(http.StatusPartialContent)
			w.Write([]byte(`[]`))
		},
	}))
	defer srv.Close()

	c := client.New(client.Options{BaseURL: srv.URL, AnonKey: "k", RestPrefix: "/"})
	res := Run(context.Background(), c, []string{"one"}, Options{Measure: true})
	if res.ColumnBudgetBound {
		t.Error("one relation exhausted the default budget, so the disclosure would fire " +
			"on ordinary scans and be ignored")
	}
}
