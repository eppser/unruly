package probe

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/eppser/unruly/internal/client"
	"github.com/eppser/unruly/internal/finding"
)

// The count the SERVER reports must survive all the way to the rendered table.
//
// Three components sit between the response header and the cell an operator
// reads -- ClassifyRead parses Content-Range, Findings copies it into
// Evidence.Rows, and Table renders it -- and each was covered on its own. A
// value can be dropped at any junction between them and every one of those
// tests still passes, which is how "how much data is exposed" managed to be
// absent from the summary table while the number was in the scan the whole
// time.
//
// So this drives the real Run against a real server and asserts on the real
// rendering: the number in the header comes out in the cell.
func TestTheServersRowCountReachesTheRenderedTable(t *testing.T) {
	serve := func(total string, body string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Range", "0-2/"+total)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusPartialContent)
			w.Write([]byte(body))
		}
	}
	srv := httptest.NewServer(onlyThese(map[string]http.HandlerFunc{
		"sessions":   serve("41233", `[{"id":1,"access_token":"x"}]`),
		"agent_runs": serve("474", `[{"id":1}]`),
	}))
	defer srv.Close()

	c := client.New(client.Options{BaseURL: srv.URL, AnonKey: "k", RestPrefix: "/"})
	res := Run(context.Background(), c, []string{"sessions", "agent_runs"}, Options{SampleRows: 3})

	// The premise: the probe actually read both, and recorded the counts.
	counts := map[string]int{}
	for _, rel := range res.Relations {
		counts[rel.Name] = rel.Rows
	}
	if counts["sessions"] != 41233 || counts["agent_runs"] != 474 {
		t.Fatalf("premise broken: the probe recorded %v, so this test cannot show the "+
			"count reaching the table", counts)
	}

	table := finding.Table(res.Findings(srv.URL, false), true)

	for name, want := range map[string]string{"sessions": "41233", "agent_runs": "474"} {
		var row string
		for _, l := range strings.Split(table, "\n") {
			if strings.Contains(l, name) {
				row = l
			}
		}
		if row == "" {
			t.Errorf("no row for %s in:\n%s", name, table)
			continue
		}
		if !strings.Contains(row, want) {
			t.Errorf("%s: the server reported %s rows and the table row does not carry it: %q",
				name, want, row)
		}
	}
}

// A relation the server gives no count for is rendered as unknown.
//
// PostgREST omits the total when the planner declines to count -- "*/*" -- and
// that is a different fact from zero. Driven through the same real path,
// because the "?" is only worth anything if it appears when the server
// genuinely said nothing.
func TestARelationWithNoServerCountRendersAsUnknown(t *testing.T) {
	srv := httptest.NewServer(onlyThese(map[string]http.HandlerFunc{
		"survival_series": func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Range", "*/*")
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusPartialContent)
			w.Write([]byte(`[{"id":1}]`))
		},
	}))
	defer srv.Close()

	c := client.New(client.Options{BaseURL: srv.URL, AnonKey: "k", RestPrefix: "/"})
	res := Run(context.Background(), c, []string{"survival_series"}, Options{SampleRows: 3})

	table := finding.Table(res.Findings(srv.URL, false), true)
	var row string
	for _, l := range strings.Split(table, "\n") {
		if strings.Contains(l, "survival_series") {
			row = l
		}
	}
	if row == "" {
		t.Fatalf("no row for survival_series in:\n%s", table)
	}
	if !strings.Contains(row, "?") {
		t.Errorf("the server reported no total and the table does not say so: %q", row)
	}
	if strings.Contains(row, " 0 ") {
		t.Errorf("an uncounted relation is rendered as holding 0 rows: %q", row)
	}
}
