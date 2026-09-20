package provider

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/eppser/unruly/internal/client"
	"github.com/eppser/unruly/internal/testrec"
)

// A Firestore scan spends the target's money, and the operator can bound it.
//
// Every collection probe is a query against the target's quota and may be
// billable. The response does not expose the billed read count, so the report
// must state the traffic without inventing a charge.
//
// -max-collections is the bound. What it must NOT do is take the first N
// alphabetically: that would spend the whole budget on names beginning with a
// and report a lower bound whose gap is one contiguous slice of the list.
func TestFirestoreCollectionBudgetIsBoundedAndSpread(t *testing.T) {
	var probes atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, ":runQuery") {
			probes.Add(1)
		}
		w.WriteHeader(403)
		_, _ = w.Write([]byte(`{"error":{"status":"PERMISSION_DENIED"}}`))
	}))
	defer srv.Close()
	old := firestoreHost
	firestoreHost = srv.URL
	t.Cleanup(func() { firestoreHost = old })

	var names []string
	for i := 0; i < 400; i++ {
		names = append(names, "collection_"+strconv.Itoa(i))
	}
	d := Detection{Provider: "firebase", Project: "p", Credential: "AIzaFAKE"}
	o := ScanOptions{Client: client.New(client.Options{Retries: 0}), Candidates: names}

	// Unbounded: every name is asked about.
	probes.Store(0)
	firestoreFindings(context.Background(), d, o)
	if got := probes.Load(); got != 400 {
		t.Errorf("unbounded scan made %d probes for 400 names", got)
	}

	// Bounded: the budget is honoured, and the report says what it cost.
	probes.Store(0)
	o.MaxCollections = 40
	fs := firestoreFindings(context.Background(), d, o)
	if got := probes.Load(); got != 40 {
		t.Errorf("-max-collections 40 made %d probes; a budget nothing enforces is a "+
			"flag that lies to whoever is paying for the reads", got)
	}
	var bound string
	for _, f := range fs {
		if strings.Contains(f.Description, "name(s) were tried") {
			bound = f.Description
		}
	}
	if !strings.Contains(bound, "40 name(s) were tried") {
		t.Errorf("the recall bound does not report the budget that produced it:\n%s", bound)
	}
	if !strings.Contains(bound, "quota") || !strings.Contains(bound, "may be billable") {
		t.Errorf("the report does not disclose the target-side cost without inventing a "+
			"document-read charge:\n%s", bound)
	}
}

// The bound spends its budget across the whole list.
func TestFirestoreBudgetIsNotTheFirstNNames(t *testing.T) {
	var asked testrec.Log
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			StructuredQuery struct {
				From []struct {
					CollectionID string `json:"collectionId"`
				} `json:"from"`
			} `json:"structuredQuery"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		if len(body.StructuredQuery.From) > 0 {
			asked.Add(body.StructuredQuery.From[0].CollectionID)
		}
		w.WriteHeader(403)
	}))
	defer srv.Close()
	old := firestoreHost
	firestoreHost = srv.URL
	t.Cleanup(func() { firestoreHost = old })

	names := []string{"aaa", "aab", "aac", "mmm", "mmn", "zzx", "zzy", "zzz"}
	firestoreFindings(context.Background(),
		Detection{Provider: "firebase", Project: "p", Credential: "k"},
		ScanOptions{Client: client.New(client.Options{Retries: 0}),
			Candidates: names, MaxCollections: 4})

	var sawLate bool
	for _, n := range asked.Entries() {
		if strings.HasPrefix(n, "z") {
			sawLate = true
		}
	}
	if !sawLate {
		t.Errorf("the budget was spent on %v, all from the start of the list. A lower "+
			"bound whose gap is one contiguous slice of the alphabet is worse than one "+
			"spread across it, because nothing in the report says which slice", asked.Entries())
	}
}
