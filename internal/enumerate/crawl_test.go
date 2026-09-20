package enumerate

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// Vocabulary that only exists on a linked page must still be found.
//
// Harvesting reads nine conventional paths and the bundles the front page
// references. An application whose domain words live on /dashboard or
// /invoices -- linked from the home page, absent from any generic list --
// contributes nothing, and the relation named after those words is never
// asked about.
//
// That matters more than it sounds. Recall on this scanner is a function of
// vocabulary: measured on one project, a pinned wordlist alone reached 2 of 7
// relations while the application's own words reached all seven. The words are
// the recall, and half of them are one link away.
//
// Bounded, same-origin, and deterministic, because a crawler that is none of
// those is a crawler nobody should point at somebody else's site.
func TestVocabularyIsHarvestedFromLinkedPages(t *testing.T) {
	var fetched sync.Map
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fetched.Store(r.URL.Path, true)
		switch r.URL.Path {
		case "/":
			// The home page names no relation of its own; it only links on.
			fmt.Fprint(w, `<html><body>
				<a href="/dashboard">Dashboard</a>
				<a href="/invoices">Invoices</a>
				<a href="https://elsewhere.example/leave">Off-site</a>
			</body></html>`)
		case "/dashboard":
			// A word no pinned wordlist would ever guess.
			fmt.Fprint(w, `<html><body><script>
				const q = "/rest/v1/quokka_sightings?select=*";
			</script></body></html>`)
		case "/invoices":
			fmt.Fprint(w, `<html><body><script>
				const t = "wombat_ledger";
			</script></body></html>`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	v := Harvest(context.Background(), HarvestOptions{
		Site: srv.URL, MaxPages: 5, MaxSeeds: 500, MaxBundles: 4,
	})

	seeds := strings.Join(v.Seeds, " ")
	for _, want := range []string{"quokka", "wombat"} {
		if !strings.Contains(seeds, want) {
			t.Errorf("%q is only on a linked page and did not reach the seeds; a relation "+
				"named after it would never be asked about", want)
		}
	}
	// Same origin only. Following a link off the target is a request to
	// somebody who was never the subject of this scan.
	if _, off := fetched.Load("/leave"); off {
		t.Error("an off-origin link was followed")
	}

	// And with crawling off, the behaviour is exactly what it was.
	none := Harvest(context.Background(), HarvestOptions{
		Site: srv.URL, MaxPages: 0, MaxSeeds: 500, MaxBundles: 4,
	})
	if strings.Contains(strings.Join(none.Seeds, " "), "quokka") {
		t.Error("a linked page was read with MaxPages 0, so the bound does not bind")
	}
}

// Deterministic: the same site must produce the same seeds every run, or two
// scans of an unchanged project disagree about what exists.
func TestCrawlIsDeterministic(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			var b strings.Builder
			for i := 0; i < 12; i++ {
				fmt.Fprintf(&b, `<a href="/p%02d">p</a>`, i)
			}
			fmt.Fprintf(w, "<html><body>%s</body></html>", b.String())
			return
		}
		fmt.Fprintf(w, `<html><body><script>const t="tbl_%s";</script></body></html>`,
			strings.TrimPrefix(r.URL.Path, "/p"))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	first := Harvest(context.Background(), HarvestOptions{
		Site: srv.URL, MaxPages: 4, MaxSeeds: 500, MaxBundles: 2,
	})
	for i := 0; i < 5; i++ {
		again := Harvest(context.Background(), HarvestOptions{
			Site: srv.URL, MaxPages: 4, MaxSeeds: 500, MaxBundles: 2,
		})
		if strings.Join(again.Seeds, ",") != strings.Join(first.Seeds, ",") {
			t.Fatalf("run %d harvested a different vocabulary from the same site", i)
		}
	}
	// The cap must bind: 12 pages offered, 4 permitted.
	if first.PagesRead > 4 {
		t.Errorf("read %d pages with MaxPages 4", first.PagesRead)
	}
}
