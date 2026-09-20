package enumerate

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// Vocabulary harvesting is what makes recall work. A generic wordlist matched
// 1 of 21 relations on the reference target; the same target's own JSON keys
// and bundle identifiers reached all 21. So this is the differentiator, and it
// was covered only by live evals.

func app(handlers map[string]string) *httptest.Server {
	mux := http.NewServeMux()
	for path, body := range handlers {
		b := body
		p := path
		mux.HandleFunc(p, func(w http.ResponseWriter, r *http.Request) {
			if strings.HasSuffix(p, ".json") || strings.HasPrefix(p, "/api") {
				w.Header().Set("Content-Type", "application/json")
			}
			w.Write([]byte(b))
		})
	}
	return httptest.NewServer(mux)
}

// JSON keys are the highest-signal source: column names predict relation names,
// and an application publishes its own column names in every API response.
func TestHarvestExtractsJSONKeys(t *testing.T) {
	srv := app(map[string]string{
		"/":                `<html><body>nothing useful here</body></html>`,
		"/api/signatories": `[{"signatory_id":1,"reviewed_at":null,"sort_order":3}]`,
	})
	defer srv.Close()

	v := Harvest(context.Background(), HarvestOptions{
		Site: srv.URL, Paths: []string{"/api/signatories"},
	})
	for _, want := range []string{"signatory_id", "reviewed_at", "sort_order"} {
		if !has(v.Seeds, want) {
			t.Errorf("JSON key %q was not harvested", want)
		}
	}
}

// Nested payloads must be walked: an API that wraps rows in {"data": [...]}
// hides every column name one level down.
func TestHarvestWalksNestedJSON(t *testing.T) {
	srv := app(map[string]string{
		"/":         `<html></html>`,
		"/api/data": `{"data":{"rows":[{"zero_day_count":5,"exploit_pct":1.5}]},"meta":{"page":1}}`,
	})
	defer srv.Close()

	v := Harvest(context.Background(), HarvestOptions{Site: srv.URL, Paths: []string{"/api/data"}})
	for _, want := range []string{"zero_day_count", "exploit_pct"} {
		if !has(v.Seeds, want) {
			t.Errorf("nested key %q was not harvested", want)
		}
	}
}

// Framework noise must not crowd out the domain vocabulary. Seeds are capped,
// so every wasted slot is a relation that might not be reached.
func TestHarvestDropsFrameworkNoise(t *testing.T) {
	srv := app(map[string]string{
		"/": `<html><div class="container"><span style="color:red">
		      <script>function render(){return window.document;}</script></div></html>`,
	})
	defer srv.Close()

	v := Harvest(context.Background(), HarvestOptions{Site: srv.URL})
	for _, noise := range []string{"function", "window", "document", "class", "style", "span"} {
		if has(v.Seeds, noise) {
			t.Errorf("framework token %q should be filtered out", noise)
		}
	}
}

// Determinism: the same site must always produce the same seed list, in the
// same order. Enumeration is capped, so a reordered list would probe a
// different subset and change what the scan finds.
func TestHarvestIsDeterministic(t *testing.T) {
	srv := app(map[string]string{
		"/":        `<html><script src="/_next/static/chunks/app.js"></script></html>`,
		"/api/one": `{"beta_column":1,"alpha_column":2,"gamma_column":3}`,
	})
	defer srv.Close()

	opts := HarvestOptions{Site: srv.URL, Paths: []string{"/api/one"}}
	first := Harvest(context.Background(), opts)
	second := Harvest(context.Background(), opts)

	if len(first.Seeds) != len(second.Seeds) {
		t.Fatalf("seed count differs between runs: %d vs %d", len(first.Seeds), len(second.Seeds))
	}
	for i := range first.Seeds {
		if first.Seeds[i] != second.Seeds[i] {
			t.Fatalf("seed %d differs: %q vs %q", i, first.Seeds[i], second.Seeds[i])
		}
	}
	// Sorted, so the cap truncates the same way every time.
	for i := 1; i < len(first.Seeds); i++ {
		if first.Seeds[i] < first.Seeds[i-1] {
			t.Fatalf("seeds are not sorted at %d: %q after %q",
				i, first.Seeds[i], first.Seeds[i-1])
		}
	}
}

// An unreachable site degrades to an empty vocabulary rather than hanging or
// panicking. The scan then leans on the pinned wordlist, and says so.
func TestHarvestSurvivesAnUnreachableSite(t *testing.T) {
	v := Harvest(context.Background(), HarvestOptions{Site: "http://127.0.0.1:59998"})
	if len(v.Seeds) != 0 {
		t.Errorf("an unreachable site should yield no seeds, got %d", len(v.Seeds))
	}
	if len(v.Sources) != 0 {
		t.Errorf("no sources should be recorded, got %v", v.Sources)
	}
}

// Sources are recorded so a scan can be explained after the fact: which of the
// application's own surfaces contributed the vocabulary.
func TestHarvestRecordsItsSources(t *testing.T) {
	srv := app(map[string]string{
		"/":        `<html></html>`,
		"/api/two": `{"some_column":1}`,
	})
	defer srv.Close()

	v := Harvest(context.Background(), HarvestOptions{Site: srv.URL, Paths: []string{"/api/two"}})
	if !has(v.Sources, "/api/two") {
		t.Errorf("the contributing path should be recorded, got %v", v.Sources)
	}
}

func has(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}

// The seed cap decides which half of an application's vocabulary is looked at.
//
// It binds on ordinary sites: the reference project yields 4,112 tokens against
// a limit of 2,000. Cutting the sorted list at the limit kept the
// alphabetically first half and discarded the rest before a single probe was
// sent -- upstream of relation discovery AND routine discovery, so every later
// stage inherited the blind spot without any of them being wrong.
//
// The cap itself is right: harvesting more costs probes, and probes are
// somebody else's server. What it may not do is pretend that "the first 2,000
// alphabetically" is a sample of the vocabulary.
func TestSeedCapSamplesTheWholeVocabulary(t *testing.T) {
	var page strings.Builder
	page.WriteString(`<html><script>const cfg = {`)
	for c := 'a'; c <= 'z'; c++ {
		for i := 0; i < 60; i++ {
			// JSON keys are the highest-signal thing this harvester reads.
			page.WriteString(string(c) + "_column_name_" + string(rune('0'+i%10)) +
				string(rune('0'+(i/10)%10)) + ":1,")
		}
	}
	page.WriteString(`};</script></html>`)
	body := page.String()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(body))
	}))
	defer srv.Close()

	const budget = 200
	v := Harvest(context.Background(), HarvestOptions{Site: srv.URL, MaxSeeds: budget})

	if len(v.Seeds) == 0 {
		t.Fatal("no seeds harvested, so this test asserts nothing about the cap")
	}
	if len(v.Seeds) > budget {
		t.Fatalf("the cap did not hold: %d seeds for a budget of %d", len(v.Seeds), budget)
	}

	letters := map[byte]bool{}
	for _, s := range v.Seeds {
		letters[s[0]] = true
	}
	// The page offers 26 leading letters and the budget can afford items from
	// all of them. Reaching only the first few means the sample is the front of
	// the alphabet rather than the vocabulary.
	if len(letters) < 20 {
		var got []string
		for c := byte('a'); c <= 'z'; c++ {
			if letters[c] {
				got = append(got, string(c))
			}
		}
		t.Errorf("a binding seed cap reached %d of 26 leading letters (%v); the rest of "+
			"the application's vocabulary is discarded before any probe is sent",
			len(letters), got)
	}
}

// A truncated vocabulary must be reported, not merely sampled well.
//
// The sampling fix made the loss unbiased; it did not make it visible. Seeds
// feed relation discovery AND routine discovery, so this is the most upstream
// bound in the scan and the one neither of those stages can notice. The
// reference project harvests 4,112 tokens against a default of 2,000 and the
// report said nothing at all -- while the routine budget one layer down has
// disclosed "1200 of 7547 probed" since an audit asked for it.
func TestTruncatedVocabularyIsReported(t *testing.T) {
	var page strings.Builder
	page.WriteString(`<html><script>const cfg = {`)
	for c := 'a'; c <= 'z'; c++ {
		for i := 0; i < 20; i++ {
			page.WriteString(string(c) + "_column_name_" + string(rune('0'+i%10)) +
				string(rune('0'+(i/10)%10)) + ":1,")
		}
	}
	page.WriteString(`};</script></html>`)
	body := page.String()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(body))
	}))
	defer srv.Close()

	bound := Harvest(context.Background(), HarvestOptions{Site: srv.URL, MaxSeeds: 50})
	if bound.Harvested <= len(bound.Seeds) {
		t.Fatalf("the cap did not bind (%d harvested, %d kept), so this test asserts nothing",
			bound.Harvested, len(bound.Seeds))
	}

	f := VocabularyBudgetFinding(srv.URL, len(bound.Seeds), bound.Harvested,
		bound.BundlesRead, bound.BundlesFound, bound.PagesRead, bound.PagesFound)
	if !strings.Contains(f.Description, "LOWER BOUND") {
		t.Error("the finding does not say the results are a lower bound, which is the only " +
			"thing it exists to say")
	}
	// The counts have to be in it: "the vocabulary was truncated" is not
	// actionable, "2,000 of 4,112" is.
	if !strings.Contains(f.Evidence.Reason, "50 of") {
		t.Errorf("the finding does not carry the numbers: %q", f.Evidence.Reason)
	}

	// And the other direction: a vocabulary that fits must not be reported as
	// truncated, or the disclosure becomes noise on every scan.
	whole := Harvest(context.Background(), HarvestOptions{Site: srv.URL, MaxSeeds: 100000})
	if whole.Harvested != len(whole.Seeds) {
		t.Errorf("an unbounded harvest reports %d harvested against %d kept; a scan that did "+
			"not truncate would claim it had", whole.Harvested, len(whole.Seeds))
	}
}

// The bundle budget must spend itself on application code.
//
// This is the one cap in the scanner where the stride that fixed the others is
// wrong, and it was only apparent from measuring: applying it to bundles
// dropped harvested tokens on the reference project from 4,112 to 3,808,
// because it discarded an application chunk and kept the webpack runtime.
//
// Seed names carry no signal about which seed is worth probing. Bundle names
// do: a framework runtime chunk contains the framework and no application
// identifiers at all, so reading it in preference to a page chunk spends the
// budget on the one file guaranteed not to mention the data model.
//
// The old front cut got the reference project right by luck -- "webpack" sorts
// last. This is the case where luck runs out: the runtime chunks sort FIRST
// and an application chunk sorts last.
func TestBundleBudgetPrefersApplicationChunks(t *testing.T) {
	runtimeChunks := []string{"/assets/framework-a.js", "/assets/polyfills-a.js",
		"/assets/runtime-a.js", "/assets/webpack-a.js"}
	appChunks := []string{"/assets/app-a.js", "/assets/app-b.js", "/assets/app-c.js",
		"/assets/app-d.js", "/assets/zzz-late.js"}

	var html strings.Builder
	html.WriteString("<html>")
	for _, b := range append(append([]string{}, runtimeChunks...), appChunks...) {
		html.WriteString(`<script src="` + b + `"></script>`)
	}
	html.WriteString("</html>")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, ".js") {
			// Each bundle contributes a token naming itself.
			name := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/assets/"), ".js")
			w.Header().Set("Content-Type", "application/javascript")
			w.Write([]byte("const " + strings.ReplaceAll(name, "-", "_") + "_marker = 1;"))
			return
		}
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(html.String()))
	}))
	defer srv.Close()

	// Nine bundles, room for eight: exactly one must be given up.
	v := Harvest(context.Background(), HarvestOptions{
		Site: srv.URL, MaxBundles: 8, MaxSeeds: 100000})

	if v.BundlesFound != 9 || v.BundlesRead != 8 {
		t.Fatalf("expected 9 bundles found and 8 read, got %d and %d; the fixture is not "+
			"exercising the cap", v.BundlesFound, v.BundlesRead)
	}

	seeds := map[string]bool{}
	for _, s := range v.Seeds {
		seeds[s] = true
	}
	// The application chunk that sorts LAST must still have been read. Under a
	// front cut it is the one thing dropped.
	if !seeds["zzz_late_marker"] {
		t.Error("the application chunk sorting last was dropped in favour of framework " +
			"runtime chunks, so the budget was spent on files that cannot mention the " +
			"data model")
	}
	// And exactly one runtime chunk should have been given up instead.
	var runtimeRead int
	for _, n := range []string{"framework_a_marker", "polyfills_a_marker",
		"runtime_a_marker", "webpack_a_marker"} {
		if seeds[n] {
			runtimeRead++
		}
	}
	if runtimeRead != 3 {
		t.Errorf("%d of 4 runtime chunks were read; expected exactly one to be given up "+
			"for the application chunk", runtimeRead)
	}
}

// Script discovery must follow the page, not a framework convention.
//
// The pattern used to match three prefixes -- /_next/static/, /assets/,
// /static/ -- which is Next.js and Vite and nothing else. A GitHub Pages site
// in a live sample served <script src="script.js">, and that file held the
// project URL and the anon key. The scanner never fetched it and reported the
// site as having no Supabase credentials at all.
//
// The origin boundary is the other half and matters more: a reference to
// another host must never be fetched, because Go strips Authorization across
// hosts but never custom headers, so the apikey would travel to whatever
// address a hostile page names.
func TestScriptDiscoveryFollowsThePageWithinTheOrigin(t *testing.T) {
	var fetched []string
	var mu sync.Mutex

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		fetched = append(fetched, r.URL.Path)
		mu.Unlock()
		if strings.HasSuffix(r.URL.Path, ".js") {
			w.Header().Set("Content-Type", "application/javascript")
			w.Write([]byte(`const marker_` + strings.NewReplacer("/", "_", ".", "_", "-", "_").
				Replace(strings.TrimPrefix(r.URL.Path, "/")) + ` = 1;`))
			return
		}
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<html>
			<script src="script.js"></script>
			<script src="js/app.js"></script>
			<script src="/assets/index-abc.js"></script>
			<script src="./nested/deep.js"></script>
			<script src="https://cdn.example.invalid/tracker.js"></script>
			<script src="//cdn.example.invalid/protocol-relative.js"></script>
		</html>`))
	}))
	defer srv.Close()

	v := Harvest(context.Background(), HarvestOptions{Site: srv.URL, MaxBundles: 20, MaxSeeds: 10000})

	mu.Lock()
	got := append([]string{}, fetched...)
	mu.Unlock()

	for _, want := range []string{"/script.js", "/js/app.js", "/assets/index-abc.js", "/nested/deep.js"} {
		found := false
		for _, p := range got {
			if p == want {
				found = true
			}
		}
		if !found {
			t.Errorf("%s was never fetched; a page that names its own script must have it "+
				"read, or the credentials in it are invisible. fetched=%v", want, got)
		}
	}
	// Tokens from the relative bundle must reach the vocabulary, which is the
	// point of fetching it.
	var sawToken bool
	for _, s := range v.Seeds {
		if strings.Contains(s, "marker_script_js") {
			sawToken = true
		}
	}
	if !sawToken {
		t.Error("the relative bundle was fetched but contributed no vocabulary")
	}
}
