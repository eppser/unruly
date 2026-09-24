//go:build js && wasm

// Command unruly-wasm is the browser build of the scanner.
//
// WHY A BROWSER BUILD EXISTS, AND WHAT IT COSTS.
//
// The first version of this file asked the operator to paste their project URL
// and anon key, on the belief that a browser cannot read another origin's HTML
// and so cannot do what the CLI does: find the key in the application's own
// bundle. That belief came from testing the apex domains of hosting providers,
// which answer a redirect and no CORS header, and it was wrong. A REAL
// deployed page answers differently:
//
//	https://www.sdy.mn/                 200  access-control-allow-origin: *
//	https://www.sdy.mn/assets/index.js  200  access-control-allow-origin: *
//
// Vercel, and the static hosts vibe-coded apps land on, serve their assets
// cross-origin. So the whole chain works here: fetch the page, read its script
// tags, fetch those, and recover the project reference and publishable key
// exactly as the CLI does, with the same patterns from internal/creds.
//
// A URL is therefore all this needs. Where a host does NOT send the header the
// fetch fails, and the page says so and offers the manual path rather than
// reporting a clean result it did not earn.
//
// What remains true: the database itself is reachable from a browser because
// these platforms are built for browsers. A Supabase project answers a
// preflight from any origin with access-control-allow-origin: *, and names
// Content-Range in access-control-expose-headers, which is where the row count
// is read from.
//
// PostgREST will not list the schema to an anon key -- Supabase answers the
// OpenAPI root with "Only the `service_role` API key can be used for this
// endpoint" -- so relation names are guessed from the same pinned wordlist the
// CLI uses.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"sort"
	"strings"
	"sync"
	"syscall/js"
	"time"

	"net/url"
	"regexp"

	"github.com/eppser/unruly/internal/browserscan"
	"github.com/eppser/unruly/internal/classify"
	"github.com/eppser/unruly/internal/creds"
	"github.com/eppser/unruly/internal/postgrest"
)

// sampleRows is how many rows are read from an exposed relation.
//
// Three, the same as the CLI. Enough to classify what the column holds and
// few enough that the tool is not quietly making a copy of the data it is
// reporting on. Values are classified and discarded; only kinds are returned.
const sampleRows = 3

// browserBudget caps how many names are probed.
//
// The CLI asks about 884 conventional names when it has nothing to harvest.
// In a browser that is 884 round trips on someone's home wifi with a progress
// bar they are watching, so this build asks about fewer and SAYS SO in the
// result. A scan that quietly checked less than the operator believes is the
// failure this whole project exists to avoid.
const browserBudget = 240

// workers bounds requests in flight. The target is someone's own project and
// this is a browser tab, not a load generator.
const workers = 8

type finding struct {
	Relation string   `json:"relation"`
	State    string   `json:"state"`
	Rows     int      `json:"rows"`
	Kinds    []string `json:"kinds"`
	// Examples are MASKED, by internal/browserscan.Mask, and keep at most four
	// characters of any original value. "contact" tells a reader nothing;
	// "a•••@n•••.de" tells them it is their customer list. That is the entire
	// reason this field exists, and the mask is the entire reason it is
	// defensible. Keyed by kind.
	Examples map[string][]string `json:"examples,omitempty"`
	// Columns names only, never values, so the page can say how wide the
	// exposure is without widening it.
	Columns []string `json:"columns,omitempty"`
	// SampleValues carries REAL values, keyed by column, for one purpose: the
	// optional model needs something to classify and it runs in this browser.
	// They never reach a server, because there is none, and the page must
	// never render them -- what it renders is Examples, which is masked. The
	// two fields exist separately so that distinction is visible here rather
	// than resting on a caller's discipline.
	SampleValues map[string][]string `json:"sample_values,omitempty"`
	// Preview is one MASKED value per column, for every readable table rather
	// than only the ones a rule recognised. Most tables hold nothing
	// structural, and "readable" on its own reads as harmless.
	Preview []browserscan.Field `json:"preview,omitempty"`
	// RuleColumns is what the RULES read, per column. The page uses it to
	// decide which columns the model may be asked about, and which classes it
	// must not repeat. Without it the page compared kind names against column
	// names, which never match, so the model re-reported proofs as opinions.
	RuleColumns map[string][]string `json:"rule_columns,omitempty"`
}

// valuesOf collects the sampled values per column, for the model to read.
// Capped at three per column: enough to classify, and the same number the CLI
// samples.
func valuesOf(rows []map[string]any) map[string][]string {
	out := map[string][]string{}
	for _, r := range rows {
		for c, v := range r {
			s, ok := v.(string)
			if !ok || s == "" || len(out[c]) >= 3 {
				continue
			}
			out[c] = append(out[c], s)
		}
	}
	return out
}

// columnsOf names the columns a sample came back with.
func columnsOf(rows []map[string]any) []string {
	seen := map[string]bool{}
	var out []string
	for _, r := range rows {
		for c := range r {
			if !seen[c] {
				seen[c] = true
				out = append(out, c)
			}
		}
	}
	sort.Strings(out)
	return out
}

// reRef matches a project reference wherever it appears, in the page or in a
// bundle. Same shape as internal/discover uses.
var reRef = regexp.MustCompile(`([a-z0-9]{20})\.supabase\.co`)

// reScript pulls script sources out of the HTML. Deliberately forgiving about
// quoting and attribute order, because this parses real minified output from
// whatever bundler the app happened to use, not a document we control.
var reScript = regexp.MustCompile(`(?i)<script[^>]+src=["']([^"']+)["']`)

// maxBundles caps how many scripts are read.
//
// The reference is usually in the main entry chunk, and every extra fetch is a
// second of someone waiting. Eight covers the apps seen so far and keeps a
// page with a hundred code-split chunks from turning this into a crawl.
const maxBundles = 8

type discovered struct {
	Ref    string `json:"ref"`
	Key    string `json:"key"`
	Source string `json:"source"`
	// Text is every byte discovery read: the page and its bundles. It is
	// handed to the scan so the probe list can be built from the names the
	// application states outright. Never rendered, never stored.
	Text string `json:"-"`
}

// discover recovers the project reference and publishable key from an app's
// own front end, the way the CLI does.
//
// Returns a reason, not an error, when it cannot: the page turns that into an
// explanation and the manual fallback. A browser fetch that fails CORS reports
// nothing useful about WHY, so the reason here is deliberately about what the
// operator can do next rather than about the network.
func discover(c *http.Client, page string) (discovered, string) {
	body, err := get(c, page)
	blocked := err != nil
	if blocked {
		// Some hosts send CORS on every path EXCEPT the rendered page.
		// Measured on a Cloudflare + Next.js site from a github.io origin:
		// the page carries no access-control-allow-origin, while robots.txt,
		// a 404 and every static chunk carry "*". A framework's 404 is still
		// one of its pages and loads the same script tags, so a readable 404
		// names the bundles the unreadable page would have named.
		probe := browserscan.ProbePath(page)
		// getAny, not get: this probe EXISTS to return 404, and get rejects
		// anything over 400. The first version of this fallback threw away the
		// exact body it went looking for.
		if b, e := getAny(c, probe); e == nil && browserscan.SameOrigin(page, probe) {
			body, err, blocked = b, nil, false
		}
	}
	if err != nil {
		return discovered{}, "could not read " + page + ", and its 404 page was not " +
			"readable either. The site blocks other websites from reading it, which is " +
			"a reasonable thing for it to do."
	}
	sources := []string{page}
	texts := []string{body}

	base, _ := url.Parse(page)
	seen := map[string]bool{}
	for _, m := range reScript.FindAllStringSubmatch(body, -1) {
		if len(texts) > maxBundles {
			break
		}
		ref, err := url.Parse(m[1])
		if err != nil {
			continue
		}
		abs := base.ResolveReference(ref).String()
		if seen[abs] || !strings.Contains(abs, ".js") {
			continue
		}
		seen[abs] = true
		if b, err := get(c, abs); err == nil {
			sources = append(sources, abs)
			texts = append(texts, b)
		}
	}

	for i, t := range texts {
		ref := ""
		if m := reRef.FindStringSubmatch(t); m != nil {
			ref = m[1]
		}
		key := ""
		if m := creds.Publishable.FindString(t); m != "" {
			key = m
		} else if m := creds.JWT.FindString(t); m != "" && creds.JWTRole(m) == "anon" {
			key = m
			if ref == "" {
				ref = creds.JWTProjectRef(m)
			}
		}
		if ref != "" && key != "" {
			return discovered{Ref: ref, Key: key, Source: sources[i],
				Text: strings.Join(texts, "\n")}, ""
		}
	}
	if len(texts) == 1 {
		return discovered{}, "read the page but found no JavaScript to search. " +
			"If this is a single page app the scripts may load later."
	}
	// "could not read it" and "read it and there is nothing there" are
	// different facts about someone's site, and the second is the more
	// reassuring one. Saying the first when the second is true is the kind of
	// error this scanner exists to refuse.
	return discovered{}, "read the page and " + fmt.Sprint(len(texts)-1) +
		" of its scripts, and found no Supabase project in any of them. That is a " +
		"result, not a failure: this page only checks Supabase, so a site built on " +
		"something else will land here."
}

// getAny reads a body whatever the status says.
//
// A 404 from a single page app is still that app's shell, with the same script
// tags in it, and that is the only reason the CORS fallback works at all.
func getAny(c *http.Client, u string) (string, error) {
	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		return "", err
	}
	resp, err := c.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 6<<20))
	return string(b), err
}

func get(c *http.Client, u string) (string, error) {
	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		return "", err
	}
	resp, err := c.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 6<<20))
	return string(b), err
}

// Backend selectors, NOT finding ids.
//
// These carried a provider prefix at first, and internal/eval's id coverage
// check read them as finding ids: its pattern matches any quoted literal in
// production source beginning supabase-, unruly-, app- or firebase-. It failed
// because no test named them and docs/checks.md did not document them.
//
// The check was right to look. A literal of that shape in the scanner IS a
// finding id everywhere else in this repository, so these are named without a
// provider prefix and the two namespaces stay apart. The comment avoids the
// shape too, because the extractor reads raw text rather than syntax.
const (
	kindRTDB       = "rtdb"
	kindFirestore  = "firestore"
	kindPocketBase = "pocketbase"
	kindSupabase   = "supabase"
)

// ---- other backends -------------------------------------------------------
//
// All of these answer a browser. Measured from a github.io origin: Firebase
// RTDB and Firestore echo the origin, Firebase Storage and PocketBase answer
// "*". An earlier version of this page called them CLI-only, which was this
// build's scope presented as a platform limit.
//
// Each is probed at its OWN shape. The grading is the same question
// throughout: did an anonymous caller get rows back.

// probeRTDB asks a Realtime Database path for data. RTDB answers a wide-open
// rule with the data itself and a closed one with 401.
func probeRTDB(c *http.Client, base, path string) (f finding, ok bool) {
	url := strings.TrimRight(base, "/") + "/" + path + ".json?shallow=true"
	resp, err := c.Get(url)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	switch {
	case resp.StatusCode == http.StatusOK && len(body) > 4 && string(body) != "null":
		var rows []map[string]any
		if json.Unmarshal(body, &rows) != nil {
			var obj map[string]any
			if json.Unmarshal(body, &obj) == nil {
				rows = []map[string]any{obj}
			}
		}
		f = finding{Relation: path, State: "exposed", Rows: len(rows)}
		if len(rows) > 0 {
			f.Kinds = classify.Kinds(rows)
			f.Examples = browserscan.Examples(rows, 2)
			f.Preview = browserscan.Preview(rows, 10)
			f.Columns = columnsOf(rows)
		}
		return f, true
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		return finding{Relation: path, State: "denied"}, true
	}
	return
}

// probeFirestore asks a collection for documents through the REST API.
func probeFirestore(c *http.Client, project, apiKey, collection string) (f finding, ok bool) {
	url := fmt.Sprintf("https://firestore.googleapis.com/v1/projects/%s/databases/(default)/documents/%s?pageSize=3",
		project, collection)
	if apiKey != "" {
		url += "&key=" + apiKey
	}
	resp, err := c.Get(url)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusUnauthorized {
		return finding{Relation: collection, State: "denied"}, true
	}
	if resp.StatusCode != http.StatusOK {
		return
	}
	var doc struct {
		Documents []struct {
			Fields map[string]map[string]any `json:"fields"`
		} `json:"documents"`
	}
	if json.Unmarshal(body, &doc) != nil || len(doc.Documents) == 0 {
		return
	}
	// Firestore wraps every value in a type envelope: {"stringValue":"x"}.
	// Unwrap so the SAME classifier sees the same shape it sees elsewhere.
	rows := make([]map[string]any, 0, len(doc.Documents))
	for _, d := range doc.Documents {
		row := map[string]any{}
		for k, typed := range d.Fields {
			for _, v := range typed {
				row[k] = v
				break
			}
		}
		rows = append(rows, row)
	}
	f = finding{Relation: collection, State: "exposed", Rows: len(rows),
		Kinds: classify.Kinds(rows), Examples: browserscan.Examples(rows, 2),
		Preview: browserscan.Preview(rows, 10), Columns: columnsOf(rows)}
	return f, true
}

// probePocketBase asks a collection for records.
func probePocketBase(c *http.Client, base, collection string) (f finding, ok bool) {
	url := fmt.Sprintf("%s/api/collections/%s/records?perPage=3",
		strings.TrimRight(base, "/"), collection)
	resp, err := c.Get(url)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return finding{Relation: collection, State: "denied"}, true
	}
	if resp.StatusCode != http.StatusOK {
		return
	}
	var page struct {
		TotalItems int              `json:"totalItems"`
		Items      []map[string]any `json:"items"`
	}
	if json.Unmarshal(body, &page) != nil || len(page.Items) == 0 {
		return
	}
	f = finding{Relation: collection, State: "exposed", Rows: page.TotalItems,
		Kinds: classify.Kinds(page.Items), Examples: browserscan.Examples(page.Items, 2),
		Preview: browserscan.Preview(page.Items, 10), Columns: columnsOf(page.Items)}
	return f, true
}

func main() {
	js.Global().Set("unrulyScan", js.FuncOf(scan))
	js.Global().Set("unrulyDiscover", js.FuncOf(discoverJS))
	// The model runs in JavaScript, because WebGPU does. But the taxonomy, the
	// prompt and the gate stay HERE, in tested Go, so the page cannot quietly
	// grow a second opinion about what counts as a finding.
	js.Global().Set("unrulyModelPrompt", js.FuncOf(modelPromptJS))
	js.Global().Set("unrulyPick", js.FuncOf(pickJS))
	js.Global().Set("unrulyBackends", js.FuncOf(backendsJS))
	js.Global().Set("unrulyNormalise", js.FuncOf(normaliseJS))
	js.Global().Set("unrulyVersion", js.ValueOf(version))
	select {} // the Go runtime must stay alive for the exported func to work
}

var version = "dev"

// normaliseJS(typed) turns what a person typed into an address, or "" when it
// is not one. In Go so the rule is tested, rather than a regex in the page
// that quietly disagrees with it.
func normaliseJS(this js.Value, args []js.Value) any {
	if len(args) < 1 {
		return ""
	}
	return js.ValueOf(browserscan.NormaliseSite(args[0].String()))
}

// backendsJS(text) lists every database an application points at.
func backendsJS(this js.Value, args []js.Value) any {
	if len(args) < 1 {
		return "[]"
	}
	b, err := json.Marshal(browserscan.DetectBackends(args[0].String()))
	if err != nil {
		return "[]"
	}
	return js.ValueOf(string(b))
}

// modelPromptJS(column, valuesCSV) returns the prompt for one column.
func modelPromptJS(this js.Value, args []js.Value) any {
	if len(args) < 2 {
		return ""
	}
	var vals []string
	if v := args[1].String(); v != "" {
		vals = strings.Split(v, " | ")
	}
	return js.ValueOf(browserscan.ModelPrompt(args[0].String(), vals))
}

// pickJS(topLogprobsJSON, threshold) renormalises over the declared slots and
// applies the gate, with the same code the tests cover.
//
// The page hands over whatever the runtime returned, as {token: logprob}. It
// does not decide anything: a page that computed its own confidence would be
// a second implementation of the only thing keeping the model's false
// positives out of the report.
func pickJS(this js.Value, args []js.Value) any {
	if len(args) < 2 {
		return js.ValueOf(map[string]any{"class": "", "p": 0.0})
	}
	var raw map[string]float64
	if err := json.Unmarshal([]byte(args[0].String()), &raw); err != nil {
		return js.ValueOf(map[string]any{"class": "", "p": 0.0})
	}
	w := make(map[string]float64, len(raw))
	for tok, lp := range raw {
		w[tok] = math.Exp(lp)
	}
	name, p := browserscan.PickClass(w, args[1].Float())
	return js.ValueOf(map[string]any{"class": name, "p": p})
}

// scan(baseURL, anonKey, onProgress, onDone) is what the page calls.
//
// Asynchronous, because a synchronous scan would freeze the tab: syscall/js
// callbacks run on the single goroutine the browser gives us, and blocking it
// blocks rendering, so the progress the operator is watching would never move.
func scan(this js.Value, args []js.Value) any {
	if len(args) < 4 {
		return nil
	}
	base := strings.TrimRight(args[0].String(), "/")
	key := strings.TrimSpace(args[1].String())
	onProgress, onDone := args[2], args[3]
	kind, ref := "supabase", ""
	if len(args) > 5 {
		kind = args[5].String()
	}
	if len(args) > 6 {
		ref = args[6].String()
	}
	// The bundle discovery already downloaded, so the scan can probe the names
	// the app states outright instead of guessing. Empty when the operator
	// entered the details by hand, which is why the pinned list still matters.
	var bundleText string
	if len(args) > 4 {
		bundleText = args[4].String()
	}

	go func() {
		defer func() {
			// A panic here would kill the Go runtime and leave the page
			// spinning with no way to say what happened.
			if r := recover(); r != nil {
				onDone.Invoke(js.ValueOf(map[string]any{
					"error": fmt.Sprintf("%v", r),
				}))
			}
		}()
		runKind(kind, base, key, ref, bundleText, onProgress, onDone)
	}()
	return nil
}

// discoverJS(pageURL, onDone) exposes discovery on its own, so the page can
// show what it found and let the operator confirm it before anything is
// probed. Finding the key is not the same act as using it, and the interface
// should not blur the two.
func discoverJS(this js.Value, args []js.Value) any {
	if len(args) < 2 {
		return nil
	}
	page, onDone := args[0].String(), args[1]
	go func() {
		defer func() {
			if r := recover(); r != nil {
				onDone.Invoke(js.ValueOf(map[string]any{"reason": fmt.Sprintf("%v", r)}))
			}
		}()
		d, reason := discover(&http.Client{Timeout: 25 * time.Second}, page)
		if reason != "" {
			onDone.Invoke(js.ValueOf(map[string]any{"reason": reason}))
			return
		}
		onDone.Invoke(js.ValueOf(map[string]any{
			"ref": d.Ref, "key": d.Key, "source": d.Source,
			"base":  "https://" + d.Ref + ".supabase.co",
			"text":  d.Text,
			"named": len(browserscan.Named(d.Text)),
		}))
	}()
	return nil
}

func run(base, key, bundleText string, onProgress, onDone js.Value) {
	runKind("supabase", base, key, "", bundleText, onProgress, onDone)
}

// runKind scans whichever backend was detected. The name list is shared: a
// vibe-coded Firestore collection is named after the domain exactly as a
// Postgres table is, and the app's own code names both.
func runKind(kind, base, key, ref, bundleText string, onProgress, onDone js.Value) {
	// Candidates come from internal/browserscan, which is NOT build-tagged and
	// therefore has tests. This line previously read
	// wordlist.RelationCandidates(nil, browserBudget), which returns an empty
	// slice: the scan probed nothing and the page reported "Nothing readable
	// was found" for a project with 30 relations.
	names := browserscan.Candidates(bundleText, browserBudget)
	if len(names) == 0 {
		onDone.Invoke(js.ValueOf(map[string]any{
			"error": "there was nothing to probe, so no conclusion can be drawn about " +
				"this project. This is a bug in the scanner, not a result.",
		}))
		return
	}
	client := &http.Client{Timeout: 20 * time.Second}

	type result struct {
		f  finding
		ok bool
	}
	out := make([]result, len(names))
	jobs := make(chan int)
	done := make(chan struct{})

	var completed int
	progress := make(chan string, len(names))
	go func() {
		for range progress {
			completed++
			onProgress.Invoke(js.ValueOf(map[string]any{
				"done": completed, "total": len(names),
			}))
		}
		close(done)
	}()

	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				switch kind {
				case kindRTDB:
					out[i].f, out[i].ok = probeRTDB(client, base, names[i])
				case kindFirestore:
					out[i].f, out[i].ok = probeFirestore(client, ref, key, names[i])
				case kindPocketBase:
					out[i].f, out[i].ok = probePocketBase(client, base, names[i])
				default:
					out[i] = probe(client, base, key, names[i])
				}
				progress <- names[i]
			}
		}()
	}
	for i := range names {
		jobs <- i
	}
	close(jobs)
	wg.Wait()
	close(progress)
	<-done

	var exposed, empty, denied []finding
	for _, r := range out {
		if !r.ok {
			continue
		}
		switch r.f.State {
		case "exposed":
			exposed = append(exposed, r.f)
		case "empty":
			empty = append(empty, r.f)
		case "denied":
			denied = append(denied, r.f)
		}
	}
	sort.Slice(exposed, func(i, j int) bool { return exposed[i].Rows > exposed[j].Rows })

	payload, _ := json.Marshal(map[string]any{
		"exposed":  exposed,
		"empty":    empty,
		"denied":   denied,
		"probed":   len(names),
		"budgeted": browserBudget,
	})
	onDone.Invoke(js.ValueOf(map[string]any{"result": string(payload)}))
}

// probe asks about one relation and grades the answer with the SAME code the
// CLI uses, so the two cannot drift into disagreeing about what "exposed"
// means.
func probe(c *http.Client, base, key, name string) (r struct {
	f  finding
	ok bool
}) {
	url := fmt.Sprintf("%s/rest/v1/%s?select=*&limit=%d", base, name, sampleRows)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return
	}
	req.Header.Set("apikey", key)
	req.Header.Set("Authorization", "Bearer "+key)
	req.Header.Set("Prefer", "count=exact")
	resp, err := c.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	state, rows := postgrest.ClassifyRead(resp.StatusCode, resp.Header.Get("Content-Range"), len(body))
	f := finding{Relation: name, Rows: rows}
	switch state {
	case postgrest.ReadExposed:
		f.State = "exposed"
		var sample []map[string]any
		if json.Unmarshal(body, &sample) == nil {
			f.Kinds = classify.Kinds(sample)
			f.Examples = browserscan.Examples(sample, 2)
			f.Columns = columnsOf(sample)
			f.SampleValues = valuesOf(sample)
			f.Preview = browserscan.Preview(sample, 10)
			f.RuleColumns = browserscan.RuleColumns(sample)
		}
	case postgrest.ReadEmpty:
		f.State = "empty"
	case postgrest.ReadDenied:
		f.State = "denied"
	default:
		return
	}
	return struct {
		f  finding
		ok bool
	}{f, true}
}
