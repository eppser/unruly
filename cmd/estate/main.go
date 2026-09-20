// Command estate summarises a whole scanned estate: which classes of data
// were reached, how much of it, and which regions hold it.
//
//	estate -dir compare-out                     # both tools, side by side files
//	estate -dir compare-out -tool unruly -o -    # one report, to stdout
//	estate -dir scans -regions                   # resolve regions from the account
//
// It reads what a scan already wrote and sends nothing to any target. The one
// exception is -regions, which asks the Supabase management API where the
// operator's own projects live; that is a request to Supabase about the
// operator's account, not to the projects being summarised.
//
// Built for a thousand targets rather than one. Every total is estate-wide,
// because one project leaking `customers` is an incident and four hundred of
// them is the finding, and a report that only ever counts per target leaves
// the reader to do the arithmetic that matters.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/eppser/unruly/internal/finding"
)

var projectRef = regexp.MustCompile(`\b([a-z]{20})\.supabase\.co\b`)

func main() {
	var (
		dir     = flag.String("dir", ".", "directory of scan reports")
		tool    = flag.String("tool", "both", "unruly, supabomb, or both")
		out     = flag.String("o", "", "write here; - for stdout. Default: estate-<tool>.md in -dir")
		asJSON  = flag.Bool("json", false, "also write the summary as JSON")
		regions = flag.Bool("regions", false, "resolve project regions from the Supabase "+
			"management API using SUPABASE_ACCESS_TOKEN")
	)
	flag.Parse()

	byRef := map[string]string{}
	if *regions {
		resolved, err := resolveRegions()
		if err != nil {
			fmt.Fprintf(os.Stderr, "! regions unresolved (%v); they will read as "+
				"\"unknown\" rather than being guessed from the edge that answered\n", err)
		} else {
			byRef = resolved
			fmt.Fprintf(os.Stderr, "resolved %d project region(s) from the account\n", len(byRef))
		}
	}

	wrote := 0
	if *tool == "unruly" || *tool == "both" {
		scans, err := loadUnruly(*dir, byRef)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		if len(scans) == 0 {
			fmt.Fprintf(os.Stderr, "no unruly reports (*.jsonl) in %s\n", *dir)
		} else {
			emit(summarizeUnruly(scans), *dir, *out, *asJSON)
			wrote++
		}
	}
	if *tool == "supabomb" || *tool == "both" {
		scans, err := loadSupabomb(*dir, byRef)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		if len(scans) == 0 {
			fmt.Fprintf(os.Stderr, "no supabomb reports (*.supabomb.*.json) in %s\n", *dir)
		} else {
			emit(summarizeSupabomb(scans), *dir, *out, *asJSON)
			wrote++
		}
	}
	if wrote == 0 {
		os.Exit(1)
	}
}

func emit(e Estate, dir, out string, alsoJSON bool) {
	body := render(e)
	if out == "-" {
		fmt.Print(body)
		return
	}
	path := out
	if path == "" {
		path = filepath.Join(dir, "estate-"+e.Tool+".md")
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	fmt.Fprintf(os.Stderr, "%s: %d target(s), %d finding(s) -> %s\n",
		e.Tool, e.Targets, e.Findings, path)

	if alsoJSON {
		jp := strings.TrimSuffix(path, ".md") + ".json"
		b, err := json.MarshalIndent(e, "", "  ")
		if err == nil {
			err = os.WriteFile(jp, b, 0o644)
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return
		}
		fmt.Fprintf(os.Stderr, "%s: -> %s\n", e.Tool, jp)
	}
}

// loadUnruly reads every JSONL report in dir.
//
// One file per target, which is what -o writes and what the comparison harness
// produces. A file that fails to parse is reported rather than skipped: a
// silent skip in a tool built for a thousand targets is how a summary comes to
// describe nine hundred of them and say so nowhere.
func loadUnruly(dir string, byRef map[string]string) ([]scanned, error) {
	paths, err := filepath.Glob(filepath.Join(dir, "*.jsonl"))
	if err != nil {
		return nil, err
	}
	sort.Strings(paths)
	var out []scanned
	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", p, err)
		}
		s := scanned{Target: targetName(p, ".unruly.jsonl", ".jsonl")}
		for i, line := range strings.Split(string(b), "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			var f finding.Finding
			if err := json.Unmarshal([]byte(line), &f); err != nil {
				return nil, fmt.Errorf("%s line %d: %w", p, i+1, err)
			}
			if s.Ref == "" {
				if m := projectRef.FindStringSubmatch(f.Matched); m != nil {
					s.Ref = m[1]
				}
			}
			s.Findings = append(s.Findings, f)
		}
		s.Region = byRef[s.Ref]
		out = append(out, s)
	}
	return out, nil
}

// loadSupabomb reads what supabomb wrote: the dump from `all`, the grades from
// `test`. Either may be absent, and a target with only one of them is still
// summarised for what that half says.
func loadSupabomb(dir string, byRef map[string]string) ([]dumped, error) {
	paths, err := filepath.Glob(filepath.Join(dir, "*.supabomb.all.json"))
	if err != nil {
		return nil, err
	}
	sort.Strings(paths)
	byTarget := map[string]*dumped{}
	order := []string{}

	for _, p := range paths {
		name := targetName(p, ".supabomb.all.json")
		var doc struct {
			Credentials struct {
				ProjectRef string `json:"project_ref"`
				URL        string `json:"url"`
			} `json:"credentials"`
			Dump struct {
				Tables map[string]struct {
					RowCount int              `json:"row_count"`
					Data     []map[string]any `json:"data"`
				} `json:"tables"`
			} `json:"dump"`
		}
		if err := readJSON(p, &doc); err != nil {
			return nil, err
		}
		d := &dumped{Target: name, Ref: doc.Credentials.ProjectRef,
			Tables: map[string][]map[string]any{}}
		for t, v := range doc.Dump.Tables {
			if len(v.Data) > 0 {
				d.Tables[t] = v.Data
			} else if v.RowCount > 0 {
				// Row count without rows: the report recorded a count and the
				// data was withheld or trimmed. Counted, but nothing to
				// classify -- and saying so beats inventing placeholder rows.
				d.Tables[t] = make([]map[string]any, v.RowCount)
			}
		}
		d.Region = byRef[d.Ref]
		byTarget[name] = d
		order = append(order, name)
	}

	tests, _ := filepath.Glob(filepath.Join(dir, "*.supabomb.test.json"))
	sort.Strings(tests)
	for _, p := range tests {
		name := targetName(p, ".supabomb.test.json")
		var doc struct {
			ProjectRef string `json:"project_ref"`
			Findings   []struct {
				Severity string `json:"severity"`
				Title    string `json:"title"`
				Resource string `json:"affected_resource"`
			} `json:"findings"`
		}
		if err := readJSON(p, &doc); err != nil {
			return nil, err
		}
		d := byTarget[name]
		if d == nil {
			d = &dumped{Target: name, Ref: doc.ProjectRef,
				Tables: map[string][]map[string]any{}, Region: byRef[doc.ProjectRef]}
			byTarget[name] = d
			order = append(order, name)
		}
		for _, f := range doc.Findings {
			sev, ok := finding.ParseSeverity(f.Severity)
			if !ok {
				sev = finding.Info
			}
			d.Findings = append(d.Findings, graded{
				Severity: sev, Resource: f.Resource, Title: f.Title})
		}
	}

	sort.Strings(order)
	var out []dumped
	seen := map[string]bool{}
	for _, name := range order {
		if seen[name] {
			continue
		}
		seen[name] = true
		out = append(out, *byTarget[name])
	}
	return out, nil
}

func readJSON(path string, v any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	if err := json.Unmarshal(b, v); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	return nil
}

func targetName(path string, suffixes ...string) string {
	name := filepath.Base(path)
	for _, s := range suffixes {
		name = strings.TrimSuffix(name, s)
	}
	return name
}

// resolveRegions asks the operator's own account where their projects live.
//
// This is the only authoritative source. Supabase serves the API behind
// Cloudflare and returns no region header at all -- measured on a live project
// whose response carried `cf-ray: ...-FRA` while the project itself is in
// eu-west-1. Reading the colo would have put Irish data under German
// jurisdiction on the one table read for exactly that question, so this tool
// asks the account or reports "unknown".
func resolveRegions() (map[string]string, error) {
	token := os.Getenv("SUPABASE_ACCESS_TOKEN")
	if token == "" {
		return nil, fmt.Errorf("SUPABASE_ACCESS_TOKEN is not set")
	}
	req, err := http.NewRequest("GET", "https://api.supabase.com/v1/projects", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("management API answered %d", resp.StatusCode)
	}
	var projects []struct {
		Ref    string `json:"ref"`
		Region string `json:"region"`
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, &projects); err != nil {
		return nil, err
	}
	out := map[string]string{}
	for _, p := range projects {
		if p.Ref != "" && p.Region != "" {
			out[p.Ref] = p.Region
		}
	}
	return out, nil
}
