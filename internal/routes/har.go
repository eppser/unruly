package routes

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"sort"
	"strings"
)

const sourceHAR = "har-runtime"

// harRefs reads only method and URL from a HAR. Headers, request bodies,
// cookies and responses are deliberately absent from the decoding shape, so
// runtime route ingestion cannot turn the scan report into another copy of a
// captured session.
func harRefs(paths []string, site string) ([]endpointRef, []string, []error) {
	seen := map[string]endpointRef{}
	origins := map[string]bool{}
	var errs []error
	for _, path := range paths {
		b, err := os.ReadFile(path)
		if err != nil {
			errs = append(errs, fmt.Errorf("read HAR %q: %w", path, err))
			continue
		}
		var doc struct {
			Log *struct {
				Entries []struct {
					Request struct {
						Method string `json:"method"`
						URL    string `json:"url"`
					} `json:"request"`
				} `json:"entries"`
			} `json:"log"`
		}
		if err := json.Unmarshal(b, &doc); err != nil || doc.Log == nil {
			if err == nil {
				err = fmt.Errorf("missing log object")
			}
			errs = append(errs, fmt.Errorf("parse HAR %q: %w", path, err))
			continue
		}
		for _, entry := range doc.Log.Entries {
			method := strings.ToUpper(strings.TrimSpace(entry.Request.Method))
			if method == "" || method == "CONNECT" {
				continue
			}
			u, err := url.Parse(entry.Request.URL)
			if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
				continue
			}
			base := strings.TrimRight(u.Scheme+"://"+u.Host, "/")
			path := u.EscapedPath()
			if path == "" {
				path = "/"
			}
			if notEndpoint(path) {
				continue
			}
			seen[base+"\x00"+path] = endpointRef{Base: base, Path: path, Source: sourceHAR}
			if base != strings.TrimRight(originOf(site), "/") {
				origins[base] = true
			}
		}
	}
	refs := make([]endpointRef, 0, len(seen))
	for _, ref := range seen {
		refs = append(refs, ref)
	}
	sort.Slice(refs, func(i, j int) bool {
		if refs[i].Base != refs[j].Base {
			return refs[i].Base < refs[j].Base
		}
		return refs[i].Path < refs[j].Path
	})
	hosts := make([]string, 0, len(origins))
	for origin := range origins {
		hosts = append(hosts, origin)
	}
	sort.Strings(hosts)
	return refs, hosts, errs
}
