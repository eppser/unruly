package eval_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/eppser/unruly/internal/graphql"
)

// The GraphQL bypass check, exercised positively for the first time.
//
// benchmark/README.md records that supabase-graphql-rls-bypass "has never
// fired": pg_graphql on every project measured is no more permissive than
// PostgREST, so the interesting branch has never run against anything. A check
// whose positive path nobody has seen work is a check nobody knows works, and
// it was reachable only through eval-graphql, which needs the gitignored cloud
// keys.
//
// So the fixture manufactures the disagreement the check exists to catch: a
// relation the REST pass genuinely cannot read on the lab, answered by GraphQL
// with rows. Nothing else can produce that, because no real project has.
func TestGraphQLBypassIsReportedEndToEnd(t *testing.T) {
	requireLiveEvals(t)
	requireReachable(t, "http://127.0.0.1:54321")
	key := os.Getenv("UNRULY_FIXTURE_KEY")
	if key == "" {
		t.Skip("set UNRULY_FIXTURE_KEY")
	}

	// RLS-protected on the lab: the REST pass cannot read it, which is what
	// makes GraphQL answering with rows a disagreement rather than a duplicate.
	const protected = "protected_rls_no_policy"
	// Readable over REST too, so it is exposure GraphQL merely repeats.
	const alsoOpen = "open_no_rls"

	for _, tc := range []struct {
		name         string
		controlKnown bool // the control relation is answered as though it exists
		wantBypass   bool
		why          string
	}{{
		name: "graphql serves what REST refuses", wantBypass: true,
		why: "GraphQL returned rows for a relation REST refuses and the binary " +
			"reported no bypass: the second read path is unwatched",
	}, {
		// Realtime's lesson, applied here: an oracle that answers the same way
		// for a name that cannot exist discriminates nothing, and a scanner
		// that reports on that basis is describing the endpoint's manners.
		name: "control answers for a relation that cannot exist", controlKnown: true,
		wantBypass: false,
		why: "the endpoint answered a relation that cannot exist as though it does, " +
			"so every candidate looks real and no claim about any of them is sound",
	}} {
		t.Run(tc.name, func(t *testing.T) {
			rest, _ := url.Parse("http://127.0.0.1:54321")
			proxy := httputil.NewSingleHostReverseProxy(rest)
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/graphql/v1" {
					proxy.ServeHTTP(w, r)
					return
				}
				serveGraphQL(w, r, tc.controlKnown, protected, alsoOpen)
			}))
			defer srv.Close()

			out := filepath.Join(t.TempDir(), "scan.json")
			cmd := exec.Command(buildScanner(t), "-u", srv.URL, "-k", key,
				"-rest-prefix", "/", "-j", "-o", out, "-silent")
			cmd.Env = append(os.Environ(), "SUPABASE_ANON_KEY=")
			_ = cmd.Run()

			b, err := os.ReadFile(out)
			if err != nil {
				t.Fatalf("scan produced no report: %v", err)
			}
			var bypass, anonRead int
			var reason string
			for _, line := range strings.Split(string(b), "\n") {
				if strings.TrimSpace(line) == "" {
					continue
				}
				var f struct {
					ID       string
					Evidence struct{ Reason string }
				}
				if json.Unmarshal([]byte(line), &f) != nil {
					t.Fatalf("report line is not JSON: %q", line)
				}
				switch f.ID {
				case "supabase-graphql-rls-bypass":
					bypass++
					reason = f.Evidence.Reason
				case "supabase-graphql-anon-read":
					anonRead++
				}
			}

			switch {
			case tc.wantBypass && bypass == 0:
				t.Fatal(tc.why)
			case !tc.wantBypass && bypass > 0:
				t.Fatalf("%s (reported anyway: %s)", tc.why, reason)
			}
			if tc.wantBypass && anonRead == 0 {
				t.Error("a relation readable over BOTH paths should still be reported as " +
					"anonymously readable over GraphQL")
			}
		})
	}
}

// serveGraphQL answers pg_graphql collection queries.
//
// controlKnown makes it answer the control relation as though it exists, which
// is the non-discriminating case: pg_graphql normally replies "Unknown field"
// for a name it has no collection for, and that reply is what makes every other
// answer meaningful.
func serveGraphQL(w http.ResponseWriter, r *http.Request, controlKnown bool, withRows ...string) {
	var in struct {
		Query string `json:"query"`
	}
	_ = json.NewDecoder(r.Body).Decode(&in)
	m := regexp.MustCompile(`(\w+)Collection`).FindStringSubmatch(in.Query)
	w.Header().Set("Content-Type", "application/json")
	if m == nil {
		fmt.Fprint(w, `{"data":{}}`)
		return
	}
	name := m[1]

	rows := func() {
		fmt.Fprintf(w, `{"data":{"%sCollection":{"edges":[`+
			`{"node":{"nodeId":"WyJwdWJsaWMiLCIx"}},`+
			`{"node":{"nodeId":"WyJwdWJsaWMiLCIy"}}]}}}`, name)
	}
	if name == graphql.ControlRelationName {
		if controlKnown {
			rows()
			return
		}
		fmt.Fprintf(w, `{"errors":[{"message":"Unknown field \"%sCollection\" on type Query"}]}`, name)
		return
	}
	for _, r := range withRows {
		if r == name {
			rows()
			return
		}
	}
	// Exists, and this role saw none of it.
	fmt.Fprintf(w, `{"data":{"%sCollection":{"edges":[]}}}`, name)
}
