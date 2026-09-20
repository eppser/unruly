package escalate

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/eppser/unruly/internal/client"
	"github.com/eppser/unruly/internal/finding"
	"github.com/eppser/unruly/internal/postgrest"
	"github.com/eppser/unruly/internal/probe"
)

// Role escalation had no offline test at all. It was exercised only by the
// fixture eval, so it was checked only when Docker was up -- and a coverage
// audit of the offline suite named it as one of just two finding sites whose
// emitting code never runs without the fixtures.
//
// It is worth pinning properly. The escalation pass is where a policy written
// TO authenticated gets caught, and public signup means anyone can hold that
// role, so a silent break here hides a whole class of exposure behind a scan
// that says "protected".
//
// These tests assert the REQUEST as well as the verdict, because the way this
// broke in the past was not a wrong conclusion from a good request. It was
// WithKey replacing the apikey as well as the Authorization header, so a
// managed project rejected every elevated request with "Invalid API key" and
// the pass reported zero gains -- a clean-looking result assembled entirely
// from refusals. A test that only checked the verdict would have agreed.

// fakeJWT builds a token whose payload names a role. Only the payload is read.
func fakeJWT(role string) string {
	payload, _ := json.Marshal(map[string]any{"role": role, "sub": "u1"})
	enc := base64.RawURLEncoding.EncodeToString
	return "eyJhbGciOiJIUzI1NiJ9." + enc(payload) + ".sig"
}

type credentialedTarget struct {
	mu sync.Mutex
	// seen records the (apikey, authorization) pair per request.
	seen [][2]string
	// visibleTo maps relation -> the role that may read it.
	visibleTo map[string]string
}

func newCredentialedTarget(visibleTo map[string]string) (*credentialedTarget, *httptest.Server) {
	ct := &credentialedTarget{visibleTo: visibleTo}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		ct.mu.Lock()
		ct.seen = append(ct.seen, [2]string{r.Header.Get("apikey"), auth})
		ct.mu.Unlock()

		rel := strings.Trim(r.URL.Path, "/")
		role := "anon"
		if strings.Contains(auth, base64.RawURLEncoding.EncodeToString([]byte(`{"role":"authenticated"`))[:12]) {
			role = "authenticated"
		}
		if want, ok := ct.visibleTo[rel]; ok && (want == role || want == "all") {
			w.Header().Set("Content-Range", "0-1/2")
			w.WriteHeader(http.StatusPartialContent)
			w.Write([]byte(`[{"id":1,"email":"a@example.invalid","api_key":"sk_live_x"},{"id":2,"email":"b@example.invalid","api_key":"sk_live_y"}]`))
			return
		}
		// Present but RLS-filtered for this role.
		w.Header().Set("Content-Range", "*/0")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`[]`))
	}))
	return ct, srv
}

func baseResultFor(names []string, readable map[string]bool) probe.Result {
	var res probe.Result
	for _, n := range names {
		rel := probe.Relation{Name: n}
		if readable[n] {
			rel.Read = postgrest.ReadExposed
			rel.Rows = 2
		} else {
			rel.Read = postgrest.ReadEmpty
		}
		res.Relations = append(res.Relations, rel)
	}
	return res
}

func TestEscalationReportsWhatOnlyTheElevatedRoleCanRead(t *testing.T) {
	elevated := fakeJWT("authenticated")
	_, srv := newCredentialedTarget(map[string]string{
		"members_only": "authenticated", // the gain
		"public_stats": "all",           // readable either way: NOT a gain
		"locked":       "service_role",  // nobody here can read it
	})
	defer srv.Close()

	c := client.New(client.Options{BaseURL: srv.URL, AnonKey: "anon-project-key", RestPrefix: "/"})
	names := []string{"members_only", "public_stats", "locked"}

	res := Compare(context.Background(), c, baseResultFor(names, map[string]bool{"public_stats": true}),
		Options{ElevatedKey: elevated, Relations: names, SampleRows: 2, Concurrency: 2})

	gained := map[string]bool{}
	for _, g := range res.Gains {
		gained[g.Relation] = true
	}
	if !gained["members_only"] {
		t.Error("a relation the authenticated role can read and anon cannot is the whole " +
			"point of this pass, and it was not reported")
	}
	if gained["public_stats"] {
		t.Error("anon could already read public_stats, so it is not a gain; reporting it " +
			"would double-count every public relation as an escalation")
	}
	if gained["locked"] {
		t.Error("locked returned no rows to either role and must not be a gain")
	}

	// Sensitive columns are present in the sample, so the finding must escalate.
	if len(res.Findings) != 1 {
		t.Fatalf("expected exactly one escalation finding, got %d", len(res.Findings))
	}
	f := res.Findings[0]
	if f.ID != "supabase-authenticated-escalation" {
		t.Errorf("unexpected id %q", f.ID)
	}
	if f.Severity != finding.Critical {
		t.Errorf("the gained rows carry email and api_key, so severity must be critical, got %v",
			f.Severity)
	}
	if !strings.Contains(f.Description, "authenticated") {
		t.Errorf("the finding must name the role that could read it; got %q", f.Description)
	}
}

// The elevated pass must send the user token as the CALLER while the apikey
// keeps naming the project. Getting that wrong made every request fail and the
// pass report zero gains.
func TestEscalationSendsUserTokenWithoutReplacingTheApiKey(t *testing.T) {
	elevated := fakeJWT("authenticated")
	ct, srv := newCredentialedTarget(map[string]string{"members_only": "authenticated"})
	defer srv.Close()

	c := client.New(client.Options{BaseURL: srv.URL, AnonKey: "anon-project-key", RestPrefix: "/"})
	Compare(context.Background(), c, baseResultFor([]string{"members_only"}, nil),
		Options{ElevatedKey: elevated, Relations: []string{"members_only"}, SampleRows: 1})

	ct.mu.Lock()
	defer ct.mu.Unlock()
	if len(ct.seen) == 0 {
		t.Fatal("the elevated pass issued no requests")
	}
	for _, pair := range ct.seen {
		apikey, auth := pair[0], pair[1]
		if apikey != "anon-project-key" {
			t.Errorf("apikey was %q: it authenticates the PROJECT and must keep doing so. "+
				"Replacing it with the user token makes a managed project answer "+
				"\"Invalid API key\" to every request, and the pass then reports zero "+
				"gains -- a clean result built entirely from refusals.", apikey)
		}
		if auth != elevated {
			t.Errorf("Authorization was %q, want the elevated token: it authenticates the "+
				"CALLER, and without it this pass re-reads everything as anon and can "+
				"never find a gain", auth)
		}
	}
}

// -redact must remove the rows and keep the finding usable.
func TestEscalationRedactionDropsSamplesNotFindings(t *testing.T) {
	elevated := fakeJWT("authenticated")
	_, srv := newCredentialedTarget(map[string]string{"members_only": "authenticated"})
	defer srv.Close()

	c := client.New(client.Options{BaseURL: srv.URL, AnonKey: "anon-project-key", RestPrefix: "/"})
	res := Compare(context.Background(), c, baseResultFor([]string{"members_only"}, nil),
		Options{ElevatedKey: elevated, Relations: []string{"members_only"}, SampleRows: 2, Redact: true})

	if len(res.Gains) != 1 {
		t.Fatalf("expected the gain to survive redaction, got %d", len(res.Gains))
	}
	if res.Gains[0].Sample != nil {
		t.Error("-redact must drop the sampled rows: they are real user records and this " +
			"report is the artifact people paste into tickets")
	}
	if res.Gains[0].Rows != 2 {
		t.Errorf("the row COUNT is evidence and must survive redaction, got %d", res.Gains[0].Rows)
	}
}
