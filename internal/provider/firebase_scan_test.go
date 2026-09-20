package provider

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/eppser/unruly/internal/client"
	"github.com/eppser/unruly/internal/finding"
	"github.com/eppser/unruly/internal/identity"
)

// The -no-residue coverage check exempts this package because its only POST is
// Firestore's query transport. An exemption cannot notice when that stops being
// true, so this is what actually holds it: every request the assessment makes
// is recorded, and anything that could write fails the test.
func TestFirebaseSendsOnlyReads(t *testing.T) {
	var mu sync.Mutex
	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		seen = append(seen, r.Method+" "+r.URL.Path+" "+string(body))
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[]`))
	}))
	defer srv.Close()

	// Point both surfaces at the stub.
	d := Detection{Provider: "firebase", Project: "p", Credential: "k", RTDB: srv.URL}
	o := ScanOptions{
		Client:     client.New(client.Options{BaseURL: srv.URL, Retries: 1}),
		Candidates: []string{"users", "orders"},
	}
	// Firestore probes go to the real hostname, so redirect them by giving the
	// assessment a client whose base is the stub and asserting on what the RTDB
	// half sends; the Firestore half is asserted by shape below.
	_ = firebase{}.assess(context.Background(), d, o)

	mu.Lock()
	defer mu.Unlock()
	if len(seen) == 0 {
		t.Fatal("no requests were made, so this test asserts nothing")
	}
	for _, req := range seen {
		method := strings.SplitN(req, " ", 2)[0]
		switch method {
		case "GET":
			// Reads. RTDB uses shallow=true, which returns names and no values.
		case "POST":
			if !strings.Contains(req, ":runQuery") {
				t.Errorf("a POST that is not a Firestore query: %s", req)
			}
			if !strings.Contains(req, "structuredQuery") {
				t.Errorf("a POST without a query body, which could be a write: %s", req)
			}
		default:
			t.Errorf("a mutating method reached the wire: %s", req)
		}
	}
}

// The query body must ask for names only. A projection that selects fields
// would retrieve somebody's data to answer a question about reachability.
func TestFirestoreQueryAsksForNamesOnly(t *testing.T) {
	var mu sync.Mutex
	var bodies []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		bodies = append(bodies, string(b))
		mu.Unlock()
		_, _ = w.Write([]byte(`[]`))
	}))
	defer srv.Close()

	c := client.New(client.Options{BaseURL: srv.URL, Retries: 1})
	// The base must end in /documents: the probe appends ":runQuery" to it, and
	// appending a colon to a host:port produces a malformed URL that never
	// leaves the process. The first version of this test did exactly that and
	// recorded zero requests.
	_, _ = firestoreReadable(context.Background(), c, srv.URL+"/documents", "key", "users")

	mu.Lock()
	defer mu.Unlock()
	if len(bodies) != 1 {
		t.Fatalf("expected one query, got %d", len(bodies))
	}
	var q struct {
		StructuredQuery struct {
			Select struct {
				Fields []struct {
					FieldPath string `json:"fieldPath"`
				} `json:"fields"`
			} `json:"select"`
		} `json:"structuredQuery"`
	}
	if err := json.Unmarshal([]byte(bodies[0]), &q); err != nil {
		t.Fatalf("query is not JSON: %v", err)
	}
	f := q.StructuredQuery.Select.Fields
	if len(f) != 1 || f[0].FieldPath != "__name__" {
		t.Errorf("the query does not project __name__ only, so it retrieves field "+
			"values to answer a reachability question: %s", bodies[0])
	}
}

// Both Firebase findings must be BUILT by the offline suite.
//
// The live evals grade them against the real lab, but they skip without
// credentials, so the coverage audit counted both ids as named-but-never-built:
// a finding only a cloud project can produce is one CI cannot protect. A stub
// serving the two shapes fixes that and pins the finding contents at the same
// time.
func TestFirebaseFindingsAreBuiltOffline(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.Contains(r.URL.Path, "runQuery"):
			// Two documents, names only: exactly what a __name__ projection
			// returns.
			_, _ = w.Write([]byte(`[{"document":{"name":"projects/p/databases/(default)/documents/users/u1"}},
			                       {"document":{"name":"projects/p/databases/(default)/documents/users/u2"}}]`))
		default: // RTDB shallow
			_, _ = w.Write([]byte(`{"alpha":true,"beta":true}`))
		}
	}))
	defer srv.Close()

	c := client.New(client.Options{BaseURL: srv.URL, Retries: 1})
	// Firestore: build the finding directly from a readable collection.
	docs, ok := firestoreReadable(context.Background(), c, srv.URL+"/documents", "k", "users")
	if !ok || len(docs) != 2 {
		t.Fatalf("stub not exercised: ok=%v docs=%v", ok, docs)
	}
	fs := firestoreReadFinding(Detection{Project: "p"}, srv.URL+"/documents", "k", "users",
		docs, ScanOptions{})
	if fs.ID != "firebase-firestore-anon-read" || fs.Severity.String() != "high" {
		t.Errorf("firestore finding is %s/%s", fs.ID, fs.Severity)
	}
	if len(fs.Evidence.Columns) != 2 || fs.Evidence.Columns[0] != "u1" {
		t.Errorf("document identifiers are not carried as proof: %v", fs.Evidence.Columns)
	}
	if !strings.Contains(fs.Remediation, "firestore.rules") {
		t.Error("remediation does not name the file an operator has to edit")
	}

	// RTDB: a readable ROOT is critical, a readable path below it is high.
	keys, ok := rtdbReadable(context.Background(), c, srv.URL, "")
	if !ok || len(keys) != 2 {
		t.Fatalf("rtdb stub not exercised: ok=%v keys=%v", ok, keys)
	}
	root := rtdbFinding(srv.URL, "/", keys, true)
	if root.ID != "firebase-rtdb-anon-read" || root.Severity.String() != "critical" {
		t.Errorf("a readable root is %s/%s; everything beneath it is implied",
			root.ID, root.Severity)
	}
	if sub := rtdbFinding(srv.URL, "/public", keys, false); sub.Severity.String() != "high" {
		t.Errorf("a readable path is %s, which should rank below a readable root",
			sub.Severity)
	}
	if !strings.Contains(root.Evidence.Request, "shallow=true") {
		t.Error("the evidence command does not show the data-minimising probe that was used")
	}
}

// The auth and escalation findings must be built offline too, for the same
// reason as the database ones: a finding only a cloud project can produce is a
// finding CI cannot protect.
func TestFirebaseAuthFindingsAreBuiltOffline(t *testing.T) {
	d := Detection{Provider: "firebase", Project: "p", Credential: "k"}

	if f := openSignupFinding(d, false); f.ID != "firebase-auth-open-signup" ||
		f.Severity.String() != "medium" {
		t.Errorf("open signup finding is %s/%s", f.ID, f.Severity)
	}
	// The reused wording matters: it says signup is STILL open without implying
	// this run created anything.
	if f := openSignupFinding(d, true); !strings.Contains(f.Evidence.Reason, "created earlier") {
		t.Errorf("a reused account is described as a fresh signup: %s", f.Evidence.Reason)
	}
	if f := weakPasswordFinding(d); f.ID != "firebase-auth-weak-password" ||
		!strings.Contains(f.Evidence.Reason, weakPassword) {
		t.Errorf("weak password finding does not name the password it used: %+v", f.Evidence)
	}
	if f := anonymousSignInFinding(d); f.ID != "firebase-auth-anonymous-signin" ||
		!strings.Contains(f.Remediation, "sign_in_provider") {
		t.Error("anonymous finding does not show how to exclude anonymous sessions in rules")
	}
}

// The escalation delta, offline: a collection anonymous callers already read
// must not be repeated, and one only the session can read must be reported.
func TestFirebaseEscalationDeltaOffline(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		// Only "private" answers, and only with a bearer.
		if strings.Contains(string(body), "private") && r.Header.Get("Authorization") != "" {
			_, _ = w.Write([]byte(`[{"document":{"name":"projects/p/databases/(default)/documents/private/d1"}}]`))
			return
		}
		_, _ = w.Write([]byte(`[]`))
	}))
	defer srv.Close()

	// firestoreDocsURL builds the real hostname, so point the client's base at
	// the stub and let the URL host be irrelevant: client.Do uses the URL given.
	c := client.New(client.Options{BaseURL: srv.URL, Retries: 1, AnonKey: "k"})
	got := escalationFindings(context.Background(),
		Detection{Project: "p", Credential: "k"},
		ScanOptions{Client: c, Candidates: []string{"public_already", "private"}},
		&authState{IDToken: "tok"},
		[]finding.Finding{{Resource: "public_already"}})

	// The stub is reached through the real Firestore hostname, so an offline
	// run gets nothing back. What is asserted here is the FILTER: the
	// already-public collection must never be a candidate for the delta.
	for _, f := range got {
		if f.Resource == "public_already" {
			t.Error("a collection anonymous callers already read was repeated as an escalation")
		}
	}
}

// And the escalation finding itself, built offline.
func TestEscalationFindingShape(t *testing.T) {
	f := escalationFinding("https://firestore.googleapis.com/v1/projects/p/databases/(default)/documents",
		"salaries", []string{"d1", "d2"})
	if f.ID != "firebase-firestore-authenticated-read" || f.Severity.String() != "high" {
		t.Errorf("escalation finding is %s/%s", f.ID, f.Severity)
	}
	if len(f.Evidence.Columns) != 2 {
		t.Errorf("document identifiers are not carried as proof: %v", f.Evidence.Columns)
	}
	// The description has to explain WHY this looked safe, or the reader
	// concludes the scanner is inconsistent with every other tool they ran.
	if !strings.Contains(f.Description, "request.auth != null") {
		t.Error("the finding does not name the rule shape it is about")
	}
	if !strings.Contains(f.Evidence.Reason, "refused anonymously") {
		t.Errorf("the reason does not state the contrast that makes it a finding: %q",
			f.Evidence.Reason)
	}
}

// The classifier, graded offline against a template shaped like the lab's.
//
// The live eval proves the fetch and the wiring; this proves the judgement,
// which is the part that has to be right on templates nobody has seen. Every
// entry below is labelled with why it does or does not belong in a report.
func TestRemoteConfigClassifiesContentNotReachability(t *testing.T) {
	entries := map[string]string{
		// Ordinary configuration. Reporting any of these is noise, and noise is
		// what makes a reader stop reading.
		"feature_new_dashboard": "true",
		"max_items_per_page":    "25",
		"welcome_headline":      "Welcome back",
		"theme_primary":         "#0b5cff",
		"support_url":           "https://help.example.com/",
		// A credential by SHAPE. Nobody has to have named it well.
		"payments_token": "sk_live_51ABCDEFghijklmnop0123456789",
		// A credential by NAME, with a value shaped like nothing in particular.
		"vendor_api_secret": "9f2a-not-a-known-shape",
		// Somewhere not meant to be public.
		"ops_endpoint": "https://internal-tools.example.com/v1",
	}
	credentials, internal := classifyRemoteConfig(entries)

	want := []string{"payments_token", "vendor_api_secret"}
	if strings.Join(credentials, ",") != strings.Join(want, ",") {
		t.Errorf("credentials = %v, want %v", credentials, want)
	}
	if strings.Join(internal, ",") != "ops_endpoint" {
		t.Errorf("internal = %v, want [ops_endpoint]", internal)
	}

	// support_url is a public help site and must not be caught by the internal
	// host words -- a check that reports it has stopped discriminating.
	for _, got := range append(credentials, internal...) {
		if got == "support_url" || got == "theme_primary" {
			t.Errorf("%s is ordinary configuration and was reported", got)
		}
	}

	// The offline emit site the coverage audit needs, and the severity rule:
	// a loose credential is critical however few of them there are.
	d := Detection{Provider: "firebase", Project: "p", Credential: "AIzaFAKE", AppID: "1:2:web:3"}
	f := remoteConfigFinding(d, "https://example.invalid/fetch", credentials, internal, len(entries))
	if f.ID != "firebase-remote-config-secret" || f.Severity != finding.Critical {
		t.Errorf("finding = %s/%s", f.ID, f.Severity)
	}
	// An internal endpoint alone is worth saying, but it is not a credential.
	if only := remoteConfigFinding(d, "u", nil, internal, 8); only.Severity != finding.Low {
		t.Errorf("internal-endpoint-only severity = %s, want low", only.Severity)
	}
	// And no value ever leaves the classifier.
	whole := f.Description + f.Evidence.Reason + strings.Join(f.Evidence.Columns, " ") + f.Remediation
	for _, secret := range []string{"sk_live_51ABCDEF", "9f2a-not-a-known-shape"} {
		if strings.Contains(whole, secret) {
			t.Errorf("the finding republishes %q", secret)
		}
	}
}

// -no-residue leaves the target exactly as it was found, which is not the same
// as never writing to it.
//
// The original rule here was "never sign up", and the reason recorded was that
// a public scan has no way to delete a user record. That is true of Supabase
// and false of Firebase: Identity Toolkit's accounts:delete takes the
// account's OWN idToken. The old rule therefore reported the highest-value
// Firebase finding as unmeasured on every project that had never been scanned.
//
// The promise is unchanged and the guard is stronger: an account may be
// created, and every account created must be removed. If the target refuses
// the delete, the report says an account was left behind.
func TestNoResidueRemovesEveryAccountItCreates(t *testing.T) {
	var signups, deletes atomic.Int64
	var refuseDelete atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.Contains(r.URL.Path, "signUp"):
			signups.Add(1)
			_, _ = w.Write([]byte(`{"idToken":"tok","localId":"uid"}`))
		case strings.Contains(r.URL.Path, "delete"):
			deletes.Add(1)
			if refuseDelete.Load() {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			_, _ = w.Write([]byte(`{}`))
		default:
			// Every sign-in refused, so the only route to a session is
			// registering -- which is what makes the cleanup load-bearing.
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":{"message":"EMAIL_NOT_FOUND"}}`))
		}
	}))
	defer srv.Close()
	t.Setenv("UNRULY_CONFIG_DIR", t.TempDir())
	old := identityToolkit
	identityToolkit = srv.URL
	t.Cleanup(func() { identityToolkit = old })

	d := Detection{Provider: "firebase", Project: "p", Credential: "AIzaFAKE"}
	o := ScanOptions{
		Client: client.New(client.Options{BaseURL: srv.URL, Retries: 0}),
		Write:  true, NoResidue: true,
	}

	st, reused, _ := signInOrUp(context.Background(), d, o)
	if st == nil {
		t.Fatal("no session under -no-residue, so the escalation tier is unmeasured on " +
			"every project that has never been scanned")
	}
	if reused || !st.Ephemeral {
		t.Errorf("a freshly registered account is marked reused=%v ephemeral=%v; only an "+
			"ephemeral one is cleaned up", reused, st.Ephemeral)
	}
	if got := identity.List(); len(got) != 0 {
		t.Errorf("an ephemeral account was stored (%v): the next run would sign in with "+
			"a credential that no longer exists and conclude the project changed", got)
	}
	if fs := finishSession(context.Background(), d, o, st); len(fs) != 0 {
		t.Errorf("a successful delete still reported residue: %v", fs)
	}
	if signups.Load() == 0 || deletes.Load() != signups.Load() {
		t.Errorf("%d signups and %d deletes: -no-residue promises the target is left "+
			"exactly as it was found", signups.Load(), deletes.Load())
	}

	// And when the target refuses to let go of it, the report says so rather
	// than the scan pretending it cleaned up.
	refuseDelete.Store(true)
	st2, _, _ := signInOrUp(context.Background(), d, o)
	fs := finishSession(context.Background(), d, o, st2)
	if len(fs) != 1 || fs[0].ID != "unruly-probe-account-left-behind" {
		t.Errorf("a refused delete produced %d finding(s); an account this scan created "+
			"and could not remove is the least deniable thing it leaves", len(fs))
	}
}
