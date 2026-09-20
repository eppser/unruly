package transcript

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Anonymous and authenticated requests to the SAME path must not collide.
//
// This is the whole reason a transcript keys on more than the URL. On the Neon
// lab, GET /rls_disabled answers 400 with no Authorization header and 200 with
// every row when a token is present. A transcript that keyed on path alone
// would serve one of those for both, and an escalation eval replaying it would
// grade a fiction.
func TestAnonAndAuthedDoNotCollide(t *testing.T) {
	tr := New()
	tr.Add("GET", "/rls_disabled?select=*", Anon, 400, "application/json",
		`{"message":"missing authentication credentials"}`)
	tr.Add("GET", "/rls_disabled?select=*", Authed, 200, "application/json",
		`[{"id":1,"card_last4":"0000"}]`)

	srv := tr.Server(func(msg string) { t.Fatalf("unexpected request: %s", msg) })
	defer srv.Close()

	anon := get(t, srv.URL+"/rls_disabled?select=*", "")
	if anon.status != 400 {
		t.Errorf("anonymous replay returned %d, want 400: the recorded anonymous "+
			"refusal was not served", anon.status)
	}
	authed := get(t, srv.URL+"/rls_disabled?select=*", "Bearer any.token.here")
	if authed.status != 200 {
		t.Fatalf("authenticated replay returned %d, want 200", authed.status)
	}
	if !strings.Contains(authed.body, "card_last4") {
		t.Errorf("authenticated replay served the anonymous body (%q); anon and "+
			"authed collided, which would let an escalation eval pass on a "+
			"response that never proved escalation", authed.body)
	}
}

// An unrecorded request must fail loudly.
//
// A replay server that answers 404 for anything it does not know turns a
// missing recording into a plausible-looking negative result. The scan would
// report "not exposed" and the eval would go green having measured nothing.
func TestAnUnrecordedRequestIsReportedNotSilentlyMissed(t *testing.T) {
	tr := New()
	tr.Add("GET", "/known", Anon, 200, "application/json", `[]`)

	var reported string
	srv := tr.Server(func(msg string) { reported = msg })
	defer srv.Close()

	_ = get(t, srv.URL+"/never-recorded", "")
	if reported == "" {
		t.Fatal("an unrecorded path was served without complaint; a missing " +
			"recording must not look like a real negative result")
	}
	if !strings.Contains(reported, "/never-recorded") {
		t.Errorf("the complaint %q does not name the path that was missing", reported)
	}
}

// Save/Load round-trips, and the file holds no credential.
//
// Transcripts get committed so the audit can run offline. CI scans committed
// content for JWT-shaped strings, and more importantly a recorded token is a
// live credential in git history.
func TestSavedTranscriptRoundTripsAndCarriesNoCredential(t *testing.T) {
	tr := New()
	tr.Add("GET", "/t?select=*", Authed, 200, "application/json", `[{"id":1}]`)

	dir := t.TempDir()
	p := filepath.Join(dir, "neon.json")
	if err := tr.Save(p); err != nil {
		t.Fatalf("save: %v", err)
	}
	back, err := Load(p)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(back.Exchanges) != 1 || back.Exchanges[0].Status != 200 {
		t.Fatalf("round trip lost the exchange: %+v", back.Exchanges)
	}

	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	jwtish := regexp.MustCompile(`eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`)
	if jwtish.Match(raw) {
		t.Error("the saved transcript contains a JWT-shaped string; recording " +
			"must store the auth CLASS, never the credential")
	}
	if strings.Contains(string(raw), "Authorization") {
		t.Error("the saved transcript mentions an Authorization header")
	}
}

// Recording stores the class, not the token.
func TestRecordingStoresAuthClassNotTheToken(t *testing.T) {
	live := http.NewServeMux()
	live.HandleFunc("/x", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Header.Get("Authorization") == "" {
			w.WriteHeader(400)
			_, _ = w.Write([]byte(`{"message":"no creds"}`))
			return
		}
		_, _ = w.Write([]byte(`[{"id":1}]`))
	})
	srv := newServer(live)
	defer srv.Close()

	tr, err := Record(context.Background(), srv.URL, "super-secret-token-value", []Request{
		{Method: "GET", Path: "/x", Auth: Anon},
		{Method: "GET", Path: "/x", Auth: Authed},
	})
	if err != nil {
		t.Fatalf("record: %v", err)
	}
	if len(tr.Exchanges) != 2 {
		t.Fatalf("recorded %d exchanges, want 2", len(tr.Exchanges))
	}
	// Check the whole serialised exchange, not one field compared for exact
	// equality: the first version of this test asserted e.Auth == token and
	// sailed straight past a break that stored "anon:" + token.
	for _, e := range tr.Exchanges {
		blob, err := json.Marshal(e)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(blob), "super-secret-token-value") {
			t.Fatalf("the token leaked into the transcript: %s", blob)
		}
		if e.Auth != Anon && e.Auth != Authed {
			t.Fatalf("auth class is %q; it must be exactly %q or %q so no "+
				"credential can ride along in the field", e.Auth, Anon, Authed)
		}
	}
	if tr.Exchanges[0].Status != 400 || tr.Exchanges[1].Status != 200 {
		t.Errorf("recording did not preserve the anon/authed difference: got %d and %d",
			tr.Exchanges[0].Status, tr.Exchanges[1].Status)
	}
}

// get is a small helper: perform a request and return status and body.
type response struct {
	status int
	body   string
}

func get(t *testing.T, url, authHeader string) response {
	t.Helper()
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		t.Fatal(err)
	}
	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return response{status: resp.StatusCode, body: string(b)}
}
