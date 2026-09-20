package transcript

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// A recording must remember what was ASKED, not only what came back.
//
// This package's whole argument is that a recorded transcript beats a
// hand-written stub because it carries provenance: it came off the real thing.
// Provenance decays the moment the request changes, and it did.
// backend/neon's write probe stopped sending {"body":"..."} and started sending
// {}; five tables answer 400 PGRST204 to the first and 403/42501 to the second.
// The committed recording went on serving the PGRST204 answers, the offline
// eval went on passing, and the scanner was being graded against responses the
// live API would never give it again.
//
// Nothing could have caught that, because an Exchange stored the response and
// forgot the request body. Replay keys on method, path and auth class -- which
// is right, since a probe should not have to send byte-identical JSON to be
// answered -- but the recorded body is what lets a test ask the question that
// matters: is this recording still an answer to the question we now ask?
func TestRecordingRemembersWhatWasAsked(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"code":"42501"}`))
	}))
	defer srv.Close()

	tr, err := Record(context.Background(), srv.URL, "tok", []Request{
		{Method: "POST", Path: "/t", Auth: Authed, Body: `{}`},
	})
	if err != nil {
		t.Fatalf("Record: %v", err)
	}
	if len(tr.Exchanges) != 1 {
		t.Fatalf("%d exchange(s), want 1", len(tr.Exchanges))
	}
	if got := tr.Exchanges[0].RequestBody; got != `{}` {
		t.Errorf("the recording kept the response and forgot the request body (%q). "+
			"Nothing downstream can then tell whether the recording still answers the "+
			"request the code makes, which is the one thing provenance is for", got)
	}
}

// A GET carries no body and must not invent one: an empty string is the honest
// record, and a recording full of "{}" for reads would make the check below
// meaningless.
func TestRecordingKeepsNoBodyForABodilessRequest(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`[]`))
	}))
	defer srv.Close()

	tr, err := Record(context.Background(), srv.URL, "tok", []Request{
		{Method: "GET", Path: "/t?select=*", Auth: Anon},
	})
	if err != nil {
		t.Fatalf("Record: %v", err)
	}
	if got := tr.Exchanges[0].RequestBody; got != "" {
		t.Errorf("a GET was recorded as carrying the body %q", got)
	}
}

// And the credential must still never be written down. The request body is
// recorded; the Authorization header is not.
func TestRecordingStillStoresNoCredential(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	const secret = "eyJhbGciOiJFZERTQSJ9.super-secret-token"
	tr, err := Record(context.Background(), srv.URL, secret, []Request{
		{Method: "POST", Path: "/t", Auth: Authed, Body: `{"x":1}`},
	})
	if err != nil {
		t.Fatalf("Record: %v", err)
	}
	blob := marshalAll(t, tr)
	if strings.Contains(blob, secret) || strings.Contains(blob, "eyJ") {
		t.Error("the token reached the transcript; only the auth CLASS may be stored")
	}
}

func marshalAll(t *testing.T, tr *Transcript) string {
	t.Helper()
	b, err := json.Marshal(tr)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
