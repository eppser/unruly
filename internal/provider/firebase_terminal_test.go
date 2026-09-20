package provider

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/eppser/unruly/internal/client"
)

func TestFirestoreProjectErrorStopsCollectionGuessing(t *testing.T) {
	var requests atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(`{"error":{"status":"PERMISSION_DENIED","message":"Cloud Firestore API is disabled","details":[{"reason":"SERVICE_DISABLED"}]}}`))
	}))
	defer srv.Close()
	old := firestoreHost
	firestoreHost = srv.URL
	t.Cleanup(func() { firestoreHost = old })

	var names []string
	for i := 0; i < 100; i++ {
		names = append(names, "collection_"+string(rune('a'+i%26)))
	}
	fs := firestoreFindings(context.Background(),
		Detection{Provider: "firebase", Project: "disabled", Credential: "k"},
		ScanOptions{Client: client.New(client.Options{Retries: 0}), Candidates: names})
	if requests.Load() != 1 {
		t.Fatalf("a project-wide SERVICE_DISABLED response was repeated %d times", requests.Load())
	}
	var description string
	for _, f := range fs {
		if f.ID == "unruly-surface-not-assessed" {
			description += f.Description
		}
	}
	if !strings.Contains(description, "SERVICE_DISABLED") ||
		!strings.Contains(description, "stopped") {
		t.Fatalf("terminal state is not explained: %s", description)
	}
	if strings.Contains(description, "spent roughly") {
		t.Fatal("the report invented a billed read count from a disabled API response")
	}
}

func TestAnonymousFirebaseAccountIsAlwaysDeleted(t *testing.T) {
	var signups, deletes atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.Contains(r.URL.Path, "signUp"):
			signups.Add(1)
			w.Write([]byte(`{"idToken":"anonymous-token","localId":"anonymous-uid"}`))
		case strings.Contains(r.URL.Path, "delete"):
			deletes.Add(1)
			w.Write([]byte(`{}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()
	old := identityToolkit
	identityToolkit = srv.URL
	t.Cleanup(func() { identityToolkit = old })

	enabled, left := anonymousSignInEnabled(context.Background(),
		Detection{Project: "p", Credential: "k"},
		ScanOptions{Client: client.New(client.Options{Retries: 0})})
	if !enabled || left != "" {
		t.Fatalf("enabled=%v left=%q", enabled, left)
	}
	if signups.Load() != 1 || deletes.Load() != 1 {
		t.Fatalf("anonymous signups=%d deletes=%d", signups.Load(), deletes.Load())
	}
}
