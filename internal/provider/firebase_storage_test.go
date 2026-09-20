package provider

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/eppser/unruly/internal/client"
	"github.com/eppser/unruly/internal/finding"
)

// The four answers Cloud Storage gives, and the four things they mean.
//
// This is the one Firebase surface where existence is decidable: 404 is "no
// such bucket", 403 is "it exists and the rules said no", 200 is a listing.
// Firestore answers 403 to both protected and absent, which is why this
// scanner claims "protected" here and never there -- so the 403 case is the
// one that must be graded most carefully, because it is a positive claim.
func TestStorageClassifiesEachAnswer(t *testing.T) {
	cases := []struct {
		name     string
		status   int
		body     string
		wantID   string
		wantSev  finding.Severity
		contains string
	}{{
		name: "lists sensitive objects", status: 200,
		body: `{"items":[{"name":"passport-scan.jpg"},{"name":"invoice-2026.pdf"},
		        {"name":"customer_email_export.csv"}]}`,
		wantID: "firebase-storage-anon-read", wantSev: finding.Critical,
		contains: "passport-scan.jpg",
	}, {
		name: "lists ordinary objects", status: 200,
		body:   `{"items":[{"name":"logo.png"},{"name":"hero-banner.jpg"}]}`,
		wantID: "firebase-storage-anon-read", wantSev: finding.High,
	}, {
		name: "listable but empty", status: 200, body: `{"items":[]}`,
		wantID: "firebase-storage-anon-read", wantSev: finding.Low,
		contains: "public the moment it lands",
	}, {
		name: "exists and refuses", status: 403, body: `{"error":{"message":"Permission denied"}}`,
		wantID: "firebase-storage-protected", wantSev: finding.Info,
		contains: "exists and its rules refuse",
	}, {
		name: "no such bucket", status: 404, body: `{"error":{"message":"Not Found"}}`,
		wantID: "firebase-storage-absent", wantSev: finding.Info,
		contains: "no such bucket",
	}}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer srv.Close()
			old := storageHost
			storageHost = srv.URL
			t.Cleanup(func() { storageHost = old })

			fs := storageFindings(context.Background(),
				Detection{Provider: "firebase", Project: "p", Bucket: "p.firebasestorage.app",
					Credential: "AIzaFAKE"},
				ScanOptions{Client: client.New(client.Options{BaseURL: srv.URL, Retries: 0})})
			if len(fs) != 1 {
				t.Fatalf("got %d findings, want 1", len(fs))
			}
			if fs[0].ID != tc.wantID || fs[0].Severity != tc.wantSev {
				t.Errorf("got %s/%s, want %s/%s", fs[0].ID, fs[0].Severity, tc.wantID, tc.wantSev)
			}
			if tc.contains != "" {
				whole := fs[0].Description + strings.Join(fs[0].Evidence.Columns, " ")
				if !strings.Contains(whole, tc.contains) {
					t.Errorf("finding does not mention %q", tc.contains)
				}
			}
		})
	}
}

// A bucket the application never names is never probed.
//
// Bucket names are a GLOBAL namespace. Guessing a name built from the
// company's own is a request to whoever owns that name, who is very likely not
// the target, and this tool only scans what it was pointed at.
func TestStorageNeverGuessesABucketName(t *testing.T) {
	var asked atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		asked.Add(1)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"items":[]}`))
	}))
	defer srv.Close()
	old := storageHost
	storageHost = srv.URL
	t.Cleanup(func() { storageHost = old })

	fs := storageFindings(context.Background(),
		Detection{Provider: "firebase", Project: "some-project", Credential: "AIzaFAKE"},
		ScanOptions{Client: client.New(client.Options{BaseURL: srv.URL, Retries: 0})})
	if n := asked.Load(); len(fs) != 0 || n != 0 {
		t.Errorf("%d finding(s) from %d request(s) for a bucket the application never "+
			"declared; a guessed bucket name addresses somebody else's project",
			len(fs), n)
	}
}
