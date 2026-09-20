package provider

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/eppser/unruly/internal/finding"

	"github.com/eppser/unruly/internal/client"
)

// Remote Config has two silent paths, and both are "could not look".
//
// The check returns nil when the application published no appId, and again
// when the fetch does not answer 200. Both produce a report that says nothing
// about Remote Config -- identical to a project whose template holds no
// credentials at all, which is the case the check exists to distinguish.
//
// The other two nil returns are honest: an empty template and a template with
// nothing sensitive in it are MEASUREMENTS, and silence is the right answer to
// both. This is the same line the Firestore and function checks draw.
//
// Remote Config matters here because it is where a project's own secrets end up
// when somebody wants to change them without shipping a release, and it is
// fetchable by anyone holding the public web API key.
func TestRemoteConfigSaysWhenItCouldNotLook(t *testing.T) {
	t.Run("no appId published", func(t *testing.T) {
		fs := remoteConfigFindings(context.Background(),
			Detection{Provider: "firebase", Project: "p", Credential: "AIza-test"},
			ScanOptions{Client: client.New(client.Options{Retries: 0})})
		if !mentions(fs, "unruly-surface-not-assessed") {
			t.Errorf("the application published no appId, so Remote Config was never "+
				"asked, and the scan reported %v. A reader cannot tell that from a "+
				"template with nothing in it", ids(fs))
		}
	})

	t.Run("the fetch is refused", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusTooManyRequests)
		}))
		defer srv.Close()
		remoteConfigHostOverride = srv.URL
		t.Cleanup(func() { remoteConfigHostOverride = "" })
		fs := remoteConfigFindings(context.Background(),
			Detection{Provider: "firebase", Project: "p", Credential: "AIza-test", AppID: "1:2:web:3"},
			ScanOptions{Client: client.New(client.Options{BaseURL: srv.URL, Retries: 0})})
		if !mentions(fs, "unruly-surface-not-assessed") {
			t.Errorf("the fetch answered 429 and the scan reported %v. A refusal is not "+
				"a clean template, and a rate limit least of all", ids(fs))
		}
	})
}

// An empty template IS a measurement. Reporting it would train readers to skip
// the notice that matters.
func TestRemoteConfigIsQuietAboutAnEmptyTemplate(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"state":"NO_TEMPLATE"}`))
	}))
	defer srv.Close()
	remoteConfigHostOverride = srv.URL
	t.Cleanup(func() { remoteConfigHostOverride = "" })
	fs := remoteConfigFindings(context.Background(),
		Detection{Provider: "firebase", Project: "p", Credential: "AIza-test", AppID: "1:2:web:3"},
		ScanOptions{Client: client.New(client.Options{BaseURL: srv.URL, Retries: 0})})
	if len(fs) != 0 {
		t.Errorf("an empty template produced %v; the fetch succeeded and there was "+
			"nothing in it, which is a result rather than a gap", ids(fs))
	}
}

func ids(fs []finding.Finding) []string {
	var out []string
	for _, f := range fs {
		out = append(out, f.ID)
	}
	return out
}

func mentions(fs []finding.Finding, id string) bool {
	for _, f := range fs {
		if strings.HasPrefix(f.ID, id) {
			return true
		}
	}
	return false
}
