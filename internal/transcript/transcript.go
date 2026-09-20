// Package transcript records real HTTP exchanges against a live lab and
// replays them offline.
//
// The audit must not depend on a live backend: labs cost quota, rate-limit,
// and drift. The usual answer is a hand-written httptest handler, and this
// repo is full of them. They have one failure mode -- the fake and the real
// backend disagree and nobody notices, so the eval grades an imitation. A
// recorded transcript is the same fake with its provenance attached: it came
// off the real thing, and re-recording is how you find out it changed.
//
// Two properties earn the package its place:
//
//   - Exchanges key on the AUTH CLASS as well as the path. Anonymous and
//     authenticated requests to one URL are different observations, and on
//     Neon they are the difference between a refusal and every row in a table.
//   - An unrecorded request is reported, never quietly answered. A missing
//     recording that returns 404 looks exactly like a real negative result.
//
// Credentials are never stored. Recording keeps the class ("anon"/"authed"),
// which is all replay needs and all a committed file should ever hold.
package transcript

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"sort"
	"strings"
)

// Auth classes. These are the only two observations that matter to a posture
// scan: what a stranger sees, and what any account sees.
const (
	Anon   = "anon"
	Authed = "authed"
)

// An Exchange is one recorded request/response pair.
type Exchange struct {
	Method      string `json:"method"`
	Path        string `json:"path"` // path plus raw query
	Auth        string `json:"auth"` // Anon or Authed -- never a credential
	Status      int    `json:"status"`
	ContentType string `json:"content_type,omitempty"`
	Body        string `json:"body"`
	// RequestBody is what was SENT, and it exists so a recording can be checked
	// against the code that replays it.
	//
	// Replay does not key on it -- a probe should not have to send byte-identical
	// JSON to be answered -- but without it nothing can ask whether the
	// recording still answers the question the scanner asks. It did not, once:
	// the Neon write probe stopped naming a column, five tables changed from
	// 400 PGRST204 to 403/42501, and the committed transcript went on serving
	// the old answers while every offline eval passed.
	//
	// Empty for requests that carry no body, which is most of them.
	RequestBody string `json:"request_body,omitempty"`
}

// A Transcript is an ordered set of exchanges. Order is normalised on save so
// re-recording an unchanged backend produces an unchanged file.
type Transcript struct {
	Exchanges []Exchange `json:"exchanges"`
}

// New returns an empty transcript.
func New() *Transcript { return &Transcript{} }

// Add appends an exchange.
func (t *Transcript) Add(method, path, auth string, status int, contentType, body string) {
	t.AddWithRequest(method, path, auth, "", status, contentType, body)
}

// AddWithRequest records an exchange and what was sent to provoke it.
func (t *Transcript) AddWithRequest(method, path, auth, requestBody string,
	status int, contentType, body string) {
	t.Exchanges = append(t.Exchanges, Exchange{
		Method: method, Path: path, Auth: auth, RequestBody: requestBody,
		Status: status, ContentType: contentType, Body: body,
	})
}

func key(method, path, auth string) string {
	return method + " " + path + " [" + auth + "]"
}

// classOf reports the auth class of a request without reading the credential.
func classOf(r *http.Request) string {
	if r.Header.Get("Authorization") == "" {
		return Anon
	}
	return Authed
}

// Server replays the transcript. onUnrecorded is called with a description of
// any request the transcript does not cover; it is not optional, because
// silently answering an unknown request is the failure this package exists to
// prevent.
func (t *Transcript) Server(onUnrecorded func(string)) *httptest.Server {
	byKey := make(map[string]Exchange, len(t.Exchanges))
	for _, e := range t.Exchanges {
		byKey[key(e.Method, e.Path, e.Auth)] = e
	}
	return newServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		if r.URL.RawQuery != "" {
			p += "?" + r.URL.RawQuery
		}
		k := key(r.Method, p, classOf(r))
		e, ok := byKey[k]
		if !ok {
			onUnrecorded(fmt.Sprintf("no recorded exchange for %s", k))
			w.WriteHeader(http.StatusNotImplemented)
			return
		}
		if e.ContentType != "" {
			w.Header().Set("Content-Type", e.ContentType)
		}
		w.WriteHeader(e.Status)
		_, _ = io.WriteString(w, e.Body)
	}))
}

// newServer exists so tests and Server share one construction point.
func newServer(h http.Handler) *httptest.Server { return httptest.NewServer(h) }

// A Request describes one exchange to record.
type Request struct {
	Method string
	Path   string
	Auth   string
	Body   string
}

// Record performs each request against base and captures the responses.
//
// token is used only to populate the Authorization header for Authed
// requests. It is never written to the transcript.
func Record(ctx context.Context, base, token string, reqs []Request) (*Transcript, error) {
	tr := New()
	for _, q := range reqs {
		var body io.Reader
		if q.Body != "" {
			body = strings.NewReader(q.Body)
		}
		req, err := http.NewRequestWithContext(ctx, q.Method, base+q.Path, body)
		if err != nil {
			return nil, fmt.Errorf("build %s %s: %w", q.Method, q.Path, err)
		}
		if q.Auth == Authed {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		if q.Body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return nil, fmt.Errorf("%s %s: %w", q.Method, q.Path, err)
		}
		b, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("read %s %s: %w", q.Method, q.Path, err)
		}
		tr.AddWithRequest(q.Method, q.Path, q.Auth, q.Body, resp.StatusCode,
			resp.Header.Get("Content-Type"), string(b))
	}
	return tr, nil
}

// Save writes the transcript with exchanges in a stable order.
func (t *Transcript) Save(path string) error {
	out := &Transcript{Exchanges: append([]Exchange(nil), t.Exchanges...)}
	sort.SliceStable(out.Exchanges, func(i, j int) bool {
		a, b := out.Exchanges[i], out.Exchanges[j]
		return key(a.Method, a.Path, a.Auth) < key(b.Method, b.Path, b.Auth)
	})
	b, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o600)
}

// Load reads a transcript from disk.
func Load(path string) (*Transcript, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var t Transcript
	if err := json.Unmarshal(b, &t); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &t, nil
}
