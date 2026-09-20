package eval_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/coder/websocket"
)

// The Realtime wiring, graded without cloud credentials.
//
// internal/realtime's own tests cover the phoenix protocol thoroughly, in both
// directions, against a stub built from frames observed live. What they cannot
// cover is whether main.go calls realtime.Run with the right options -- and
// that wiring was graded ONLY by eval-exploitability, which needs a cloud
// project whose keys are gitignored. Measured on this repository: moving
// .secrets aside leaves four checks unable to run, and that is one of them.
//
// Wiring is worth grading separately from logic. Two defects this session were
// wiring rather than logic: -plain rendered nothing for a Firebase target, and
// -html wrote no file at all, both because a correct implementation was never
// reached on that path.
//
// The server below proxies REST to the real lab fixture, so relation discovery
// is genuine, and answers the Realtime path itself. Nothing leaves the machine.
func TestRealtimeSubscriptionIsReportedEndToEnd(t *testing.T) {
	requireLiveEvals(t)
	requireReachable(t, "http://127.0.0.1:54321")
	key := os.Getenv("UNRULY_FIXTURE_KEY")
	if key == "" {
		t.Skip("set UNRULY_FIXTURE_KEY")
	}

	// Only this relation's join is acknowledged in the first case.
	const published = "open_no_rls"

	// Two servers, because the two properties are different claims and a
	// single case cannot separate them. Discovered by measurement: a server
	// that acknowledges EVERY relation makes the binary report nothing at all,
	// not everything -- so an assertion of the form "only the published
	// relation was reported" can never fail, and the absence assertion would
	// have blamed the wiring for what is actually the scanner being sound.
	for _, tc := range []struct {
		name        string
		ackAny      bool
		wantReports bool
		why         string
	}{{
		name: "one relation published", wantReports: true,
		why: "Realtime acknowledged an anonymous subscription with a populated " +
			"binding and the binary reported nothing: the wiring from main.go to " +
			"realtime.Run is not reached",
	}, {
		name: "every relation acknowledged", ackAny: true, wantReports: false,
		why: "the server acknowledged a relation that cannot exist, so an " +
			"acknowledgement distinguishes nothing here -- reporting a subscription " +
			"on that basis is a finding about the server's manners, not the project",
	}} {
		t.Run(tc.name, func(t *testing.T) {
			rest, err := url.Parse("http://127.0.0.1:54321")
			if err != nil {
				t.Fatal(err)
			}
			proxy := httputil.NewSingleHostReverseProxy(rest)
			ack := published
			if tc.ackAny {
				ack = ""
			}
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if !strings.HasPrefix(r.URL.Path, "/realtime/v1/websocket") {
					proxy.ServeHTTP(w, r)
					return
				}
				servePhoenix(r.Context(), w, r, ack)
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
			var subscribed []string
			for _, line := range strings.Split(string(b), "\n") {
				if strings.TrimSpace(line) == "" {
					continue
				}
				var f struct{ ID, Resource string }
				if json.Unmarshal([]byte(line), &f) != nil {
					t.Fatalf("report line is not JSON: %q", line)
				}
				if f.ID == "supabase-realtime-anon-subscription" {
					subscribed = append(subscribed, f.Resource)
				}
			}

			switch {
			case tc.wantReports && len(subscribed) == 0:
				t.Fatal(tc.why)
			case !tc.wantReports && len(subscribed) > 0:
				t.Fatalf("%s (reported %v)", tc.why, subscribed)
			}
			for _, rel := range subscribed {
				if rel != published {
					t.Errorf("reported a subscription for %q; only %q is published",
						rel, published)
				}
			}
		})
	}
}

// servePhoenix answers postgres_changes joins for one published relation and
// refuses every other, which is the shape internal/realtime's own stub uses.
// An empty published name acknowledges everything, which is how the real
// service behaves and the reason the acknowledgement alone proves nothing.
func servePhoenix(ctx context.Context, w http.ResponseWriter, r *http.Request, published string) {
	c, err := websocket.Accept(w, r, nil)
	if err != nil {
		return
	}
	defer c.Close(websocket.StatusNormalClosure, "")
	for {
		_, data, err := c.Read(ctx)
		if err != nil {
			return
		}
		var m struct {
			Topic, Event, Ref string
			Payload           struct {
				Config struct {
					PostgresChanges []struct{ Table string } `json:"postgres_changes"`
				} `json:"config"`
			} `json:"payload"`
		}
		if json.Unmarshal(data, &m) != nil || m.Event != "phx_join" {
			continue
		}
		table := ""
		if len(m.Payload.Config.PostgresChanges) > 0 {
			table = m.Payload.Config.PostgresChanges[0].Table
		}
		payload := map[string]any{"status": "error",
			"response": map[string]any{"reason": "no such relation"}}
		if published == "" || table == published {
			// A populated binding is what makes the acknowledgement mean
			// something: Realtime answers ok to anything.
			payload = map[string]any{"status": "ok",
				"response": map[string]any{
					"postgres_changes": []map[string]any{{"id": 42}}}}
		}
		reply, _ := json.Marshal(map[string]any{
			"topic": m.Topic, "event": "phx_reply", "ref": m.Ref, "payload": payload,
		})
		if c.Write(ctx, websocket.MessageText, reply) != nil {
			return
		}
	}
}
