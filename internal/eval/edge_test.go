package eval_test

// Edge Functions against the real runtime.
//
// These two checks were the last entries in the finding-ID coverage allowlist,
// and neither could be closed by replaying a recorded response: what is under
// test is which statuses Supabase's runtime actually returns for a deployed
// function, an absent one, and a host that answers everything. A mock would
// grade the scanner against my assumptions about the platform.
//
//   make fixtures-edge && UNRULY_LIVE=1 go test ./internal/eval -run Edge -v

import (
	"context"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/eppser/unruly/internal/client"
	"github.com/eppser/unruly/internal/surface"
	"github.com/eppser/unruly/internal/wordlist"
)

const (
	edgeDeployedURL = "http://127.0.0.1:54351"
	edgeCatchAllURL = "http://127.0.0.1:54352"
)

func edgeClient(t *testing.T, base string) *client.Client {
	t.Helper()
	requireLiveEvals(t)
	key := os.Getenv("UNRULY_FIXTURE_KEY")
	if key == "" {
		t.Skip("UNRULY_FIXTURE_KEY required")
	}
	return client.New(client.Options{
		ProjectRef: "edge", BaseURL: base, RestPrefix: "/", AnonKey: key, Retries: 1,
	})
}

// warmEdgeRuntime issues requests until the runtime answers.
//
// edge-runtime boots a Deno worker on the first request for a function and
// drops that connection while it does, so a cold host reports zero functions
// and the eval fails for a reason that has nothing to do with the scanner.
// make fixtures-edge warms it with a curl, which meant these tests passed
// under `make eval-edge` and failed under a plain `go test ./...` -- a test
// that depends on the harness that usually runs it is a test that will fail on
// someone else's machine.
func warmEdgeRuntime(t *testing.T, base string) {
	t.Helper()
	hc := &http.Client{Timeout: 5 * time.Second}
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := hc.Post(base+"/functions/v1/hello", "application/json",
			strings.NewReader("{}"))
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Skipf("edge-runtime at %s did not become ready; run `make fixtures-edge`", base)
}

func runEdgeSurface(t *testing.T, base string) surface.Result {
	t.Helper()
	// THE GATE COMES FIRST. Warming the Deno runtime before checking
	// UNRULY_LIVE cost a plain `go test ./...` 30 seconds per Edge test --
	// 120.7 seconds measured, more than half the offline suite -- waiting for
	// a host nobody started, and then skipping anyway. A suite whose offline
	// path is dominated by a deliberate stall is a suite people stop running.
	requireLiveEvals(t)
	warmEdgeRuntime(t, edgeDeployedURL)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	return surface.Run(ctx, edgeClient(t, base), surface.Options{
		FunctionSeeds:  wordlist.Functions(),
		AllowFunctions: true,
		AllowInvoke:    true,
	})
}

// A function deployed without Kong in front verifies no JWT, so an anonymous
// POST reaches it. That is the finding, and until this fixture existed nothing
// had ever produced it.
func TestEdgeFunctionWithoutJWTIsReported(t *testing.T) {
	res := runEdgeSurface(t, edgeDeployedURL)

	var found *surface.EdgeFunction
	for i := range res.Functions {
		if res.Functions[i].Name == "hello" {
			found = &res.Functions[i]
		}
	}
	if found == nil {
		t.Fatalf("hello is deployed and answers 200 to an anonymous POST; got %d functions",
			len(res.Functions))
	}
	if found.RequiresJWT {
		t.Error("nothing verifies a JWT in this fixture, so it must not be reported protected")
	}

	var sawFinding bool
	for _, f := range res.Findings {
		if f.ID == "supabase-edge-function-no-jwt" && f.Resource == "hello" {
			sawFinding = true
			if f.Evidence.Reason == "" {
				t.Error("the finding must carry what was observed")
			}
		}
	}
	if !sawFinding {
		t.Error("a function reachable without credentials must produce " +
			"supabase-edge-function-no-jwt")
	}
}

// Honest recall. send-invoice is deployed and is not in the pinned wordlist,
// so it is not found. Name-based discovery finds what it has names for, and
// recording that here stops the fixture from implying otherwise.
func TestEdgeFunctionOutsideTheWordlistIsMissed(t *testing.T) {
	res := runEdgeSurface(t, edgeDeployedURL)
	for _, f := range res.Functions {
		if f.Name == "send-invoice" {
			t.Skip("send-invoice is now in the wordlist; update the answer key")
		}
	}
	if len(res.Functions) == 0 {
		t.Fatal("the deployed host must yield at least the wordlist hit")
	}
}

// The control case. A host that answers every function name makes every
// candidate look deployed, and reporting zero functions would read as a
// project that has none.
func TestEdgeCatchAllHostIsRefusedNotReportedEmpty(t *testing.T) {
	res := runEdgeSurface(t, edgeCatchAllURL)

	if len(res.Functions) != 0 {
		t.Errorf("a host answering every name must yield no functions, got %d: %v",
			len(res.Functions), res.Functions)
	}
	var sawNotAssessed bool
	for _, f := range res.Findings {
		if f.ID == "unruly-surface-not-assessed" && f.Resource == "edge-functions" {
			sawNotAssessed = true
		}
	}
	if !sawNotAssessed {
		t.Error("silence is not enough: the scan must say Edge Functions were not " +
			"assessed, or zero functions reads as no functions")
	}
}

// The same host is not an auth server either. Any 200 with a JSON body used to
// be accepted as GoTrue settings, and because disable_signup is absent from
// such a body it decoded to false, which reads as signup being OPEN.
func TestEdgeCatchAllHostDoesNotFakeOpenSignup(t *testing.T) {
	res := runEdgeSurface(t, edgeCatchAllURL)
	for _, f := range res.Findings {
		if f.ID == "supabase-open-signup" {
			t.Error("a host that is not GoTrue must not produce an open-signup finding")
		}
	}
	if res.Auth.Reachable {
		t.Error("a payload naming none of GoTrue's own fields is not GoTrue")
	}
}
