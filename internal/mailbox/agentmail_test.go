package mailbox

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/eppser/unruly/internal/client"
)

// A stub of the real API, shaped from responses observed against the live
// service: an inbox create returning {email, inbox_id}, a message list whose
// ids are angle-bracketed SES ids, and a message body carrying the link.
func stubAgentMail(t *testing.T, deliverAfter int32) (*AgentMail, *int32, *int32) {
	t.Helper()
	var listCalls, deletes int32
	mux := http.NewServeMux()
	// The stub refuses a repeat create with 403 already_exists, because that is
	// what the live service does. The first version of this file returned 200
	// for a repeat -- modelling an assumption rather than the API -- so it
	// passed while the real second scan of a project failed outright. A stub
	// that agrees with your belief tests your belief.
	created := map[string]bool{}
	var mu sync.Mutex
	mux.HandleFunc("/v0/inboxes", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Username string `json:"username"`
		}
		json.NewDecoder(r.Body).Decode(&in)
		mu.Lock()
		defer mu.Unlock()
		if created[in.Username] {
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(map[string]string{"code": "already_exists"})
			return
		}
		created[in.Username] = true
		json.NewEncoder(w).Encode(map[string]string{
			"email":    in.Username + "@agentmail.to",
			"inbox_id": in.Username + "@agentmail.to",
		})
	})
	mux.HandleFunc("/v0/inboxes/", func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodDelete:
			atomic.AddInt32(&deletes, 1)
			w.WriteHeader(http.StatusAccepted)
		case r.Method == http.MethodGet && !strings.Contains(r.URL.Path, "/messages"):
			// GET /v0/inboxes/{addr} -- how Open re-opens an existing mailbox.
			addr := strings.TrimPrefix(r.URL.Path, "/v0/inboxes/")
			user := strings.TrimSuffix(addr, "@agentmail.to")
			mu.Lock()
			ok := created[user]
			mu.Unlock()
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			json.NewEncoder(w).Encode(map[string]string{"email": addr, "inbox_id": addr})
		case strings.HasSuffix(r.URL.Path, "/messages"):
			// Empty until the caller has polled `deliverAfter` times, so the
			// waiting path is exercised rather than only the happy one.
			if atomic.AddInt32(&listCalls, 1) <= deliverAfter {
				json.NewEncoder(w).Encode(map[string]any{"messages": []any{}})
				return
			}
			json.NewEncoder(w).Encode(map[string]any{"messages": []map[string]string{
				{"message_id": "<0100-abc-def@email.amazonses.com>"},
			}})
		default: // a single message
			json.NewEncoder(w).Encode(map[string]string{
				"text": "Confirm your account:\nhttps://ref.supabase.co/auth/v1/verify?token=abc123&type=signup\n",
			})
		}
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return &AgentMail{
		Key:    "test-key",
		Base:   srv.URL,
		Client: client.New(client.Options{BaseURL: srv.URL, RestPrefix: "/", Retries: 0}),
	}, &listCalls, &deletes
}

// The whole flow, because each step is useless without the others: an address
// to register, a link to follow, and removal afterwards.
func TestAgentMailOpensAwaitsAndCloses(t *testing.T) {
	api, _, deletes := stubAgentMail(t, 0)
	ctx := context.Background()

	mb, err := api.Open(ctx, "someproject")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !strings.HasSuffix(mb.Address(), "@agentmail.to") {
		t.Errorf("address %q is not a usable mailbox", mb.Address())
	}

	link, err := mb.Await(ctx, 5*time.Second)
	if err != nil {
		t.Fatalf("Await: %v", err)
	}
	if !strings.Contains(link, "/auth/v1/verify?token=") {
		t.Errorf("recovered %q, which is not the confirmation link", link)
	}
	// The link must be clean enough to follow. A trailing quote or bracket
	// from surrounding HTML produces a 404 that reads like an expired token.
	if strings.ContainsAny(link, "\"'<>") {
		t.Errorf("link carries surrounding markup: %q", link)
	}

	if err := mb.Close(ctx); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if atomic.LoadInt32(deletes) != 1 {
		t.Error("Close did not delete the inbox; every scan would leave one behind")
	}
}

// Waiting must actually wait, and then give up saying what happened.
func TestAgentMailWaitsThenReportsTheTimeoutAsItself(t *testing.T) {
	api, calls, _ := stubAgentMail(t, 2) // empty for the first two polls
	ctx := context.Background()
	mb, err := api.Open(ctx, "p")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := mb.Await(ctx, 10*time.Second); err != nil {
		t.Fatalf("Await gave up on a message that did arrive: %v", err)
	}
	if atomic.LoadInt32(calls) < 3 {
		t.Errorf("only polled %d times; the waiting path was not exercised", *calls)
	}

	// And when nothing ever arrives, the error must name the timeout rather
	// than assert that no mail was sent. A project whose mail is slow,
	// filtered or misrouted has not declined to send one, and reporting it
	// that way would be a false statement about somebody else's system.
	slow, _, _ := stubAgentMail(t, 1000)
	mb2, _ := slow.Open(ctx, "p2")
	_, err = mb2.Await(ctx, 1*time.Millisecond)
	if err == nil {
		t.Fatal("Await returned success with no message")
	}
	for _, want := range []string{"within", "@agentmail.to"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("timeout error %q does not say %q", err, want)
		}
	}
}

// One address per project, stable across runs: the alternative registers a new
// account in somebody's user table on every scan.
func TestAddressIsDeterministicPerProjectAndHidesTheRef(t *testing.T) {
	a, b := UserFor("abcdefghijklmnopqrst"), UserFor("abcdefghijklmnopqrst")
	if a != b {
		t.Errorf("same project produced %q then %q: a repeat scan would register "+
			"a second account", a, b)
	}
	if UserFor("one") == UserFor("two") {
		t.Error("different projects share an address, so one project's confirmation " +
			"mail would land in another's inbox")
	}
	if strings.Contains(a, "abcdefghijklmnopqrst") {
		t.Errorf("the address %q contains the project reference; it is stored in a "+
			"third party's inbox list and does not need to name the target", a)
	}
}

// A second scan of the same project must reuse the first scan's mailbox.
//
// This is the assertion the live API taught: creating an existing username
// returns 403, so an Open that only ever POSTs fails on every scan after the
// first -- at exactly the step whose purpose is to avoid registering a second
// account in somebody's user table.
func TestOpenReusesAnExistingInboxInsteadOfFailing(t *testing.T) {
	api, _, _ := stubAgentMail(t, 0)
	ctx := context.Background()

	first, err := api.Open(ctx, "repeat-project")
	if err != nil {
		t.Fatalf("first Open: %v", err)
	}
	second, err := api.Open(ctx, "repeat-project")
	if err != nil {
		t.Fatalf("second Open failed, so a repeat scan cannot reuse its identity: %v", err)
	}
	if first.Address() != second.Address() {
		t.Errorf("reopened a different address: %q then %q", first.Address(), second.Address())
	}
}
