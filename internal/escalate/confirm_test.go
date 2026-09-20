package escalate

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/eppser/unruly/internal/client"
	"github.com/eppser/unruly/internal/mailbox"
)

// A project that requires email confirmation is not a closed project.
//
// It admits anyone willing to receive a message, and on the open internet that
// is anyone at all -- so every relation whose policy reads `TO authenticated`
// is reachable by that person. Without a mailbox the scan stops at "signup
// succeeded but no session was issued", which is honest and leaves the entire
// authenticated tier unmeasured on a large share of real projects.
//
// The fake GoTrue below behaves the way the real one does: signup returns 200
// with a user and NO session, the confirmation link must be followed, and only
// then does password sign-in yield a token.
type fakeMailbox struct {
	addr    string
	link    string
	closed  *int32
	awaited *int32
}

func (f *fakeMailbox) Address() string { return f.addr }
func (f *fakeMailbox) Await(ctx context.Context, within time.Duration) (string, error) {
	atomic.AddInt32(f.awaited, 1)
	return f.link, nil
}
func (f *fakeMailbox) Close(ctx context.Context) error {
	atomic.AddInt32(f.closed, 1)
	return nil
}

type fakeProvider struct {
	mb *fakeMailbox
}

func (f *fakeProvider) Name() string { return "fake" }
func (f *fakeProvider) Open(ctx context.Context, project string) (mailbox.Mailbox, error) {
	return f.mb, nil
}

func confirmingGoTrue(t *testing.T, confirmed *int32) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/auth/v1/signup", func(w http.ResponseWriter, r *http.Request) {
		// 200 with a user and no session: "confirm your email".
		json.NewEncoder(w).Encode(map[string]any{
			"id": "user-1", "email": "someone@example.org",
		})
	})
	mux.HandleFunc("/auth/v1/verify", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(confirmed, 1)
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/auth/v1/token", func(w http.ResponseWriter, r *http.Request) {
		if atomic.LoadInt32(confirmed) == 0 {
			// Unconfirmed accounts cannot sign in, which is the whole point of
			// the setting.
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"access_token": "session-token"})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func TestConfirmRequiredProjectIsMeasuredWhenAMailboxIsSupplied(t *testing.T) {
	var confirmed, closed, awaited int32
	srv := confirmingGoTrue(t, &confirmed)
	c := client.New(client.Options{BaseURL: srv.URL, RestPrefix: "/", Retries: 0})

	mb := &fakeMailbox{
		addr:   "unruly-abc@agentmail.to",
		link:   srv.URL + "/auth/v1/verify?token=abc&type=signup",
		closed: &closed, awaited: &awaited,
	}
	acct, err := Acquire(context.Background(), c, "proj-confirm", AcquireOptions{
		Mailbox: &fakeProvider{mb: mb}, ConfirmWait: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("a confirm-required project was not measured despite a mailbox: %v", err)
	}
	if acct.Token == "" {
		t.Error("no session obtained, so the authenticated tier is still unmeasured")
	}
	if atomic.LoadInt32(&confirmed) == 0 {
		t.Error("the confirmation link was never followed")
	}
	if !strings.HasSuffix(acct.Email, "@agentmail.to") {
		t.Errorf("registered %q rather than the mailbox address, so the confirmation "+
			"mail had nowhere to arrive", acct.Email)
	}
	// The inbox is residue this tool created. It must be removed, or reported.
	if atomic.LoadInt32(&closed) == 0 {
		t.Error("the mailbox was left behind; every confirm-required scan would " +
			"accumulate one")
	}
}

// Without a mailbox the behaviour must be exactly what it was: report the
// project as unmeasured and say why. Silence, or a claim that signup was
// refused, would both be wrong.
func TestConfirmRequiredWithoutAMailboxStillReportsItHonestly(t *testing.T) {
	var confirmed int32
	srv := confirmingGoTrue(t, &confirmed)
	c := client.New(client.Options{BaseURL: srv.URL, RestPrefix: "/", Retries: 0})

	_, err := Acquire(context.Background(), c, "proj-nomail", AcquireOptions{})
	if err == nil {
		t.Fatal("a confirm-required project reported success with no session")
	}
	if !strings.Contains(err.Error(), "confirmation") {
		t.Errorf("the error does not name the cause: %v", err)
	}
	if atomic.LoadInt32(&confirmed) != 0 {
		t.Error("a confirmation link was followed without a mailbox being configured")
	}
}

// -no-residue must refuse to open a mailbox at all.
//
// Not because an inbox on the operator's own mail service is residue on the
// TARGET -- it is not, and that distinction is why internal/mailbox is exempt
// from the writing-package check. The reason is narrower and stronger: opening
// one is only ever a prelude to registering an account, and -no-residue's whole
// promise is that no account gets registered. A mailbox opened and then unused
// would be a third-party artefact created for nothing.
//
// This is the test the exemption in internal/eval names, so the exemption is a
// claim somebody can check rather than a hole.
func TestNoResidueOpensNoMailbox(t *testing.T) {
	var confirmed, closed, awaited int32
	srv := confirmingGoTrue(t, &confirmed)
	c := client.New(client.Options{BaseURL: srv.URL, RestPrefix: "/", Retries: 0})

	var opened int32
	prov := &countingProvider{
		inner:  &fakeProvider{mb: &fakeMailbox{addr: "x@agentmail.to", closed: &closed, awaited: &awaited}},
		opened: &opened,
	}
	_, err := Acquire(context.Background(), c, "proj-noresidue", AcquireOptions{
		NoResidue: true, Mailbox: prov,
	})
	if err == nil {
		t.Fatal("-no-residue produced an account on a project with none stored")
	}
	if atomic.LoadInt32(&opened) != 0 {
		t.Error("-no-residue opened a mailbox; nothing may be created anywhere when " +
			"the operator has asked for the target to be left exactly as found")
	}
}

type countingProvider struct {
	inner  *fakeProvider
	opened *int32
}

func (c *countingProvider) Name() string { return "counting" }
func (c *countingProvider) Open(ctx context.Context, project string) (mailbox.Mailbox, error) {
	atomic.AddInt32(c.opened, 1)
	return c.inner.Open(ctx, project)
}
