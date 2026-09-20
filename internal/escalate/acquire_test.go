package escalate

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/eppser/unruly/internal/client"
	"github.com/eppser/unruly/internal/identity"
)

// gotrue is a stand-in for the auth server, counting what it is asked to do.
type gotrue struct {
	mu               sync.Mutex
	signups, signins atomic.Int64
	// accounts that exist, email -> password
	users map[string]string
	// confirmRequired makes signup succeed without issuing a session, which is
	// what a project with email confirmation on does.
	confirmRequired bool
	// closed refuses every signup.
	closed bool
}

func (g *gotrue) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// One lock for the handler: this fixture models a signup service, and
		// the users map is both read and written per request.
		g.mu.Lock()
		defer g.mu.Unlock()
		var in struct{ Email, Password string }
		_ = json.NewDecoder(r.Body).Decode(&in)
		w.Header().Set("Content-Type", "application/json")

		switch {
		case strings.HasSuffix(r.URL.Path, "/signup"):
			g.signups.Add(1)
			if g.closed {
				w.WriteHeader(http.StatusUnprocessableEntity)
				_, _ = w.Write([]byte(`{"msg":"signups not allowed"}`))
				return
			}
			if _, exists := g.users[in.Email]; exists {
				w.WriteHeader(http.StatusUnprocessableEntity)
				_, _ = w.Write([]byte(`{"msg":"user already registered"}`))
				return
			}
			// A six-character floor, as GoTrue has by default.
			if len(in.Password) < 8 {
				w.WriteHeader(http.StatusUnprocessableEntity)
				_, _ = w.Write([]byte(`{"msg":"password too short"}`))
				return
			}
			g.users[in.Email] = in.Password
			if g.confirmRequired {
				_, _ = w.Write([]byte(`{"id":"uid-1","email":"` + in.Email + `"}`))
				return
			}
			_, _ = w.Write([]byte(`{"access_token":"session-for-` + in.Email + `"}`))

		case strings.Contains(r.URL.Path, "/token"):
			g.signins.Add(1)
			if pw, ok := g.users[in.Email]; ok && pw == in.Password {
				_, _ = w.Write([]byte(`{"access_token":"session-for-` + in.Email + `"}`))
				return
			}
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
		}
	}
}

func newGoTrue(t *testing.T, g *gotrue) *client.Client {
	t.Helper()
	// Never the operator's real config: a test that writes there alters the
	// machine it runs on.
	t.Setenv("UNRULY_CONFIG_DIR", t.TempDir())
	srv := httptest.NewServer(g.handler())
	t.Cleanup(srv.Close)
	return client.New(client.Options{BaseURL: srv.URL, Retries: 0})
}

// One account per project, not one per run.
//
// Signing up is a mutation. Doing it every scan leaves a trail of accounts in
// somebody's user table, which is rude on a project you own and indefensible
// on one you are auditing for a client.
func TestAcquireCreatesOneAccountAndThenReusesIt(t *testing.T) {
	g := &gotrue{users: map[string]string{}}
	c := newGoTrue(t, g)

	first, err := Acquire(context.Background(), c, "proj", AcquireOptions{})
	if err != nil {
		t.Fatalf("first acquire: %v", err)
	}
	if !first.Created || first.Token == "" {
		t.Fatalf("first = %+v, want a created account with a session", first)
	}
	// The stub enforces an eight-character floor and weakPassword clears it,
	// so the weak password was the one accepted -- which is itself the
	// password-policy answer, obtained without a second request.
	if !first.WeakAccepted {
		t.Error("the project accepted the weak password but the account does not say so")
	}

	second, err := Acquire(context.Background(), c, "proj", AcquireOptions{})
	if err != nil {
		t.Fatalf("second acquire: %v", err)
	}
	if second.Created {
		t.Error("the second scan created another account; the store is not being reused")
	}
	if second.Email != first.Email || second.Token == "" {
		t.Errorf("second = %+v, want the same account signed in", second)
	}
	if n := g.signups.Load(); n > 2 {
		t.Errorf("%d signup attempts across two scans; one account per project means "+
			"the second scan signs IN", n)
	}
}

// A lost store must not become a new account per run.
//
// The address is derived from the project precisely so it can be recovered.
// Without this the store's whole purpose -- not littering -- fails the first
// time somebody moves a config directory.
func TestAcquireRecoversAnAccountWhenTheStoreIsLost(t *testing.T) {
	g := &gotrue{users: map[string]string{}}
	c := newGoTrue(t, g)

	first, err := Acquire(context.Background(), c, "proj", AcquireOptions{})
	if err != nil {
		t.Fatalf("first: %v", err)
	}
	// Lose the store, exactly as moving machines or clearing a cache does.
	t.Setenv("UNRULY_CONFIG_DIR", t.TempDir())

	again, err := Acquire(context.Background(), c, "proj", AcquireOptions{})
	if err != nil {
		t.Fatalf("after losing the store: %v", err)
	}
	if again.Email != first.Email {
		t.Errorf("recovered %q, want the project's own address %q", again.Email, first.Email)
	}
	if again.Created {
		t.Error("a lost store created a second account; that is the litter the " +
			"store exists to prevent")
	}
	if len(g.users) != 1 {
		t.Errorf("%d accounts exist on the target, want exactly 1", len(g.users))
	}
}

// Confirmation-required is not "signup closed", and must not be reported as it.
func TestAcquireSaysWhenConfirmationBlocksTheSession(t *testing.T) {
	g := &gotrue{users: map[string]string{}, confirmRequired: true}
	c := newGoTrue(t, g)

	_, err := Acquire(context.Background(), c, "proj", AcquireOptions{})
	if err == nil {
		t.Fatal("a project that issues no session must not report an authenticated pass")
	}
	if !strings.Contains(err.Error(), "confirmation") {
		t.Errorf("error %q does not tell the operator why, so they cannot act on it", err)
	}
	if !strings.Contains(err.Error(), "-user-jwt") {
		t.Error("the operator is not told the one way forward on such a project")
	}
}

// A closed project yields nothing, and says so rather than inventing a session.
func TestAcquireFailsClosedOnAClosedProject(t *testing.T) {
	g := &gotrue{users: map[string]string{}, closed: true}
	c := newGoTrue(t, g)

	got, err := Acquire(context.Background(), c, "proj", AcquireOptions{})
	if err == nil {
		t.Fatalf("closed signup produced %+v", got)
	}
	if _, ok := identity.Lookup("supabase", "proj"); ok {
		t.Error("an account was remembered for a project that never created one")
	}
}

// The address is stable and derived, never random: an operator cleaning up has
// to be able to find it, and this tool has to be able to find it again.
func TestProbeEmailIsDerivedAndStable(t *testing.T) {
	a, b := ProbeEmail("proj-one"), ProbeEmail("proj-one")
	if a != b {
		t.Errorf("%q != %q; a random address cannot be recovered or cleaned up", a, b)
	}
	if a == ProbeEmail("proj-two") {
		t.Error("two projects share an address, so one deployment's account would be " +
			"handed to another")
	}
	if !strings.Contains(a, "unruly-probe") {
		t.Errorf("%q is not identifiable as this scanner's doing", a)
	}
}

// -no-residue must not register an account.
//
// The flag promises the target is left exactly as it was found, and an account
// in somebody's user table is the least deniable thing this scanner could
// leave. A stored or recoverable one is still used: signing in creates nothing.
func TestNoResidueNeverCreatesAnAccount(t *testing.T) {
	t.Run("nothing exists yet", func(t *testing.T) {
		g := &gotrue{users: map[string]string{}}
		c := newGoTrue(t, g)

		_, err := Acquire(context.Background(), c, "proj", AcquireOptions{NoResidue: true})
		if err == nil {
			t.Fatal("an account was obtained under -no-residue")
		}
		if len(g.users) != 0 || g.signups.Load() != 0 {
			t.Errorf("%d accounts created and %d signup attempts under -no-residue",
				len(g.users), g.signups.Load())
		}
		if !strings.Contains(err.Error(), "-user-jwt") {
			t.Error("the operator is not told how to measure this tier anyway")
		}
	})

	t.Run("one this scanner made earlier", func(t *testing.T) {
		g := &gotrue{users: map[string]string{ProbeEmail("proj"): weakPassword}}
		c := newGoTrue(t, g)

		got, err := Acquire(context.Background(), c, "proj", AcquireOptions{NoResidue: true})
		if err != nil {
			t.Fatalf("an existing account is usable without creating anything: %v", err)
		}
		if got.Created || g.signups.Load() != 0 {
			t.Error("signing in to an existing account must create nothing")
		}
		if got.Token == "" {
			t.Error("no session, so the authenticated tier goes unmeasured for no reason")
		}
	})
}

// The password-policy answer must survive into later scans.
//
// It was set only on the run that created the account, so a second scan of an
// unchanged project reported nothing -- and the second scan is the one an
// operator is more likely to read. Found against a real project, not the stub:
// the stub was always exercising a fresh signup.
func TestWeakPasswordVerdictSurvivesReuse(t *testing.T) {
	g := &gotrue{users: map[string]string{}}
	c := newGoTrue(t, g)

	first, err := Acquire(context.Background(), c, "proj", AcquireOptions{})
	if err != nil || !first.WeakAccepted {
		t.Fatalf("first = %+v, err = %v", first, err)
	}
	second, err := Acquire(context.Background(), c, "proj", AcquireOptions{})
	if err != nil {
		t.Fatalf("second: %v", err)
	}
	if second.Created {
		t.Fatal("the second acquire registered again")
	}
	if !second.WeakAccepted {
		t.Error("the reused account forgot that a weak password was accepted, so the " +
			"policy finding disappears on every scan after the first")
	}
}
