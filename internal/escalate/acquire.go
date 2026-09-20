package escalate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/projectdiscovery/gologger"

	"github.com/eppser/unruly/internal/client"
	"github.com/eppser/unruly/internal/identity"
	"github.com/eppser/unruly/internal/mailbox"
)

// Becoming a logged-in user, so the middle tier can be measured at all.
//
// The threat model names three tiers an attacker can occupy, and says the
// middle one is the one that gets missed: a policy granting SELECT TO
// authenticated reads as secured, and where signup is open the set it admits is
// everyone. Distinguishing "scoped to the owner" from "open to anybody who
// registers" requires holding a real authenticated token.
//
// Until now the Supabase side only ran that comparison when an operator pasted
// a JWT in by hand with -user-jwt. Nothing minted one, so on every scan where
// nobody had gone and made an account first, the most-missed tier in this
// tool's own threat model was simply not measured -- and an "any authenticated
// user" policy was reported as protected.
//
// Signing up is a mutation. It is gated behind -write -yes-i-own-this exactly
// as INSERT probing is, the account is written down and reused rather than
// recreated per run, and it is reported as residue because it is.

const (
	// Weak first, because if it is accepted that IS the password-policy answer
	// and the account exists after one request rather than two. Both are
	// constants rather than random so a lost identity store can be recovered by
	// signing in, instead of turning into a new account on every run.
	weakPassword = "password123"
	// WeakPassword is exported so the report can name what was accepted. A
	// finding that says "a weak password" without saying which one cannot be
	// checked by the reader.
	WeakPassword   = weakPassword
	strongPassword = "Unruly-Probe-9f2a7c41!"
)

// Account is a credential this scanner holds for a project.
type Account struct {
	Token string
	Email string
	// Created is true when THIS run made the account, which is what decides
	// whether there is residue to report.
	Created bool
	// WeakAccepted is true when the project took a password no policy worth the
	// name would allow.
	WeakAccepted bool
}

// ProbeEmail is the address this scanner uses for a project. Derived from the
// project rather than random, so the account is findable again -- both by this
// tool when its store is lost, and by an operator cleaning up.
func ProbeEmail(project string) string {
	sum := sha256.Sum256([]byte(project))
	// One format string, not a concatenation. "unruly-probe-" standing alone as
	// a literal sits in the finding-id namespace and the audit indexes it as a
	// finding nobody documented -- the same trap the Firebase probe's
	// appInstanceId fell into.
	return fmt.Sprintf("unruly-probe-%s@example.invalid", hex.EncodeToString(sum[:])[:10])
}

// AcquireOptions controls how far this is allowed to go.
type AcquireOptions struct {
	// NoResidue forbids creating anything. A stored or recoverable account is
	// still used -- signing in leaves nothing behind -- but a project where
	// this scanner has no account yet is reported as unmeasured rather than
	// registered on.
	//
	// -no-residue promises the target is left exactly as it was found, and an
	// account in somebody's user table is the least deniable thing this scanner
	// could leave. The audit checks that every package issuing a mutating
	// request honours the flag, and caught this one.
	NoResidue bool

	// Mailbox receives the confirmation mail when a project withholds the
	// session until the address is verified.
	//
	// Nil is the default and means the previous behaviour: such a project is
	// reported as unmeasured, with the reason named. Supplying one is the
	// operator asking for a third-party call, which the scan path otherwise
	// does not make -- the same shape as -write.
	//
	// mailbox.Provider, not a structural copy of it. The first attempt declared
	// an anonymous interface here to avoid the import, and Go does not allow it:
	// return types are invariant, so a provider whose Open returns
	// mailbox.Mailbox does not satisfy an interface whose Open returns an
	// identical-looking anonymous one. The dependency is one-way and small --
	// internal/mailbox knows nothing about escalation -- and a fake in a test
	// implements the same two interfaces.
	Mailbox mailbox.Provider
	// ConfirmWait bounds how long to wait for that mail. Zero selects
	// defaultConfirmWait.
	ConfirmWait time.Duration
}

// defaultConfirmWait is fifteen times the delivery time measured against the
// mailbox provider (a probe message was listed on the first poll, under two
// seconds). Generous enough that a slow sender is not mistaken for a silent
// one, short enough that a scan does not hang on a project whose mail never
// arrives.
const defaultConfirmWait = 30 * time.Second

// Acquire returns an authenticated token for the project, reusing a stored
// account before creating one.
//
// The order matters and each step earns its place:
//
//  1. a remembered account, signed in    -- no mutation at all
//  2. a fresh signup, weak then strong   -- one account, ever
//  3. sign-in with the two passwords this scanner uses -- recovers an account
//     a previous run created when the store was lost, moved, or never written
//
// Without step 3 a lost store becomes a new account per run, which is the exact
// litter the store exists to prevent.
func Acquire(ctx context.Context, c *client.Client, project string, o AcquireOptions) (Account, error) {
	if rec, ok := identity.Lookup("supabase", project); ok {
		if tok := signIn(ctx, c, rec.Email, rec.Password); tok != "" {
			// The stored password answers the policy question without asking
			// again. Without this the weak-password finding appeared only on
			// the run that created the account and never afterwards, so two
			// scans of an unchanged project disagreed -- and the second one,
			// the one an operator is more likely to read, was the silent one.
			return Account{Token: tok, Email: rec.Email,
				WeakAccepted: rec.Password == weakPassword}, nil
		}
		// Deleted, or the password policy changed. Fall through rather than
		// reporting the project as closed on the strength of a stale file.
	}

	email := ProbeEmail(project)

	// With a mailbox, the address to register IS the mailbox, and it has to be
	// decided here rather than after signup: the confirmation mail is sent to
	// whatever address the account was created with, so choosing it later would
	// mean the message went to example.invalid and nothing could receive it.
	var inbox mailbox.Mailbox
	if o.Mailbox != nil && !o.NoResidue {
		mb, err := o.Mailbox.Open(ctx, project)
		if err != nil {
			return Account{}, fmt.Errorf("opening a mailbox with %s: %w", o.Mailbox.Name(), err)
		}
		inbox = mb
		email = mb.Address()
		// The inbox is residue this tool created. Removing it is not optional,
		// and a removal that fails is reported rather than swallowed -- the
		// same rule the probe rows and the probe account already follow.
		defer func() {
			if cerr := inbox.Close(context.Background()); cerr != nil {
				gologger.Warning().Msgf("mailbox %s could not be removed: %v",
					inbox.Address(), cerr)
			}
		}()
	}

	// Sign in FIRST under -no-residue: an account a previous run created is
	// still usable, and using it creates nothing.
	if o.NoResidue {
		for _, pw := range []string{weakPassword, strongPassword} {
			if tok := signIn(ctx, c, email, pw); tok != "" {
				remember(project, email, pw)
				return Account{Token: tok, Email: email, WeakAccepted: pw == weakPassword}, nil
			}
		}
		return Account{}, fmt.Errorf("-no-residue forbids creating an account and none " +
			"exists for this project, so what a logged-in user can reach was not " +
			"measured; drop -no-residue, or supply -user-jwt")
	}

	for _, pw := range []string{weakPassword, strongPassword} {
		tok, confirmNeeded := signUp(ctx, c, email, pw)
		if confirmNeeded && inbox != nil {
			wait := o.ConfirmWait
			if wait <= 0 {
				wait = defaultConfirmWait
			}
			link, err := inbox.Await(ctx, wait)
			if err != nil {
				// Reported as what it is. A project whose mail is slow,
				// filtered or misrouted has not declined to send one, and
				// saying otherwise would be a false statement about somebody
				// else's system.
				return Account{}, fmt.Errorf("signup succeeded and the project requires "+
					"email confirmation, but %w", err)
			}
			// Following the link is what confirms the account. It addresses the
			// project's own auth service, not a third party.
			if r := c.Do(ctx, "GET", link, nil, nil); r.Err != nil {
				return Account{}, fmt.Errorf("following the confirmation link: %w", r.Err)
			}
			if tok := signIn(ctx, c, email, pw); tok != "" {
				remember(project, email, pw)
				return Account{Token: tok, Email: email, Created: true,
					WeakAccepted: pw == weakPassword}, nil
			}
			return Account{}, fmt.Errorf("the confirmation link was followed but sign-in "+
				"still failed for %s", email)
		}
		if confirmNeeded {
			return Account{}, fmt.Errorf("signup succeeded but the project requires email "+
				"confirmation, so no session was issued; supply -user-jwt for a confirmed "+
				"account, or -mailbox to receive the confirmation (%s)", email)
		}
		if tok != "" {
			remember(project, email, pw)
			return Account{Token: tok, Email: email, Created: true,
				WeakAccepted: pw == weakPassword}, nil
		}
	}

	for _, pw := range []string{weakPassword, strongPassword} {
		if tok := signIn(ctx, c, email, pw); tok != "" {
			remember(project, email, pw)
			return Account{Token: tok, Email: email, WeakAccepted: pw == weakPassword}, nil
		}
	}
	return Account{}, fmt.Errorf("could not obtain an authenticated session: signup was " +
		"refused and no account this scanner created could be signed in to")
}

// signUp returns a session token, and whether the project accepted the account
// but withheld a session pending email confirmation.
//
// Those two are deliberately separated. A confirmation-required project is not
// a closed one, and reporting it as "signup refused" would be wrong in the
// direction that matters: it hides a tier that IS reachable by anybody willing
// to receive an email.
func signUp(ctx context.Context, c *client.Client, email, password string) (string, bool) {
	r := c.Do(ctx, "POST", c.BaseURL()+"/auth/v1/signup",
		mustJSON(map[string]string{"email": email, "password": password}),
		map[string]string{"Content-Type": "application/json"})
	if r.Err != nil || r.Status < 200 || r.Status >= 300 {
		return "", false
	}
	var out struct {
		AccessToken string `json:"access_token"`
		ID          string `json:"id"`
		Email       string `json:"email"`
	}
	if json.Unmarshal(r.Body, &out) != nil {
		return "", false
	}
	if out.AccessToken != "" {
		return out.AccessToken, false
	}
	// 200 with a user and no session is GoTrue saying "confirm your email".
	return "", out.ID != "" || out.Email != ""
}

func signIn(ctx context.Context, c *client.Client, email, password string) string {
	r := c.Do(ctx, "POST", c.BaseURL()+"/auth/v1/token?grant_type=password",
		mustJSON(map[string]string{"email": email, "password": password}),
		map[string]string{"Content-Type": "application/json"})
	if r.Err != nil || r.Status != 200 {
		return ""
	}
	var out struct {
		AccessToken string `json:"access_token"`
	}
	if json.Unmarshal(r.Body, &out) != nil {
		return ""
	}
	return out.AccessToken
}

func remember(project, email, password string) {
	// A store that cannot be written is not worth failing a scan over; the
	// cost is one extra account next time, and the scan itself is unaffected.
	_ = identity.Remember(identity.Record{
		Provider: "supabase", Project: project, Email: email,
		Password: password, Created: time.Now().UTC().Format(time.RFC3339),
	})
}

func mustJSON(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}
