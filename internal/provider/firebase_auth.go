package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/eppser/unruly/internal/client"
	"github.com/eppser/unruly/internal/finding"
	"github.com/eppser/unruly/internal/identity"
)

// Firebase Auth, and the finding that makes Firebase worth scanning.
//
// The most common Firestore rule in the wild is
//
//	allow read: if request.auth != null
//
// which reads as secured and is not. "Authenticated" in Firebase means anyone
// who can call accounts:signUp, and signup is open by default, so that rule
// grants access to the entire internet at the cost of one HTTP request.
// Measured on the lab: authed_profiles answers 403 anonymously and 200 to an
// account created seconds earlier.
//
// Establishing that requires BEING such a user, and becoming one creates an
// account. That is a mutation, so it is gated behind -write -yes-i-own-this,
// exactly as the Supabase escalation is, and the account is remembered so that
// scanning a project twice does not leave two of them.
//
// The password policy answer falls out of the same request for free. The first
// signup attempt uses a deliberately weak password: if the project accepts it,
// there is no policy above Firebase's six-character floor, and the account
// needed for the escalation probe has been created in the same call.

const (
	weakPassword   = "123456"
	strongPassword = "unruly-Pr0be-98f3a1c7!"
)

type authState struct {
	IDToken string
	Local   string
	// Ephemeral marks an account this run created and must remove again.
	//
	// -no-residue used to refuse to sign up at all, and the reason recorded
	// was that account removal needs a privileged credential. That is true of
	// Supabase, where deleting a user needs the service_role key. It is NOT
	// true of Firebase: Identity Toolkit's accounts:delete takes the account's
	// OWN idToken. Measured against the lab -- signUp 200, authed_profiles 200
	// with 2 documents, accounts:delete 200, and signing in afterwards
	// refused.
	//
	// So the promise can be kept while still measuring the tier that matters
	// most on this backend: create, ask, delete. What such an account must
	// never be is REMEMBERED -- a stored credential that no longer exists is
	// worse than none, because the next run signs in, fails, and concludes the
	// project changed.
	Ephemeral bool
}

// identityToolkit is where Identity Toolkit lives. A variable, not a constant,
// so a test can point the auth probes at a stub -- which is what lets the
// no-residue guarantee be graded without sending a unit test's traffic to
// somebody else's API.
var identityToolkit = "https://identitytoolkit.googleapis.com"

func idtURL(method, key string) string {
	return identityToolkit + "/v1/accounts:" + method +
		"?key=" + url.QueryEscape(key)
}

// authFindings probes sign-in configuration and returns a token for the
// escalation diff when one could be obtained.
func authFindings(ctx context.Context, d Detection, o ScanOptions) ([]finding.Finding, *authState) {
	if d.Credential == "" {
		return nil, nil
	}
	base := "https://identitytoolkit.googleapis.com/v1/accounts:signUp"
	if !o.Write {
		// Honest rather than silent. Every other unmeasured surface in this
		// scanner says so, and this one hides the highest-value Firebase
		// finding there is.
		return []finding.Finding{finding.NotAssessedVerb(base, "firebase-auth", "SIGNUP",
			"establishing what a signed-up user can reach means signing up, which creates "+
				"an account on the target. That is a mutation, so it is gated: re-run with "+
				"-write -yes-i-own-this on a project you own. Until then, any rule of the "+
				"form 'allow read: if request.auth != null' is UNMEASURED, and on a project "+
				"with open signup such a rule is equivalent to public")}, nil
	}

	var out []finding.Finding
	st, reused, weak := signInOrUp(ctx, d, o)
	if weak {
		out = append(out, weakPasswordFinding(d))
	}
	if st != nil {
		out = append(out, openSignupFinding(d, reused))
	}
	if enabled, left := anonymousSignInEnabled(ctx, d, o); enabled {
		out = append(out, anonymousSignInFinding(d))
		if left != "" {
			out = append(out, finding.ProbeAccountLeftBehind(identityToolkit, left))
		}
	}
	return out, st
}

// signInOrUp reuses a remembered account, and only creates one when it must.
// Returns the session, whether an existing account was reused, and whether a
// weak password was accepted.
func signInOrUp(ctx context.Context, d Detection, o ScanOptions) (*authState, bool, bool) {
	if rec, ok := identity.Lookup("firebase", d.Project); ok {
		if st := authCall(ctx, o.Client, idtURL("signInWithPassword", d.Credential),
			map[string]any{"email": rec.Email, "password": rec.Password, "returnSecureToken": true}); st != nil {
			return st, true, false
		}
		// The account was deleted, or the password policy changed. Fall through
		// and make a new one rather than reporting the project as closed.
	}
	email := probeEmail(d.Project)

	// -no-residue: an account a previous run created is still usable, because
	// signing in leaves nothing behind. Creating one is what is forbidden.
	if o.NoResidue {
		for _, pw := range []string{weakPassword, strongPassword} {
			if st := authCall(ctx, o.Client, idtURL("signInWithPassword", d.Credential),
				map[string]any{"email": email, "password": pw, "returnSecureToken": true}); st != nil {
				remember(d, email, pw, st)
				return st, true, pw == weakPassword
			}
		}
		// Nothing to sign in to. An account can still be created here, because
		// this backend lets it delete itself afterwards -- see authState.
		// Ephemeral. Refusing outright would report the highest-value Firebase
		// finding as unmeasured on every project that has never been scanned,
		// which is most of them.
		for _, pw := range []string{weakPassword, strongPassword} {
			if st := authCall(ctx, o.Client, idtURL("signUp", d.Credential),
				map[string]any{"email": email, "password": pw, "returnSecureToken": true}); st != nil {
				st.Ephemeral = true
				return st, false, pw == weakPassword
			}
		}
		return nil, false, false
	}

	// Weak first: if it is accepted, that IS the password-policy answer, and
	// the account the escalation probe needs exists after one request rather
	// than two.
	if st := authCall(ctx, o.Client, idtURL("signUp", d.Credential),
		map[string]any{"email": email, "password": weakPassword, "returnSecureToken": true}); st != nil {
		remember(d, email, weakPassword, st)
		return st, false, true
	}
	if st := authCall(ctx, o.Client, idtURL("signUp", d.Credential),
		map[string]any{"email": email, "password": strongPassword, "returnSecureToken": true}); st != nil {
		remember(d, email, strongPassword, st)
		return st, false, false
	}

	// Signup refused. The commonest reason is not that signup is closed but
	// that this address already exists -- a previous scan created it and the
	// store was lost, moved, or never written. The address is derived from the
	// project id precisely so it can be recovered: try the two passwords this
	// scanner ever uses before concluding the project is shut.
	//
	// Without this, a lost store turns into a new account per run, which is the
	// litter the store exists to prevent.
	for _, pw := range []string{weakPassword, strongPassword} {
		if st := authCall(ctx, o.Client, idtURL("signInWithPassword", d.Credential),
			map[string]any{"email": email, "password": pw, "returnSecureToken": true}); st != nil {
			remember(d, email, pw, st)
			return st, true, pw == weakPassword
		}
	}
	return nil, false, false
}

// finishSession removes an account this run created, after the questions have
// been asked.
//
// Only when this run created it. An account signed INTO belongs to a previous
// scan and is deliberately kept: that is the reason a project accumulates one
// probe account rather than one per run.
//
// Separate from Assess so it can be graded offline. The guard that matters
// here -- every account created is removed -- cannot be checked by exercising
// Assess in a unit test, because Assess also talks to firestore.googleapis.com
// at an absolute URL and a stub cannot stand in front of it.
func finishSession(ctx context.Context, d Detection, o ScanOptions, st *authState) []finding.Finding {
	if st == nil || !st.Ephemeral {
		return nil
	}
	if deleteAccount(ctx, o.Client, d.Credential, st) {
		return nil
	}
	return []finding.Finding{finding.ProbeAccountLeftBehind(
		identityToolkit, probeEmail(d.Project))}
}

// deleteAccount removes an account using its own session, and reports whether
// the target agreed.
func deleteAccount(ctx context.Context, c *client.Client, apiKey string, st *authState) bool {
	if st == nil || st.IDToken == "" {
		return false
	}
	b, _ := json.Marshal(map[string]any{"idToken": st.IDToken})
	resp := c.Do(ctx, "POST", idtURL("delete", apiKey), b,
		map[string]string{"Content-Type": "application/json"})
	return resp.Err == nil && resp.Status == 200
}

// probeEmail is the address this scanner signs up with, derived from the
// project so a lost store can recover it rather than littering a new account
// per run.
func probeEmail(project string) string {
	return fmt.Sprintf("unruly-probe-%s@example.invalid", shortID(project))
}

func remember(d Detection, email, password string, st *authState) {
	_ = identity.Remember(identity.Record{
		Provider: "firebase", Project: d.Project,
		Email: email, Password: password, UID: st.Local,
	})
}

// anonymousSignInEnabled asks for a session with no credentials at all.
// ADMIN_ONLY_OPERATION is the clean negative, measured on the lab.
func anonymousSignInEnabled(ctx context.Context, d Detection, o ScanOptions) (bool, string) {
	st := authCall(ctx, o.Client, idtURL("signUp", d.Credential),
		map[string]any{"returnSecureToken": true})
	if st == nil {
		return false, ""
	}
	// An anonymous account has no reusable credential and no value to a later
	// scan. Always remove it, regardless of -no-residue; otherwise every scan
	// silently adds one user while claiming to perform a read assessment.
	if deleteAccount(ctx, o.Client, d.Credential, st) {
		return true, ""
	}
	left := "anonymous account"
	if st.Local != "" {
		left += " " + st.Local
	}
	return true, left
}

func authCall(ctx context.Context, c *client.Client, url string, body map[string]any) *authState {
	b, _ := json.Marshal(body)
	resp := c.Do(ctx, "POST", url, b, map[string]string{"Content-Type": "application/json"})
	if resp.Err != nil || resp.Status != 200 {
		return nil
	}
	var got struct {
		IDToken string `json:"idToken"`
		LocalID string `json:"localId"`
	}
	if json.Unmarshal(resp.Body, &got) != nil || got.IDToken == "" {
		return nil
	}
	return &authState{IDToken: got.IDToken, Local: got.LocalID}
}

// shortID keeps the probe address stable per project, so re-running against a
// project whose store was lost reuses the same address instead of accumulating
// one per run.
func shortID(project string) string {
	s := strings.ToLower(project)
	if len(s) > 24 {
		s = s[:24]
	}
	return strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			return r
		}
		return '-'
	}, s)
}

func openSignupFinding(d Detection, reused bool) finding.Finding {
	how := "an account was created with the public web API key"
	if reused {
		how = "an account this scanner created earlier was signed back in with the " +
			"public web API key, so signup remains open"
	}
	return finding.Finding{
		ID:       "firebase-auth-open-signup",
		Name:     "Anyone can create an account",
		Severity: finding.Medium,
		Protocol: "firebase-auth",
		Matched:  idtURL("signUp", "$FIREBASE_API_KEY"),
		Resource: "auth:signup",
		Description: "Anyone holding the web API key -- which ships in every visitor's " +
			"browser -- can mint an authenticated identity. On its own that is a normal " +
			"product decision. It matters because it decides what 'request.auth != null' " +
			"means in the rules: with signup open, a rule that admits any signed-in user " +
			"admits the whole internet, at the cost of one HTTP request.",
		FixKind: finding.FixConsole,
		Remediation: "-- Not a rules change. Decide whether self-service signup is intended:\n" +
			"--   Firebase Console -> Authentication -> Sign-in method\n" +
			"-- If it is, stop treating request.auth != null as an authorisation check.\n" +
			"-- Scope rules to the caller instead:\n" +
			"--   allow read: if request.auth != null && request.auth.uid == resource.data.owner;",
		Evidence: finding.Evidence{
			Request: "curl -sS -X POST '" + idtURL("signUp", "$FIREBASE_API_KEY") + "' " +
				"-H 'Content-Type: application/json' " +
				"-d '{\"email\":\"...\",\"password\":\"...\",\"returnSecureToken\":true}'",
			Status: 200,
			Reason: how,
		},
	}
}

func weakPasswordFinding(d Detection) finding.Finding {
	return finding.Finding{
		ID:       "firebase-auth-weak-password",
		Name:     "No password policy beyond the six-character floor",
		Severity: finding.Low,
		Protocol: "firebase-auth",
		Matched:  idtURL("signUp", "$FIREBASE_API_KEY"),
		Resource: "auth:password-policy",
		Description: "The project accepted \"" + weakPassword + "\" as a password. Firebase " +
			"enforces six characters and nothing else unless a policy is configured, so " +
			"accounts here are only as strong as the users choose to make them. This is " +
			"reported low on its own and matters most where accounts guard something: an " +
			"open rule that trusts any signed-in user is reachable by guessing as well as " +
			"by signing up.",
		FixKind: finding.FixConsole,
		Remediation: "-- Firebase Console -> Authentication -> Settings -> Password policy\n" +
			"-- Require length and character classes, and enforce it on sign-up.",
		Evidence: finding.Evidence{Status: 200,
			Reason: "signUp returned a session for the password " + weakPassword},
	}
}

func anonymousSignInFinding(d Detection) finding.Finding {
	return finding.Finding{
		ID:       "firebase-auth-anonymous-signin",
		Name:     "Anonymous sign-in is enabled",
		Severity: finding.Medium,
		Protocol: "firebase-auth",
		Matched:  idtURL("signUp", "$FIREBASE_API_KEY"),
		Resource: "auth:anonymous",
		Description: "A caller with no email, no password and no account received a session " +
			"token. Anonymous sign-in is a legitimate feature, and it means request.auth " +
			"!= null is satisfied by anybody at all -- with no signup form to rate-limit, " +
			"no address to block and no record that identifies who did it.",
		FixKind: finding.FixConsole,
		Remediation: "-- Firebase Console -> Authentication -> Sign-in method -> Anonymous\n" +
			"-- If the app needs it, do not let rules treat an anonymous session as a user:\n" +
			"--   allow read: if request.auth != null && request.auth.token.firebase.sign_in_provider != 'anonymous';",
		Evidence: finding.Evidence{Status: 200,
			Reason: "accounts:signUp issued a session for a request carrying no credentials"},
	}
}
