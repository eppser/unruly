package surface

import (
	"fmt"

	"github.com/eppser/unruly/internal/client"
	"github.com/eppser/unruly/internal/finding"
)

// Anonymous sign-in, which makes `authenticated` free.
//
// Supabase's anonymous sign-ins issue a real session to a caller who supplies
// nothing at all -- no email, no password, no confirmation. Every row-level
// security policy written TO authenticated then admits the entire internet, and
// unlike open signup there is no form to rate-limit, no address to block and no
// record of who did it.
//
// The threat model prices attacker tiers by what they cost. Open signup makes
// the middle tier cost one HTTP request; anonymous sign-in makes it cost
// nothing and leaves nothing behind. That is a real difference to a defender
// deciding what to fix first, so it is reported separately rather than folded
// into open signup.
//
// No mutation is needed to establish it. GoTrue's settings document states it
// outright under external.anonymous_users -- which is better than the Firebase
// equivalent can manage, since Identity Toolkit publishes nothing and the only
// way to find out there is to sign in and leave a user behind.

// AnonymousSignInFinding reports anonymous sign-ins being enabled.
func AnonymousSignInFinding(c *client.Client, a AuthConfig) (finding.Finding, bool) {
	if !a.Reachable || !a.External["anonymous_users"] {
		return finding.Finding{}, false
	}
	return finding.Finding{
		ID:       "supabase-anonymous-signin-enabled",
		Name:     "Anonymous sign-in issues a session to anybody",
		Severity: finding.Medium,
		Protocol: "gotrue",
		Matched:  c.BaseURL() + "/auth/v1/settings",
		Resource: "auth",
		Description: "This project issues an `authenticated` session to a caller who supplies " +
			"no credentials at all -- no email, no password, no confirmation step. Every " +
			"policy written TO authenticated therefore admits the entire internet. This is " +
			"weaker than open signup rather than the same thing: there is no form to " +
			"rate-limit, no address to block, and no record of who obtained the session. " +
			"Anonymous sign-in is a legitimate feature for guest carts and trials; the " +
			"question is whether the policies granting access to authenticated were " +
			"written knowing that authenticated includes everyone.",
		Remediation: `-- Every policy below admits anyone who calls signInAnonymously().
SELECT schemaname, tablename, policyname, cmd, qual
FROM pg_policies
WHERE 'authenticated' = ANY (roles)
ORDER BY tablename;

-- Where a policy was meant for real users, exclude anonymous sessions. The
-- claim is on the JWT, so it can be tested directly:
-- CREATE POLICY "real_users_only" ON your_table
--   FOR SELECT TO authenticated
--   USING (coalesce((auth.jwt() ->> 'is_anonymous')::boolean, false) = false);

-- If guest sessions are not a feature of this product, turn them off in
-- Authentication > Sign In / Providers > Anonymous sign-ins.`,
		Evidence: finding.Evidence{
			Request: fmt.Sprintf("curl -sS '%s/auth/v1/settings' -H 'apikey: $SUPABASE_ANON_KEY'",
				c.BaseURL()),
			Reason:   "external.anonymous_users=true",
			Response: `{"external":{"anonymous_users":true}}`,
		},
	}, true
}
