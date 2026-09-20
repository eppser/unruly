package surface

import (
	"strings"
	"testing"

	"github.com/eppser/unruly/internal/client"
	"github.com/eppser/unruly/internal/finding"
)

// Anonymous sign-in is reported when it is on, and never when it is off.
//
// The precision half is the one that costs a report its credibility: the
// settings document lists two dozen providers, almost all false on any real
// project, and a check that misreads the map reports every project in the world
// as issuing anonymous sessions.
func TestAnonymousSignInFinding(t *testing.T) {
	c := client.New(client.Options{BaseURL: "https://x.supabase.co"})

	t.Run("enabled", func(t *testing.T) {
		f, ok := AnonymousSignInFinding(c, AuthConfig{
			Reachable: true,
			External:  map[string]bool{"anonymous_users": true, "email": true},
		})
		if !ok {
			t.Fatal("anonymous sign-ins are on and nothing was reported")
		}
		if f.ID != "supabase-anonymous-signin-enabled" || f.Severity != finding.Medium {
			t.Errorf("finding = %s/%s", f.ID, f.Severity)
		}
		// The remediation has to be usable by someone who wants to KEEP the
		// feature; "turn it off" alone is advice most products cannot take.
		if !strings.Contains(f.Remediation, "is_anonymous") {
			t.Error("no way offered to keep guest sessions and still exclude them " +
				"from policies meant for real users")
		}
		for _, line := range strings.Split(f.Remediation, "\n") {
			if line == "" || strings.HasPrefix(line, "--") {
				continue
			}
			if !strings.ContainsAny(line, "SFWO)") { // SELECT/FROM/WHERE/ORDER fragments
				t.Errorf("non-comment line is not SQL and would be executed: %q", line)
			}
		}
	})

	t.Run("disabled, among many providers", func(t *testing.T) {
		if f, ok := AnonymousSignInFinding(c, AuthConfig{
			Reachable: true,
			External: map[string]bool{
				"anonymous_users": false, "email": true, "google": true, "github": true,
			},
		}); ok {
			t.Errorf("reported %q on a project with anonymous sign-ins off", f.ID)
		}
	})

	t.Run("auth not reachable", func(t *testing.T) {
		// Absent is not false. An unreachable auth server decodes to a zero
		// map, and reading that as "disabled" would be a clean result produced
		// by not looking.
		if _, ok := AnonymousSignInFinding(c, AuthConfig{
			Reachable: false,
			External:  map[string]bool{"anonymous_users": true},
		}); ok {
			t.Error("claimed a setting on an auth server that never answered")
		}
	})
}
