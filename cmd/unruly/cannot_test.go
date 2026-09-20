package main

import (
	"strings"
	"testing"
)

func TestCannotStartNamesWhatIsActuallyMissing(t *testing.T) {
	if err := cannotStart("https://app.example", "https://app.example"); err != nil {
		t.Errorf("a site is all discovery needs; got %v", err)
	}

	// THE RECORDED BUG: with a URL in hand the gap is the credential. A message
	// leading with -site sends the operator to add a flag that will not help.
	err := cannotStart("https://ref.supabase.co", "")
	if err == nil {
		t.Fatal("no site and no credential is not a scannable state")
	}
	if !strings.Contains(err.Error(), "https://ref.supabase.co") {
		t.Errorf("the message does not name the target it is about: %v", err)
	}
	if !strings.Contains(err.Error(), "-key") {
		t.Errorf("the gap is the credential and the message does not say -key: %v", err)
	}
	if i, j := strings.Index(err.Error(), "-key"), strings.Index(err.Error(), "-site"); j != -1 && j < i {
		t.Errorf("the message leads with -site, which is the flag that would not have "+
			"helped; the credential is what is missing: %v", err)
	}

	// Nothing to discover from: every route in is worth naming.
	err = cannotStart("examplerefexampleref", "")
	if err == nil {
		t.Fatal("a bare reference with no site and no key cannot start a scan")
	}
	for _, flag := range []string{"-site", "-key", "-project-ref", "-base-url"} {
		if !strings.Contains(err.Error(), flag) {
			t.Errorf("with nothing to discover from the message must name every way in; "+
				"%s is missing: %v", flag, err)
		}
	}
}

func TestNoKeySaysWhenASignInScreenIsTheReason(t *testing.T) {
	wall := noKey("https://app.example", true)
	plain := noKey("https://app.example", false)
	if wall == nil || plain == nil {
		t.Fatal("no key is not a scannable state either way")
	}
	// The whole value of the first case is the diagnosis. Asserting each
	// message alone would pass even if both branches returned the same string,
	// and collapsing them is the change that looks like simplification.
	if wall.Error() == plain.Error() {
		t.Error("a site behind a sign-in gets the same sentence as one that simply " +
			"ships no key; the diagnosis is the whole value of the first case")
	}
	if !strings.Contains(wall.Error(), "sign-in") {
		t.Errorf("the login-wall message does not say a sign-in screen was found: %v", wall)
	}
	if !strings.Contains(wall.Error(), "https://app.example") {
		t.Errorf("the message does not name the site it is about: %v", wall)
	}
	for _, route := range []string{"-site", "-key"} {
		if !strings.Contains(wall.Error(), route) {
			t.Errorf("the login-wall message omits %s, and either may be the route the "+
				"operator can actually take: %v", route, wall)
		}
	}
	if !strings.Contains(plain.Error(), "SUPABASE_ANON_KEY") {
		t.Errorf("the plain message omits the environment variable: %v", plain)
	}
}
