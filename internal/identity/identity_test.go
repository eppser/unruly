package identity

import (
	"os"
	"path/filepath"
	"testing"
)

// The store holds passwords for accounts on real projects, so its permissions
// are a security property and not a detail.
//
// This package had no test file at all. Four other packages exercise it
// indirectly -- they set UNRULY_CONFIG_DIR to a temp dir so a test run does not
// write to the operator's real config -- but none of them assert anything about
// the file itself. A regression from 0600 to 0644 would have left every account
// this scanner ever created world-readable on the auditor's machine, and
// nothing would have failed.
func TestTheStoreIsNotReadableByOtherUsers(t *testing.T) {
	// A directory the package must CREATE. Pointing the override at one that
	// already exists grades t.TempDir()'s mode instead of the code's.
	dir := filepath.Join(t.TempDir(), "cfg")
	t.Setenv("UNRULY_CONFIG_DIR", dir)

	if err := Remember(Record{Provider: "supabase", Project: "abc",
		Email: "probe@example.test", Password: "s3cret", Created: "2026-08-21"}); err != nil {
		t.Fatal(err)
	}

	fi, err := os.Stat(Path())
	if err != nil {
		t.Fatalf("the store was not created: %v", err)
	}
	if mode := fi.Mode().Perm(); mode != 0o600 {
		t.Errorf("the identity store is mode %o, want 600. It holds passwords for "+
			"accounts on projects somebody is auditing.", mode)
	}
	// The directory too: 0600 on the file is undone by a world-listable parent
	// that names the projects a scanner has accounts on. The package creates it
	// with MkdirAll(..., 0o700); this is what grades that.
	di, err := os.Stat(filepath.Dir(Path()))
	if err != nil {
		t.Fatal(err)
	}
	if mode := di.Mode().Perm(); mode&0o077 != 0 {
		t.Errorf("the store's directory is mode %o; it names every project this "+
			"scanner holds an account on", mode)
	}
}

// UNRULY_CONFIG_DIR must actually redirect the store.
//
// Every other package's tests depend on this to avoid writing to the
// operator's real ~/.config/unruly. If the override stopped working, those
// tests would silently start mutating the machine they run on -- and passing.
func TestTheConfigDirOverrideRedirectsTheStore(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("UNRULY_CONFIG_DIR", dir)

	if got := Path(); filepath.Dir(got) != dir {
		t.Fatalf("Path() is %q, which is not under the override %q: a test run would "+
			"write to the operator's real config", got, dir)
	}
	home, err := os.UserHomeDir()
	if err == nil {
		if real := filepath.Join(home, ".config", "unruly"); filepath.Dir(Path()) == real {
			t.Fatal("Path() resolved to the real config directory despite the override")
		}
	}
}

// One account per project, not one per run.
//
// That is the entire reason this package exists: signing up is a mutation that
// leaves a user record in somebody's table, so doing it on every scan leaves a
// trail. Remembering the account and reusing it is what keeps the trail to one.
func TestAnAccountIsReusedRatherThanRecreated(t *testing.T) {
	t.Setenv("UNRULY_CONFIG_DIR", t.TempDir())

	first := Record{Provider: "supabase", Project: "abc", Email: "first@example.test",
		Password: "p1", Created: "2026-08-21"}
	if err := Remember(first); err != nil {
		t.Fatal(err)
	}
	got, ok := Lookup("supabase", "abc")
	if !ok {
		t.Fatal("an account was remembered and cannot be found again, so the next scan " +
			"signs up a second time and leaves a second user behind")
	}
	if got.Email != first.Email || got.Password != first.Password {
		t.Errorf("looked up %+v, want the remembered credential back", got)
	}
	// A different project is a different account.
	if _, ok := Lookup("supabase", "other"); ok {
		t.Error("an account for one project was returned for another")
	}
	if _, ok := Lookup("pocketbase", "abc"); ok {
		t.Error("an account for one provider was returned for another")
	}
}
