package eval_test

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The auth surface, graded locally.
//
// Every Supabase auth check -- open signup, the password policy, anonymous
// sign-in, and the escalation pass that has to BE a logged-in user -- was
// measurable only against the cloud exploit lab, which needs network access and
// a secret CI does not have. A check graded only where the secrets are is a
// check that quietly stops being graded, and anonymous sign-in had no live
// grading anywhere: the cloud lab has the feature switched off, so only the
// silent half was ever exercised.
//
// The fixture is a real GoTrue behind a gateway that mounts it where the
// managed product does, so this measures the scanner against a server that
// behaves like the product rather than against canned JSON.
func TestAuthSurfaceIsGradedAgainstARealAuthServer(t *testing.T) {
	requireLiveEvals(t)
	requireReachable(t, "http://127.0.0.1:54327/auth/v1/settings")
	key := os.Getenv("UNRULY_FIXTURE_KEY")
	if key == "" {
		t.Skip("set UNRULY_FIXTURE_KEY")
	}

	// Delete any account a previous run created, so "was an account created"
	// is a question this test actually decides. Without it the residue finding
	// is correctly SILENT -- the account is reused, which is the design -- and
	// the assertion below would be measuring the order the tests happened to
	// run in.
	del := exec.Command("docker", "exec", "unruly-lab-db-1", "psql", "-U", "postgres",
		"-d", "fixture", "-c", "DELETE FROM auth.users WHERE email LIKE 'unruly-probe%';")
	if out, err := del.CombinedOutput(); err != nil {
		t.Skipf("FIXTURE UNREACHABLE: could not reset the auth fixture's users: %v\n%s",
			err, out)
	}

	dir := t.TempDir()
	out := filepath.Join(dir, "scan.json")
	cmd := exec.Command(buildScanner(t), "-u", "http://127.0.0.1:54327",
		"-provider", "supabase", "-k", key,
		"-write", "-yes-i-own-this", "-j", "-o", out, "-silent")
	// Never the operator's real identity store, and never an inherited key.
	cmd.Env = append(os.Environ(), "UNRULY_CONFIG_DIR="+dir, "SUPABASE_ANON_KEY=")
	_ = cmd.Run()

	b, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("scan produced no report: %v", err)
	}
	got := map[string]string{}
	for _, line := range strings.Split(string(b), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var f struct{ ID, Severity string }
		if json.Unmarshal([]byte(line), &f) != nil {
			t.Fatalf("report line is not JSON: %q", line)
		}
		got[f.ID] = f.Severity
	}

	// The fixture is deliberately the vulnerable case: signup open, autoconfirm
	// on, anonymous sign-in enabled, no password policy above the floor.
	want := map[string]string{
		"supabase-open-signup":              "medium",
		"supabase-anonymous-signin-enabled": "medium",
		"supabase-weak-password-policy":     "low",
		// And the account this created is reported, because a scan holding only
		// the public key cannot delete it.
		"unruly-probe-account-left-behind": "info",
	}
	for id, sev := range want {
		switch actual, ok := got[id]; {
		case !ok:
			t.Errorf("%s was not reported against a real auth server", id)
		case actual != sev:
			t.Errorf("%s reported at %s, want %s", id, actual, sev)
		}
	}

	// Being a logged-in user is the point: a policy granting SELECT TO
	// authenticated is the tier the threat model calls most-missed.
	//
	// Severity is asserted as a floor rather than a value. It is a function of
	// WHAT the elevated role can reach -- credentials and personal data rate
	// critical, ordinary rows high -- so pinning one number would make this
	// test fail whenever the fixture's seed data changed, for a reason that has
	// nothing to do with the capability being graded.
	switch got["supabase-authenticated-escalation"] {
	case "critical", "high":
	case "":
		t.Error("signing up reached rows the anonymous role cannot, and nothing " +
			"reported it: this is the tier the threat model calls most-missed")
	default:
		t.Errorf("escalation reported at %s, want high or critical",
			got["supabase-authenticated-escalation"])
	}
}

// The storage surface, graded locally.
//
// supabase-public-storage-bucket, supabase-storage-anon-write and
// unruly-probe-object-left-behind were graded only through the cloud exploit
// lab's answer key, behind a secret CI does not have.
//
// The fixture serves storage's RESPONSES from the gateway rather than running
// storage-api, which was tried and did not land (docs/lessons-learned.md). What
// the checks consume is the response shape, and that is what this measures. It
// models the configuration people actually write: a bucket that accepts an
// anonymous upload and refuses to let it be deleted again.
func TestStorageSurfaceIsGradedLocally(t *testing.T) {
	requireLiveEvals(t)
	requireReachable(t, "http://127.0.0.1:54327/storage/v1/bucket")
	key := os.Getenv("UNRULY_FIXTURE_KEY")
	if key == "" {
		t.Skip("set UNRULY_FIXTURE_KEY")
	}

	dir := t.TempDir()
	out := filepath.Join(dir, "scan.json")
	cmd := exec.Command(buildScanner(t), "-u", "http://127.0.0.1:54327",
		"-provider", "supabase", "-k", key,
		"-write", "-yes-i-own-this", "-j", "-o", out, "-silent")
	cmd.Env = append(os.Environ(), "UNRULY_CONFIG_DIR="+dir, "SUPABASE_ANON_KEY=")
	_ = cmd.Run()

	b, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("scan produced no report: %v", err)
	}
	got := map[string]string{}
	res := map[string]string{}
	for _, line := range strings.Split(string(b), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var f struct{ ID, Severity, Resource string }
		if json.Unmarshal([]byte(line), &f) != nil {
			t.Fatalf("report line is not JSON: %q", line)
		}
		got[f.ID] = f.Severity
		res[f.ID] = f.Resource
	}

	for id, sev := range map[string]string{
		"supabase-public-storage-bucket": "medium",
		// Writing to a stranger's bucket is critical: it is the one storage
		// finding where an attacker changes the target rather than reading it.
		"supabase-storage-anon-write": "critical",
		// And the probe object could not be removed, which the operator has to
		// be told because this scanner put it there.
		"unruly-probe-object-left-behind": "high",
	} {
		switch actual, ok := got[id]; {
		case !ok:
			t.Errorf("%s was not reported against the storage fixture", id)
		case actual != sev:
			t.Errorf("%s reported at %s, want %s", id, actual, sev)
		}
	}

	// The private bucket must not be reported. The list endpoint returns it
	// alongside the public one, and a check that reads the flag wrongly would
	// report every bucket on every project.
	if r := res["supabase-public-storage-bucket"]; r != "public-uploads" {
		t.Errorf("public-bucket finding names %q, want public-uploads: the private "+
			"bucket in the same listing must not be reported", r)
	}
}
