package eval_test

import (
	"os"
	"strings"
	"testing"
)

// There must be ONE way to build the client that talks to an application.
//
// When application traffic was moved onto a shared client, two constructions
// were left: client.NewApplication, which the three fetching packages fall back
// to, and a hand-written client.Options literal in main.go carrying the same
// body cap, the same cleared credentials and the same policy. Identical on the
// day they were written, and free to drift on any day after -- with the
// divergence landing precisely where it is hardest to notice, between what the
// binary does and what the packages' own tests exercise.
//
// The policy is not incidental. That client must never carry a Supabase
// credential to a web server, and must read bundles past the 1MB an API
// response deserves. Both are decided inside NewApplication so a caller cannot
// get them wrong by omission, which is the same reasoning the repeated-stage
// check applies to the fields of a single literal, one level up.
func TestTheApplicationClientIsBuiltInOnePlace(t *testing.T) {
	src, err := os.ReadFile("../../cmd/unruly/main.go")
	if err != nil {
		t.Fatal(err)
	}
	main := string(src)

	if !strings.Contains(main, "client.NewApplication(") {
		t.Error("main.go does not build its application client through " +
			"client.NewApplication, so the policy for talking to somebody's web " +
			"server is written in two places")
	}
	// The body cap is the tell: it is the one field whose value differs from the
	// API clients, so a copy of it outside internal/client is a copy of the
	// policy.
	for _, cap := range []string{"MaxBody: 8", "MaxBody:  8", "MaxBody: 8 << 20"} {
		if strings.Contains(main, cap) {
			t.Errorf("main.go sets the application body cap itself (%q); it belongs to "+
				"client.NewApplication, or the two definitions drift", cap)
		}
	}
}
