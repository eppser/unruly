package main

import (
	"context"
	"encoding/json"
	"os"
	"testing"

	"github.com/eppser/unruly/internal/client"
)

// Function names are case-sensitive, and the vocabulary pipeline folds case.
//
// wordlist.Merge folds every ASCII name to lower case, which is right for
// Postgres relations -- unquoted identifiers are case-insensitive, and the
// folding is what lets a harvested `Users` and a pinned `users` count once.
// A Cloud Function name is not an identifier. It is a path segment, and
// https://<region>-<project>.cloudfunctions.net/publicEcho answers 200 while
// .../publicecho answers 404. Measured against the lab on 2026-08-22.
//
// So the fold silently emptied the one check that consumes this list: Firebase
// convention is camelCase (`exports.publicEcho`, `sendInvoices`), the probe
// asked for the lower-cased spelling, every answer was 404, and 404 is
// deliberately reported as nothing -- a name that is not there says nothing
// about the ones that are. The capability was dead and every existing test
// passed, because they all handed the provider a name directly and never went
// through the pipeline that mangles it.
//
// Found by the Firebase cross-check: the exploit harness used the answer key's
// spelling and got a payload, the scan reported no finding, and a false
// negative is the failure this tool exists to refuse.
func TestSuppliedFunctionNamesKeepTheirCase(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/vocab.json"
	b, err := json.Marshal(map[string]any{
		"schema_version": 1, "stage": "vocabulary",
		"seeds": []string{"publicEcho", "privateControl", "sendInvoices"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatal(err)
	}

	// A site MUST be set. Without one harvestFor returns the supplied names
	// untouched and this test passes while the defect is fully present -- the
	// fold lives on the merge path, which is the path taken whenever there is
	// an application to harvest from, which is every real scan and the
	// cross-check both. The site here refuses connections, so harvesting
	// contributes nothing and what survives is exactly what was supplied.
	o := &options{vocabFile: path, site: "http://127.0.0.1:1", timeout: 1}
	got := harvestFor(context.Background(), o, client.NewLimiter(0))

	have := map[string]bool{}
	for _, s := range got {
		have[s] = true
	}
	for _, want := range []string{"publicEcho", "privateControl", "sendInvoices"} {
		if !have[want] {
			t.Errorf("the vocabulary handed to the function check does not contain %q "+
				"(it has %v). A folded name addresses a URL that does not exist, the "+
				"probe answers 404, and 404 is reported as nothing -- so the check goes "+
				"silent on exactly the names Firebase convention produces", want, got)
		}
	}
}
