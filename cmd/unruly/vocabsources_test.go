package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestVocabOnlyProbesNothingElse: the flag's whole promise is a cost bound on
// somebody else's metered project, so "only" has to mean only. If the pinned
// list leaks back in, the operator pays for 884 guesses they declined.
func TestVocabOnlyProbesNothingElse(t *testing.T) {
	o := &options{vocabOnly: true}
	got := vocabularySources(o, []string{"harvested_one"}, []string{"advertised_one"},
		[]string{"orders", "invoices"})

	if len(got.Pinned) != 0 || len(got.Harvested) != 0 || len(got.Advertised) != 0 {
		t.Errorf("-vocab-only still carries other sources: pinned=%d harvested=%d advertised=%d",
			len(got.Pinned), len(got.Harvested), len(got.Advertised))
	}
	if len(got.Supplied) != 2 {
		t.Errorf("supplied names must survive: %v", got.Supplied)
	}
}

// Without the flag the pinned list is the recall, so it must still be there.
func TestWithoutVocabOnlyThePinnedListRemains(t *testing.T) {
	o := &options{}
	got := vocabularySources(o, nil, nil, []string{"orders"})
	if len(got.Pinned) == 0 {
		t.Error("the pinned list is the recall when nothing is supplied; it must not be dropped")
	}
}

// -vocab-only with no -vocab file would probe nothing and report a clean
// project, which is the false negative this tool exists to refuse.
func TestVocabOnlyWithoutAFileIsRefused(t *testing.T) {
	o := &options{vocabOnly: true}
	err := validateFlags(o)
	if err == nil {
		t.Fatal("-vocab-only with no -vocab file was accepted; it would probe nothing")
	}
	if !strings.Contains(err.Error(), "vocab") {
		t.Errorf("the error should name the flag: %v", err)
	}
}

// TestFirebaseCandidatesHonourVocabOnly: the Firestore path builds its own
// candidate list, so restricting the Supabase sources alone would leave this
// path probing the full ~884 names while the flag promised otherwise -- and
// every one of those is a metered read billed to the project's owner.
func TestFirebaseCandidatesHonourVocabOnly(t *testing.T) {
	o := &options{vocabOnly: true, vocabFile: writeVocab(t, "orders", "invoices")}
	got := firebaseCandidates(context.Background(), o, nil)
	if len(got) != 2 {
		t.Errorf("-vocab-only must probe only the supplied names, got %d: %v", len(got), got)
	}
}

// Off, the pinned Firestore vocabulary is the recall and must survive.
func TestFirebaseCandidatesKeepThePinnedListByDefault(t *testing.T) {
	o := &options{}
	got := firebaseCandidates(context.Background(), o, nil)
	if len(got) < 100 {
		t.Errorf("without -vocab-only the pinned collections list is the recall; got %d", len(got))
	}
}

func writeVocab(t *testing.T, names ...string) string {
	t.Helper()
	f := filepath.Join(t.TempDir(), "vocab.json")
	b, err := json.Marshal(map[string]any{
		"schema_version": 1, "stage": "vocabulary", "tool": "test",
		"note": "test fixture", "sources": []string{}, "seeds": names,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(f, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return f
}

// TestVocabOnlyRefusesAnUnreadableFile: naming a file is not enough.
// suppliedVocabulary swallows read and parse errors and returns nil, so an
// unreadable handoff would leave -vocab-only probing nothing and reporting the
// project clean.
func TestVocabOnlyRefusesAnUnreadableFile(t *testing.T) {
	f := filepath.Join(t.TempDir(), "not-a-handoff.txt")
	if err := os.WriteFile(f, []byte("orders\ninvoices\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := validateFlags(&options{vocabOnly: true, vocabFile: f})
	if err == nil {
		t.Fatal("an unreadable -vocab file was accepted with -vocab-only; the scan would probe nothing")
	}
	if !strings.Contains(err.Error(), "no usable names") {
		t.Errorf("the error should say why: %v", err)
	}
}

// The credential decision, tested without a network, a fixture or Docker.
//
// Its one recorded failure produced a scan that reported 0 relations on a
// target where the right key finds 21 -- a report that looked clean. Until
// now it could only be exercised end-to-end with the fixtures up.
func TestChooseKey(t *testing.T) {
	for _, tc := range []struct {
		name                                  string
		current                               string
		fromEnv                               bool
		discovered, discoveredRef, currentRef string
		wantKey                               string
		wantWarn                              bool
		wantDiscovered                        bool
	}{
		{name: "nothing in hand adopts the key the target ships",
			discovered: "target", wantKey: "target", wantDiscovered: true},

		// The regression. A self-hosted target has NO project reference, so
		// the old condition never held and the ambient key was kept.
		{name: "a self-hosted target with no reference still overrules the ambient key",
			current: "ambient", fromEnv: true, discovered: "target",
			wantKey: "target", wantWarn: true, wantDiscovered: true},

		{name: "references present only change the wording, not the decision",
			current: "ambient", fromEnv: true, discovered: "target",
			currentRef: "aaa", discoveredRef: "bbb",
			wantKey: "target", wantWarn: true, wantDiscovered: true},

		// -k is an instruction; SUPABASE_ANON_KEY is ambience.
		{name: "an explicitly supplied key is never overruled",
			current: "supplied", fromEnv: false, discovered: "target",
			wantKey: "supplied"},

		{name: "the same key discovered is not a surprise",
			current: "same", fromEnv: true, discovered: "same", wantKey: "same"},

		{name: "nothing discovered keeps what we had",
			current: "ambient", fromEnv: true, discovered: "", wantKey: "ambient"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := chooseKey(tc.current, tc.fromEnv, tc.discovered, tc.discoveredRef, tc.currentRef)
			if got.Key != tc.wantKey {
				t.Errorf("used key %q, want %q", got.Key, tc.wantKey)
			}
			if (got.Warn != "") != tc.wantWarn {
				t.Errorf("warn=%q, wantWarn=%v", got.Warn, tc.wantWarn)
			}
			if got.Discovered != tc.wantDiscovered {
				t.Errorf("discovered=%v, want %v", got.Discovered, tc.wantDiscovered)
			}
		})
	}
}

// The warning has to name both projects when both are known: "your key is for
// another project" is actionable, "your key does not match" is not.
func TestChooseKeyNamesBothProjectsWhenItCan(t *testing.T) {
	got := chooseKey("ambient", true, "target", "target-ref", "env-ref")
	if !strings.Contains(got.Warn, "env-ref") || !strings.Contains(got.Warn, "target-ref") {
		t.Errorf("the warning should name both projects: %q", got.Warn)
	}
}

// The credential decision after discovery, tested without a network.
//
// Deliberately NOT an end-to-end fixture: reproducing it needs an application
// whose bundle names a managed project origin, and a scanner pointed at that
// fixture follows the declared origin -- so the requests would leave this
// machine and land on a third party's host. A made-up project reference is
// somebody's project, or will be.
func TestCredentialFor(t *testing.T) {
	for _, tc := range []struct {
		name                                        string
		current, currentRef, projectRef, discovered string
		inList                                      bool
		wantKey, wantWithheld                       string
		wantErr                                     bool
	}{
		{name: "no project reference to compare against keeps the key",
			current: "k", currentRef: "aaa", wantKey: "k"},
		{name: "a key that is not a JWT has no reference and is taken as given",
			current: "opaque", projectRef: "bbb", wantKey: "opaque"},
		{name: "the key belongs to this project",
			current: "k", currentRef: "bbb", projectRef: "bbb", wantKey: "k"},

		{name: "a mismatch on one explicit target aborts",
			current: "k", currentRef: "aaa", projectRef: "bbb", wantErr: true},

		// THE BUG: the scan had this target's own key and threw it away.
		{name: "in a list the discovered key is used instead of giving up",
			current: "k", currentRef: "aaa", projectRef: "bbb", discovered: "own",
			inList: true, wantKey: "own", wantWithheld: "aaa"},

		// Old behaviour, still correct -- kept in the table so a later
		// simplification cannot drop the disclosure on the grounds that
		// nothing else changed.
		{name: "with nothing discovered the scan goes on without a key, and says so",
			current: "k", currentRef: "aaa", projectRef: "bbb",
			inList: true, wantWithheld: "aaa"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// fromEnv=false: this table is about an explicitly supplied -k.
			// The ambient case has its own table in ambientkey_test.go,
			// because the two now diverge and folding them together would
			// hide which behaviour a row is pinning.
			got := credentialFor(tc.current, tc.currentRef, tc.projectRef,
				tc.discovered, tc.inList, false)
			if (got.Err != nil) != tc.wantErr {
				t.Fatalf("err=%v, wantErr=%v", got.Err, tc.wantErr)
			}
			if tc.wantErr {
				for _, want := range []string{tc.currentRef, tc.projectRef} {
					if !strings.Contains(got.Err.Error(), want) {
						t.Errorf("the error must name %q so the operator can act: %v",
							want, got.Err)
					}
				}
				return
			}
			if got.Key != tc.wantKey {
				t.Errorf("key %q, want %q", got.Key, tc.wantKey)
			}
			if got.WithheldRef != tc.wantWithheld {
				t.Errorf("withheld %q, want %q -- the report has to say that a supplied "+
					"key was not used", got.WithheldRef, tc.wantWithheld)
			}
		})
	}
}
