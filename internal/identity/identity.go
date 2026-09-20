// Package identity remembers accounts this scanner created, so it creates one
// per project rather than one per run.
//
// Testing what a logged-in user can reach requires being one, and on a project
// with open signup the only way to become one is to sign up. That is a
// mutation: it leaves a user record behind. Doing it on every scan leaves a
// trail of accounts in somebody's user table, which is rude on a project you
// own and indefensible on one you are auditing for a client.
//
// So the credential is written down and reused. The file holds passwords for
// accounts on real projects, so it lives outside the repository, is created
// 0600, and is never part of a report.
package identity

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// Record is one account this scanner created.
type Record struct {
	Provider string `json:"provider"`
	Project  string `json:"project"`
	Email    string `json:"email"`
	Password string `json:"password"`
	UID      string `json:"uid,omitempty"`
	Created  string `json:"created"`
}

func (r Record) key() string { return r.Provider + "/" + r.Project }

var mu sync.Mutex

// Path is where identities are stored. UNRULY_CONFIG_DIR overrides it, which
// is what the tests use -- a test that wrote to the operator's real config
// would be a test that alters the machine it runs on.
func Path() string {
	if d := os.Getenv("UNRULY_CONFIG_DIR"); d != "" {
		return filepath.Join(d, "identities.json")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".config", "unruly", "identities.json")
}

func load() (map[string]Record, error) {
	out := map[string]Record{}
	p := Path()
	if p == "" {
		return out, nil
	}
	b, err := os.ReadFile(p)
	if os.IsNotExist(err) {
		return out, nil
	}
	if err != nil {
		return out, err
	}
	if err := json.Unmarshal(b, &out); err != nil {
		// A corrupt store must not stop a scan, and must not be silently
		// overwritten either: the operator may have credentials in there that
		// are the only copy.
		return map[string]Record{}, fmt.Errorf("identity store at %s is unreadable: %w", p, err)
	}
	return out, nil
}

// Lookup returns a previously created account for this project.
func Lookup(provider, project string) (Record, bool) {
	mu.Lock()
	defer mu.Unlock()
	all, err := load()
	if err != nil {
		return Record{}, false
	}
	r, ok := all[Record{Provider: provider, Project: project}.key()]
	return r, ok && r.Email != "" && r.Password != ""
}

// Remember stores an account, replacing any earlier one for the same project.
func Remember(r Record) error {
	mu.Lock()
	defer mu.Unlock()
	p := Path()
	if p == "" {
		return fmt.Errorf("no config directory")
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	all, _ := load() // a corrupt store is replaced rather than losing this record
	if r.Created == "" {
		r.Created = time.Now().UTC().Format(time.RFC3339)
	}
	all[r.key()] = r

	// Sorted keys: the file is small, and a stable one is diffable by anybody
	// who wants to see what this tool has created on their behalf.
	keys := make([]string, 0, len(all))
	for k := range all {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	ordered := make(map[string]Record, len(all))
	for _, k := range keys {
		ordered[k] = all[k]
	}
	b, err := json.MarshalIndent(ordered, "", "  ")
	if err != nil {
		return err
	}
	// 0600: this file holds working passwords for real projects.
	return os.WriteFile(p, append(b, '\n'), 0o600)
}

// List returns every remembered account, so an operator can find what to clean
// up without reading JSON.
func List() []Record {
	mu.Lock()
	defer mu.Unlock()
	all, _ := load()
	keys := make([]string, 0, len(all))
	for k := range all {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]Record, 0, len(all))
	for _, k := range keys {
		out = append(out, all[k])
	}
	return out
}
