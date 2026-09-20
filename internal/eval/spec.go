// Package eval defines ground-truth targets and scores a scan against them.
//
// Evals come before the scanner on purpose. Every tool surveyed during the
// research that motivated unruly fails in the same direction: it reports
// "no findings" against a database that is in fact world-writable, and nothing
// in its own test suite catches that. Recall against a known answer is the
// only thing that does.
//
// A Target is a declaration of what is true about a Supabase project. The
// runner scans it and scores the result, so every change to the scanner is
// measured rather than eyeballed.
package eval

import (
	"fmt"
	"os"
	"sort"

	"gopkg.in/yaml.v3"
)

// Target is a ground-truth specification for one project in the corpus.
type Target struct {
	// Backend names the product, defaulting to supabase.
	//
	// It exists because the anon-key rule in Validate is not universal.
	// Supabase's anon key is a JWT, and committing one would publish a
	// credential -- so a target must name the environment variable holding it
	// and never carry it inline. Firebase has no anon key at all: its web API
	// key is documented by Google as public, and the Firestore REST surface is
	// reached unauthenticated.
	//
	// Applying the Supabase rule to every target dropped the corpus's only
	// Firebase project from every scoreboard, and RESULTS.md printed the
	// validation error as though it were a decision.
	Backend string `yaml:"backend,omitempty"`

	// Name identifies the target in eval output.
	Name string `yaml:"name"`
	// ProjectRef is the Supabase project reference.
	ProjectRef string `yaml:"project_ref"`
	// Site is the public application URL, used for blackbox discovery evals.
	Site string `yaml:"site,omitempty"`
	// BaseURL overrides the derived cloud origin, for self-hosted or local
	// fixture targets.
	BaseURL string `yaml:"base_url,omitempty"`
	// RestPrefix overrides the PostgREST mount path.
	RestPrefix string `yaml:"rest_prefix,omitempty"`
	// AnonKeyEnv names the environment variable holding the anon key, so no
	// credential is ever committed to the repository.
	AnonKeyEnv string `yaml:"anon_key_env"`
	// AuthenticatedKeyEnv names the variable holding a token for the
	// authenticated role, so the escalation dimension can be graded. The
	// corpus keys have carried this since they were written and Target did
	// not read it, so every corpus project would have been scored with the
	// escalation pass silently switched off.
	AuthenticatedKeyEnv string `yaml:"authenticated_key_env,omitempty"`
	// Fixture marks a target we provisioned ourselves and may safely mutate.
	// Write evals only run against fixtures.
	Fixture bool `yaml:"fixture"`
	// Notes records provenance and any caveats.
	Notes string `yaml:"notes,omitempty"`

	Expect Expectation `yaml:"expect"`
}

// Expectation is the known-correct answer for a target.
type Expectation struct {
	// Relations the scanner must discover. This is the recall denominator.
	Relations []Relation `yaml:"relations"`
	// DiscoverableRef asserts the project ref is recoverable blackbox from
	// Site alone, and names the channel it leaks through.
	DiscoverableRef string `yaml:"discoverable_ref,omitempty"`
	// KeyInBundles asserts whether a credential is currently retrievable from
	// the site's shipped JavaScript.
	KeyInBundles bool `yaml:"key_in_bundles"`
	// OpenRoutes are application endpoints that answer without authentication
	// but should not.
	OpenRoutes []string `yaml:"open_routes,omitempty"`
	// Routines the scanner must discover via the function hint oracle.
	Routines []string `yaml:"routines,omitempty"`
	// EscalationGains are relations readable by an elevated role but not anon.
	EscalationGains []string `yaml:"escalation_gains,omitempty"`
}

// Relation is the expected state of one database relation.
type Relation struct {
	Name string `yaml:"name"`
	// Rows is the exact anon-visible row count. Zero means RLS filters all
	// rows (the relation exists but leaks nothing).
	Rows int `yaml:"rows"`
	// ReadExposed is true when anonymous SELECT returns real rows.
	ReadExposed bool `yaml:"read_exposed"`
	// InsertReachable is true when an anonymous INSERT passes RLS and is
	// rejected by the schema rather than the security layer.
	InsertReachable bool `yaml:"insert_reachable"`
	// SensitiveColumns are columns that must trip the secret/PII classifier.
	SensitiveColumns []string `yaml:"sensitive_columns,omitempty"`
	// Classes are the KINDS of sensitive data the report must name for this
	// relation -- credential, financial, government-id, health, pii, contact,
	// location.
	//
	// Distinct from SensitiveColumns, which names the columns that carry them.
	// A relation can have classes and NO sensitive columns: that is the whole
	// point of the German-named table in corpus project 16, where no column
	// name matches an English rule and only the sampled VALUES carry the
	// answer.
	//
	// NIL AND EMPTY MEAN DIFFERENT THINGS, as everywhere else here. Nil says
	// the key makes no claim and the target is not scored on classification.
	// Empty says the correct answer is that NO class is reported -- the
	// lookalike tables, whose columns end in address and token and name and
	// hold none of those things.
	Classes []string `yaml:"classes,omitempty"`
}

// ExpectedClasses returns the relation:class pairs the report must carry.
//
// Paired rather than flat, so a class found on the WRONG relation counts as a
// false positive and a false negative instead of cancelling out.
func (t *Target) ExpectedClasses() []string {
	var out []string
	for _, r := range t.Expect.Relations {
		for _, c := range r.Classes {
			out = append(out, r.Name+":"+c)
		}
	}
	sort.Strings(out)
	return out
}

// ClaimsClasses reports whether this target makes any classification claim.
//
// Fifteen of the sixteen corpus projects make none, and their scans do report
// sensitive columns. Scoring those against an empty expectation would turn
// every correct classification into a false positive on a dimension they never
// claimed to measure.
func (t *Target) ClaimsClasses() bool {
	for _, r := range t.Expect.Relations {
		if r.Classes != nil {
			return true
		}
	}
	return false
}

// LoadTarget reads a ground-truth spec from disk.
func LoadTarget(path string) (*Target, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var t Target
	if err := yaml.Unmarshal(b, &t); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if err := t.Validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &t, nil
}

// Validate rejects malformed specs early: a wrong eval is worse than none.
func (t *Target) Validate() error {
	if t.Name == "" {
		return fmt.Errorf("name is required")
	}
	if t.ProjectRef == "" {
		return fmt.Errorf("project_ref is required")
	}
	if t.AnonKeyEnv == "" && t.presentsAnAnonJWT() {
		return fmt.Errorf("anon_key_env is required for a %s target "+
			"(credentials must never be committed)", t.BackendOrDefault())
	}
	seen := map[string]bool{}
	for _, r := range t.Expect.Relations {
		if r.Name == "" {
			return fmt.Errorf("relation with empty name")
		}
		if seen[r.Name] {
			return fmt.Errorf("duplicate relation %q", r.Name)
		}
		seen[r.Name] = true
		if r.ReadExposed && r.Rows == 0 {
			return fmt.Errorf("relation %q: read_exposed requires a non-zero row count", r.Name)
		}
		if !r.ReadExposed && r.Rows != 0 {
			return fmt.Errorf("relation %q: rows set but read_exposed is false", r.Name)
		}
	}
	return nil
}

// AnonKey resolves the target's credential from the environment.
//
// A backend with no anonymous credential returns the empty string and no
// error. Firebase is that case: there is nothing to resolve, so demanding a
// variable produced "env  is empty" -- naming no variable, because there was
// none to name -- and excluded the target one layer below Validate.
func (t *Target) AnonKey() (string, error) {
	if !t.presentsAnAnonJWT() {
		return "", nil
	}
	v := os.Getenv(t.AnonKeyEnv)
	if v == "" {
		return "", fmt.Errorf("env %s is empty; export it to run live evals", t.AnonKeyEnv)
	}
	return v, nil
}

// RelationNames returns every expected relation, sorted.
func (t *Target) RelationNames() []string {
	out := make([]string, 0, len(t.Expect.Relations))
	for _, r := range t.Expect.Relations {
		out = append(out, r.Name)
	}
	sort.Strings(out)
	return out
}

// ReadExposed returns relations that must be reported as anonymously readable.
func (t *Target) ReadExposed() []string {
	var out []string
	for _, r := range t.Expect.Relations {
		if r.ReadExposed {
			out = append(out, r.Name)
		}
	}
	sort.Strings(out)
	return out
}

// InsertReachable returns relations that must be reported as anon-writable.
func (t *Target) InsertReachable() []string {
	var out []string
	for _, r := range t.Expect.Relations {
		if r.InsertReachable {
			out = append(out, r.Name)
		}
	}
	sort.Strings(out)
	return out
}

// Routines returns expected RPC routine names, sorted.
func (t *Target) Routines() []string {
	out := append([]string{}, t.Expect.Routines...)
	sort.Strings(out)
	return out
}

// EscalationGains returns expected escalation results, sorted.
func (t *Target) EscalationGains() []string {
	out := append([]string{}, t.Expect.EscalationGains...)
	sort.Strings(out)
	return out
}

// Protected returns relations that must NOT be reported as exposed. Scoring
// these guards against the opposite failure: a scanner that cries wolf on
// every table would score perfect recall and be useless.
func (t *Target) Protected() []string {
	var out []string
	for _, r := range t.Expect.Relations {
		if !r.ReadExposed && !r.InsertReachable {
			out = append(out, r.Name)
		}
	}
	sort.Strings(out)
	return out
}

// BackendOrDefault is the declared backend, or supabase when none is given.
// Every key predates the field and every one of those is Supabase.
func (t Target) BackendOrDefault() string {
	if t.Backend == "" {
		return "supabase"
	}
	return t.Backend
}

// presentsAnAnonJWT reports whether this backend has an anonymous credential
// that would be a secret if committed. Firebase does not: the web API key is
// public by design, so requiring a variable to hold it protects nothing and
// excludes the target.
func (t Target) presentsAnAnonJWT() bool {
	return t.BackendOrDefault() != "firebase"
}
