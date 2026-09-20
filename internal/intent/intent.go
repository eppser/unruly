// Package intent carries what access a project INTENDED, so a scan can say
// whether reality matches it.
//
// unruly proves what an attacker can reach. Until this, it did not know what
// the attacker was SUPPOSED to reach -- so a relation readable by anyone was
// reported identically whether it held a public price list or a table of
// payslips, and a relation that was correctly locked was reported as nothing
// at all. The operator supplies the missing half.
//
// NO MODEL RUNS DURING A SCAN. An agent reads the application once, out of
// band, and writes this down; verification is then a comparison. The same
// manifest and the same target give the same answer, every time, and the
// answer can be re-checked after a fix -- which is the whole difference
// between an assessment and a test.
package intent

import (
	"bytes"
	"fmt"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// SchemaVersion is the manifest format this binary understands.
//
// A manifest from a newer version is REFUSED rather than half-read: ignoring
// unrecognised fields would silently drop expectations and report the
// remainder as full coverage, which is the failure this package exists to
// prevent, committed by the package itself.
const SchemaVersion = 1

// A Subject is who is asking.
//
// The five tiers a real policy distinguishes. anonymous and authenticated are
// what unruly already measures; owner and other_tenant are the pair that
// catches broken ownership, which anonymous testing cannot see at all -- a
// relation correctly closed to strangers and open to every signed-in user
// reads as protected until somebody asks as a DIFFERENT signed-in user.
type Subject string

const (
	Anonymous     Subject = "anonymous"
	Authenticated Subject = "authenticated"
	Owner         Subject = "owner"
	OtherTenant   Subject = "other_tenant"
	Admin         Subject = "admin"
)

var subjects = map[Subject]bool{
	Anonymous: true, Authenticated: true, Owner: true, OtherTenant: true, Admin: true,
}

// An Operation is what they are trying to do.
type Operation string

const (
	Read   Operation = "read"
	Insert Operation = "insert"
	Update Operation = "update"
	Delete Operation = "delete"
)

var operations = map[Operation]bool{Read: true, Insert: true, Update: true, Delete: true}

// A Result is whether the operation should succeed.
type Result string

const (
	Allow Result = "allow"
	Deny  Result = "deny"
)

// A Scope narrows an allow to the subject's own rows.
//
// `owner` may read invoices -- their own. Recorded because the difference
// between "the owner can read invoices" and "the owner can read ALL invoices"
// is the difference between a working product and a data breach, and a
// manifest that cannot express it would have to be written the loose way.
type Scope string

const (
	ScopeOwn Scope = "own"
	ScopeAll Scope = "all"
)

// An Expectation is one intended rule.
type Expectation struct {
	Resource  string    `yaml:"resource"`
	Operation Operation `yaml:"operation"`
	Subject   Subject   `yaml:"subject"`
	Scope     Scope     `yaml:"scope,omitempty"`
	// Result defaults to allow when a scope is given and deny otherwise, but
	// it is written out in practice: an omitted field is a decision nobody can
	// see.
	Result Result `yaml:"result,omitempty"`
}

// A Manifest is the whole intended policy.
type Manifest struct {
	SchemaVersion int           `yaml:"schema_version"`
	Expect        []Expectation `yaml:"expect"`
}

// Parse reads a manifest and refuses anything it cannot fully understand.
func Parse(b []byte) (Manifest, error) {
	var m Manifest
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(&m); err != nil {
		return Manifest{}, fmt.Errorf("manifest: %w", err)
	}
	if m.SchemaVersion != SchemaVersion {
		return Manifest{}, fmt.Errorf("manifest: schema_version %d, this binary "+
			"understands %d. Reading it anyway would drop the expectations it does not "+
			"recognise and report the rest as full coverage",
			m.SchemaVersion, SchemaVersion)
	}
	for i, e := range m.Expect {
		if e.Resource == "" {
			return Manifest{}, fmt.Errorf("manifest: expectation %d names no resource", i)
		}
		if !subjects[e.Subject] {
			return Manifest{}, fmt.Errorf("manifest: expectation %d has subject %q, "+
				"which is not one of %s. A misspelt subject matches no observation and "+
				"would be reported as unverified forever", i, e.Subject, subjectList())
		}
		if !operations[e.Operation] {
			return Manifest{}, fmt.Errorf("manifest: expectation %d has operation %q, "+
				"which is not one of read, insert, update, delete", i, e.Operation)
		}
		if e.Result != Allow && e.Result != Deny {
			return Manifest{}, fmt.Errorf("manifest: expectation %d has result %q, "+
				"which is not allow or deny", i, e.Result)
		}
		if e.Scope != "" && e.Scope != ScopeOwn && e.Scope != ScopeAll {
			return Manifest{}, fmt.Errorf("manifest: expectation %d has scope %q, "+
				"which is not own or all", i, e.Scope)
		}
		if e.Result == Deny && e.Scope != "" {
			return Manifest{}, fmt.Errorf("manifest: expectation %d denies access but also "+
				"sets scope %q; denied access has no row scope", i, e.Scope)
		}
	}
	return m, nil
}

func subjectList() string {
	out := make([]string, 0, len(subjects))
	for s := range subjects {
		out = append(out, string(s))
	}
	sort.Strings(out)
	return strings.Join(out, ", ")
}

// An Observation is what the scan actually established.
//
// Only facts the scan MEASURED belong here. A relation nobody probed produces
// no observation, which is what makes the expectation unverified rather than
// satisfied.
type Observation struct {
	Resource  string
	Operation Operation
	Subject   Subject
	// Scope is what the measurement established. Empty means the instrument
	// did not distinguish own rows from all rows and cannot satisfy an own-only
	// expectation.
	Scope   Scope
	Allowed bool
}

// State is how one expectation came out.
type State string

const (
	// Matched: reality agrees with the intent.
	Matched State = "matched"
	// Violated: reality and the intent disagree. Usually reality is more
	// permissive, which is a hole; occasionally more restrictive, which is an
	// outage waiting to happen and still evidence that one of the two is
	// wrong.
	Violated State = "violated"
	// Unverified: the scan never established this, so nothing is known. NOT a
	// pass -- counting it as one would let a manifest of intentions produce a
	// clean report from a scan that measured none of them.
	Unverified State = "unverified"
)

// An Outcome is one expectation, checked.
type Outcome struct {
	Expectation Expectation
	State       State
	// Detail says what was observed, or why nothing was.
	Detail string
}

// Verify compares intent against what the scan measured.
//
// Pure and total: every expectation produces exactly one outcome, in the
// manifest's own order, so the result is a statement about the WHOLE intended
// policy rather than a list of the parts that went wrong.
func Verify(m Manifest, obs []Observation) []Outcome {
	seen := map[string]Observation{}
	for _, o := range obs {
		k := key(o.Resource, o.Operation, o.Subject)
		if previous, ok := seen[k]; ok {
			seen[k] = combineObservation(previous, o)
		} else {
			seen[k] = o
		}
	}

	out := make([]Outcome, 0, len(m.Expect))
	for _, e := range m.Expect {
		o, ok := seen[key(e.Resource, e.Operation, e.Subject)]
		if !ok {
			out = append(out, Outcome{Expectation: e, State: Unverified,
				Detail: fmt.Sprintf("the scan did not establish whether %s may %s %s: "+
					"the relation may not have been discovered, or no identity for that "+
					"subject was supplied", e.Subject, e.Operation, e.Resource)})
			continue
		}
		want := e.Result == Allow
		scopeMatches := e.Scope == "" || e.Scope == o.Scope || !want
		if o.Allowed == want && scopeMatches {
			out = append(out, Outcome{Expectation: e, State: Matched,
				Detail: fmt.Sprintf("%s %s %s: %s, as intended",
					e.Subject, e.Operation, e.Resource, allowed(o.Allowed))})
			continue
		}
		detail := fmt.Sprintf("%s %s %s: %s, and the manifest says %s",
			e.Subject, e.Operation, e.Resource, allowed(o.Allowed), e.Result)
		if o.Allowed && want && e.Scope != "" && e.Scope != o.Scope {
			detail = fmt.Sprintf("%s %s %s: allowed with scope %q, and the manifest "+
				"requires scope %q", e.Subject, e.Operation, e.Resource, o.Scope, e.Scope)
		}
		out = append(out, Outcome{Expectation: e, State: Violated, Detail: detail})
	}
	return out
}

// combineObservation is conservative from an access-control perspective. If
// any measured interface permits an operation, the resource is permitted; a
// denial elsewhere does not undo that path. For two permits, all/unknown scope
// dominates own-only scope so a narrow measurement cannot hide a broader one.
func combineObservation(a, b Observation) Observation {
	if !a.Allowed && b.Allowed {
		return b
	}
	if a.Allowed && !b.Allowed {
		return a
	}
	if !a.Allowed { // both deny; scope has no meaning
		return a
	}
	a.Scope = broaderScope(a.Scope, b.Scope)
	return a
}

func broaderScope(a, b Scope) Scope {
	if a == ScopeAll || b == ScopeAll {
		return ScopeAll
	}
	if a == "" || b == "" {
		return ""
	}
	return ScopeOwn
}

func allowed(b bool) string {
	if b {
		return "allowed"
	}
	return "denied"
}

func key(resource string, op Operation, s Subject) string {
	return resource + "\x00" + string(op) + "\x00" + string(s)
}
