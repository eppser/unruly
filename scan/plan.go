package scan

import (
	"fmt"
	"sort"
	"strings"
)

// An ArtifactType names something one stage produces and another consumes.
//
// A string rather than a Go type, because validation happens before anything
// runs and a plan has to be checkable -- and printable -- without constructing
// the values it describes. The typed artifact store (Put/Get) is what carries
// the value; this is what lets the ORDER be argued about in advance.
type ArtifactType string

// A StageDescriptor is what a stage declares about itself.
//
// The Supabase stage list is documented as a dependency graph and its order is
// tested as one, but until this the dependencies were implicit: a stage called
// Get and either found something or did not. Reorder two stages, delete a
// producer, add a consumer above its producer, and the failure is a stage that
// quietly finds nothing -- at the far end of a scan that has already spent
// thousands of requests on somebody else's server.
//
// Declaring them makes the graph checkable at the cheapest possible moment:
// before the first request.
type StageDescriptor struct {
	// ID is the stage's name. It is also the ledger label and the resource on
	// its not-assessed finding, so two stages sharing one make the spend
	// breakdown ambiguous in a way no reader can see.
	ID string
	// Requires must be produced by an EARLIER stage. Absent is a planning
	// error, not a run-time surprise.
	Requires []ArtifactType
	// Optional may be absent legitimately. The schemas artifact is the case:
	// absent means no extra schema was discovered, which is the common case,
	// and the default schema is examined either way.
	Optional []ArtifactType
	// Produces is what this stage publishes.
	Produces []ArtifactType

	// MutatesTarget is true when the stage writes to somebody else's project.
	// Declared so a plan can be refused before it starts rather than audited
	// afterwards.
	MutatesTarget bool
	// SendsSecrets is true when the stage transmits a credential the operator
	// supplied to a host that is not the target's own origin.
	SendsSecrets bool
}

// Describer is implemented by stages that declare their dependencies and
// side effects. A stage without one is not runnable: optional metadata cannot
// enforce a graph or a consent boundary.
type Describer interface {
	Describe() StageDescriptor
}

// Validate checks a plan before anything is sent.
//
// Sequential execution, so "earlier in the list" is the whole of the ordering
// question and a cycle is impossible by construction -- a consumer above its
// producer is the shape a cycle takes here, and it is checked directly.
func Validate(stages []Stage) error {
	seen := map[string]bool{}
	produced := map[ArtifactType]string{}
	var problems []string

	for _, s := range stages {
		if _, skipped := s.(skipped); skipped {
			// A disabled stage asks for and produces nothing. Its name remains in
			// the runtime coverage result, but it has no live plan node.
			continue
		}
		d, ok := s.(Describer)
		if !ok {
			problems = append(problems, fmt.Sprintf("stage %q has no descriptor: "+
				"dependencies and side effects cannot be validated", s.Name()))
			continue
		}
		desc := d.Describe()

		if desc.ID == "" {
			problems = append(problems, "a stage declares an empty ID; the ID is the "+
				"ledger label and the coverage resource, so it cannot be blank")
		} else if seen[desc.ID] {
			problems = append(problems, fmt.Sprintf("two stages share the ID %q: the "+
				"spend breakdown and the not-assessed finding both key on it, so one "+
				"stage's traffic and silence would be attributed to the other", desc.ID))
		}
		seen[desc.ID] = true

		// Requirements are checked against what is produced ABOVE, which is
		// what makes producer-before-consumer and no-producer-at-all one
		// check rather than two.
		for _, a := range desc.Requires {
			if _, ok := produced[a]; !ok {
				problems = append(problems, fmt.Sprintf("stage %q requires artifact %q, "+
					"which no earlier stage produces: at run time it finds nothing and "+
					"reports that surface as empty", desc.ID, a))
			}
		}

		// OPTIONAL means "may be absent", NOT "may arrive late". A stage that
		// optionally reads an artifact produced by a LATER stage never sees
		// it: it takes the absent branch on every scan, silently, and reports
		// a narrower result than it could. Absent altogether is fine and is
		// the point of the field.
		for _, a := range desc.Optional {
			if producedLater(stages, a, desc.ID) {
				problems = append(problems, fmt.Sprintf("stage %q optionally reads "+
					"artifact %q, which is produced by a LATER stage: it would take the "+
					"absent branch on every scan and nothing would say so", desc.ID, a))
			}
		}

		for _, a := range desc.Produces {
			if first, dup := produced[a]; dup {
				problems = append(problems, fmt.Sprintf("stages %q and %q both produce "+
					"artifact %q: Put replaces, so whichever runs last silently discards "+
					"the other's work and which that is depends on list order",
					first, desc.ID, a))
				continue
			}
			produced[a] = desc.ID
		}
	}

	if len(problems) == 0 {
		return nil
	}
	sort.Strings(problems)
	return fmt.Errorf("the scan plan is not runnable:\n  - %s",
		strings.Join(problems, "\n  - "))
}

// Consent is what the operator agreed to.
//
// Separate permissions, because they are separate questions. Writing to
// somebody else's project and telling a third party what you are scanning are
// different things to agree to, and an operator who said yes to one has not
// said yes to the other.
type Consent struct {
	// Write authorises requests that change the target: an INSERT probe, a
	// routine invocation, a POST to an application route.
	Write bool
	// ThirdParty authorises telling a party that is not the target about the
	// target -- asking a public archive what a site used to serve, for
	// instance, which discloses what is being scanned to somebody who was not
	// asked.
	ThirdParty bool
}

// CheckConsent refuses a plan the operator has not authorised.
//
// Consent is already checked INSIDE each stage that writes. That is six places,
// each of which has to remember, and a stage added tomorrow that forgets is
// unguarded -- discovered when a row appears in a database nobody agreed to
// have written to. This makes it structural: the plan as a whole is compared
// against the permission as a whole, before anything runs.
//
// It does not replace the per-stage checks. Two independent guards for an
// irreversible action is the right number, and this one is the cheap one:
// it costs the target nothing because it happens first.
//
// The descriptor describes the CONFIGURED stage, not the type. The same stage
// with writes disabled mutates nothing and must not be blocked, or every
// ordinary scan would be refused and the check would be switched off within a
// week.
func CheckConsent(stages []Stage, c Consent) error {
	var writes, discloses []string
	for _, s := range stages {
		if _, skipped := s.(skipped); skipped {
			continue
		}
		d, ok := s.(Describer)
		if !ok {
			continue
		}
		desc := d.Describe()
		if desc.MutatesTarget && !c.Write {
			writes = append(writes, desc.ID)
		}
		if desc.SendsSecrets && !c.ThirdParty {
			discloses = append(discloses, desc.ID)
		}
	}
	sort.Strings(writes)
	sort.Strings(discloses)

	var problems []string
	if len(writes) > 0 {
		problems = append(problems, fmt.Sprintf("these stages would change the target "+
			"and no write consent was given: %s", strings.Join(writes, ", ")))
	}
	if len(discloses) > 0 {
		problems = append(problems, fmt.Sprintf("these stages would tell a third party "+
			"about the target and no such consent was given: %s",
			strings.Join(discloses, ", ")))
	}
	if len(problems) == 0 {
		return nil
	}
	return fmt.Errorf("the scan plan exceeds what was authorised:\n  - %s",
		strings.Join(problems, "\n  - "))
}

// producedLater reports whether any stage after consumer produces a.
func producedLater(stages []Stage, a ArtifactType, consumer string) bool {
	after := false
	for _, s := range stages {
		d, ok := s.(Describer)
		if !ok {
			continue
		}
		desc := d.Describe()
		if desc.ID == consumer {
			after = true
			continue
		}
		if !after {
			continue
		}
		for _, p := range desc.Produces {
			if p == a {
				return true
			}
		}
	}
	return false
}
