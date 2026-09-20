package scan

import (
	"context"
	"strings"
	"testing"
)

// A plan is checked BEFORE a single request goes out.
//
// The stage list is called a dependency graph and its order is documented as
// one, but the dependencies are implicit: a stage calls scan.Get and finds
// something or does not. Get something wrong -- reorder two stages, delete a
// producer, add a consumer above its producer -- and the failure is a stage
// that quietly finds nothing, at the far end of a scan that has already spent
// thousands of requests on somebody else's server.
//
// Declaring what each stage requires and produces makes that checkable without
// sending anything, which is the point: the cheapest possible moment to
// discover the scan cannot work is before it starts.
func TestAConsumerBeforeItsProducerIsRejected(t *testing.T) {
	err := Validate([]Stage{
		described{id: "probe", requires: []ArtifactType{"relations"}},
		described{id: "relations", produces: []ArtifactType{"relations"}},
	})
	if err == nil {
		t.Fatal("a stage that consumes an artifact produced after it was accepted; " +
			"at run time it finds nothing and reports a surface as empty")
	}
	if !strings.Contains(err.Error(), "relations") {
		t.Errorf("error %q does not name the artifact, so the operator cannot tell "+
			"which dependency is wrong", err)
	}
}

// A required artifact nobody produces.
func TestARequirementWithNoProducerIsRejected(t *testing.T) {
	err := Validate([]Stage{
		described{id: "probe", requires: []ArtifactType{"relations"}},
	})
	if err == nil {
		t.Fatal("a stage requiring an artifact no stage produces was accepted")
	}
}

// Two stages claiming the same artifact.
//
// Put replaces, so the second silently wins and the first's work is discarded.
// Which one ran last then depends on list order, which is exactly the kind of
// thing that changes without anyone deciding it did.
func TestTwoProducersOfOneArtifactAreRejected(t *testing.T) {
	err := Validate([]Stage{
		described{id: "a", produces: []ArtifactType{"relations"}},
		described{id: "b", produces: []ArtifactType{"relations"}},
	})
	if err == nil {
		t.Fatal("two stages producing the same artifact were accepted; Put replaces, so " +
			"one of them is silently discarded")
	}
}

// Duplicate stage IDs.
//
// The ID is the ledger label and the not-assessed finding's resource, so two
// stages sharing one make the spend breakdown and the coverage report
// ambiguous in a way no reader can see.
func TestDuplicateStageIDsAreRejected(t *testing.T) {
	if err := Validate([]Stage{described{id: "probe"}, described{id: "probe"}}); err == nil {
		t.Fatal("two stages with the same ID were accepted")
	}
}

// OPTIONAL requirements are not requirements.
//
// The schemas artifact is the case: absent means no extra schema was
// discovered, which is the common case, and the default schema is examined
// either way. Treating that as a missing dependency would refuse to run a
// perfectly ordinary scan.
func TestAnOptionalArtifactNeedsNoProducer(t *testing.T) {
	if err := Validate([]Stage{
		described{id: "realtime", optional: []ArtifactType{"schemas"}},
	}); err != nil {
		t.Errorf("an optional artifact with no producer was rejected: %v", err)
	}
}

// A stage that declares nothing is not a broken stage.
//
// An optional descriptor cannot enforce dependencies or consent. Once every
// built-in provider has adopted the seam, an undescribed stage is a broken
// plugin rather than a compatibility mode.
func TestUndescribedStagesAreRejected(t *testing.T) {
	if err := Validate([]Stage{plain{}, described{id: "probe"}}); err == nil {
		t.Error("a stage with no descriptor was accepted, so its side effects are unknowable")
	}
}

type described struct {
	id        string
	requires  []ArtifactType
	optional  []ArtifactType
	produces  []ArtifactType
	mutates   bool
	discloses bool
}

func (d described) Name() string                      { return d.id }
func (d described) Run(context.Context, *State) error { return nil }
func (d described) Describe() StageDescriptor {
	return StageDescriptor{ID: d.id, Requires: d.requires, Optional: d.optional,
		Produces: d.produces, MutatesTarget: d.mutates, SendsSecrets: d.discloses}
}

type plain struct{}

func (plain) Name() string                      { return "plain" }
func (plain) Run(context.Context, *State) error { return nil }

// A plan that would write to somebody else's project without consent is
// refused before it runs.
//
// Consent is currently checked INSIDE each stage that writes -- six places,
// each of which has to remember. A stage added tomorrow that forgets is
// unguarded, and the way that is discovered is a row appearing in a database
// nobody agreed to have written to.
//
// The descriptor makes it structural: a stage says whether it will mutate, and
// a plan carrying one refuses to start unless the operator said yes. The
// declaration is about the CONFIGURED stage, not the type -- the same stage
// with -write off mutates nothing and must not be blocked.
func TestAMutatingPlanWithoutConsentIsRefused(t *testing.T) {
	err := CheckConsent([]Stage{
		described{id: "probe", mutates: true},
	}, Consent{})
	if err == nil {
		t.Fatal("a plan containing a stage that writes to the target was accepted " +
			"without the operator having agreed to any writes")
	}
	if !strings.Contains(err.Error(), "probe") {
		t.Errorf("error %q does not name the stage that would write", err)
	}
}

func TestAMutatingPlanWithConsentIsAllowed(t *testing.T) {
	if err := CheckConsent([]Stage{described{id: "probe", mutates: true}},
		Consent{Write: true}); err != nil {
		t.Errorf("a plan the operator authorised was refused: %v", err)
	}
}

// The same stage, configured not to write, is not a mutating stage.
//
// If the descriptor described the TYPE, every default scan would carry four
// stages declaring themselves mutators and the check would refuse every
// ordinary run -- which is how a safety check comes to be disabled.
func TestAStageConfiguredNotToWriteIsNotAMutator(t *testing.T) {
	if err := CheckConsent([]Stage{described{id: "probe", mutates: false}},
		Consent{}); err != nil {
		t.Errorf("a read-only scan was refused: %v", err)
	}
}

// A stage that sends the operator's credential to a third party needs its own
// consent, separately.
//
// Writing to the target and telling somebody else about the target are
// different permissions. The history pass asks a public archive about the
// operator's site, which discloses what is being scanned to a party that is
// not the target -- and an operator who authorised writes has not thereby
// authorised that.
func TestAPlanThatDisclosesToThirdPartiesNeedsItsOwnConsent(t *testing.T) {
	stages := []Stage{described{id: "history", discloses: true}}
	if err := CheckConsent(stages, Consent{Write: true}); err == nil {
		t.Error("a stage that tells a third party about the target ran on write " +
			"consent alone; those are different permissions")
	}
	if err := CheckConsent(stages, Consent{ThirdParty: true}); err != nil {
		t.Errorf("a disclosure the operator authorised was refused: %v", err)
	}
}

// A SKIPPED stage produces nothing, and the plan must be checked knowing that.
//
// Skip wraps a stage the operator turned off. The wrapper implements Name and
// Run and NOT Describe, so a skipped stage was invisible to validation
// entirely -- which cuts both ways and one of them is dangerous:
//
//   - harmless: its own requirements are not checked. It will not run, so it
//     will not ask for anything.
//   - DANGEROUS: if the wrapper forwarded Describe unchanged, the plan would
//     believe a skipped stage still PUBLISHES its artifact, and a live
//     consumer requiring it would validate cleanly and then find nothing.
//
// So a skipped stage declares its ID and nothing else. A consumer that needs
// what it would have produced is then a planning error, discovered before the
// scan rather than as an empty surface at the end of it.
func TestASkippedProducerLeavesItsConsumerUnsatisfiable(t *testing.T) {
	err := Validate([]Stage{
		Skip(described{id: "relations", produces: []ArtifactType{"relations"}},
			"-no-relations was set"),
		described{id: "probe", requires: []ArtifactType{"relations"}},
	})
	if err == nil {
		t.Fatal("a plan whose only producer of an artifact is SKIPPED, with a live " +
			"consumer requiring it, validated cleanly. At run time the consumer finds " +
			"nothing and reports its surface as empty")
	}
}

// And a skipped stage's own requirements are not held against it.
func TestASkippedConsumerNeedsNothing(t *testing.T) {
	if err := Validate([]Stage{
		Skip(described{id: "probe", requires: []ArtifactType{"relations"}}, "off"),
	}); err != nil {
		t.Errorf("a skipped stage was required to have its inputs produced, though it "+
			"will never ask for them: %v", err)
	}
}

// An OPTIONAL artifact produced after its consumer can never be read.
//
// Optional means "may legitimately be absent" -- the schemas artifact is the
// case. It does not mean "may arrive late". A stage listing an optional
// artifact that some LATER stage produces will never see it, and the failure
// is silent: the consumer takes its absent branch every time, on every scan,
// and reports a narrower result than it could.
//
// That is the same silent-narrowing failure Requires exists to prevent, and
// it went unchecked because Optional was declared and read by nothing --
// found by a test asking which descriptor fields anything actually reads.
func TestAnOptionalArtifactProducedTooLateIsRejected(t *testing.T) {
	err := Validate([]Stage{
		described{id: "realtime", optional: []ArtifactType{"schemas"}},
		described{id: "schemas", produces: []ArtifactType{"schemas"}},
	})
	if err == nil {
		t.Fatal("a stage optionally reading an artifact produced AFTER it was accepted; " +
			"it takes the absent branch on every scan and nothing says so")
	}
	if !strings.Contains(err.Error(), "schemas") {
		t.Errorf("error %q does not name the artifact", err)
	}
}
