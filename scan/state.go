package scan

import (
	"reflect"

	"github.com/eppser/unruly/internal/finding"
)

// State is what stages share.
//
// It is the migration's hard part and its main risk. Roughly 30 variables
// cross the stage boundaries in the original function, and the temptation is
// to move all of them here at once. That would produce a struct every backend
// must accept and only one populates, which is worse than the honest
// asymmetry it replaces. Fields arrive here only as a stage that needs them is
// ported, and each arrival should be justified by a test.
type State struct {
	// Target is where the scan is pointed, used as the Matched value on
	// findings the pipeline itself emits.
	Target string

	fs    []finding.Finding
	spend map[string]int
	// artifacts are the typed values stages hand to each other. Reached only
	// through Put and Get, which are generic, so this map is the one place
	// the pipeline touches provider-specific data and it never names a
	// provider type. See artifact.go.
	artifacts map[reflect.Type]any
	// artifactWrites and artifactReads make the runtime exchange auditable
	// against StageDescriptor. The descriptor and the store are now keyed from
	// the same Go type (ArtifactOf), and these ledgers catch a stage publishing
	// something it never declared before that becomes a silent empty result in
	// a downstream stage.
	artifactWrites map[string]map[ArtifactType]bool
	artifactReads  map[string]map[ArtifactType]bool

	// Stage is the stage currently running, set by the pipeline so a note can
	// attribute itself without every stage having to repeat its own name.
	Stage string
	// OnNote, when set, receives each note AS IT IS MADE.
	//
	// Progress lines have to arrive while the stage is still working. Without
	// this, a note is only visible once the stage returns, so "enumerating
	// relations" prints after enumeration -- announcing finished work -- and
	// those lines stay in the command instead of moving to the stage that
	// knows when to say them.
	//
	// Optional. Notes are recorded either way, so a consumer reading the run
	// afterwards sees the same list.
	OnNote func(Note)
	notes  []Note
}

func (s *State) recordArtifactWrite(a ArtifactType) {
	if s == nil || s.Stage == "" {
		return
	}
	if s.artifactWrites == nil {
		s.artifactWrites = map[string]map[ArtifactType]bool{}
	}
	if s.artifactWrites[s.Stage] == nil {
		s.artifactWrites[s.Stage] = map[ArtifactType]bool{}
	}
	s.artifactWrites[s.Stage][a] = true
}

func (s *State) recordArtifactRead(a ArtifactType) {
	if s == nil || s.Stage == "" {
		return
	}
	if s.artifactReads == nil {
		s.artifactReads = map[string]map[ArtifactType]bool{}
	}
	if s.artifactReads[s.Stage] == nil {
		s.artifactReads[s.Stage] = map[ArtifactType]bool{}
	}
	s.artifactReads[s.Stage][a] = true
}

// Add records findings in the order stages produce them.
//
// Order is stable by construction: stages run in declared order and append.
// Report-level sorting happens on the way out, but nothing above this layer
// can be deterministic if this one is not.
func (s *State) Add(fs ...finding.Finding) { s.fs = append(s.fs, fs...) }

// Findings returns everything recorded so far.
func (s *State) Findings() []finding.Finding { return s.fs }
