package provider

import "github.com/eppser/unruly/scan"

// Staged is implemented by a provider whose scan is expressed as pipeline
// stages rather than as a block of orchestration somewhere else.
//
// It completes the seam. A provider already declares what it can measure
// (Capability) and what it structurally cannot (Limited), but the code that
// does the measuring lives in main -- 1,390 lines of it for Supabase, in a
// single function. A provider that hands back its own stages is one whose scan
// can be run, and tested, without main being involved at all, which is what
// makes a backend contributable by someone who has never read main.go.
//
// Mandatory. The seam was optional during the migration, which left Firebase
// on Assess, Supabase on a command-owned path, and newer providers here. Three
// execution paths meant three accounting and consent behaviours. A registered
// provider now has exactly one way to contribute executable work.
type Staged interface {
	Stages(Detection, scan.Inputs) []scan.Stage
}

// StagesFor returns the stages the provider named by a detection contributes.
//
// Nil for a provider that does not implement Staged, and nil for a detection
// naming a backend nobody registered: that is a bug elsewhere, and the runner
// has to survive it well enough to still report the rest of the scan.
//
// The lookup lives here beside the registry for the same reason NotMeasuredFor
// does -- the caller holds a Detection, not a Detector.
func StagesFor(d Detection, in scan.Inputs) []scan.Stage {
	mu.RLock()
	defer mu.RUnlock()
	for _, det := range detectors {
		if det.Name() != d.Provider {
			continue
		}
		return det.Stages(d, in)
	}
	return nil
}
