package provider

import (
	"context"
	"fmt"
	"strings"

	"github.com/eppser/unruly/internal/finding"
	"github.com/eppser/unruly/scan"
)

// Preparation is provider-owned work required before a plan can be built,
// such as resolving a protocol mount point. It may replace the provider-neutral
// inputs, publish findings, and stop a provider whose endpoint was proven
// unusable. It never hides the stop behind an empty stage list.
type Preparation struct {
	Detection Detection
	Inputs    scan.Inputs
	Findings  []finding.Finding
	Spending  []scan.StageSpend
	Requests  int
	Stop      bool
}

// PreparationDescriptor makes pre-plan network work reviewable. Preparation
// is deliberately smaller than a stage: it may refine generic Inputs, but it
// cannot publish assessment artifacts or findings about access. MaxRequests is
// a hard contract checked by the engine so endpoint negotiation cannot grow
// into an unmetered private scan.
type PreparationDescriptor struct {
	ID                 string
	MaxRequests        int
	MutatesTarget      bool
	ContactsThirdParty bool
}

type Preparer interface {
	DescribePreparation(Detection, scan.Inputs) PreparationDescriptor
	Prepare(context.Context, Detection, scan.Inputs) Preparation
}

// PrepareFor dispatches optional pre-plan lifecycle work. Providers that need
// none receive their inputs unchanged.
func PrepareFor(ctx context.Context, d Detection, in scan.Inputs, consent scan.Consent) Preparation {
	p := Preparation{Detection: d, Inputs: in}
	mu.RLock()
	var owner Detector
	for _, det := range detectors {
		if det.Name() == d.Provider {
			owner = det
			break
		}
	}
	mu.RUnlock()
	if owner != nil {
		if preparer, ok := any(owner).(Preparer); ok {
			desc := preparer.DescribePreparation(d, in)
			switch {
			case desc.MutatesTarget && !consent.Write:
				p.Stop = true
				p.Findings = append(p.Findings, finding.NotAssessedStage(d.Project, desc.ID,
					"provider preparation would change the target without write consent"))
				return p
			case desc.ContactsThirdParty && !consent.ThirdParty:
				p.Stop = true
				p.Findings = append(p.Findings, finding.NotAssessedStage(d.Project, desc.ID,
					"provider preparation would contact a third party without consent"))
				return p
			}
			p = preparer.Prepare(ctx, d, in)
			if p.Requests > desc.MaxRequests {
				p.Stop = true
				p.Findings = append(p.Findings, finding.NotAssessedStage(d.Project, desc.ID,
					fmt.Sprintf("provider preparation exceeded its declared request bound: %d sent, maximum %d",
						p.Requests, desc.MaxRequests)))
			}
			return p
		}
		return p
	}
	p.Stop = true
	p.Findings = append(p.Findings, finding.NotAssessedStage(d.Project, d.Provider,
		"no registered provider owns this detection"))
	return p
}

func validatePreparation(d Detector) error {
	p, ok := any(d).(Preparer)
	if !ok {
		return nil
	}
	desc := p.DescribePreparation(Detection{}, scan.Inputs{})
	if strings.TrimSpace(desc.ID) == "" {
		return fmt.Errorf("provider %q has preparation with no id", d.Name())
	}
	if desc.MaxRequests <= 0 {
		return fmt.Errorf("provider %q preparation %q has no positive request bound",
			d.Name(), desc.ID)
	}
	return nil
}
