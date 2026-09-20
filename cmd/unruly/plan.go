package main

import (
	"github.com/projectdiscovery/gologger"

	"github.com/eppser/unruly/internal/engine"
	"github.com/eppser/unruly/internal/provider"
	"github.com/eppser/unruly/scan"
)

// planIsRunnable checks the SHAPE of the scan before anything is sent.
//
// This used to sit just above the stage loop, with a comment claiming it ran
// before the first request. It did not: by then the scan had already harvested
// the application's bundles and fetched the OpenAPI document. A check that
// runs after the target has served requests is an audit, not a precondition,
// and the difference is precisely those requests.
//
// It can honestly run first because the plan's SHAPE does not depend on
// anything discovered. Stages() is a pure function of the operator's flags:
// which stages exist, what each requires and produces, and which of them will
// mutate are all fixed before the first packet. Only the CONTENTS of the
// stages -- seed lists, relation names -- come from discovery, and none of
// those are what this checks.
//
// Fatal rather than a finding, twice over. An unrunnable plan is a defect in
// this program rather than a fact about the project being scanned, and a plan
// exceeding its consent is a refusal rather than a result; reporting either as
// a finding would file our problem under their name.
func planIsRunnable(o *options) {
	// Built from the flags alone, which is what makes this callable before any
	// client exists. The stages carry nil clients here and are never run.
	in := seamInputs(o, nil, nil)
	// Describe the configured work, not the already-authorised subset. That is
	// what lets preflight compare a mutating plan with consent independently.
	in.Write = o.write
	in.Controls.Write = o.write
	in.Controls.Invoke = o.invoke
	project := o.projectRef
	if project == "" {
		project = o.baseURL
	}
	if project == "" {
		project = "preflight"
	}
	if err := engine.Validate(engine.Request{
		Application: &engine.ApplicationTarget{
			Site: o.site, SkipRoutes: o.skipRoutes, AllowPOST: o.write,
			WriteConsent: o.write && o.confirmOwn, NoResidue: o.noResidue,
		},
		Providers: []engine.ProviderTarget{{
			Detection: provider.Detection{Provider: "supabase", Project: project},
			Inputs:    in,
			Consent: scan.Consent{Write: o.write && o.confirmOwn,
				ThirdParty: o.checkHistory},
		}},
	}); err != nil {
		gologger.Fatal().Msgf("%s", err)
	}
}
