// Package engine owns scan execution.
//
// Commands parse and render. Discovery acquires facts. Providers construct
// plans. This package is the only place that validates, authorises, runs and
// merges those plans, so a backend cannot take a quieter execution path merely
// because it was found through a different channel.
package engine

import (
	"context"
	"fmt"
	"sort"

	"time"

	"github.com/eppser/unruly/backend/application"
	"github.com/eppser/unruly/internal/client"
	"github.com/eppser/unruly/internal/finding"
	"github.com/eppser/unruly/internal/intent"
	"github.com/eppser/unruly/internal/provider"
	"github.com/eppser/unruly/internal/routes"
	"github.com/eppser/unruly/scan"
)

// Workload is one independently planned surface, such as application routes
// or one detected backend instance.
type Workload struct {
	ID       string
	Target   string
	Stages   []scan.Stage
	Consent  scan.Consent
	Findings []finding.Finding
	Stopped  bool
}

// ProviderTarget asks the registry to construct a workload for a detection.
// Inputs carry the shared transport, discovered vocabulary and operator
// controls; no command package needs to know which stages result.
type ProviderTarget struct {
	Detection provider.Detection
	Inputs    scan.Inputs
	Consent   scan.Consent
}

// ApplicationTarget is provider-neutral application route configuration.
// engine owns the backend/application adapter so commands do not construct a
// second kind of scan plan beside provider plans.
type ApplicationTarget struct {
	Site            string
	HARFiles        []string
	AllowedOrigins  []string
	Web             *client.Client
	Limiter         *client.Limiter
	Timeout         time.Duration
	Concurrency     int
	MaxBundles      int
	MaxRoutes       int
	MaxBypassRoutes int
	UserAgent       string
	Redact          bool
	AllowPOST       bool
	WriteConsent    bool
	NoResidue       bool
	SkipRoutes      bool
	RouteParams     []string
	Principals      []string
}

// Request is a complete execution request. Workloads cover provider-neutral
// surfaces; Providers cover registered backends. Both pass through the same
// validation and merge path.
type Request struct {
	Target string
	// Findings are acquisition or lifecycle facts produced before execution.
	// Including them here gives interruption attribution, sorting and dedup one
	// owner instead of leaving early command paths with different semantics.
	Findings    []finding.Finding
	Intent      *intent.Manifest
	Application *ApplicationTarget
	Workloads   []Workload
	Providers   []ProviderTarget
	OnNote      func(scan.Note)
}

// Report is the provider-neutral result of execution.
type Report struct {
	Findings []finding.Finding
	Access   scan.Access
	// Coverage is keyed by workload id. Absence means the workload published no
	// coverage statement; it must never be interpreted as zero coverage.
	Coverage    map[string]scan.Coverage
	Spending    []scan.StageSpend
	Requests    int
	Ran         []string
	Application scan.ApplicationCoverage
	Interrupted bool
	Worst       finding.Severity
	Blind       []string
}

// Run validates, authorises and executes every requested surface.
//
// A broken workload does not discard valid findings from its siblings. Its
// failure becomes a not-assessed finding and execution continues, matching the
// scanner's central rule that silence must never masquerade as a clean result.
func Run(ctx context.Context, req Request) Report {
	workloads, prep := runtimeWorkloads(ctx, req)

	// Stable execution and report order regardless of map or detector order.
	sort.SliceStable(workloads, func(i, j int) bool { return workloads[i].ID < workloads[j].ID })

	out := Report{Coverage: map[string]scan.Coverage{},
		Findings: append(append([]finding.Finding(nil), req.Findings...), prep.Findings...),
		Spending: prep.Spending, Requests: prep.Requests}
	seen := map[string]bool{}
	for _, w := range workloads {
		if w.ID == "" {
			w.ID = w.Target
		}
		if seen[w.ID] {
			out.Findings = append(out.Findings, finding.NotAssessedStage(w.Target, w.ID,
				"the engine received the same workload twice and refused to probe it twice"))
			continue
		}
		seen[w.ID] = true
		out.Ran = append(out.Ran, w.ID)
		out.Findings = append(out.Findings, w.Findings...)
		if w.Stopped {
			continue
		}

		if len(w.Stages) == 0 {
			out.Findings = append(out.Findings, finding.NotAssessedStage(w.Target, w.ID,
				"the registered provider produced no executable stages"))
			continue
		}
		if err := validateWorkload(w); err != nil {
			out.Findings = append(out.Findings, finding.NotAssessedStage(w.Target, w.ID, err.Error()))
			continue
		}

		st := &scan.State{Target: w.Target, OnNote: req.OnNote}
		if _, err := scan.Pipeline(w.Stages).Run(ctx, st); err != nil {
			out.Findings = append(out.Findings, finding.NotAssessedStage(w.Target, w.ID,
				fmt.Sprintf("the workload violated its runtime contract: %v", err)))
		}
		out.Findings = append(out.Findings, st.Findings()...)
		out.Requests += st.Attributed()
		out.Spending = mergeSpending(out.Spending, st.Spending())
		if access, ok := scan.Get[scan.Access](st); ok {
			out.Access = scan.MergeAccess(out.Access, access)
		}
		if coverage, ok := scan.Get[scan.Coverage](st); ok {
			out.Coverage[w.ID] = coverage
		}
		if coverage, ok := scan.Get[scan.ApplicationCoverage](st); ok {
			out.Application.Routes += coverage.Routes
			out.Application.Origins += coverage.Origins
		}
	}

	if req.Intent != nil {
		out.Findings = append(out.Findings, intent.Findings(req.Target,
			intent.Verify(*req.Intent, intent.Observations(out.Access)))...)
	}
	if err := ctx.Err(); err != nil {
		where := req.Target
		if where == "" && len(workloads) > 0 {
			where = workloads[0].Target
		}
		out.Findings = append(out.Findings, finding.Interrupted(where, err))
		finding.AttributeBlindnessToInterruption(out.Findings)
		out.Interrupted = true
	}
	return Finalize(out)
}

// Finalize applies the report contract after any caller-owned summary facts
// have been added. Rendering remains an edge concern; ordering, deduplication,
// exit severity and coverage blindness do not.
func Finalize(r Report, add ...finding.Finding) Report {
	r.Findings = append(r.Findings, add...)
	finding.Sort(r.Findings)
	r.Findings = finding.Dedup(r.Findings)
	r.Worst = finding.Info
	for _, f := range r.Findings {
		if f.Severity > r.Worst {
			r.Worst = f.Severity
		}
	}
	_, r.Blind = finding.CoverageIncomplete(r.Findings)
	return r
}

type preparationResult struct {
	Findings []finding.Finding
	Spending []scan.StageSpend
	Requests int
}

func runtimeWorkloads(ctx context.Context, req Request) ([]Workload, preparationResult) {
	base := req
	base.Providers = nil
	workloads := buildWorkloads(base)
	var out preparationResult
	for _, target := range req.Providers {
		if target.Inputs.Client == nil {
			d := target.Detection
			workloads = append(workloads, Workload{ID: d.Provider + "/" + d.Project,
				Target: provider.APIBase(d), Consent: target.Consent, Stopped: true,
				Findings: []finding.Finding{finding.NotAssessedStage(d.Project, d.Provider,
					"the provider received no shared transport; it was not allowed to improvise one")}})
			continue
		}
		p := provider.PrepareFor(ctx, target.Detection, target.Inputs, target.Consent)
		id := p.Detection.Provider + "/" + p.Detection.Project
		w := Workload{ID: id, Target: provider.APIBase(p.Detection), Consent: target.Consent,
			Findings: append(provider.NotMeasuredFor(p.Detection), p.Findings...),
			Stopped:  p.Stop}
		if !p.Stop {
			w.Stages = provider.StagesFor(p.Detection, p.Inputs)
		}
		workloads = append(workloads, w)
		out.Requests += p.Requests
		out.Spending = mergeSpending(out.Spending, p.Spending)
	}
	return workloads, out
}

// Validate checks every statically constructible workload without running it.
// Commands use this before creating a network client; dynamically detected
// providers are checked by Run immediately before their first stage.
func Validate(req Request) error {
	for _, w := range buildWorkloads(req) {
		if len(w.Stages) == 0 {
			return fmt.Errorf("workload %q produced no executable stages", w.ID)
		}
		if err := validateWorkload(w); err != nil {
			return fmt.Errorf("workload %q: %w", w.ID, err)
		}
	}
	return nil
}

func validateWorkload(w Workload) error {
	if err := scan.Validate(w.Stages); err != nil {
		return fmt.Errorf("the workload plan is not runnable: %w", err)
	}
	if err := scan.CheckConsent(w.Stages, w.Consent); err != nil {
		return fmt.Errorf("the workload plan exceeds consent: %w", err)
	}
	return nil
}

func buildWorkloads(req Request) []Workload {
	workloads := append([]Workload(nil), req.Workloads...)
	if a := req.Application; a != nil {
		workloads = append(workloads, Workload{
			ID: "application", Target: a.Site,
			Consent: scan.Consent{Write: a.WriteConsent},
			Stages: application.Stages(application.Config{
				Site: a.Site, AllowedOrigins: a.AllowedOrigins, Web: a.Web,
				HARFiles: append([]string(nil), a.HARFiles...),
				Limiter:  a.Limiter, Timeout: a.Timeout, Concurrency: a.Concurrency,
				MaxBundles: a.MaxBundles, MaxRoutes: a.MaxRoutes,
				MaxBypassRoutes: a.MaxBypassRoutes, UserAgent: a.UserAgent,
				Redact: a.Redact, AllowPOST: a.AllowPOST, NoResidue: a.NoResidue,
				SkipRoutes: a.SkipRoutes, RouteParams: routes.ParseParams(a.RouteParams),
				Principals: a.Principals,
			}),
		})
	}
	for _, p := range req.Providers {
		d := p.Detection
		id := d.Provider + "/" + d.Project
		workloads = append(workloads, Workload{
			ID: id, Target: provider.APIBase(d),
			Stages: provider.StagesFor(d, p.Inputs), Consent: p.Consent,
			Findings: provider.NotMeasuredFor(d),
		})
	}

	return workloads
}

func mergeSpending(into, add []scan.StageSpend) []scan.StageSpend {
	totals := map[string]int{}
	for _, s := range into {
		totals[s.Stage] += s.Requests
	}
	for _, s := range add {
		totals[s.Stage] += s.Requests
	}
	out := make([]scan.StageSpend, 0, len(totals))
	for stage, requests := range totals {
		out = append(out, scan.StageSpend{Stage: stage, Requests: requests})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Stage < out[j].Stage })
	return out
}
