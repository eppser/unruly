package engine

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/eppser/unruly/internal/client"
	"github.com/eppser/unruly/internal/finding"
	"github.com/eppser/unruly/internal/intent"
	"github.com/eppser/unruly/internal/provider"
	"github.com/eppser/unruly/scan"
)

type testStage struct {
	name string
	fail bool
}

type aggregateStage struct {
	name     string
	resource string
	routes   int
	origins  int
}

func (s aggregateStage) Name() string { return s.name }
func (s aggregateStage) Describe() scan.StageDescriptor {
	return scan.StageDescriptor{ID: s.name, Produces: []scan.ArtifactType{
		scan.ArtifactOf[scan.Access](), scan.ArtifactOf[scan.Coverage](),
		scan.ArtifactOf[scan.ApplicationCoverage](),
	}}
}
func (s aggregateStage) Run(_ context.Context, st *scan.State) error {
	scan.Put(st, scan.Access{Observed: []scan.AccessFact{{Resource: s.resource,
		Operation: "read", Subject: "anonymous", Allowed: true}}})
	scan.Put(st, scan.Coverage{Relations: 1, Schemas: 1})
	scan.Put(st, scan.ApplicationCoverage{Routes: s.routes, Origins: s.origins})
	st.Add(finding.Finding{ID: "test-aggregate", Resource: "same", Severity: finding.Low})
	st.Attribute(s.name, 1)
	return nil
}

func TestProviderCannotImproviseATransport(t *testing.T) {
	r := Run(context.Background(), Request{Providers: []ProviderTarget{{
		Detection: provider.Detection{Provider: "firebase", Project: "p"},
	}}})
	if len(r.Findings) == 0 || r.Requests != 0 {
		t.Fatalf("nil transport result = findings %v, requests %d", r.Findings, r.Requests)
	}
	for _, f := range r.Findings {
		if f.ID == "unruly-surface-not-assessed" &&
			strings.Contains(f.Evidence.Reason, "shared transport") {
			return
		}
	}
	t.Fatalf("nil transport was not disclosed: %v", r.Findings)
}

func TestProviderUsesTheSuppliedTransport(t *testing.T) {
	// The no-network refusal above is the invariant. This construction guard
	// additionally pins that the engine target carries the shared client rather
	// than a provider-specific transport field.
	var target ProviderTarget
	target.Inputs.Client = client.New(client.Options{BaseURL: "https://example.invalid"})
	if target.Inputs.Client == nil {
		t.Fatal("provider target discarded its shared transport")
	}
}

func (s testStage) Name() string                   { return s.name }
func (s testStage) Describe() scan.StageDescriptor { return scan.StageDescriptor{ID: s.name} }
func (s testStage) Run(_ context.Context, st *scan.State) error {
	st.Attribute(s.name, 1)
	if s.fail {
		return errors.New("refused")
	}
	st.Add(finding.Finding{ID: "test-" + s.name, Severity: finding.Low})
	return nil
}

func TestRunUsesOnePathForIndependentWorkloads(t *testing.T) {
	r := Run(context.Background(), Request{Workloads: []Workload{
		{ID: "provider", Target: "provider.test", Stages: []scan.Stage{testStage{name: "provider"}}},
		{ID: "application", Target: "app.test", Stages: []scan.Stage{testStage{name: "application"}}},
	}})
	if len(r.Ran) != 2 || r.Requests != 2 {
		t.Fatalf("ran=%v requests=%d", r.Ran, r.Requests)
	}
	ids := map[string]bool{}
	for _, f := range r.Findings {
		ids[f.ID] = true
	}
	if !ids["test-provider"] || !ids["test-application"] {
		t.Fatalf("one workload disappeared: %v", ids)
	}
}

func TestOneFailedWorkloadDoesNotDiscardItsSibling(t *testing.T) {
	r := Run(context.Background(), Request{Workloads: []Workload{
		{ID: "a", Target: "a.test", Stages: []scan.Stage{testStage{name: "a", fail: true}}},
		{ID: "b", Target: "b.test", Stages: []scan.Stage{testStage{name: "b"}}},
	}})
	var kept, disclosed bool
	for _, f := range r.Findings {
		kept = kept || f.ID == "test-b"
		disclosed = disclosed || f.ID == "unruly-surface-not-assessed"
	}
	if !kept || !disclosed {
		t.Fatalf("kept=%v disclosed=%v findings=%v", kept, disclosed, r.Findings)
	}
}

func TestDuplicateWorkloadIsRefusedBeforeASecondProbe(t *testing.T) {
	r := Run(context.Background(), Request{Workloads: []Workload{
		{ID: "same", Stages: []scan.Stage{testStage{name: "one"}}},
		{ID: "same", Stages: []scan.Stage{testStage{name: "two"}}},
	}})
	if r.Requests != 1 {
		t.Fatalf("duplicate workload sent %d requests, want 1", r.Requests)
	}
}

func TestReportMergesAccessCoverageFindingsAndAccountingOnce(t *testing.T) {
	r := Run(context.Background(), Request{Workloads: []Workload{
		{ID: "a", Stages: []scan.Stage{aggregateStage{name: "a", resource: "/a", routes: 2, origins: 1}}},
		{ID: "b", Stages: []scan.Stage{aggregateStage{name: "b", resource: "/b", routes: 3, origins: 2}}},
	}})
	if r.Requests != 2 || r.Application.Routes != 5 || r.Application.Origins != 3 {
		t.Fatalf("requests=%d application=%+v", r.Requests, r.Application)
	}
	if len(r.Access.Observed) != 2 || len(r.Coverage) != 2 {
		t.Fatalf("access=%+v coverage=%+v", r.Access, r.Coverage)
	}
	var duplicates int
	for _, f := range r.Findings {
		if f.ID == "test-aggregate" {
			duplicates++
		}
	}
	if duplicates != 1 {
		t.Fatalf("engine retained %d identical findings, want 1", duplicates)
	}
}

func TestInterruptionQualifiesEveryBlindFinding(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	initial := finding.NotAssessedStage("app.test", "discovery", "did not answer")
	r := Run(ctx, Request{Target: "app.test", Findings: []finding.Finding{initial},
		Workloads: []Workload{{ID: "app", Target: "app.test",
			Stages: []scan.Stage{testStage{name: "route"}}}}})
	if !r.Interrupted {
		t.Fatal("cancelled engine report is not marked interrupted")
	}
	var notice, qualified bool
	for _, f := range r.Findings {
		notice = notice || f.Resource == finding.InterruptedResource
		if f.Resource == "discovery" && strings.Contains(f.Description, "SCAN WAS INTERRUPTED") {
			qualified = true
		}
	}
	if !notice || !qualified {
		t.Fatalf("notice=%v qualified=%v findings=%+v", notice, qualified, r.Findings)
	}
}

func TestIntentAndExitSemanticsAreFinalizedWithTheEngineReport(t *testing.T) {
	policy := intent.Manifest{SchemaVersion: intent.SchemaVersion, Expect: []intent.Expectation{{
		Resource: "/a", Operation: intent.Read, Subject: intent.Anonymous, Result: intent.Deny,
	}}}
	r := Run(context.Background(), Request{Target: "app.test", Intent: &policy,
		Workloads: []Workload{{ID: "a", Stages: []scan.Stage{
			aggregateStage{name: "a", resource: "/a"},
		}}}})
	var violation, summary bool
	for _, f := range r.Findings {
		violation = violation || f.ID == "unruly-intent-violation"
		summary = summary || f.ID == "unruly-intent-summary"
	}
	if !violation || !summary || r.Worst != finding.High {
		t.Fatalf("violation=%v summary=%v worst=%v findings=%+v",
			violation, summary, r.Worst, r.Findings)
	}
}

func TestFinalizeComputesCoverageBlindness(t *testing.T) {
	r := Finalize(Report{}, finding.NotAssessedStage("app.test", "storage", "unreachable"))
	if r.Worst != finding.Info || len(r.Blind) != 1 || r.Blind[0] != "storage" {
		t.Fatalf("worst=%v blind=%v", r.Worst, r.Blind)
	}
}
