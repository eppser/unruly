package provider

import (
	"context"
	"strings"
	"testing"

	"github.com/eppser/unruly/internal/client"
	"github.com/eppser/unruly/scan"
)

type preparationProvider struct {
	name     string
	desc     PreparationDescriptor
	requests int
	ran      *bool
}

func (p preparationProvider) Name() string { return p.name }
func (p preparationProvider) Measures() []Capability {
	return append([]Capability(nil), allCapabilities...)
}
func (p preparationProvider) Cannot() map[Capability]string { return nil }
func (p preparationProvider) Detect(Surface) (Detection, bool) {
	return Detection{Provider: p.name, Project: "project"}, true
}
func (p preparationProvider) Stages(Detection, scan.Inputs) []scan.Stage { return nil }
func (p preparationProvider) DescribePreparation(Detection, scan.Inputs) PreparationDescriptor {
	return p.desc
}
func (p preparationProvider) Prepare(_ context.Context, d Detection, in scan.Inputs) Preparation {
	*p.ran = true
	return Preparation{Detection: d, Inputs: in, Requests: p.requests}
}

func TestPreparationConsentIsCheckedBeforeProviderCodeRuns(t *testing.T) {
	ran := false
	p := preparationProvider{name: "preparation-consent", ran: &ran,
		desc: PreparationDescriptor{ID: "prepare", MaxRequests: 1, MutatesTarget: true}}
	Register(p)
	t.Cleanup(func() { unregister(p.name) })

	got := PrepareFor(context.Background(), Detection{Provider: p.name, Project: "p"},
		scan.Inputs{}, scan.Consent{})
	if ran {
		t.Fatal("mutating preparation ran before write consent was checked")
	}
	if !got.Stop || len(got.Findings) == 0 {
		t.Fatalf("unconsented preparation was not made visible: %+v", got)
	}
}

func TestPreparationRequestBoundIsEnforced(t *testing.T) {
	ran := false
	p := preparationProvider{name: "preparation-bound", ran: &ran, requests: 3,
		desc: PreparationDescriptor{ID: "prepare", MaxRequests: 2}}
	Register(p)
	t.Cleanup(func() { unregister(p.name) })

	got := PrepareFor(context.Background(), Detection{Provider: p.name, Project: "p"},
		scan.Inputs{}, scan.Consent{})
	if !ran || !got.Stop || len(got.Findings) == 0 ||
		!strings.Contains(got.Findings[0].Evidence.Reason, "exceeded") {
		t.Fatalf("over-budget preparation was not stopped and disclosed: %+v", got)
	}
}

func TestRegistrationRejectsUnboundedPreparation(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("provider with unbounded preparation registered successfully")
		}
	}()
	ran := false
	Register(preparationProvider{name: "unbounded-preparation", ran: &ran,
		desc: PreparationDescriptor{ID: "prepare"}})
}

func TestSupabasePreparationBoundIncludesWireRetries(t *testing.T) {
	desc := (supabase{}).DescribePreparation(Detection{}, scan.Inputs{
		Client: client.New(client.Options{BaseURL: "http://127.0.0.1:1", Retries: 2}),
	})
	if desc.MaxRequests != 9 {
		t.Fatalf("preparation bound = %d, want three logical calls with three wire attempts each", desc.MaxRequests)
	}
}
