package supabase

import (
	"context"
	"testing"

	"github.com/eppser/unruly/internal/postgrest"
	"github.com/eppser/unruly/internal/probe"
	"github.com/eppser/unruly/scan"
)

func TestCoveragePublishesOnlyMeasuredAccessFacts(t *testing.T) {
	st := &scan.State{}
	scan.Put(st, probe.Result{Relations: []probe.Relation{
		{Name: "public_rows", Read: postgrest.ReadExposed,
			Write: postgrest.WriteReached, Update: postgrest.WriteUnknown},
		{Name: "denied", Read: postgrest.ReadDenied,
			Write: postgrest.WriteBlockedRLS},
		{Name: "empty_or_filtered", Read: postgrest.ReadEmpty},
	}})
	if err := (CoverageStage{}).Run(context.Background(), st); err != nil {
		t.Fatal(err)
	}
	access, ok := scan.Get[scan.Access](st)
	if !ok {
		t.Fatal("coverage stage published no neutral access artifact")
	}
	facts := map[string]bool{}
	for _, f := range access.Observed {
		facts[f.Resource+"/"+f.Operation] = f.Allowed
	}
	if !facts["public_rows/read"] || !facts["public_rows/insert"] {
		t.Fatalf("measured allows missing: %+v", access.Observed)
	}
	if got, ok := facts["denied/read"]; !ok || got {
		t.Fatalf("measured denial missing: %+v", access.Observed)
	}
	if _, ok := facts["empty_or_filtered/read"]; ok {
		t.Fatal("an empty-or-filtered response was invented as an allow or denial")
	}
	if _, ok := facts["public_rows/update"]; ok {
		t.Fatal("an unknown update outcome was published as measured")
	}
}
