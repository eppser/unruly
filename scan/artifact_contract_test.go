package scan

import (
	"context"
	"strings"
	"testing"
)

type contractArtifact struct{ Value string }
type wrongContractArtifact struct{}

type contractStage struct{ wrong bool }

type undeclaredReader struct{}

func (undeclaredReader) Name() string { return "undeclared-reader" }
func (undeclaredReader) Describe() StageDescriptor {
	return StageDescriptor{ID: "undeclared-reader"}
}
func (undeclaredReader) Run(_ context.Context, st *State) error {
	_, _ = Get[contractArtifact](st)
	return nil
}

func (contractStage) Name() string { return "contract" }
func (contractStage) Describe() StageDescriptor {
	return StageDescriptor{ID: "contract", Produces: []ArtifactType{ArtifactOf[contractArtifact]()}}
}
func (s contractStage) Run(_ context.Context, st *State) error {
	if s.wrong {
		Put(st, wrongContractArtifact{})
	} else {
		Put(st, contractArtifact{Value: "ok"})
	}
	return nil
}

func TestArtifactNamesAreDerivedFromTheRuntimeType(t *testing.T) {
	got := ArtifactOf[contractArtifact]()
	if got == "" || !strings.Contains(string(got), "contractArtifact") {
		t.Fatalf("ArtifactOf returned %q", got)
	}
	if got == ArtifactOf[wrongContractArtifact]() {
		t.Fatal("different Go artifact types share one plan identity")
	}
}

func TestPipelineRejectsAnUndeclaredRuntimeArtifact(t *testing.T) {
	st := &State{}
	_, err := (Pipeline{contractStage{wrong: true}}).Run(context.Background(), st)
	if err == nil || !strings.Contains(err.Error(), "undeclared artifact") {
		t.Fatalf("pipeline accepted a runtime artifact its descriptor did not publish: %v", err)
	}
}

func TestPipelineAcceptsTheArtifactItsDescriptorNames(t *testing.T) {
	st := &State{}
	if _, err := (Pipeline{contractStage{}}).Run(context.Background(), st); err != nil {
		t.Fatal(err)
	}
	if got, ok := Get[contractArtifact](st); !ok || got.Value != "ok" {
		t.Fatalf("published artifact = %+v, %v", got, ok)
	}
}

func TestPipelineRejectsAnUndeclaredRuntimeArtifactRead(t *testing.T) {
	st := &State{}
	Put(st, contractArtifact{Value: "already present"})
	_, err := (Pipeline{undeclaredReader{}}).Run(context.Background(), st)
	if err == nil || !strings.Contains(err.Error(), "read undeclared artifact") {
		t.Fatalf("pipeline accepted an undeclared artifact dependency: %v", err)
	}
}
