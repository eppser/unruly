package scan

import (
	"context"
	"reflect"
	"testing"
)

type spender struct {
	name string
	n    int
}

func (s spender) Name() string { return s.name }

func (s spender) Run(_ context.Context, st *State) error {
	st.Attribute(s.name, s.n)
	return nil
}

// Stages attribute the requests they spend, so a reader can see where a scan's
// traffic went rather than only how much there was.
func TestStagesAttributeTheRequestsTheySpend(t *testing.T) {
	p := Pipeline{spender{name: "probe", n: 40}, spender{name: "discover", n: 12}}
	st := &State{}
	if _, err := p.Run(context.Background(), st); err != nil {
		t.Fatal(err)
	}
	if got := st.Attributed(); got != 52 {
		t.Errorf("attributed %d requests, want 52", got)
	}
}

// The breakdown is sorted by stage name, not by execution order.
//
// Two scans of an unchanged project must produce identical bytes, and
// execution order is not stable across a pipeline whose stages may be skipped
// or reordered by flags.
func TestTheSpendBreakdownIsSortedAndDeterministic(t *testing.T) {
	p := Pipeline{spender{name: "realtime", n: 3}, spender{name: "discover", n: 12},
		spender{name: "probe", n: 40}}
	st := &State{}
	if _, err := p.Run(context.Background(), st); err != nil {
		t.Fatal(err)
	}
	want := []StageSpend{{Stage: "discover", Requests: 12}, {Stage: "probe", Requests: 40},
		{Stage: "realtime", Requests: 3}}
	if got := st.Spending(); !reflect.DeepEqual(got, want) {
		t.Errorf("breakdown %v, want %v", got, want)
	}
}

// A stage that runs twice accumulates rather than overwriting. Schema scans
// re-run the same stage once per exposed schema, and a breakdown that reported
// only the last one would understate the traffic that actually left.
func TestARepeatedStageAccumulates(t *testing.T) {
	st := &State{}
	st.Attribute("schema", 10)
	st.Attribute("schema", 5)
	if got := st.Attributed(); got != 15 {
		t.Errorf("attributed %d, want 15 -- a repeated stage overwrote instead of adding", got)
	}
}
