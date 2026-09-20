package application

import (
	"context"
	"testing"

	"github.com/eppser/unruly/internal/finding"
	"github.com/eppser/unruly/internal/parity"
	"github.com/eppser/unruly/internal/routes"
	"github.com/eppser/unruly/scan"
)

// The stage must report exactly what the code it replaced reported.
func TestTheRoutesStageAgreesWithTheCodeItReplaced(t *testing.T) {
	opts := routes.Options{Site: "http://127.0.0.1:1", Concurrency: 2}

	var old []finding.Finding
	rt := routes.Run(context.Background(), opts)
	oldRequests := int(rt.Requests)
	old = append(old, rt.Findings...)

	st := &scan.State{Target: opts.Site}
	if _, err := (scan.Pipeline{RoutesStage{Opts: opts}}).
		Run(context.Background(), st); err != nil {
		t.Fatal(err)
	}
	if d := parity.Diff(old, st.Findings()); d != "" {
		t.Errorf("the ported stage disagrees with the code it replaced:\n%s", d)
	}
	if st.Attributed() != oldRequests {
		t.Errorf("attributed %d, original counted %d", st.Attributed(), oldRequests)
	}
}

// No site means no route probing, rather than probing the empty string.
//
// The original guarded on o.site != "" before doing any work. Without the
// guard a scan pointed at a bare project ref starts fetching an application
// that was never named.
func TestNoSiteMeansNoRouteProbing(t *testing.T) {
	st := &scan.State{}
	if _, err := (scan.Pipeline{RoutesStage{Opts: routes.Options{Site: ""}}}).
		Run(context.Background(), st); err != nil {
		t.Fatal(err)
	}
	if st.Attributed() != 0 || len(st.Findings()) != 0 {
		t.Errorf("probed with no site: %d requests, %d findings",
			st.Attributed(), len(st.Findings()))
	}
}

func TestTheRoutesStageHasAStableName(t *testing.T) {
	if got := (RoutesStage{}).Name(); got != "routes" {
		t.Errorf("stage name %q", got)
	}
}
