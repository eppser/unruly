package application

import (
	"testing"

	"github.com/eppser/unruly/internal/routes"
)

func TestRouteAccessPublishesOnlyConclusiveGETFacts(t *testing.T) {
	got := routeAccess(routes.Result{Routes: []routes.Route{
		{Path: "/public", GET: 200},
		{Path: "/private", GET: 401},
		{Path: "/forbidden", GET: 403},
		{Path: "/stale", GET: 404},
		{Path: "/post-only", GET: 405, POST: 200},
	}})
	if len(got.Observed) != 3 {
		t.Fatalf("published ambiguous route facts: %+v", got.Observed)
	}
	want := map[string]bool{"/public": true, "/private": false, "/forbidden": false}
	for _, fact := range got.Observed {
		allowed, ok := want[fact.Resource]
		if !ok || fact.Operation != "read" || fact.Subject != "anonymous" || fact.Allowed != allowed {
			t.Errorf("unexpected access fact: %+v", fact)
		}
	}
}
