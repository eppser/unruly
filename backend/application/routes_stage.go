package application

import (
	"context"

	"github.com/eppser/unruly/internal/routes"
	"github.com/eppser/unruly/scan"
)

// RoutesStage checks the application's own endpoints for inconsistent
// authorisation.
//
// Ported from the "// ---- application routes ----" section of scanTarget. The
// database is not the only holder of privilege: app routes usually run with
// the service_role key, which ignores RLS entirely, so a route that answers
// anonymously while its siblings demand credentials is a hole the database
// checks cannot see.
type RoutesStage struct {
	Opts routes.Options
}

func (RoutesStage) Name() string { return "routes" }

// Run probes the application's routes.
//
// The empty-site guard is carried over deliberately: without it a scan pointed
// at a bare project ref, with no application named, would start fetching one.
func (r RoutesStage) Run(ctx context.Context, st *scan.State) error {
	if r.Opts.Site == "" {
		return nil
	}
	// After the guard, deliberately: announcing this above it would tell the
	// operator a check was starting and then silently skip it.
	st.Note(scan.Info, "checking application routes for inconsistent authorisation")
	res := routes.Run(ctx, r.Opts)
	scan.Put(st, res)
	scan.Put(st, routeAccess(res))
	bases := map[string]bool{}
	for _, route := range res.Routes {
		if route.GETAttempted && route.Base != "" {
			bases[route.Base] = true
		}
	}
	scan.Put(st, scan.ApplicationCoverage{Routes: res.ProbedRoutes(), Origins: len(bases)})
	st.Note(scan.Info, "%d routes probed, %d families, %d anonymously open in a protected family",
		res.ProbedRoutes(), len(res.Families), len(res.OpenRoutes()))
	// GET-only is a real blind spot: a POST-only family can look consistent
	// when it is not, and a scan that does not say so reports a gap as a pass.
	if !res.PostProbed {
		st.Note(scan.Info, "routes probed with GET only: POST could trigger side effects "+
			"on an application's own endpoints, so it needs -write. A POST-only route "+
			"family may therefore look consistent when it is not")
	}
	st.Attribute(r.Name(), int(res.Requests))
	st.Add(res.Findings...)
	return nil
}

func routeAccess(res routes.Result) scan.Access {
	var access scan.Access
	for _, r := range res.Routes {
		var allowed bool
		switch r.GET {
		case 200:
			allowed = true
		case 401, 403:
			allowed = false
		default:
			// A 404 may be a stale bundle path rather than a denial, and 405
			// says nothing about reads. Neither can satisfy policy intent.
			continue
		}
		access.Observed = append(access.Observed, scan.AccessFact{
			Resource: r.Path, Operation: "read", Subject: "anonymous", Allowed: allowed,
		})
	}
	return scan.MergeAccess(access)
}
