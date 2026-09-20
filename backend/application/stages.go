// Package application holds the checks that belong to the APPLICATION rather
// than to whatever backend sits behind it.
//
// It exists because application-route scanning was inside the Supabase plan.
// The routes pass probes an application's own endpoints for inconsistent
// authorisation -- a family where /api/orders/1 requires a session and
// /api/orders/2 does not -- and that has nothing to do with PostgREST, RLS or
// any database. It lived there because that is where the scan happened to be
// built, and the consequence was measured on a live target: a Firebase project
// whose routes run on Cloud Run with the service account's own privilege, and
// a scan that reported "no application routes assessed".
//
// Nothing here may import a backend. That is the whole point: these checks run
// whatever was found behind the application, including nothing.
package application

import (
	"time"

	"github.com/eppser/unruly/internal/client"
	"github.com/eppser/unruly/internal/routes"
	"github.com/eppser/unruly/scan"
)

// Config is what the application checks need: the site, the shared clients and
// the operator's controls. No project reference, no anon key, no backend.
type Config struct {
	Site     string
	HARFiles []string
	// AllowedOrigins is the exact set of cross-origin application backends the
	// operator explicitly placed in scope.
	AllowedOrigins []string
	// Web is the ordinary HTTP client. Application routes are not an API
	// origin and must not inherit its headers.
	Web     *client.Client
	Limiter *client.Limiter
	Timeout time.Duration

	Concurrency int
	// MaxBundles is the operator's -max-bundles, threaded to the route reader
	// so the flag actually binds it.
	MaxBundles int
	// MaxRoutes bounds endpoint paths across every scoped application origin.
	MaxRoutes int
	// MaxBypassRoutes bounds the more expensive alternative-request matrix.
	MaxBypassRoutes int
	UserAgent       string

	Redact bool
	// AllowPOST is write consent. A POST to an application's own endpoint can
	// trigger side effects in a system this scanner knows nothing about.
	AllowPOST bool
	NoResidue bool

	SkipRoutes bool
	// RouteParams are values the operator supplied for path templates, so an
	// endpoint like /invoices/{id} can be probed as a record they named.
	RouteParams map[string]string
	// Principals are labelled identities (-principal a=<jwt>), so a record one
	// account reads can be asked for as another. Two are required: the check
	// compares three answers and cannot be made sound with fewer.
	Principals []string
}

// Stages is the ordered application scan.
//
// One stage today. The shape is what matters: history, preview deployments and
// subdomain enumeration are also application-level rather than database-level,
// and they stay in the Supabase plan for now only because each of them
// currently looks for a SUPABASE credential -- moving them needs that
// dependency broken first, which is a separate change and not one to fold in
// silently here.
func Stages(cfg Config) []scan.Stage {
	enabled := func(on bool, reason string, s scan.Stage) scan.Stage {
		if on {
			return s
		}
		return scan.Skip(s, reason)
	}
	return []scan.Stage{
		enabled(cfg.Site != "" && !cfg.SkipRoutes,
			"no -site was supplied, or -no-routes was set",
			RoutesStage{Opts: routes.Options{
				Web: cfg.Web, Site: cfg.Site, Concurrency: cfg.Concurrency,
				HARFiles:       append([]string(nil), cfg.HARFiles...),
				AllowedOrigins: cfg.AllowedOrigins,
				Redact:         cfg.Redact, Limiter: cfg.Limiter, Timeout: cfg.Timeout,
				MaxBundles: cfg.MaxBundles, MaxRoutes: cfg.MaxRoutes,
				MaxBypassRoutes: cfg.MaxBypassRoutes,
				AllowPOST:       cfg.AllowPOST, NoResidue: cfg.NoResidue,
				UserAgent:  cfg.UserAgent,
				Params:     routes.Params(cfg.RouteParams),
				Principals: routes.ParsePrincipals(cfg.Principals),
			}}),
	}
}
