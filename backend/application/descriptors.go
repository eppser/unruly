package application

import (
	"github.com/eppser/unruly/internal/routes"
	"github.com/eppser/unruly/scan"
)

var (
	ArtRoutes   = scan.ArtifactOf[routes.Result]()
	ArtAccess   = scan.ArtifactOf[scan.Access]()
	ArtCoverage = scan.ArtifactOf[scan.ApplicationCoverage]()
)

// RoutesStage declares itself, so the application plan is validated like any
// other. It requires nothing: an application's endpoints are discovered from
// the application, not from a database.
func (r RoutesStage) Describe() scan.StageDescriptor {
	// POSTing to an application's own endpoint can trigger side effects in a
	// system this scanner knows nothing about, which is why it needs -write.
	return scan.StageDescriptor{ID: "routes", Produces: []scan.ArtifactType{ArtRoutes, ArtAccess, ArtCoverage},
		MutatesTarget: r.Opts.AllowPOST}
}
