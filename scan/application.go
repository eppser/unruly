package scan

// ApplicationCoverage is the denominator for backend-independent route
// assessment. It is published by the application workload so the engine never
// needs to import the route implementation merely to count what ran.
type ApplicationCoverage struct {
	Routes  int
	Origins int
}
