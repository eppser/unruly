package client

import "fmt"

// Version is stamped at build time from git describe.
var Version = "dev"

// UserAgent identifies this scanner to the systems it probes.
//
// Defined once and shared, for two reasons. It was previously the bare string
// "unruly" hardcoded in five places, which drifts and cannot carry a
// version. More importantly: when an operator finds unexplained traffic in
// their logs, the User-Agent is how they learn what it was and where to
// complain. A scanner that probes third-party systems and does not say what it
// is has decided its own convenience matters more than their ability to
// respond.
func UserAgent() string {
	return fmt.Sprintf("unruly/%s (+https://github.com/eppser/unruly)", Version)
}
