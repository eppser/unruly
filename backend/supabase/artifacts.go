package supabase

import (
	"github.com/eppser/unruly/internal/escalate"
	"github.com/eppser/unruly/internal/schemas"
)

// Schemas is what the schemas stage publishes.
//
// The two halves travel together because they are one fact: which schemas
// PostgREST exposes beyond the default, and what was found in each. As
// separate out-params a caller could hold the scan list without the discovery
// that explains it, and the log line that names the extra schemas would then
// disagree with the scans that follow it.
type Schemas struct {
	Scans      []SchemaScan
	Discovered schemas.Result
}

// Escalation is what the escalation stage publishes.
//
// Both passes, in one artifact. The default schema's comparison and the
// per-schema ones answer the same question -- what does signing up gain -- and
// a consumer holding only the first under-reports every project with an extra
// exposed schema, which is exactly the shape the schemas pass exists to catch.
type Escalation struct {
	Result    escalate.Result
	PerSchema []SchemaEscalation
}

// Credential is an elevated token the scan ACQUIRED, as opposed to one the
// operator supplied.
//
// It exists because the two arrive at different times. A supplied token is
// known before the stage list is built; a minted one is not -- unruly creates
// an account mid-scan when writes were authorised and no token was given, and
// that is how the middle tier of the threat model gets measured at all.
//
// Baking the token into the stage at construction time therefore silently
// disabled the escalation pass on exactly the path that needs it most: the
// stage was wrapped as "not run: no -user-jwt was supplied" and then said so
// while the scan held a working credential.
type Credential struct {
	Token string
	// Role is what the token claims to be, for the finding's wording.
	Role string
}
