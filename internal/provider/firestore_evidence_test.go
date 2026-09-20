package provider

import (
	"strings"
	"testing"
)

// The published command must be the data-minimising one the scan actually ran.
//
// firestoreReadable sends a structuredQuery with select.fields = __name__,
// which is the whole reason this check can claim it retrieves document paths
// and no field values. The curl printed as evidence omitted the projection, so
// replaying it returns FULL DOCUMENTS.
//
// That is not a cosmetic drift. The finding tells the reader that values were
// never retrieved and then hands them a command that retrieves values -- from
// somebody else's database, in a report they may well paste to a colleague or
// a customer. The tool's most load-bearing safety claim is contradicted by the
// tool's own output.
func TestFirestoreEvidenceReplaysTheMinimisingQuery(t *testing.T) {
	for _, tc := range []struct {
		name string
		req  string
	}{
		{"anonymous read", firestoreReadEvidence("posts")},
		{"authenticated read", firestoreAuthedEvidence("posts")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if !strings.Contains(tc.req, "__name__") {
				t.Errorf("the published command omits the __name__ projection, so replaying "+
					"it retrieves field values the scan deliberately did not take:\n  %s", tc.req)
			}
			if !strings.Contains(tc.req, "\"limit\":5") {
				t.Errorf("the published command uses a different limit than the scan did, "+
					"so it does not reproduce the observation:\n  %s", tc.req)
			}
		})
	}
}
