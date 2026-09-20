package graphql

import (
	"strings"
	"testing"
)

// The published query must be the query that was run.
//
// The probe builds "{ XCollection(first: N) ... }" where N is o.SampleRows, an
// operator-controlled flag (-sample, default 3). The evidence hardcoded
// "first: 3", so it was right until somebody passed -sample 10 and wrong
// afterwards -- silently, because a curl that returns 10 rows where the report
// says 3 looks like the tool miscounted rather than like the tool printed a
// command it never ran.
//
// Third instance of one pattern today: the prose a finding hands the operator
// is read by no test, so it drifts from the code that produced it.
func TestGraphQLEvidenceCarriesTheLimitThatWasUsed(t *testing.T) {
	for _, n := range []int{3, 10} {
		req := bypassFinding("https://x/graphql/v1", "posts", []string{"a"}, n).Evidence.Request
		want := "first: " + itoa(n)
		if !strings.Contains(req, want) {
			t.Errorf("-sample %d was used and the published command says something else, "+
				"so replaying it does not reproduce the report:\n  %s", n, req)
		}
	}
}

func itoa(n int) string {
	if n == 3 {
		return "3"
	}
	return "10"
}
