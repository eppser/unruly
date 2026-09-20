package eval_test

import (
	"context"
	"testing"
	"time"

	"github.com/eppser/unruly/internal/postgrest"
	"github.com/eppser/unruly/internal/probe"
)

// A relation anyone may write to and nobody may read must be reported as
// writable.
//
// The shape is ordinary: INSERT granted, SELECT not. Every contact form,
// waitlist and abuse-report table looks like this. The scanner reported it as
// blocked, because its INSERT probe asks for the row back so a landed row can
// be removed, and building that response needs SELECT -- so PostgREST answers
// 401 with SQLSTATE 42501, which is the same code a genuine row-level-security
// refusal produces.
//
// Measured on the fixture, PostgREST v14.3:
//
//	Prefer: return=representation  ->  401 42501, 0 rows created
//	Prefer: return=minimal         ->  201,       1 row  created
//
// Same relation, same credential, opposite verdicts. 42501 from a
// representation probe does not mean "the write was refused"; it means the
// write and the read could not be told apart, and the scan must either
// separate them or say it could not.
func TestWriteOnlyRelationIsNotReportedAsBlocked(t *testing.T) {
	_, c := loadFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	const rel = "insert_no_select"
	pr := probe.Run(ctx, c, []string{rel}, probe.Options{Write: true, SampleRows: 2})

	var got postgrest.WriteState
	var why string
	for _, r := range pr.Relations {
		if r.Name == rel {
			got, why = r.Write, r.WriteWhy
		}
	}

	if got == postgrest.WriteBlockedRLS {
		t.Errorf("%s accepts anonymous INSERT and was reported as blocked (%q). A "+
			"false negative on a table that takes anonymous writes is the failure "+
			"this scanner exists to refuse", rel, why)
	}
	// Reported writable is the right answer; reported undetermined is an
	// acceptable one, because it tells the reader to look. Silence is not.
	if got != postgrest.WriteReached && got != postgrest.WriteInconclusive {
		t.Errorf("%s was reported as %v (%q), which is neither writable nor "+
			"undetermined", rel, got, why)
	}
	if why == "" {
		t.Error("no reason recorded, so a reader cannot tell which of the two it was")
	}
	t.Logf("insert_no_select -> state=%v why=%q", got, why)
}
