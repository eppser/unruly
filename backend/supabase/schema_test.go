package supabase

import (
	"testing"

	"github.com/eppser/unruly/internal/postgrest"
	"github.com/eppser/unruly/internal/probe"
)

// SchemaScan is what one non-default schema's pass produced.
//
// It was a type declared INSIDE scanTarget, which meant every stage that
// consumes it -- realtime, escalation, the summary -- had to live inside that
// function too. A type scoped to a function scopes its consumers to the same
// function, so this is not bookkeeping: it is one of the things holding the
// 1,400-line body together.
func TestASchemaScanCarriesWhatLaterStagesNeed(t *testing.T) {
	s := SchemaScan{
		Name:      "reporting",
		Relations: []string{"daily_revenue"},
		Result: probe.Result{Relations: []probe.Relation{{
			Name: "daily_revenue", Read: postgrest.ReadExposed, Rows: 3,
		}}},
	}
	if s.Name != "reporting" {
		t.Errorf("Name %q", s.Name)
	}
	if len(s.Relations) != 1 {
		t.Errorf("Relations %v", s.Relations)
	}
	// Realtime steers on which relations were readable, and escalation needs
	// the whole result. Both must survive the move out of main.
	if got := s.Result.ReadExposed(); len(got) != 1 || got[0] != "daily_revenue" {
		t.Errorf("ReadExposed %v, want [daily_revenue]", got)
	}
}

// The zero value is usable: a schema that produced nothing is still a schema
// the scan looked at, and later stages iterate over it without special-casing.
func TestAZeroSchemaScanIsSafeToConsume(t *testing.T) {
	var s SchemaScan
	if got := s.Result.ReadExposed(); len(got) != 0 {
		t.Errorf("a zero SchemaScan reported readable relations: %v", got)
	}
	if len(s.Relations) != 0 {
		t.Errorf("a zero SchemaScan reported relations: %v", s.Relations)
	}
}
