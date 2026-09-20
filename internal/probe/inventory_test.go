package probe

import (
	"strings"
	"testing"

	"github.com/eppser/unruly/internal/finding"
	"github.com/eppser/unruly/internal/postgrest"
)

// Two schemas, two inventories, one report.
//
// A finding is deduplicated on id, protocol, matched URL and resource. The
// inventory finding answered to the same three of those for every schema, so a
// project exposing a second schema had that schema's protected relations built
// and then dropped. On the lab that hid two of the three relations in
// reporting, and the survivor was the one that leaks -- the failure direction
// that makes a target look cleaner than it is.
func TestEachSchemaKeepsItsOwnInventory(t *testing.T) {
	public := inventoryFinding("http://x/rest/v1", []Relation{
		{Name: "sessions", Read: postgrest.ReadDenied},
	})
	reporting := inventoryFinding("http://x/rest/v1", []Relation{
		{Name: "revenue_secrets", Schema: "reporting", Read: postgrest.ReadDenied},
	})
	if public == nil || reporting == nil {
		t.Fatal("a schema with a protected relation produced no inventory finding")
	}
	kept := finding.Dedup([]finding.Finding{*public, *reporting})
	if len(kept) != 2 {
		t.Errorf("deduplication kept %d of 2 inventories: a second schema's protected "+
			"relations never reach the report, and nothing in it says so", len(kept))
	}
	if !strings.Contains(reporting.Description, "reporting.revenue_secrets") {
		t.Errorf("the inventory does not qualify the relation: %s", reporting.Description)
	}
	// The remediation is pasted into psql, where querying the wrong schema
	// returns nothing and reads as confirmation.
	if !strings.Contains(reporting.Remediation, "'reporting'") {
		t.Errorf("the remediation asks about the wrong schema:\n%s", reporting.Remediation)
	}
	if !strings.Contains(public.Remediation, "'public'") {
		t.Errorf("the default schema's remediation lost its schema:\n%s", public.Remediation)
	}
}
